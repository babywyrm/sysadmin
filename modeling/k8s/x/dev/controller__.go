// cmd/challenge-controller/main.go
package main

import (
    "context"
    "crypto/rsa"
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "flag"
    "fmt"
    "io/ioutil"
    "net/http"
    "path"
    "time"

    "github.com/go-redis/redis/v8"
    "github.com/google/uuid"
    "github.com/golang-jwt/jwt/v4"
    "github.com/spiffe/go-spiffe/v2/spiffeid"
    serverv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/v1"
    istioclient "istio.io/client-go/pkg/clientset/versioned"
    istiov1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
    securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/util/intstr"
    "k8s.io/apimachinery/pkg/util/wait"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "gopkg.in/yaml.v2"
    "k8s.io/apimachinery/pkg/api/resource"
    "google.golang.org/protobuf/types/known/durationpb"
)

// TierConfig defines per-tier resource & concurrency limits.
type TierConfig struct {
    MaxChallenges int    `yaml:"maxChallenges"`
    CPU           string `yaml:"maxCPU"`
    Memory        string `yaml:"maxMemory"`
}

// Config holds all controller configuration loaded from YAML.
type Config struct {
    TrustDomain         string                `yaml:"trustDomain"`
    ProjectDomain       string                `yaml:"projectDomain"`
    ImageRegistry       string                `yaml:"imageRegistry"`
    DefaultTTL          time.Duration         `yaml:"defaultChallengeTTL"`
    TierLimits          map[string]TierConfig `yaml:"tierLimits"`
    SPIREServerAddr     string                `yaml:"spireServerAddr"`
    RedisAddr           string                `yaml:"redisAddr"`
    RedisPassword       string                `yaml:"redisPassword"`
    JWTPrivateKeyPath   string                `yaml:"jwtPrivateKeyPath"`
    ChallengeNamespace  string                `yaml:"challengeNamespace"`
    IstioNamespace      string                `yaml:"istioNamespace"`
    SPIREParentID       string                `yaml:"spireParentID"`
}

// SpawnRequest is the JSON payload for creating a challenge.
type SpawnRequest struct {
    ChallengeType string `json:"challengeType"`
    Tier          string `json:"tier"`
}

// SpawnResponse is returned to the user after a successful spawn.
type SpawnResponse struct {
    ID        string    `json:"id"`
    Endpoint  string    `json:"endpoint"`
    ExpiresAt time.Time `json:"expiresAt"`
    Token     string    `json:"token"`
}

// Controller orchestrates challenge lifecycle: k8s, SPIRE, Istio, Redis.
type Controller struct {
    cfg           Config
    k8sClient     *kubernetes.Clientset
    istioClient   *istioclient.Clientset
    spireClient   serverv1.RegistrationClient
    redisClient   *redis.Client
    jwtPrivateKey *rsa.PrivateKey
    trustDomain   spiffeid.TrustDomain
}

func main() {
    // 1. Load configuration
    configPath := flag.String("config", "/etc/project-x/config.yaml", "path to config")
    flag.Parse()
    cfg := mustLoadConfig(*configPath)

    // 2. Load JWT signing key
    privKey := mustLoadPrivateKey(cfg.JWTPrivateKeyPath)

    // 3. Initialize Kubernetes & Istio clients
    restCfg := must(rest.InClusterConfig())
    k8s := mustClient(kubernetes.NewForConfig, restCfg)
    istio := mustClient(istioclient.NewForConfig, restCfg)

    // 4. Connect to SPIRE gRPC
    spireConn := mustDial(cfg.SPIREServerAddr)
    spire := serverv1.NewRegistrationClient(spireConn)

    // 5. Connect to Redis
    rdb := redis.NewClient(&redis.Options{
        Addr:     cfg.RedisAddr,
        Password: cfg.RedisPassword,
    })

    // 6. Parse SPIFFE trust domain
    td := mustTrustDomain(cfg.TrustDomain)

    ctrl := &Controller{
        cfg:           cfg,
        k8sClient:     k8s,
        istioClient:   istio,
        spireClient:   spire,
        redisClient:   rdb,
        jwtPrivateKey: privKey,
        trustDomain:   td,
    }

    // 7. HTTP API
    http.HandleFunc("/api/challenges", ctrl.handleSpawn)
    http.HandleFunc("/api/challenges/", ctrl.handleDestroy)
    http.ListenAndServe(":8080", nil)
}

// handleSpawn validates the user, enforces tier limits, spawns the resources,
// registers with SPIRE, configures Istio, and returns the challenge endpoint.
func (c *Controller) handleSpawn(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    ctx := r.Context()
    userID := r.Header.Get("X-User-ID")
    if userID == "" {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // Parse and validate request
    var req SpawnRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    tierCfg, ok := c.cfg.TierLimits[req.Tier]
    if !ok {
        http.Error(w, "invalid tier", http.StatusForbidden)
        return
    }

    // Enforce per-user, per-tier concurrency
    countKey := fmt.Sprintf("user:%s:tier:%s:count", userID, req.Tier)
    if cnt, _ := c.redisClient.Get(ctx, countKey).Int(); cnt >= tierCfg.MaxChallenges {
        http.Error(w, "challenge limit reached", http.StatusForbidden)
        return
    }

    // Generate unique IDs
    challengeID := uuid.NewString()
    spiffeID := spiffeid.Must(c.trustDomain, "challenge", challengeID)

    // 1) Kubernetes: Deployment + Service
    deploy := c.buildDeployment(userID, req.Tier, req.ChallengeType, challengeID, spiffeID.String())
    if _, err := c.k8sClient.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Create(ctx, deploy, metav1.CreateOptions{}); err != nil {
        http.Error(w, "deployment failed", http.StatusInternalServerError)
        return
    }
    svc := c.buildService(challengeID)
    if _, err := c.k8sClient.CoreV1().
        Services(c.cfg.ChallengeNamespace).
        Create(ctx, svc, metav1.CreateOptions{}); err != nil {
        http.Error(w, "service failed", http.StatusInternalServerError)
        return
    }

    // 2) SPIRE: Register workload entry
    entryID, err := c.registerSpireEntry(ctx, spiffeID.String(), challengeID)
    if err != nil {
        http.Error(w, "SPIRE registration failed", http.StatusInternalServerError)
        return
    }
    // Persist entryID for cleanup
    c.redisClient.Set(ctx, fmt.Sprintf("challenge:%s:entry", challengeID),
        entryID, c.cfg.DefaultTTL)

    // 3) Istio: VirtualService + AuthorizationPolicy
    vs := c.buildVirtualService(challengeID, userID)
    c.istioClient.NetworkingV1alpha3().
        VirtualServices(c.cfg.ChallengeNamespace).
        Create(ctx, vs, metav1.CreateOptions{})

    ap := c.buildAuthPolicy(challengeID, userID)
    c.istioClient.SecurityV1beta1().
        AuthorizationPolicies(c.cfg.ChallengeNamespace).
        Create(ctx, ap, metav1.CreateOptions{})

    // 4) Increment user count
    c.redisClient.Incr(ctx, countKey)

    // 5) Issue scoped JWT and respond
    token, err := c.makeChallengeToken(userID, challengeID)
    if err != nil {
        http.Error(w, "token issuance failed", http.StatusInternalServerError)
        return
    }
    endpoint := fmt.Sprintf("https://%s.%s?token=%s",
        challengeID, c.cfg.ProjectDomain, token)
    resp := SpawnResponse{
        ID:        challengeID,
        Endpoint:  endpoint,
        ExpiresAt: time.Now().Add(c.cfg.DefaultTTL),
        Token:     token,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

// handleDestroy tear-down a challenge: revokes SPIRE entry, deletes Istio + k8s,
// updates Redis, and returns 204 No Content.
func (c *Controller) handleDestroy(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    ctx := r.Context()
    id := path.Base(r.URL.Path)
    userID := r.Header.Get("X-User-ID")
    if userID == "" {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // 1) Revoke SPIRE entry
    entryKey := fmt.Sprintf("challenge:%s:entry", id)
    entryID, err := c.redisClient.Get(ctx, entryKey).Result()
    if err == nil {
        c.spireClient.DeleteEntry(ctx, &serverv1.DeleteEntryRequest{Id: entryID})
    }

    // 2) Decrement user count
    if deploy, err := c.k8sClient.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Get(ctx, id, metav1.GetOptions{}); err == nil {
        tier := deploy.Annotations["project-x/tier"]
        c.redisClient.Decr(ctx, fmt.Sprintf("user:%s:tier:%s:count", userID, tier))
    }

    // 3) Delete Istio resources
    c.istioClient.NetworkingV1alpha3().
        VirtualServices(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})
    c.istioClient.SecurityV1beta1().
        AuthorizationPolicies(c.cfg.ChallengeNamespace).
        Delete(ctx, id+"-authz", metav1.DeleteOptions{})

    // 4) Delete k8s Deployment & Service
    c.k8sClient.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})
    c.k8sClient.CoreV1().
        Services(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})

    // 5) Clean up Redis
    c.redisClient.Del(ctx, entryKey)
    w.WriteHeader(http.StatusNoContent)
}

// registerSpireEntry asks SPIRE to mint a workload entry for this challenge.
func (c *Controller) registerSpireEntry(
    ctx context.Context, spiffeID, challengeID string,
) (string, error) {
    req := &serverv1.CreateEntryRequest{
        Entry: &serverv1.Entry{
            SpiffeId: spiffeID,
            ParentId: c.cfg.SPIREParentID,
            Selectors: []*serverv1.Selector{
                {Type: "k8s", Value: "ns:" + c.cfg.ChallengeNamespace},
                {Type: "k8s", Value: "pod-label:project-x/challenge-id:" + challengeID},
            },
            Ttl: int32(c.cfg.DefaultTTL.Seconds()),
        },
    }
    resp, err := c.spireClient.CreateEntry(ctx, req)
    if err != nil {
        return "", err
    }
    return resp.Entry.Id, nil
}

// buildDeployment returns the k8s Deployment spec for a challenge pod.
func (c *Controller) buildDeployment(
    userID, tier, chalType, id, spiffeID string,
) *appsv1.Deployment {
    labels := map[string]string{
        "project-x/challenge-id":   id,
        "project-x/user-id":        userID,
        "project-x/tier":           tier,
        "project-x/challenge-type": chalType,
    }
    ann := map[string]string{
        "spiffe.io/spiffe-id": spiffeID,
        "sidecar.istio.io/inject": "true",
    }
    tc := c.cfg.TierLimits[tier]
    replicas := int32(1)

    return &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:        id,
            Namespace:   c.cfg.ChallengeNamespace,
            Labels:      labels,
            Annotations: ann,
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: &replicas,
            Selector: &metav1.LabelSelector{MatchLabels: labels},
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: ann},
                Spec: corev1.PodSpec{
                    ServiceAccountName:           "challenge-runner",
                    AutomountServiceAccountToken: boolPtr(false),
                    SecurityContext: &corev1.PodSecurityContext{
                        RunAsNonRoot: boolPtr(true),
                        RunAsUser:    int64Ptr(65534),
                        FSGroup:      int64Ptr(65534),
                    },
                    Containers: []corev1.Container{{
                        Name:  "challenge",
                        Image: fmt.Sprintf("%s/%s:%s", c.cfg.ImageRegistry, chalType, tier),
                        Ports: []corev1.ContainerPort{{ContainerPort: 8080}},
                        Env: []corev1.EnvVar{
                            {Name: "SPIFFE_ENDPOINT_SOCKET", Value: "/run/spire/sockets/agent.sock"},
                            {Name: "CHALLENGE_ID", Value: id},
                            {Name: "USER_ID", Value: userID},
                            {Name: "TIER", Value: tier},
                        },
                        Resources: corev1.ResourceRequirements{
                            Limits: corev1.ResourceList{
                                corev1.ResourceCPU:    mustParse(tc.CPU),
                                corev1.ResourceMemory: mustParse(tc.Memory),
                            },
                            Requests: corev1.ResourceList{
                                corev1.ResourceCPU:    mustParse("100m"),
                                corev1.ResourceMemory: mustParse("128Mi"),
                            },
                        },
                        VolumeMounts: []corev1.VolumeMount{{
                            Name:      "spire-agent-socket",
                            MountPath: "/run/spire/sockets",
                            ReadOnly:  true,
                        }},
                    }},
                    Volumes: []corev1.Volume{{
                        Name: "spire-agent-socket",
                        VolumeSource: corev1.VolumeSource{
                            HostPath: &corev1.HostPathVolumeSource{
                                Path: "/run/spire/sockets",
                                Type: hostPathDirOrCreate(),
                            },
                        },
                    }},
                },
            },
        },
    }
}

// buildService returns the k8s Service for a challenge deployment.
func (c *Controller) buildService(id string) *corev1.Service {
    return &corev1.Service{
        ObjectMeta: metav1.ObjectMeta{
            Name:      id,
            Namespace: c.cfg.ChallengeNamespace,
        },
        Spec: corev1.ServiceSpec{
            Selector: map[string]string{"project-x/challenge-id": id},
            Ports:    []corev1.ServicePort{{Port: 8080, TargetPort: intstr.FromInt(8080)}},
        },
    }
}

// buildVirtualService constructs an Istio VirtualService for challenge routing.
func (c *Controller) buildVirtualService(id, userID string) *istiov1alpha3.VirtualService {
    host := fmt.Sprintf("%s.%s", id, c.cfg.ProjectDomain)
    return &istiov1alpha3.VirtualService{
        ObjectMeta: metav1.ObjectMeta{
            Name:      id,
            Namespace: c.cfg.ChallengeNamespace,
        },
        Spec: istiov1alpha3.VirtualService{
            Hosts:    []string{host},
            Gateways: []string{"project-x-gateway"},
            Http: []*istiov1alpha3.HTTPRoute{{
                Match: []*istiov1alpha3.HTTPMatchRequest{{
                    Headers: map[string]*istiov1alpha3.StringMatch{
                        "authorization": {
                            MatchType: &istiov1alpha3.StringMatch_Regex{
                                Regex: fmt.Sprintf(".*challenge_id:%s.*", id),
                            },
                        },
                    },
                }},
                Route: []*istiov1alpha3.HTTPRouteDestination{{
                    Destination: &istiov1alpha3.Destination{
                        Host: fmt.Sprintf("%s.%s.svc.cluster.local", id, c.cfg.ChallengeNamespace),
                        Port: &istiov1alpha3.PortSelector{Number: 8080},
                    },
                }},
                Timeout: &durationpb.Duration{Seconds: int64(c.cfg.DefaultTTL.Seconds())},
            }},
        },
    }
}

// buildAuthPolicy constructs an Istio AuthorizationPolicy enforcing
// that only the correct scoped JWT may access the challenge.
func (c *Controller) buildAuthPolicy(id, userID string) *securityv1beta1.AuthorizationPolicy {
    return &securityv1beta1.AuthorizationPolicy{
        ObjectMeta: metav1.ObjectMeta{
            Name:      id + "-authz",
            Namespace: c.cfg.ChallengeNamespace,
        },
        Spec: securityv1beta1.AuthorizationPolicy{
            Selector: &securityv1beta1.WorkloadSelector{
                MatchLabels: map[string]string{"project-x/challenge-id": id},
            },
            Action: securityv1beta1.AuthorizationPolicy_ALLOW,
            Rules: []*securityv1beta1.Rule{{
                From: []*securityv1beta1.Rule_From{{
                    Source: &securityv1beta1.Source{
                        Principals: []string{
                            fmt.Sprintf("cluster.local/ns/%s/sa/istio-ingressgateway-service-account", c.cfg.IstioNamespace),
                        },
                    },
                }},
                When: []*securityv1beta1.Condition{
                    {Key: "request.auth.claims.challenge_id", Values: []string{id}},
                    {Key: "request.auth.claims.user_id", Values: []string{userID}},
                },
            }},
        },
    }
}

// makeChallengeToken issues a short-lived JWT scoped to this challenge.
func (c *Controller) makeChallengeToken(userID, chalID string) (string, error) {
    now := time.Now()
    claims := jwt.MapClaims{
        "iss":          "project-x.auth",
        "sub":          userID,
        "aud":          fmt.Sprintf("challenge:%s", chalID),
        "iat":          now.Unix(),
        "nbf":          now.Unix(),
        "exp":          now.Add(c.cfg.DefaultTTL).Unix(),
        "user_id":      userID,
        "challenge_id": chalID,
        "scope":        "challenge_access",
    }
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    return token.SignedString(c.jwtPrivateKey)
}

// ------------------ Utility Functions ------------------

func must[T any](v T, err error) T {
    if err != nil {
        panic(err)
    }
    return v
}

func mustClient[T any](fn func(*rest.Config) (T, error), cfg *rest.Config) T {
    client, err := fn(cfg)
    if err != nil {
        panic(err)
    }
    return client
}

func mustDial(addr string) *grpc.ClientConn {
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        panic(err)
    }
    return conn
}

func mustTrustDomain(s string) spiffeid.TrustDomain {
    td, err := spiffeid.TrustDomainFromString(s)
    if err != nil {
        panic(err)
    }
    return td
}

func mustLoadConfig(path string) Config {
    b, err := ioutil.ReadFile(path)
    if err != nil {
        panic(err)
    }
    var cfg Config
    if err := yaml.Unmarshal(b, &cfg); err != nil {
        panic(err)
    }
    return cfg
}

func mustLoadPrivateKey(path string) *rsa.PrivateKey {
    b, err := ioutil.ReadFile(path)
    if err != nil {
        panic(err)
    }
    block, _ := pem.Decode(b)
    if block == nil {
        panic("invalid PEM data")
    }
    key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        panic(err)
    }
    return key
}

func boolPtr(b bool) *bool       { return &b }
func int64Ptr(i int64) *int64    { return &i }
func hostPathDirOrCreate() *corev1.HostPathType {
    t := corev1.HostPathDirectoryOrCreate
    return &t
}
func mustParse(s string) resource.Quantity {
    q, err := resource.ParseQuantity(s)
    if err != nil {
        panic(err)
    }
    return q
}

