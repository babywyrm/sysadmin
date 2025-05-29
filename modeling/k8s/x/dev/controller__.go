// cmd/challenge-controller/main.go
package main

import (
    "context"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "flag"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "path"
    "strings"
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
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "gopkg.in/yaml.v2"
)

type TierConfig struct {
    MaxChallenges int    `yaml:"maxChallenges"`
    CPU           string `yaml:"maxCPU"`
    Memory        string `yaml:"maxMemory"`
}

type Config struct {
    TrustDomain          string                `yaml:"trustDomain"`
    ProjectDomain        string                `yaml:"projectDomain"`
    ImageRegistry        string                `yaml:"imageRegistry"`
    DefaultChallengeTTL  time.Duration         `yaml:"defaultChallengeTTL"`
    TierLimits           map[string]TierConfig `yaml:"tierLimits"`
    SPIREServerAddr      string                `yaml:"spireServerAddr"`
    RedisAddr            string                `yaml:"redisAddr"`
    RedisPassword        string                `yaml:"redisPassword"`
    JWTPrivateKeyPath    string                `yaml:"jwtPrivateKeyPath"`
    ChallengeNamespace   string                `yaml:"challengeNamespace"`
    IstioNamespace       string                `yaml:"istioNamespace"`
    SPIRERootEntryParent string                `yaml:"spireParentID"`
}

type SpawnRequest struct {
    ChallengeType string `json:"challengeType"`
    Tier          string `json:"tier"`
}

type SpawnResponse struct {
    ID        string    `json:"id"`
    Endpoint  string    `json:"endpoint"`
    ExpiresAt time.Time `json:"expiresAt"`
    Token     string    `json:"token"`
}

type Controller struct {
    cfg            Config
    k8sClient      *kubernetes.Clientset
    istioClient    *istioclient.Clientset
    spireClient    serverv1.RegistrationClient
    redisClient    *redis.Client
    jwtPrivateKey  *rsa.PrivateKey
    trustDomain    spiffeid.TrustDomain
}

func main() {
    // Parse flags
    var cfgPath string
    flag.StringVar(&cfgPath, "config", "/etc/project-x/config.yaml", "")
    flag.Parse()

    // Load config
    data, err := ioutil.ReadFile(cfgPath)
    if err != nil {
        panic(fmt.Errorf("read config: %w", err))
    }
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        panic(fmt.Errorf("parse config: %w", err))
    }

    // Load JWT private key
    keyData, err := ioutil.ReadFile(cfg.JWTPrivateKeyPath)
    if err != nil {
        panic(fmt.Errorf("read jwt key: %w", err))
    }
    block, _ := pem.Decode(keyData)
    if block == nil {
        panic("failed to decode PEM block")
    }
    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        panic(fmt.Errorf("parse private key: %w", err))
    }

    // In-cluster Kubernetes config
    restCfg, err := rest.InClusterConfig()
    if err != nil {
        panic(fmt.Errorf("in-cluster config: %w", err))
    }
    k8sClient, err := kubernetes.NewForConfig(restCfg)
    if err != nil {
        panic(fmt.Errorf("k8s client: %w", err))
    }
    istioClient, err := istioclient.NewForConfig(restCfg)
    if err != nil {
        panic(fmt.Errorf("istio client: %w", err))
    }

    // SPIRE gRPC client
    conn, err := grpc.Dial(cfg.SPIREServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        panic(fmt.Errorf("dial spire: %w", err))
    }
    spireClient := serverv1.NewRegistrationClient(conn)

    // Redis client
    rdb := redis.NewClient(&redis.Options{
        Addr:     cfg.RedisAddr,
        Password: cfg.RedisPassword,
    })

    // Trust domain
    td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
    if err != nil {
        panic(fmt.Errorf("invalid trust domain: %w", err))
    }

    ctrl := &Controller{
        cfg:           cfg,
        k8sClient:     k8sClient,
        istioClient:   istioClient,
        spireClient:   spireClient,
        redisClient:   rdb,
        jwtPrivateKey: priv,
        trustDomain:   td,
    }

    http.HandleFunc("/api/challenges", ctrl.handleSpawn)
    http.HandleFunc("/api/challenges/", ctrl.handleDestroy) // DELETE /api/challenges/{id}
    http.ListenAndServe(":8080", nil)
}

// handleSpawn creates a new challenge
func (c *Controller) handleSpawn(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    ctx := r.Context()

    // Extract user ID from header (populated by Ambassador)
    userID := r.Header.Get("X-User-ID")
    if userID == "" {
        http.Error(w, "missing user", http.StatusUnauthorized)
        return
    }

    // Parse request
    var req SpawnRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }

    // Tier validation
    tierCfg, ok := c.cfg.TierLimits[req.Tier]
    if !ok {
        http.Error(w, "invalid tier", http.StatusForbidden)
        return
    }

    // Check existing challenge count in Redis
    countKey := fmt.Sprintf("user:%s:tier:%s:count", userID, req.Tier)
    cnt, _ := c.redisClient.Get(ctx, countKey).Int()
    if cnt >= tierCfg.MaxChallenges {
        http.Error(w, "challenge limit reached", http.StatusForbidden)
        return
    }

    // Generate unique ID
    challengeID := uuid.NewString()

    // Construct SPIFFE ID
    spiffeID := spiffeid.Must(c.trustDomain, "challenge", challengeID)

    // Create Kubernetes Deployment
    deploy := c.buildDeployment(userID, req.Tier, req.ChallengeType, challengeID, spiffeID.String())
    if _, err := c.k8sClient.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Create(ctx, deploy, metav1.CreateOptions{}); err != nil {
        http.Error(w, "failed to create deployment", http.StatusInternalServerError)
        return
    }

    // Create Service
    svc := c.buildService(challengeID)
    if _, err := c.k8sClient.CoreV1().
        Services(c.cfg.ChallengeNamespace).
        Create(ctx, svc, metav1.CreateOptions{}); err != nil {
        http.Error(w, "failed to create service", http.StatusInternalServerError)
        return
    }

    // Register SPIRE entry
    entryReq := &serverv1.CreateEntryRequest{
        Entry: &serverv1.Entry{
            SpiffeId: spiffeID.String(),
            ParentId: c.cfg.SPIRERootEntryParent,
            Selectors: []*serverv1.Selector{
                {Type: "k8s", Value: "ns:" + c.cfg.ChallengeNamespace},
                {Type: "k8s", Value: "pod-label:challenge-id:" + challengeID},
            },
            Ttl: int32(c.cfg.DefaultChallengeTTL.Seconds()),
            Clusters: []string{c.cfg.ChallengeNamespace},
            FederationRelationships: []string{},
            Extra: map[string]string{
                "user_id":        userID,
                "tier":           req.Tier,
                "challenge_type": req.ChallengeType,
                "challenge_id":   challengeID,
            },
        },
    }
    entryResp, err := c.spireClient.CreateEntry(ctx, entryReq)
    if err != nil {
        http.Error(w, "failed to register spire entry", http.StatusInternalServerError)
        return
    }
    // Store mapping for cleanup
    redisKey := fmt.Sprintf("challenge:%s:entry", challengeID)
    _ = c.redisClient.Set(ctx, redisKey, entryResp.EntryId,
        c.cfg.DefaultChallengeTTL).Err()

    // Create Istio VirtualService
    vs := c.buildVirtualService(challengeID, userID)
    if _, err := c.istioClient.NetworkingV1alpha3().
        VirtualServices(c.cfg.ChallengeNamespace).
        Create(ctx, vs, metav1.CreateOptions{}); err != nil {
        http.Error(w, "failed to create virtualservice", http.StatusInternalServerError)
        return
    }

    // Create Istio AuthorizationPolicy
    ap := c.buildAuthPolicy(challengeID, userID)
    if _, err := c.istioClient.SecurityV1beta1().
        AuthorizationPolicies(c.cfg.ChallengeNamespace).
        Create(ctx, ap, metav1.CreateOptions{}); err != nil {
        http.Error(w, "failed to create authorizationpolicy", http.StatusInternalServerError)
        return
    }

    // Increment user challenge count
    c.redisClient.Incr(ctx, countKey)

    // Generate scoped JWT token for challenge
    token, err := c.makeChallengeToken(userID, challengeID)
    if err != nil {
        http.Error(w, "failed to create token", http.StatusInternalServerError)
        return
    }

    // Build endpoint URL
    endpoint := fmt.Sprintf("https://%s.%s?token=%s",
        challengeID, c.cfg.ProjectDomain, token)

    resp := SpawnResponse{
        ID:        challengeID,
        Endpoint:  endpoint,
        ExpiresAt: time.Now().Add(c.cfg.DefaultChallengeTTL),
        Token:     token,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

// handleDestroy cleans up a challenge
func (c *Controller) handleDestroy(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    ctx := r.Context()
    // URL: /api/challenges/{id}
    id := path.Base(r.URL.Path)
    userID := r.Header.Get("X-User-ID")
    if userID == "" {
        http.Error(w, "missing user", http.StatusUnauthorized)
        return
    }

    // Retrieve SPIRE entry ID from Redis
    entryKey := fmt.Sprintf("challenge:%s:entry", id)
    entryID, err := c.redisClient.Get(ctx, entryKey).Result()
    if err != nil {
        http.Error(w, "entry not found", http.StatusNotFound)
        return
    }
    // Delete SPIRE entry
    _, _ = c.spireClient.DeleteEntry(ctx, &serverv1.DeleteEntryRequest{Id: entryID})

    // Get deployment to fetch tier and annotations
    deploy, err := c.k8sClient.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Get(ctx, id, metav1.GetOptions{})
    if err == nil {
        tier := deploy.Annotations["project-x/tier"]
        countKey := fmt.Sprintf("user:%s:tier:%s:count", userID, tier)
        c.redisClient.Decr(ctx, countKey)
    }
    // Delete Istio resources
    _ = c.istioClient.NetworkingV1alpha3().
        VirtualServices(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})
    _ = c.istioClient.SecurityV1beta1().
        AuthorizationPolicies(c.cfg.ChallengeNamespace).
        Delete(ctx, id+"-authz", metav1.DeleteOptions{})

    // Delete Kubernetes resources
    _ = c.k8sClient.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})
    _ = c.k8sClient.CoreV1().
        Services(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})

    // Clean Redis mapping
    c.redisClient.Del(ctx, entryKey)

    w.WriteHeader(http.StatusNoContent)
}

// buildDeployment constructs the challenge Deployment
func (c *Controller) buildDeployment(
    userID, tier, chalType, id, spiffeID string,
) *appsv1.Deployment {
    labels := map[string]string{
        "app":                        "challenge",
        "project-x/challenge-id":     id,
        "project-x/user-id":          userID,
        "project-x/tier":             tier,
        "project-x/challenge-type":   chalType,
    }
    annotations := map[string]string{
        "spiffe.io/spiffe-id": spiffeID,
        "sidecar.istio.io/inject": "true",
        "project-x/user-id":       userID,
        "project-x/tier":          tier,
    }
    tierCfg := c.cfg.TierLimits[tier]
    replicas := int32(1)
    return &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:        id,
            Namespace:   c.cfg.ChallengeNamespace,
            Labels:      labels,
            Annotations: annotations,
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: &replicas,
            Selector: &metav1.LabelSelector{MatchLabels: labels},
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels:      labels,
                    Annotations: annotations,
                },
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
                        Resources: corev1.ResourceRequirements{
                            Limits: corev1.ResourceList{
                                corev1.ResourceCPU:    resourceMustParse(tierCfg.CPU),
                                corev1.ResourceMemory: resourceMustParse(tierCfg.Memory),
                            },
                            Requests: corev1.ResourceList{
                                corev1.ResourceCPU:    resourceMustParse("100m"),
                                corev1.ResourceMemory: resourceMustParse("128Mi"),
                            },
                        },
                        Ports: []corev1.ContainerPort{{
                            ContainerPort: 8080,
                            Protocol:      corev1.ProtocolTCP,
                        }},
                        Env: []corev1.EnvVar{
                            {Name: "SPIFFE_ENDPOINT_SOCKET", Value: "/run/spire/sockets/agent.sock"},
                            {Name: "CHALLENGE_ID", Value: id},
                            {Name: "USER_ID", Value: userID},
                            {Name: "TIER", Value: tier},
                            {Name: "CHALLENGE_TYPE", Value: chalType},
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
                                Type: hostPathDirectoryOrCreate(),
                            },
                        },
                    }},
                },
            },
        },
    }
}

// buildService constructs the ClusterIP service for the challenge
func (c *Controller) buildService(id string) *corev1.Service {
    return &corev1.Service{
        ObjectMeta: metav1.ObjectMeta{
            Name:      id,
            Namespace: c.cfg.ChallengeNamespace,
            Labels:    map[string]string{"project-x/challenge-id": id},
        },
        Spec: corev1.ServiceSpec{
            Selector: map[string]string{"project-x/challenge-id": id},
            Ports: []corev1.ServicePort{{
                Name:       "http",
                Protocol:   corev1.ProtocolTCP,
                Port:       8080,
                TargetPort: intstr.FromInt(8080),
            }},
            Type: corev1.ServiceTypeClusterIP,
        },
    }
}

// buildVirtualService builds an Istio VirtualService for the challenge
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
                        "authorization": {MatchType: &istiov1alpha3.StringMatch_Regex{
                            Regex: fmt.Sprintf(".*challenge_id:%s.*", id),
                        }},
                    },
                }},
                Route: []*istiov1alpha3.HTTPRouteDestination{{
                    Destination: &istiov1alpha3.Destination{
                        Host: fmt.Sprintf("%s.%s.svc.cluster.local", id, c.cfg.ChallengeNamespace),
                        Port: &istiov1alpha3.PortSelector{Number: 8080},
                    },
                }},
                Timeout: &durationpb.Duration{Seconds: 300},
            }},
        },
    }
}

// buildAuthPolicy builds an Istio AuthorizationPolicy for the challenge
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
                            fmt.Sprintf("cluster.local/ns/%s/sa/istio-ingressgateway-service-account",
                                c.cfg.IstioNamespace),
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

// makeChallengeToken generates a scoped JWT for challenge access
func (c *Controller) makeChallengeToken(userID, chalID string) (string, error) {
    now := time.Now()
    claims := jwt.MapClaims{
        "iss":          "project-x.auth",
        "sub":          userID,
        "aud":          fmt.Sprintf("challenge:%s", chalID),
        "iat":          now.Unix(),
        "nbf":          now.Unix(),
        "exp":          now.Add(c.cfg.DefaultChallengeTTL).Unix(),
        "user_id":      userID,
        "challenge_id": chalID,
        "scope":        "challenge_access",
    }
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    return token.SignedString(c.jwtPrivateKey)
}

// Utility functions

func boolPtr(b bool) *bool       { return &b }
func int64Ptr(i int64) *int64    { return &i }
func hostPathDirectoryOrCreate() *corev1.HostPathType {
    t := corev1.HostPathDirectoryOrCreate
    return &t
}
func resourceMustParse(s string) resource.Quantity {
    r, err := resource.ParseQuantity(s)
    if err != nil {
        panic(fmt.Sprintf("invalid resource quantity: %s", s))
    }
    return r
}
