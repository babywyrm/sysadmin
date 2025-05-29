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
    "log"
    "net/http"
    "path"
    "strings"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/cors"
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
    "k8s.io/apimachinery/pkg/api/resource"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/util/intstr"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "gopkg.in/yaml.v2"
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
    TrustDomain        string                `yaml:"trustDomain"`
    ProjectDomain      string                `yaml:"projectDomain"`
    ImageRegistry      string                `yaml:"imageRegistry"`
    DefaultTTL         time.Duration         `yaml:"defaultChallengeTTL"`
    TierLimits         map[string]TierConfig `yaml:"tierLimits"`
    SPIREServerAddr    string                `yaml:"spireServerAddr"`
    SPIREParentID      string                `yaml:"spireParentID"`
    RedisAddr          string                `yaml:"redisAddr"`
    RedisPassword      string                `yaml:"redisPassword"`
    JWTPrivateKeyPath  string                `yaml:"jwtPrivateKeyPath"`
    JWTPublicKeyPath   string                `yaml:"jwtPublicKeyPath"`
    ChallengeNamespace string                `yaml:"challengeNamespace"`
    IstioNamespace     string                `yaml:"istioNamespace"`
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
    jwtPubKey     *rsa.PublicKey
    jwtPrivKey    *rsa.PrivateKey
    k8s           *kubernetes.Clientset
    istio         *istioclient.Clientset
    spire         serverv1.RegistrationClient
    redis         *redis.Client
    trustDomain   spiffeid.TrustDomain
}

func main() {
    var cfgPath string
    flag.StringVar(&cfgPath, "config", "/etc/project-x/config.yaml", "path to config")
    flag.Parse()

    // Load configuration
    cfg := mustLoadConfig(cfgPath)

    // Load JWT keys
    priv := mustLoadPrivateKey(cfg.JWTPrivateKeyPath)
    pub := mustLoadPublicKey(cfg.JWTPublicKeyPath)

    // In-cluster Kubernetes & Istio clients
    restCfg := must(rest.InClusterConfig())
    k8sCli := mustClient(kubernetes.NewForConfig, restCfg)
    istioCli := mustClient(istioclient.NewForConfig, restCfg)

    // SPIRE gRPC client
    spireConn := mustDial(cfg.SPIREServerAddr)
    spireCli := serverv1.NewRegistrationClient(spireConn)

    // Redis client
    rdb := redis.NewClient(&redis.Options{
        Addr:     cfg.RedisAddr,
        Password: cfg.RedisPassword,
    })

    // Parse SPIFFE trust domain
    td := mustTrustDomain(cfg.TrustDomain)

    ctrl := &Controller{
        cfg:         cfg,
        jwtPubKey:   pub,
        jwtPrivKey:  priv,
        k8s:         k8sCli,
        istio:       istioCli,
        spire:       spireCli,
        redis:       rdb,
        trustDomain: td,
    }

    // Router with CORS and auth middleware
    r := chi.NewRouter()
    r.Use(middlewareLogger)
    r.Use(cors.Handler(cors.Options{
        AllowedOrigins:   []string{"https://" + cfg.ProjectDomain},
        AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
        AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
        AllowCredentials: true,
    }))
    r.Use(ctrl.authMiddleware)

    // Routes
    r.Get("/api/challenges", ctrl.listChallenges)
    r.Post("/api/challenges", ctrl.handleSpawn)
    r.Delete("/api/challenges/{id}", ctrl.handleDestroy)

    log.Println("Challenge Controller listening on :8080")
    http.ListenAndServe(":8080", r)
}

// middlewareLogger is a simple request logger.
func middlewareLogger(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s", r.Method, r.URL.Path)
        next.ServeHTTP(w, r)
    })
}

// authMiddleware validates JWT from Authorization header or cookie.
func (c *Controller) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        var tokenString string
        if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
            tokenString = strings.TrimPrefix(auth, "Bearer ")
        } else if ck, err := r.Cookie("jwt"); err == nil {
            tokenString = ck.Value
        }
        if tokenString == "" {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
            if t.Method != jwt.SigningMethodRS256 {
                return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
            }
            return c.jwtPubKey, nil
        })
        if err != nil || !token.Valid {
            http.Error(w, "invalid token", http.StatusUnauthorized)
            return
        }
        claims := token.Claims.(jwt.MapClaims)
        uid, ok := claims["user_id"].(string)
        if !ok || uid == "" {
            http.Error(w, "invalid token claims", http.StatusUnauthorized)
            return
        }
        ctx := context.WithValue(r.Context(), "user_id", uid)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// listChallenges returns active challenges for the authenticated user.
func (c *Controller) listChallenges(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    userID := ctx.Value("user_id").(string)

    deps, err := c.k8s.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        List(ctx, metav1.ListOptions{
            LabelSelector: fmt.Sprintf("project-x/user-id=%s", userID),
        })
    if err != nil {
        http.Error(w, "failed to list challenges", http.StatusInternalServerError)
        return
    }
    var out []SpawnResponse
    for _, d := range deps.Items {
        id := d.Name
        endpoint := fmt.Sprintf("https://%s.%s", id, c.cfg.ProjectDomain)
        out = append(out, SpawnResponse{
            ID:        id,
            Endpoint:  endpoint,
            ExpiresAt: time.Now().Add(c.cfg.DefaultTTL),
        })
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(out)
}

// handleSpawn creates a new challenge deployment and returns its info.
func (c *Controller) handleSpawn(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    userID := ctx.Value("user_id").(string)

    var req SpawnRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid JSON", http.StatusBadRequest)
        return
    }
    tierCfg, ok := c.cfg.TierLimits[req.Tier]
    if !ok {
        http.Error(w, "invalid tier", http.StatusBadRequest)
        return
    }
    countKey := fmt.Sprintf("user:%s:tier:%s:count", userID, req.Tier)
    if cnt, _ := c.redis.Get(ctx, countKey).Int(); cnt >= tierCfg.MaxChallenges {
        http.Error(w, "challenge limit reached", http.StatusForbidden)
        return
    }

    id := uuid.NewString()
    spiffeID := spiffeid.Must(c.trustDomain, "challenge", id).String()

    // 1) Kubernetes Deployment & Service
    deploy := c.buildDeployment(userID, req.Tier, req.ChallengeType, id, spiffeID)
    if _, err := c.k8s.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Create(ctx, deploy, metav1.CreateOptions{}); err != nil {
        http.Error(w, "deployment failed", http.StatusInternalServerError)
        return
    }
    svc := c.buildService(id)
    if _, err := c.k8s.CoreV1().
        Services(c.cfg.ChallengeNamespace).
        Create(ctx, svc, metav1.CreateOptions{}); err != nil {
        http.Error(w, "service failed", http.StatusInternalServerError)
        return
    }

    // 2) SPIRE entry
    entryID, err := c.registerSpireEntry(ctx, spiffeID, id)
    if err != nil {
        http.Error(w, "SPIRE registration failed", http.StatusInternalServerError)
        return
    }
    c.redis.Set(ctx, fmt.Sprintf("challenge:%s:entry", id), entryID, c.cfg.DefaultTTL)

    // 3) Istio VirtualService & AuthorizationPolicy
    vs := c.buildVirtualService(id, userID)
    c.istio.NetworkingV1alpha3().
        VirtualServices(c.cfg.ChallengeNamespace).
        Create(ctx, vs, metav1.CreateOptions{})
    ap := c.buildAuthPolicy(id, userID)
    c.istio.SecurityV1beta1().
        AuthorizationPolicies(c.cfg.ChallengeNamespace).
        Create(ctx, ap, metav1.CreateOptions{})

    c.redis.Incr(ctx, countKey)

    // 4) Scoped JWT for challenge access
    token, err := c.makeChallengeToken(userID, id)
    if err != nil {
        http.Error(w, "token issuance failed", http.StatusInternalServerError)
        return
    }
    endpoint := fmt.Sprintf("https://%s.%s", id, c.cfg.ProjectDomain)
    resp := SpawnResponse{id, endpoint, time.Now().Add(c.cfg.DefaultTTL), token}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

// handleDestroy tears down a challenge and cleans up related resources.
func (c *Controller) handleDestroy(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    userID := ctx.Value("user_id").(string)
    id := chi.URLParam(r, "id")

    // Revoke SPIRE entry
    entryKey := fmt.Sprintf("challenge:%s:entry", id)
    if entryID, err := c.redis.Get(ctx, entryKey).Result(); err == nil {
        c.spire.DeleteEntry(ctx, &serverv1.DeleteEntryRequest{Id: entryID})
    }

    // Delete Istio CRDs
    c.istio.NetworkingV1alpha3().
        VirtualServices(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})
    c.istio.SecurityV1beta1().
        AuthorizationPolicies(c.cfg.ChallengeNamespace).
        Delete(ctx, id+"-authz", metav1.DeleteOptions{})

    // Delete k8s Deployment & Service
    c.k8s.AppsV1().
        Deployments(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})
    c.k8s.CoreV1().
        Services(c.cfg.ChallengeNamespace).
        Delete(ctx, id, metav1.DeleteOptions{})

    // Cleanup Redis
    c.redis.Del(ctx, entryKey)
    // Decrement count if desired

    w.WriteHeader(http.StatusNoContent)
}

// registerSpireEntry creates a SPIRE registration entry for the challenge.
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
    resp, err := c.spire.CreateEntry(ctx, req)
    if err != nil {
        return "", err
    }
    return resp.Entry.Id, nil
}

// buildDeployment constructs the k8s Deployment for a challenge pod.
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
        "spiffe.io/spiffe-id":     spiffeID,
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

// buildService constructs the k8s Service for a challenge deployment.
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

// buildVirtualService constructs an Istio VirtualService for a challenge.
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

// buildAuthPolicy constructs an Istio AuthorizationPolicy for a challenge.
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
    return token.SignedString(c.jwtPrivKey)
}

// ------------------ Utility Functions ------------------

// mustLoadConfig reads and parses the YAML config file.
func mustLoadConfig(path string) Config {
    b, err := ioutil.ReadFile(path)
    if err != nil {
        log.Panicf("read config: %v", err)
    }
    var cfg Config
    if err := yaml.Unmarshal(b, &cfg); err != nil {
        log.Panicf("parse config: %v", err)
    }
    return cfg
}

// mustLoadPrivateKey loads an RSA private key from PEM.
func mustLoadPrivateKey(path string) *rsa.PrivateKey {
    b, err := ioutil.ReadFile(path)
    if err != nil {
        log.Panicf("read private key: %v", err)
    }
    block, _ := pem.Decode(b)
    if block == nil {
        log.Panic("invalid private key PEM")
    }
    key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        log.Panicf("parse private key: %v", err)
    }
    return key
}

// mustLoadPublicKey loads an RSA public key from PEM.
func mustLoadPublicKey(path string) *rsa.PublicKey {
    b, err := ioutil.ReadFile(path)
    if err != nil {
        log.Panicf("read public key: %v", err)
    }
    block, _ := pem.Decode(b)
    if block == nil {
        log.Panic("invalid public key PEM")
    }
    keyIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        log.Panicf("parse public key: %v", err)
    }
    pub, ok := keyIfc.(*rsa.PublicKey)
    if !ok {
        log.Panic("not RSA public key")
    }
    return pub
}

// must wraps a value and error into a panic on error.
func must[T any](v T, err error) T {
    if err != nil {
        log.Panic(err)
    }
    return v
}

// mustClient wraps k8s/istio client creation.
func mustClient[T any](fn func(*rest.Config) (T, error), cfg *rest.Config) T {
    client, err := fn(cfg)
    if err != nil {
        log.Panic(err)
    }
    return client
}

// mustDial opens a gRPC connection or panics.
func mustDial(addr string) *grpc.ClientConn {
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Panicf("dial spire: %v", err)
    }
    return conn
}

// mustTrustDomain parses a SPIFFE trust domain.
func mustTrustDomain(s string) spiffeid.TrustDomain {
    td, err := spiffeid.TrustDomainFromString(s)
    if err != nil {
        log.Panicf("invalid trust domain: %v", err)
    }
    return td
}

func boolPtr(b bool) *bool       { return &b }
func int64Ptr(i int64) *int64    { return &i }
func hostPathDirOrCreate() *corev1.HostPathType {
    t := corev1.HostPathDirectoryOrCreate
    return &t
}

// mustParse parses a k8s resource.Quantity or panics.
func mustParse(s string) resource.Quantity {
    q, err := resource.ParseQuantity(s)
    if err != nil {
        log.Panicf("parse quantity %q: %v", s, err)
    }
    return q
}

//
//
