
------------------------------------------------------------------------------
1) Repository Layout (project-x/)
------------------------------------------------------------------------------
.
├── .env.example
├── .github
│   └── workflows
│       ├── ci.yaml
│       └── cd.yaml
├── README.md
├── LICENSE
├── docs
│   ├── architecture.md
│   ├── flow-diagram.mmd
│   └── ENV.md
├── infra
│   ├── terraform
│   │   ├── gke-cluster.tf
│   │   └── redis-cluster.tf
│   └── kustomize
│       ├── base
│       │   ├── namespace.yaml
│       │   └── common-labels.yaml
│       ├── overlays
│       │   ├── dev
│       │   └── prod
│       └── kustomization.yaml
├── config
│   ├── spire
│   │   ├── server-config.hcl
│   │   └── agent-config.hcl
│   ├── istio
│   │   ├── virtual-service-challenge.yaml
│   │   └── authorization-policy.yaml
│   ├── opa
│   │   ├── templates
│   │   │   ├── signed-images-template.yaml
│   │   │   └── resource-limits-template.yaml
│   │   └── constraints
│   │       ├── signed-images.yaml
│   │       └── resource-limits.yaml
│   └── ambassador
│       ├── authservice.yaml
│       ├── mapping-login.yaml
│       └── mapping-challenges.yaml
├── apps
│   ├── auth-service
│   │   ├── Dockerfile
│   │   ├── main.go
│   │   └── config.yaml
│   └── challenge-controller
│       ├── Dockerfile
│       ├── main.go
│       └── config.yaml
└── charts
    ├── spire
    ├── istio-config
    ├── opa
    └── ambassador

------------------------------------------------------------------------------
2) .env.example
------------------------------------------------------------------------------
# project-x environment
PROJECT_X_DOMAIN=project-x.example.com
TRUST_DOMAIN=project-x.local
JWT_PRIVATE_KEY=/secrets/jwt/private.key
JWT_PUBLIC_KEY=/secrets/jwt/public.key
MONGO_URI=mongodb+srv://user:pass@cluster0.mongodb.net/projectx
REDIS_ADDR=redis-cluster.project-x.svc.cluster.local:6379
IMAGE_REGISTRY=registry.project-x.local
SESSION_TTL=24h
CHALLENGE_TTL=2h
OPA_DATA_PATH=/opa/data
SPIRE_SERVER_ADDR=spire-server.project-x.svc.cluster.local:8081
SPIRE_AGENT_SOCKET=/run/spire/sockets/agent.sock
ISTIO_NAMESPACE=istio-system

------------------------------------------------------------------------------
3) config/spire/server-config.hcl
------------------------------------------------------------------------------
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  trust_domain = "project-x.local"
  data_dir     = "/opt/spire/data"
  ca_subject {
    country      = ["US"]
    organization = ["Project X"]
    common_name  = "Project-X SPIRE Server"
  }
}

plugin "datastore/sql" {
  plugin_data {
    database_type     = "postgres"
    connection_string = "postgresql://spire:spirepass@postgres-svc:5432/spire?sslmode=disable"
  }
}

plugin "node_attestor" {
  plugin_data {
    plugin_name = "k8s_sat"
    # allow SPIRE agent service account
    service_account_allow_list = ["spire-system:spire-agent"]
  }
}

plugin "workload_attestor" {
  plugin_data {
    plugin_name = "k8s"
    node_name_env       = "K8S_NODE_NAME"
    required_annotations = ["project-x/challenge-id", "project-x/user-id", "project-x/tier"]
  }
}

------------------------------------------------------------------------------
4) config/spire/agent-config.hcl
------------------------------------------------------------------------------
agent {
  data_dir       = "/opt/spire/data"
  log_level      = "INFO"
  server_address = "spire-server.project-x.svc.cluster.local"
  server_port    = "8081"
  trust_domain   = "project-x.local"
  socket_path    = "/run/spire/sockets/agent.sock"
}

plugin "node_attestor" {
  plugin_data {
    plugin_name = "k8s_sat"
    cluster     = "project-x-cluster"
    token_path  = "/var/run/secrets/tokens/spire-agent"
  }
}

plugin "workload_attestor" {
  plugin_data {
    plugin_name             = "k8s"
    kubelet_read_only_port  = 10255
    required_annotations    = ["project-x/challenge-id","project-x/user-id","project-x/tier"]
    verify_image_signature  = true
    cosign_public_key_path  = "/opt/spire/conf/cosign.pub"
  }
}

------------------------------------------------------------------------------
5) config/istio/virtual-service-challenge.yaml
------------------------------------------------------------------------------
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: challenge-{{CHALLENGE_ID}}
  namespace: project-x-challenges
spec:
  hosts:
  - "{{CHALLENGE_ID}}.{{PROJECT_X_DOMAIN}}"
  gateways:
  - project-x-gateway
  http:
  - match:
    - headers:
        authorization:
          regex: ".*challenge_id:{{CHALLENGE_ID}}.*"
    route:
    - destination:
        host: "{{CHALLENGE_ID}}.project-x-challenges.svc.cluster.local"
        port:
          number: 8080
    timeout: 300s
    retries:
      attempts: 3
      perTryTimeout: 30s

------------------------------------------------------------------------------
6) config/istio/authorization-policy.yaml
------------------------------------------------------------------------------
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: challenge-{{CHALLENGE_ID}}-authz
  namespace: project-x-challenges
spec:
  selector:
    matchLabels:
      project-x/challenge-id: "{{CHALLENGE_ID}}"
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
    when:
    - key: "request.auth.claims.challenge_id"
      values: ["{{CHALLENGE_ID}}"]
    - key: "request.auth.claims.user_id"
      values: ["{{USER_ID}}"]

------------------------------------------------------------------------------
7) config/opa/templates/signed-images-template.yaml
------------------------------------------------------------------------------
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: signedimagesonly
spec:
  crd:
    spec:
      names:
        kind: SignedImagesOnly
      validation:
        properties:
          allowedRegistries:
            type: array
            items: {type: string}
          cosignPublicKey:
            type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package signedimagesonly
        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          image := input.review.object.spec.containers[_].image
          not startswith(image, input.parameters.allowedRegistries[_])
          msg := sprintf("Image %v not in allowed registries", [image])
        }
        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          image := input.review.object.spec.containers[_].image
          not image_has_valid_signature(image, input.parameters.cosignPublicKey)
          msg := sprintf("Image %v missing valid cosign signature", [image])
        }

------------------------------------------------------------------------------
8) config/opa/constraints/signed-images.yaml
------------------------------------------------------------------------------
apiVersion: config.gatekeeper.sh/v1alpha1
kind: SignedImagesOnly
metadata:
  name: projectx-signed-images
spec:
  allowedRegistries:
    - "{{IMAGE_REGISTRY}}/"
  cosignPublicKey: |
    -----BEGIN PUBLIC KEY-----
    {{COSIGN_PUBKEY}}
    -----END PUBLIC KEY-----

------------------------------------------------------------------------------
9) config/opa/templates/resource-limits-template.yaml
------------------------------------------------------------------------------
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: projectxresourcelimits
spec:
  crd:
    spec:
      names:
        kind: ProjectXResourceLimits
      validation:
        properties:
          tierLimits:
            type: object
            additionalProperties:
              type: object
              properties:
                maxChallenges: {type: integer}
                maxCPU: {type: string}
                maxMemory: {type: string}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package projectxresourcelimits
        violation[{"msg": msg}] {
          pod := input.review.object
          tier := pod.metadata.annotations["project-x/tier"]
          user := pod.metadata.annotations["project-x/user-id"]
          # count existing
          existing := count([
            p | p := data.inventory.namespace["project-x-challenges"].v1.Pod[_];
                  p.metadata.annotations["project-x/user-id"] == user;
                  p.metadata.annotations["project-x/tier"] == tier
          ])
          limits := input.parameters.tierLimits[tier]
          existing >= limits.maxChallenges
          msg := sprintf("User %v has too many challenges for tier %v", [user,tier])
        }

------------------------------------------------------------------------------
10) config/opa/constraints/resource-limits.yaml
------------------------------------------------------------------------------
apiVersion: config.gatekeeper.sh/v1alpha1
kind: ProjectXResourceLimits
metadata:
  name: projectx-tier-limits
spec:
  tierLimits:
    tier-1:
      maxChallenges: 3
      maxCPU: "500m"
      maxMemory: "1Gi"
    tier-2:
      maxChallenges: 5
      maxCPU: "1000m"
      maxMemory: "2Gi"
    tier-3:
      maxChallenges: 10
      maxCPU: "2000m"
      maxMemory: "4Gi"

------------------------------------------------------------------------------
11) config/ambassador/authservice.yaml
------------------------------------------------------------------------------
apiVersion: getambassador.io/v3alpha1
kind: AuthService
metadata:
  name: projectx-auth-service
  namespace: ambassador
spec:
  auth_service: "project-x-auth.project-x.svc.cluster.local:8080"
  path_prefix: "/auth"
  timeout_ms: 5000
  allowed_request_headers:
  - "content-type"
  - "authorization"
  - "x-session-id"
  allowed_authorization_headers:
  - "x-user-id"
  - "x-user-tiers"
  - "x-session-id"

------------------------------------------------------------------------------
12) config/ambassador/mapping-login.yaml
------------------------------------------------------------------------------
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: auth-login
  namespace: ambassador
spec:
  hostname: project-x.example.com
  prefix: /auth/login
  service: project-x-auth.project-x.svc.cluster.local:8080
  timeout_ms: 10000
  cors:
    origins: ["https://project-x.example.com"]
    methods: ["POST","OPTIONS"]
    headers: ["Content-Type","Authorization"]
    credentials: true

------------------------------------------------------------------------------
13) config/ambassador/mapping-challenges.yaml
------------------------------------------------------------------------------
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: challenge-api
  namespace: ambassador
spec:
  hostname: project-x.example.com
  prefix: /api/challenges
  service: project-x-challenge-api.project-x.svc.cluster.local:8080
  timeout_ms: 30000
  auth_service: "projectx-auth-service"
  filters:
  - name: jwt-validation
    jwt:
      issuer: "project-x.example.com"
      audience: "project-x"
      jwksURI: "https://project-x.example.com/.well-known/jwks.json"
  - name: rate-limiting
    rateLimit:
      domain: project-x
      rates:
      - unit: minute
        requestsPerUnit: 10
      descriptors:
      - key: "user_id"
        value: "%REQ(x-user-id)%"

------------------------------------------------------------------------------
14) apps/auth-service/main.go  (skeleton)
------------------------------------------------------------------------------
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v4"
    "go.mongodb.org/mongo-driver/mongo"
    "github.com/go-redis/redis/v8"
)

func main() {
    // load config, connect Mongo, Redis, load RSA keys
    // expose /auth/login, /auth/logout, /auth/validate
    log.Println("Project-X Auth Service starting…")
    http.ListenAndServe(":8080", nil)
}

// handlers: Login, ValidateJWT, CreateChallengeToken
// use JWTClaims { UserID, Email, Subscriptions, TierLimits, SessionID }
```

------------------------------------------------------------------------------
15) apps/challenge-controller/main.go  (skeleton)
------------------------------------------------------------------------------
package main

import (
    "context"
    "log"
    "time"

    "k8s.io/client-go/kubernetes"
)

func main() {
    // load config, connect to K8s, SPIRE, OPA, Istio CRD client
    // start HTTP server on :8080 for /challenges endpoint
    // start background cleanup ticker
    log.Println("Project-X Challenge Controller starting…")
    select {}
}

// SpawnChallenge ->
// 1. validate via OPA gRPC  
// 2. gen SPIFFE ID  
// 3. k8s.Deploy Deployment+Service  
// 4. SPIRE CreateEntry  
// 5. Istio CRDs (VirtualService, AuthorizationPolicy)
// 6. return {ID, Endpoint, ExpiresAt}

```

------------------------------------------------------------------------------
16) docs/architecture.md (excerpt)
------------------------------------------------------------------------------
# Project-X Architecture

- **Auth Service**: MongoDB + Redis session store → JWT minting  
- **Ambassador Gateway**: JWT validation, rate limiting, CORS, routing  
- **OPA/Gatekeeper**: Admission policies for resource & image security  
- **SPIRE/SPIFFE**: Workload identity (SVIDs) with k8s attestors  
- **Istio Service Mesh**: mTLS, routing, AuthorizationPolicy  
- **Challenge Controller**: on-demand challenge pod lifecycle  
- **Kubernetes Namespaces**: tier-1, tier-2, tier-3, infra  
- **Infra**: GKE/EKS (Terraform), Redis, MongoDB Atlas  

See `flow-diagram.mmd` for sequence diagrams & ASCII art  

------------------------------------------------------------------------------
17) docs/flow-diagram.mmd (excerpt)
------------------------------------------------------------------------------
```mermaid
sequenceDiagram
    participant U as User
    participant AM as Ambassador
    participant AU as Auth Service
    participant MO as MongoDB
    participant RE as Redis
    participant CH as Challenge API
    participant CC as Controller
    participant KS as Kubernetes
    participant SP as SPIRE
    participant IS as Istio
    participant OP as OPA

    U->>AM: POST /auth/login
    AM->>AU: validate creds → JWT + session
    AU->>MO: user lookup
    AU->>RE: store session
    AU->>AM: return JWT
    U->>AM: POST /api/challenges + JWT
    AM->>RE: session check
    AM->>CH: forward request
    CH->>OP: pre-admission check
    CH->>KS: create Deployment/Service
    KS->>OP: admit Pod via Gatekeeper
    KS->>SP: agent attest → SVID issued
    KS->>IS: sidecar mTLS injected
    CH->>SP: register entry
    CH->>IS: apply VS & AuthZ
    AM->>U: return challenge URL
    U->>AM: GET challenge URL + token
    AM->>IS: route → Envoy → Pod
```

------------------------------------------------------------------------------
18) README.md (excerpt)
------------------------------------------------------------------------------
# Project-X CTF Platform Blueprint

## 🛠 Technologies
- Kubernetes (GKE/EKS)
- SPIFFE/SPIRE for workload identity
- Istio for mTLS & routing
- OPA/Gatekeeper for admission policies
- Ambassador for edge JWT auth & rate-limiting
- MongoDB Atlas, Redis for state
- Go microservices for Auth & Controller

## 🚀 Getting Started
1. `cp .env.example .env` & fill in your secrets  
2. Deploy infra:  
   - `terraform apply infra/terraform`  
   - `kubectl apply -k infra/kustomize/overlays/dev`
3. Install SPIRE via Helm: `helm install spire charts/spire`  
4. Apply SPIRE server/agent configs: `kubectl apply -f config/spire`  
5. Install OPA & Gatekeeper: `helm install gatekeeper charts/opa`  
6. Apply OPA templates & constraints: `kubectl apply -f config/opa`  
7. Install Istio core + CRDs: `istioctl install --set profile=demo`  
8. Apply Istio config: `kubectl apply -f config/istio`  
9. Install Ambassador: `helm install ambassador charts/ambassador`  
10. Apply Ambassador mappings: `kubectl apply -f config/ambassador`  
11. Build & push auth & controller images to `IMAGE_REGISTRY`  
12. Deploy apps:  
    - `kubectl apply -f apps/auth-service`  
    - `kubectl apply -f apps/challenge-controller`

## 📚 Docs
- `docs/architecture.md` – high-level design  
- `docs/flow-diagram.mmd` – sequence diagrams  
- `docs/ENV.md` – detailed env vars

## 📈 Scaling
- **Nodes**: autoscaled via GKE/EKS  
- **Control Plane**: SPIRE (10 replicas), Controller (50), Istiod (20)  
- **DB**: MongoDB Atlas M60 auto-scale  
- **Cache**: Redis cluster with 6 shards  
- **WAN**: Ambassador + Istio ingress  

## 🛡 Security
- Zero-trust via SPIFFE/SPIRE  
- Automatic mTLS in Istio  
- Image signing with Cosign  
- Admission policies (OPA)  
- Per-challenge SVIDs & scoped JWTs  
- Namespace & network policy isolation  

---

