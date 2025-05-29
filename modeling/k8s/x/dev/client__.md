
```
INTERNET
   │
DNS *.project-x.example.com
   │
AWS ALB/NLB
   │
Ambassador Ingress (ambassador ns)
   │ 
   ├── /auth/*  → Auth Service (project-x-auth)
   ├── /api/*   → Challenge API (project-x-challenge-api)
   └── /challenge/ → Challenge Router (project-x-infra)
               │
Challenge Router (project-x-infra)
   │
   └───────────────────────────────────────────────┐
                                                   ▼
project-x-challenges namespace                     │
  ┌───────────────┐      ┌───────────────┐       ┌──────────────---┐
  │ challenge-id: │      │ challenge-id:  │  …    │ challenge-id:  │
  │   abc123 pod  │      │   def456 pod   │       │   xyz789 pod   │
  │ + envoy sidecar│     │ + envoy sidecar│      │ + envoy sidecar │
  │ + spire-agent │      │ + spire-agent  │       │ + spire-agent  │
  └───────────────┘      └────────-───────┘       └────────────---─┘

```
##
##

```
flowchart TD
  U[Browser SPA] -->|HTTP GET /| StaticHost
  StaticHost --> U
  
  U -->|POST /auth/login| AMB[Ambassador]
  AMB --> AUTH[Auth Service]
  AUTH --> REDIS[Redis]
  AUTH --> MONGO[MongoDB]
  AUTH --> AMB
  AMB --> U{Set-Cookie(jwt)}

  U -->|POST /api/challenges| AMB
  AMB --> CHAPI[Challenge API]
  CHAPI --> OPA[OPA Gatekeeper]
  CHAPI --> K8s[Kubernetes API]
  K8s --> CHNS[Challenge Pods]
  CHAPI --> SPIRE[ SPIRE Server ]
  CHAPI --> ISTIO[Istio CRDs]
  CHAPI --> AMB
  AMB --> U

  U -->|NAV /challenge/abc123| AMB
  AMB --> ROUTER[Challenge Router]
  ROUTER -->|proxy| CP[Pod abc123]
  CP --> U

```


```
```
( alternatively )
```
##
## replace iframes
##

Client Browser
  │
  │ 1) GET / (React SPA)
  ▼
Static Host (S3/CloudFront or Ambassador)
  │
  │ 2) POST /auth/login {email,password}
  ▼
Ambassador (namespace: ambassador)
  │  • TLS Termination
  │  • /auth/login → Auth Service
  │  • issues Set-Cookie + JWT
  ▼
Auth Service Pods (project-x-auth)
  │  • MongoDB lookup
  │  • Redis session write
  │  • JWT RS256 mint
  ▼
Client Browser (stores JWT in memory or cookie)

  │
  │ 3) GET /dashboard (React)
  │
  │ 4) POST /api/challenges {type,tier} + Authorization: Bearer <JWT>
  ▼
Ambassador → Challenge API (project-x-challenge-api)
  │  • JWT validation
  │  • Rate-limit per user
  ▼
Challenge Controller
  │  • OPA pre-check
  │  • k8s Deployment + Service
  │  • SPIRE entry
  │  • Istio VS + AuthZ
  │  • Redis increment
  ▼
Response: {id, endpoint, expiresAt, token}

  │
  │ 5) React SPA navigates to endpoint
  │    e.g. https://<id>.project-x.example.com?token=<scopedJWT>
  ▼
Istio Ingress → Envoy sidecars → Challenge Pod
  │  • mTLS + AuthZ via SPIRE SVID & scopedJWT
  ▼
Challenge UI in iframe or new window  
```

##
##

```
sequenceDiagram
  participant U as Browser (React SPA)
  participant AM as Ambassador
  participant AU as Auth Service
  participant MO as MongoDB
  participant RE as Redis
  participant FE as React/API client
  participant CH as Challenge API
  participant CC as Controller
  participant OP as OPA
  participant KS as Kubernetes API
  participant SP as SPIRE Server
  participant IS as Istio
  participant CP as Challenge Pod

  U->>FE: visit “/”
  FE->>AM: POST /auth/login {email,password}
  AM->>AU: forward login
  AU->>MO: find user document
  MO->>AU: return user
  AU->>RE: store session
  AU-->>AM: JWT+session-id
  AM-->>U: set-cookie + JWT

  U->>FE: POST /api/challenges {type,tier} + JWT
  FE->>AM: forward to /api/challenges
  AM->>CH: validated JWT
  CH->>OP: pre-admission: tier+quota
  OP-->>CH: allowed
  CH->>KS: create Deployment+Service
  KS->>OP: admission webhook
  OP-->>KS: pass
  KS->>SP: workload attest
  SP-->>KS: SVID
  CH->>SP: CreateEntry
  SP-->>CH: entryID
  CH->>IS: apply VirtualService+AuthZ
  CH-->>FE: {id, endpoint, token}

  U->>FE: window.open(endpoint)
  FE->>CP: GET /?token=<scopedJWT>
  CP->>IS: mTLS+AuthZ (SPIRE SVID + scopedJWT)
  IS-->>CP: allow
  CP-->>U: challenge UI
```
