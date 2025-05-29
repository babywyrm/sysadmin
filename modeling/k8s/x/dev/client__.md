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
