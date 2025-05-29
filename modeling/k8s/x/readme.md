┌──────────────────────────────────────────────────┐
│ Admin Workstation                               │
│ • terraform, eksctl, aws, kubectl, helm, istioctl│
└───────────────┬──────────────────────────────────┘
                │ terraform apply infra/terraform
                ▼
┌──────────────────────────────────────────────────┐
│ AWS EKS Control Plane (managed)                  │
└───────────────┬──────────────────────────────────┘
                │ aws eks update-kubeconfig / gcloud get-credentials
                ▼
┌──────────────────────────────────────────────────┐
│ Kubernetes Cluster: project-x                    │
│ Namespaces:                                      │
│  spire-system, istio-system, ambassador,         │
│  gatekeeper-system, project-x-challenges,        │
│  project-x-infra                                 │
└───────────────┬──────────────────────────────────┘
                │ helm install spire-server + spire-agent
                │ helm install gatekeeper
                │ istioctl install --set profile=default
                │ kubectl label ns project-x-challenges istio-injection=enabled
                │ helm install ambassador
                │ kubectl apply -k infra/kustomize/base
                │ kubectl apply -k infra/kustomize/overlays/${ENV}
                ▼
┌──────────────────────────────────────────────────┐
│ Control-plane components all installed:         │
│ • SPIRE (server + agent)                        │
│ • OPA/Gatekeeper                                │
│ • Istio Service-Mesh                            │
│ • Ambassador Edge Stack                         │
└──────────────────────────────────────────────────┘

##
##
```
sequenceDiagram
    actor Admin
    participant TF as Terraform
    participant EKS as AWS EKS
    participant KC as kubeconfig
    participant Helm
    participant Istioctl

    Admin->>TF: terraform apply infra/terraform
    TF->>EKS: create VPC, EKS cluster, nodegroups
    EKS->>KC: update-kubeconfig
    Admin->>Helm: helm install spire-server, spire-agent
    Helm->>EKS: deploy SPIRE
    Admin->>Helm: helm install gatekeeper
    Helm->>EKS: deploy Gatekeeper
    Admin->>Istioctl: istioctl install
    Istioctl->>EKS: deploy Istio
    Admin->>KC: kubectl label namespace project-x-challenges istio-injection=enabled
    Admin->>Helm: helm install ambassador
    Helm->>EKS: deploy Ambassador
    Admin->>KC: kubectl apply -k infra/kustomize/base
    Admin->>KC: kubectl apply -k infra/kustomize/overlays/${ENV}
```

##
##
```
┌───────────────┐            ┌────────────────────────┐
│ User Browser  │            │ Ambassador Ingress     │
│               │─HTTPS────▶│ (TLS Termination, JWT) │
└───────┬───────┘            └─────────┬──────────────┘
        │ POST /auth/login                │
        ▼                                ▼
  ┌───────────────┐    MongoDB Atlas    ┌──────────────┐
  │ Auth Service  │◀──────────────────▶│ User Store   │
  └───────┬───────┘                     └──────────────┘
          │ find user, verify hash
          │
          │ store session in Redis
          ▼
     ┌───────────────┐
     │ Redis Session │
     └───────┬───────┘
             │ return JWT
             ▼
┌───────────────┐            ┌───────────────┐
│ User Browser  │◀─Set-Cookie│ Ambassador    │
│  (has JWT)    │            │ Ingress       │
└───────┬───────┘            └──────┬────────┘
        │ POST /api/challenges (JWT)
        ▼
┌───────────────┐    ┌───────────────┐
│ Ambassador    │──▶│ Challenge API  │
│ Ingress       │   │ (Controller)   │
└───────┬───────┘   └───────────────┘
        │ forward with claims
        ▼
```

..continuing on..
```

sequenceDiagram
    participant U as User Browser
    participant AM as Ambassador
    participant AU as Auth Service
    participant MO as MongoDB
    participant RE as Redis
    participant CH as Challenge API

    U->>AM: POST /auth/login {email,password}
    AM->>AU: forward to Auth Service
    AU->>MO: find user document
    MO->>AU: return user data
    AU->>AU: verify password, generate JWT+session_id
    AU->>RE: set(session_id → user data)
    AU-->>AM: return JWT
    AM-->>U: Set-Cookie & JWT

    U->>AM: POST /api/challenges {type,tier} + JWT
    AM->>AM: validate JWT
    AM->>CH: forward request + claims
    CH->>OP: OPA pre-admission check
    OP-->>CH: allow/deny
    alt allowed
      CH->>… next flow (deployment)
    else denied
      CH-->>AM: 403 Forbidden
      AM-->>U: 403 Forbidden
    end
```
##
##

```
┌──────────────────────────────┐
│ Challenge Controller        │
└──────────────┬───────────────┘
               │
               │ 1) OPA pre-admission (tier, limits)
               ├───────────────────▶ OPA Gatekeeper
               │                   ◀─ allow/deny
               │
               │ 2) Generate ChallengeID & SPIFFE ID
               │
               │ 3) Kubernetes API calls
               │   • Deployment
               │   • Service
               │
               ├───────────────────▶ Kubernetes API
               │                   ◀─ Admission webhooks
               │                     • Gatekeeper
               │                     • Namespace/resource-quota
               │
               │ 4) Pod scheduling & startup
               │   • kube-scheduler → kubelet
               │   • container + Istio sidecar
               │
               │ 5) SPIRE: CreateEntry for workload identity
               ├───────────────────▶ SPIRE Server
               │                   ◀─ entry created
               │
               │ 6) Istio: VirtualService + AuthorizationPolicy
               ├───────────────────▶ Istio Pilot
               │                   ◀─ config accepted
               │
               │ 7) Return endpoint & scoped JWT to user
               └───────────────────────────────────────────▶ Userland  
```

##
##

```
sequenceDiagram
    participant CC as Challenge Controller
    participant OPA as OPA Gatekeeper
    participant K8s as Kubernetes API
    participant Gate as Gatekeeper Webhook
    participant KS as kube-scheduler
    participant KL as kubelet
    participant CR as Container Runtime
    participant AG as SPIRE Agent
    participant SP as SPIRE Server
    participant IP as Istio Pilot
    participant U as User

    CC->>OPA: Pre-admission check (tier, quotas)
    OPA-->>CC: allow

    CC->>K8s: create Deployment & Service
    K8s->>Gate: admission review
    Gate-->>K8s: validated

    K8s->>KS: schedule pod
    KS->>KL: bind pod to node
    KL->>CR: pull image & start container
    KL->>AG: attest workload
    AG->>SP: attest & request SVID
    SP-->>AG: issue SVID

    CC->>SP: CreateEntry (selectors, TTL, claims)
    SP-->>CC: entry ID

    CC->>IP: apply VirtualService & AuthorizationPolicy
    IP-->>CC: config OK

    CC-->>U: return {challengeID, endpoint, token}
```
##
##

```
```
**Namespace Legend**  
- **ambassador**: Ambassador Edge Stack (Ingress, Auth, Mappings)  
- **project-x-auth**: Auth Service pods (login, JWT minting)  
- **project-x-challenge-api**: Challenge Controller API pods  
- **project-x-infra**: Redis cluster, shared secrets, config  
- **project-x-challenges**: Dynamic challenge workloads  
- **spire-system**: SPIRE Server & Agent  
- **istio-system**: Istio control plane & ingress gateway  
- **gatekeeper-system**: OPA Gatekeeper admission controller  

────────────────────────────────────────────────────────────────────────  
2) MERMAID TOPOLOGY GRAPH  
────────────────────────────────────────────────────────────────────────  
```
graph LR
  subgraph "Internet"
    U[Users] 
  end

  subgraph "AWS EKS Cluster"
    direction TB

    ALB["AWS ALB/NLB\n*.project-x.example.com"]
    AMB["Ambassador\n(namespace: ambassador)"]
    Auth["Auth Service\n(project-x-auth)"]
    API["Challenge API\n(project-x-challenge-api)"]
    IstioGW["Istio Ingress\n(namespace: istio-system)"]
    Redis["Redis Cluster\n(namespace: project-x-infra)"]
    Mongo["MongoDB Atlas\n(external)"]
    Gate["OPA Gatekeeper\n(namespace: gatekeeper-system)"]
    SPIRE_S["SPIRE Server\n(namespace: spire-system)"]
    SPIRE_A["SPIRE Agent\n(DaemonSet)"]
    Pilot["Istio Pilot\n(namespace: istio-system)"]

    subgraph "project-x-challenges NS"
      CPods["Challenge Pods\n(web/pwn/etc)"]
    end

    U --> ALB
    ALB --> AMB

    AMB -->|/auth/*| Auth
    AMB -->|/api/challenges| API
    AMB -->|*.project-x.example.com| IstioGW

    Auth --> Redis
    Auth --> Mongo

    API --> Gate
    API --> Redis
    API --> SPIRE_S
    API --> K8sAPI["Kubernetes API"]

    K8sAPI --> Gate
    K8sAPI --> CPods

    SPIRE_S --> SPIRE_A
    CPods --> SPIRE_A
    SPIRE_A --> SPIRE_S

    IstioGW --> Pilot
    Pilot --> CPods
    CPods -->|sidecar| PIL["Envoy Sidecar"]

    CPods --> Redis
  end
```
##
##
```
```

                                       WORLD_WIDE_WEB_LOL
                                          │
                             DNS *.project-x.example.com
                                          │
                                 AWS ALB / NLB
                                          │
             ┌────────────────────────────────────────────────┐
             │ Ambassador Ingress (namespace: ambassador)   │
             │  • TLS termination                            │
             │  • JWT validation                             │
             │  • Rate-limiting                              │
             │  • Edge routing                               │
             └───────────────┬────────────────────────────────┘
                             │
                ┌────────────┴───────────┐
                │                        │
     /auth/*    ▼                        ▼    /api/challenges
```
┌────────────────────────┐       ┌───────────────────────────┐
│ Auth Service Pods      │       │ Challenge API Pods        │
│ (project-x-auth ns)    │       │ (project-x-challenge-api) │
└──────────────┬─────────┘       └──────────────┬────────────┘
               │                                │
               ▼                                ▼
     ┌────────────────────────────────────────────────┐
     │ Redis Cluster (sessions)                      │
     │ (project-x-infra namespace)                   │
     └────────────────────────────────────────────────┘
                             │
                             ▼
     ┌────────────────────────────────────────────────┐
     │ MongoDB Atlas (user store)                    │
     │ (external managed service)                    │
     └────────────────────────────────────────────────┘
                             │
                             ▼
     ┌────────────────────────────────────────────────┐
     │ Kubernetes API Server                         │
     └──────────────┬───────────────────────┬─────────┘
                    │                       │
                    ▼                       ▼
     ┌──────────────────────────────┐  ┌──────────────────────────┐
     │ OPA Gatekeeper Webhook       │  │ SPIRE Server             │
     │ (gatekeeper-system namespace)│  │ (spire-system namespace) │
     └──────────────┬───────────────┘  └──────────────┬──────────┘
                    │                                 │
                    ▼                                 ▼
     ┌────────────────────────────────────────────────┐
     │ SPIRE Agent DaemonSet                          │
     │ (spire-system namespace)                       │
     └────────────────────────────────────────────────┘
                             │
                             ▼
     ┌────────────────────────────────────────────────┐
     │ project-x-challenges namespace                │
     │ +--------------------------------------------+ │
     │ | Challenge Pod #1 (envoy + spire-agent)     | │
     │ +--------------------------------------------+ │
     │ | Challenge Pod #2 (envoy + spire-agent)     | │
     │ +--------------------------------------------+ │
     │ | ...                                        | │
     │ +--------------------------------------------+ │
     └────────────────────────────────────────────────┘
                             │
                             ▼
     ┌────────────────────────────────────────────────┐
     │ Istio Ingress Gateway & Service Mesh          │
     │ (istio-system namespace)                      │
     └────────────────────────────────────────────────┘
                             │
                             ▼
     ┌────────────────────────────────────────────────┐
     │ Istio Pilot & Control Plane                   │
     │ (istio-system namespace)                      │
     └────────────────────────────────────────────────┘

```

##
##
```
  U --> LB[AWS ALB／NLB<br/>*.project-x.example.com]
  LB --> AMB[Ambassador Ingress<br/>(ambassador ns)]
  AMB -->|/auth/*| AUTH[Auth Service Pods<br/>(project-x-auth)]
  AMB -->|/api/challenges| API[Challenge API Pods<br/>(project-x-challenge-api)]
  AUTH --> REDIS[Redis Cluster<br/>(project-x-infra)]
  API --> REDIS
  REDIS --> MONGO[MongoDB Atlas<br/>(external)]
  MONGO --> APISERVER[Kubernetes API Server]
  APISERVER --> OPA[OPA Gatekeeper Webhook<br/>(gatekeeper-system)]
  APISERVER --> SPIRE_S[ SPIRE Server<br/>(spire-system)]
  OPA --> AGENT[SPIRE Agent DaemonSet<br/>(spire-system)]
  SPIRE_S --> AGENT
  AGENT --> CHNS[project-x-challenges NS]
  CHNS --> CH_PODS[Challenge Pods<br/>(envoy + spire-agent)]
  AMB --> ISTIO_ING[Istio Ingress Gateway<br/>(istio-system)]
  ISTIO_ING --> PILOT[Istio Pilot & Control Plane<br/>(istio-system)]
  PILOT --> CH_PODS


