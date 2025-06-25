
# Testing..

```
flowchart TB
  %% External Entry
  subgraph Internet
    EC[/"External Clients"/]
  end

  %% Ingress Layer
  subgraph Ambassador_Namespace["Ambassador Namespace"]
    direction TB
    ALB["AWS ALB/NLB\n(w/JWT)"]
    AmbIngress["Ambassador Edge Stack\n• Ingress Gateway\n• Rate Limit\n• JWT Validation"]
    JWTAuth["JWT Auth Service\n(validates & mints tokens)"]
    ALB --> AmbIngress
    AmbIngress --> JWTAuth
  end

  %% Service Layer
  subgraph Services["Service Namespaces"]
    direction LR
    WebApp["WebApp (frontend)\nClusterIP + Envoy"]
    API["API Service\nClusterIP + Envoy"]
    DB["Database Service\nClusterIP + Envoy"]
    WebApp -- JWT + Identity --> API
    API -- JWT + Identity --> DB
  end

  %% Mesh & Discovery
  subgraph Mesh["Istio Mesh & Discovery"]
    CoreDNS["CoreDNS\n(service discovery)"]
    Pilot["Pilot\n(traffic management)"]
    Citadel["Citadel\n(cert & identity)"]
    MeshPolicies["AuthN/AuthZ Policies\n(mTLS, RBAC)"]
    Services --> CoreDNS
    CoreDNS --> Pilot
    Pilot --> MeshPolicies
    Citadel --> MeshPolicies
  end

  %% Observability
  subgraph Obs["Observability Plane"]
    Prom["Prometheus\n(metrics"] 
    Graf["Grafana\ndashboards"]
    Jaeger["Jaeger\ntracing"]
    Kiali["Kiali\nservice mesh viz"]
  end

  %% Connections
  EC -->|HTTPS w/ OIDC JWT| ALB
  JWTAuth -->|propagate token| WebApp
  MeshPolicies --> WebApp
  Services --> Prom
  Services --> Graf
  Services --> Jaeger
  Services --> Kiali
