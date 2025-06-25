
# Testing.. ( Mermaid ) 

![Editor _ Mermaid Chart-2025-06-25-031228](https://github.com/user-attachments/assets/59b92386-eaea-4481-bcab-98fb7ec04a08)



```
flowchart TB
  %% Layer 1: Edge – Zero Trust Layer
  subgraph Layer1["Layer 1: Edge – Zero Trust"]
    direction TB
    EC[External Clients]
    EC -->|1 TLS with OIDC ID Token| ALB[AWS ALB or NLB]
    ALB -->|2 Ambassador JWT Filter| AMB[Ambassador Ingress Gateway
      Ingress Gateway
      Rate Limiting
      JWT Validation]
    AMB -->|3 Call Auth Service| AUTH[JWT Auth Service
      Validate Credentials
      Mint Short-Lived JWT
      Embed Claims: roles, scopes, origins]
    AUTH -->|4 Return JWT| AMB
    AMB -->|5 Inject and Propagate JWT| MeshEntry[Enter Service Mesh]
  end

  %% Layer 2: Control Plane – Zero Trust Layer
  subgraph Layer2["Layer 2: Istio Control Plane – Zero Trust"]
    direction TB
    MeshEntry -->|6 Service Discovery| DNS[CoreDNS Service Discovery]
    DNS --> PILOT[Pilot Traffic Management]
    DNS --> CITADEL[Citadel Certificates and Identity]
    PILOT --> POLICY[AuthN and AuthZ Policies
      mTLS Enforcement
      JWT-based RBAC]
    CITADEL --> POLICY
    POLICY --> SIDE[Envoy Sidecars]
  end

  %% Layer 3: Workloads – Zero Trust Layer
  subgraph Layer3["Layer 3: Workloads and Identity – Zero Trust"]
    direction TB

    FE[Frontend Pod
      App Container plus Envoy Sidecar]
    SIDE --> FE
    FE -->|7 Call API with JWT| API[API Pod
      App Container plus Envoy Sidecar]
    SIDE --> API
    API -->|8 Call Database with JWT| DB[Database Pod
      DB Container plus Envoy Sidecar]
    SIDE --> DB
  end

  %% Observability Plane
  subgraph Obs["Observability Plane – Visibility and Audit"]
    direction LR
    PROM[Prometheus Metrics]
    JAEGER[Jaeger Traces]
    GRAF[Grafana Dashboards]
    KIALI[Kiali Mesh Visualization]

    FE --> PROM
    FE --> JAEGER
    API --> PROM
    API --> JAEGER
    DB --> PROM
    DB --> JAEGER

    PROM --> GRAF
    JAEGER --> GRAF
    PILOT --> KIALI
    POLICY --> KIALI
  end
