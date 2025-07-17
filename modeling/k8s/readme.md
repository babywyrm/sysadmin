
```mermaid

flowchart TB
  subgraph External_Access_Layer[External Access Layer]
    LB["Load Balancer"]
    WAF["WAF / DDoS Protection"]
    APIGW["API Gateway"]
    IDP["Identity Provider
(SPIFFE / SPIRE)"]
  end

  subgraph Istio_Service_Mesh[Istio Service Mesh]
    IGW["Istio Ingress Gateway"]
    mTLS["mTLS Enforcement"]
    Authz["Auth Policy
(Envoy AuthZ)"]
    Rate["Rate Limiting"]
  end

  subgraph Kubernetes_Cluster[Kubernetes Cluster]
    direction TB
    Cilium["Cilium
(eBPF)"]
    OPA["OPA / Gatekeeper"]
    Shared["Shared Services"]
    TenantA["Namespace: bank-a"]
    TenantB["Namespace: bank-b"]
  end

  LB --> WAF --> APIGW --> IDP
  APIGW --> IGW

  IGW --> mTLS
  mTLS --> Authz
  Authz --> Rate
  Rate --> Cilium

  Cilium --> OPA
  OPA --> TenantA
  OPA --> TenantB
  Cilium --> Shared

  subgraph TenantA_Services["Tenant A Services"]
    A_API["API MS
(SPIFFE ID)"]
    A_Auth["Auth MS
(SPIFFE ID)"]
    A_Trans["Transaction MS
(SPIFFE ID)"]
    A_DB["Database PVC"]
    A_Cache["Redis"]
    A_API -->|"mTLS & AuthN/Z"| A_Auth --> A_Trans --> A_DB
    A_Trans --> A_Cache
  end

  subgraph TenantB_Services["Tenant B Services"]
    B_API["API MS
(SPIFFE ID)"]
    B_Auth["Auth MS
(SPIFFE ID)"]
    B_Trans["Transaction MS
(SPIFFE ID)"]
    B_DB["Database PVC"]
    B_Cache["Redis"]
    B_API -->|"mTLS & AuthN/Z"| B_Auth --> B_Trans --> B_DB
    B_Trans --> B_Cache
  end

```
