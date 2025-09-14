
```mermaid
flowchart TB
    %% External Layer
    Internet["🌐 Internet<br/>External Users/APIs"]
    ALB["🔒 AWS ALB/NLB<br/>• TLS Termination<br/>• WAF Rules<br/>• DDoS Protection"]
    
    %% Ambassador Layer
    subgraph Ambassador["🛡️ Ambassador Edge Stack"]
        AuthFilter["🔐 Auth Filter<br/>• Validate OAuth2 JWT<br/>• Extract User Identity"]
        SpiffeMap["🆔 SPIFFE Mapper<br/>• user@bank-a →<br/>• spiffe://bank-a/user/123"]
        TokenGen["🎫 Internal JWT Generator<br/>• Issue SPIFFE Claims<br/>• Add Tenant Context"]
    end
    
    %% Istio Layer
    subgraph Istio["🕸️ Istio Service Mesh"]
        IstioGW["🚪 Ingress Gateway<br/>SPIFFE: ingress-gw<br/>AWS Pod: EKSIngressRole"]
        EnvoyProxy["🔄 Envoy Proxy<br/>• mTLS Enforcement<br/>• AuthZ Policies (OPA)"]
        ServiceDiscovery["📡 Service Discovery<br/>• SPIFFE Identity Routing<br/>• Zero-Trust Network"]
    end
    
    %% SPIFFE Layer
    subgraph SPIFFE["🔑 SPIFFE/SPIRE Identity Layer"]
        SpireServer["🏛️ SPIRE Server<br/>• Root CA Authority<br/>• Identity Registry<br/>• SVID Issuance"]
        SpireAgent["🤖 SPIRE Agents<br/>• Node Attestation<br/>• Workload Attestation<br/>• Certificate Distribution"]
    end
    
    %% Services Layer
    subgraph BankA["🏦 Namespace: bank-a"]
        GatewayA["🚪 API Gateway<br/>SPIFFE: bank-a/gateway<br/>AWS Pod: BankAGatewayRole"]
        UserServiceA["👤 User Service<br/>SPIFFE: bank-a/user-svc<br/>AWS Pod: BankAUserRole"]
        AcctServiceA["💰 Account Service<br/>SPIFFE: bank-a/acct-svc<br/>AWS Pod: BankAAcctRole"]
    end
    
    subgraph BankB["🏛️ Namespace: bank-b"]
        GatewayB["🚪 API Gateway<br/>SPIFFE: bank-b/gateway<br/>AWS Pod: BankBGatewayRole"]
        PayServiceB["💳 Payment Service<br/>SPIFFE: bank-b/pay-svc<br/>AWS Pod: BankBPayRole"]
        LedgerServiceB["📊 Ledger Service<br/>SPIFFE: bank-b/ledger<br/>AWS Pod: BankBLedgerRole"]
    end
    
    %% AWS Native Services
    subgraph AWS["☁️ AWS Native Security"]
        PodIdentity["🆔 Pod Identity (IRSA)<br/>• SPIFFE → IAM Role Mapping<br/>• No Long-lived Credentials"]
        RDS["🗄️ RDS + IAM Auth<br/>• 15-min Auth Tokens<br/>• CloudTrail Logging"]
        SecretsManager["🔐 Secrets Manager<br/>• API Keys & Certificates<br/>• Auto-rotation<br/>• KMS Encryption"]
        ParameterStore["⚙️ Parameter Store<br/>• Application Config<br/>• Hierarchical Access<br/>• KMS Integration"]
    end
    
    %% Observability
    subgraph Observability["📊 Observability & Audit"]
        Prometheus["📈 Prometheus<br/>Metrics Collection"]
        Grafana["📊 Grafana<br/>Security Dashboards"]
        Loki["📝 Loki<br/>Centralized Logging"]
        Jaeger["🔍 Jaeger<br/>Distributed Tracing"]
        Falco["⚠️ Falco<br/>Runtime Security"]
        CloudTrail["📋 CloudTrail<br/>AWS API Audit Trail"]
        SecurityHub["🛡️ Security Hub<br/>Compliance Findings"]
    end
    
    %% Flow Connections
    Internet --> ALB
    ALB --> AuthFilter
    
    AuthFilter --> SpiffeMap
    SpiffeMap --> TokenGen
    TokenGen --> IstioGW
    
    IstioGW --> EnvoyProxy
    EnvoyProxy --> ServiceDiscovery
    
    SpireServer <--> SpireAgent
    SpireAgent --> GatewayA
    SpireAgent --> GatewayB
    
    ServiceDiscovery --> GatewayA
    ServiceDiscovery --> GatewayB
    
    GatewayA --> UserServiceA
    GatewayA --> AcctServiceA
    UserServiceA --> AcctServiceA
    
    GatewayB --> PayServiceB
    GatewayB --> LedgerServiceB
    PayServiceB --> LedgerServiceB
    
    %% AWS Integration
    GatewayA --> PodIdentity
    UserServiceA --> PodIdentity
    AcctServiceA --> PodIdentity
    GatewayB --> PodIdentity
    PayServiceB --> PodIdentity
    LedgerServiceB --> PodIdentity
    
    PodIdentity --> RDS
    PodIdentity --> SecretsManager
    PodIdentity --> ParameterStore
    
    %% Observability Connections
    GatewayA --> Prometheus
    UserServiceA --> Prometheus
    AcctServiceA --> Prometheus
    GatewayB --> Prometheus
    PayServiceB --> Prometheus
    LedgerServiceB --> Prometheus
    
    Prometheus --> Grafana
    Falco --> SecurityHub
    RDS --> CloudTrail
    SecretsManager --> CloudTrail
    
    %% Zero Trust Flow Annotations
    IstioGW -.->|"mTLS + SPIFFE ID Validation"| GatewayA
    IstioGW -.->|"mTLS + SPIFFE ID Validation"| GatewayB
    GatewayA -.->|"Service-to-Service mTLS"| UserServiceA
    GatewayB -.->|"Service-to-Service mTLS"| PayServiceB
    UserServiceA -.->|"IAM Auth Token (15min TTL)"| RDS
    PayServiceB -.->|"IAM Auth Token (15min TTL)"| RDS
    
    %% Styling
    classDef zeroTrust fill:#ff6b6b,stroke:#d63031,stroke-width:3px,color:#fff
    classDef aws fill:#ff9f43,stroke:#e17055,stroke-width:2px,color:#fff  
    classDef security fill:#00cec9,stroke:#00b894,stroke-width:2px,color:#fff
    classDef service fill:#6c5ce7,stroke:#5f3dc4,stroke-width:2px,color:#fff
    classDef observability fill:#fd79a8,stroke:#e84393,stroke-width:2px,color:#fff
    
    class AuthFilter,SpiffeMap,TokenGen,EnvoyProxy zeroTrust
    class PodIdentity,RDS,SecretsManager,ParameterStore aws
    class SpireServer,SpireAgent,IstioGW security
    class GatewayA,UserServiceA,AcctServiceA,GatewayB,PayServiceB,LedgerServiceB service
    class Prometheus,Grafana,Loki,Jaeger,Falco,CloudTrail,SecurityHub observability

```
##
##
```

sequenceDiagram
    participant User as 👤 External User
    participant ALB as 🔒 AWS ALB
    participant Ambassador as 🛡️ Ambassador
    participant Istio as 🕸️ Istio Gateway
    participant Gateway as 🚪 API Gateway
    participant UserSvc as 👤 User Service
    participant AWS as ☁️ AWS Services
    participant RDS as 🗄️ RDS Database
    
    Note over User,RDS: 🔐 Zero Trust Authentication Flow
    
    User->>ALB: 1. HTTPS + OAuth2 JWT
    ALB->>Ambassador: 2. Forward request
    
    Ambassador->>Ambassador: 3. Validate JWT
    Ambassador->>Ambassador: 4. Extract user identity
    Ambassador->>Ambassador: 5. Map to SPIFFE ID<br/>user@bank-a → spiffe://bank-a/user/123
    Ambassador->>Ambassador: 6. Issue Internal JWT<br/>with SPIFFE claims
    
    Ambassador->>Istio: 7. Forward + Internal JWT<br/>+ X-Spiffe-ID header
    
    Istio->>Istio: 8. Validate Internal JWT
    Istio->>Istio: 9. Request SPIFFE SVID
    Istio->>Gateway: 10. Establish mTLS connection<br/>Gateway SVID ↔ Istio SVID
    
    Note over Istio,Gateway: 🔒 Mutual TLS with SPIFFE Identity
    
    Gateway->>Gateway: 11. Verify peer SPIFFE ID
    Gateway->>Gateway: 12. Check authorization<br/>@PreAuthorize validation
    Gateway->>UserSvc: 13. Service-to-Service mTLS call<br/>with SPIFFE context
    
    UserSvc->>UserSvc: 14. Verify caller SPIFFE ID<br/>Only bank-a/api-gateway allowed
    UserSvc->>UserSvc: 15. Validate user context<br/>User can only access own data
    
    UserSvc->>AWS: 16. Request database credentials<br/>using AWS Pod Identity
    AWS->>AWS: 17. Map SPIFFE ID → IAM Role
    AWS->>RDS: 18. Generate 15-min auth token
    RDS->>AWS: 19. Return IAM auth token
    AWS->>UserSvc: 20. Return credentials
    
    UserSvc->>RDS: 21. Connect with IAM auth token
    RDS->>UserSvc: 22. Return user data
    
    Note over UserSvc,RDS: 🔍 Full audit trail in CloudTrail
    
    UserSvc->>Gateway: 23. Return response
    Gateway->>Istio: 24. Return response
    Istio->>Ambassador: 25. Return response  
    Ambassador->>ALB: 26. Return response
    ALB->>User: 27. HTTPS Response<br/>Signed, Encrypted, Audited
```

##
##

```
mindmap
  root((🔐 Zero Trust))
    🆔 Identity Everywhere
      External OAuth2 JWT
      Internal SPIFFE IDs
      AWS Pod Identity
      Service Certificates
    🔍 Always Verify
      Ambassador JWT validation
      Istio mTLS enforcement
      Spring Security authorization
      AWS IAM authentication
    🎯 Least Privilege
      Tenant namespace isolation
      Method-level authorization
      Scoped database credentials
      Time-limited tokens (15min)
    📊 Continuous Monitoring
      SPIFFE identity in all logs
      CloudTrail API audit
      Falco runtime security
      Real-time policy violations
    🚫 Never Trust Network
      mTLS between all services
      No network-based assumptions
      Encrypted data in transit
      Cryptographic identity proof
    ⏰ Short-lived Everything
      15-min database tokens
      Rotated certificates
      Dynamic secrets
      Session-based context
