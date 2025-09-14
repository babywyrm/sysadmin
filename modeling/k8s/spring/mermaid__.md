
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
