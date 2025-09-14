

```
INTERNET ( www )
                                        │
                                        │ HTTPS
                                        ▼
                     ┌─────────────────────────────────────┐
                     │          AWS ALB / NLB              │
                     │    - TLS Termination                │
                     │    - DDoS Protection                │
                     │    - WAF Rules                      │
                     └─────────────────┬───────────────────┘
                                       │
                                       │ mTLS
                                       ▼
    ┌──────────────────────────────────────────────────────────────────────┐
    │                        EKS CLUSTER                                   │
    │                                                                      │
    │  ┌─────────────────────────────────────────────────────────────────┐
    │  │                AMBASSADOR EDGE STACK                            │
    │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐
    │  │  │   Ingress   │  │    Auth     │  │      Rate Limiting      │
    │  │  │ Controller  │→ │   Service   │→ │   & Circuit Breaker     │
    │  │  └─────────────┘  └─────────────┘  └─────────────────────────┘
    │  │         │               │                        │
    │  │         ▼               ▼                        ▼
    │  │  ┌─────────────────────────────────────────────────────────────┐
    │  │  │          JWT VALIDATION & SPIFFE ID MAPPING                 │
    │  │  │   - OAuth2/OIDC → SPIFFE ID                                 │
    │  │  │   - Issues internal JWT with SPIFFE claims                  │ 
    │  │  └─────────────────────────────────────────────────────────────┘
    │  └─────────────────────────┬───────────────────────────────────────┘
    │                            │
    │                            │ Internal JWT + SPIFFE Context
    │                            ▼
    │  ┌─────────────────────────────────────────────────────────────────┐
    │  │                   ISTIO SERVICE MESH                            │
    │  │                                                                 │
    │  │  ┌─────────────┐         ┌─────────────┐
    │  │  │   Ingress   │    mTLS │   Envoy     │  AuthZ Policy
    │  │  │   Gateway   │◄───────►│   Proxy     │  (OPA Integration)
    │  │  └─────────────┘         └─────────────┘
    │  │         │                        │
    │  │         │ SPIFFE mTLS           │ SPIFFE mTLS
    │  │         ▼                        ▼
    │  │  ┌─────────────────────────────────────────────────────────────┐
    │  │  │              SERVICE DISCOVERY & ROUTING                    │
    │  │  │   - SPIFFE IDs for service identity                         │
    │  │  │   - Zero-trust service-to-service                           │
    │  │  └─────────────────────────────────────────────────────────────┘
    │  └─────────────────────────┬───────────────────────────────────────┘
    │                            │
    │  ┌─────────────────────────────────────────────────────────────────┐
    │  │                    SPIFFE/SPIRE LAYER                           │
    │  │                                                                 │
    │  │  ┌─────────────┐         ┌─────────────────────────────────────┐
    │  │  │SPIRE Server │◄───────►│        SPIRE Agents                 │
    │  │  │- Root CA    │         │  - Node attestation                 │
    │  │  │- Identity   │         │  - Workload attestation             │
    │  │  │  Registry   │         │  - SVID issuance                    │
    │  │  └─────────────┘         └─────────────────────────────────────┘
    │  │         │
    │  │         │ Issues SVIDs
    │  │         ▼
    │  └─────────────────────────────────────────────────────────────────┘
    │                            │
    │                            │ SPIFFE ID Assignment
    │                            ▼
    │                                                                      
    │  ┌─────────────────────────────────────────────────────────────────┐
    │  │                    SPRING SERVICES LAYER                        │
    │  │                                                                 │
    │  │   Namespace: bank-a        Namespace: bank-b
    │  │  ┌─────────────────┐      ┌─────────────────┐
    │  │  │   API Gateway   │      │   API Gateway   │
    │  │  │ SPIFFE ID:      │      │ SPIFFE ID:      │
    │  │  │ bank-a/gateway  │      │ bank-b/gateway  │
    │  │  │ AWS Pod Ident.  │      │ AWS Pod Ident.  │
    │  │  └─────────────────┘      └─────────────────┘
    │  │          │                        │
    │  │          ▼                        ▼
    │  │  ┌─────────────────┐      ┌─────────────────┐
    │  │  │  User Service   │      │  Payment Service│
    │  │  │ SPIFFE ID:      │      │ SPIFFE ID:      │
    │  │  │ bank-a/user-svc │      │ bank-b/pay-svc  │
    │  │  │ IAM Role:       │      │ IAM Role:       │
    │  │  │ BankAUserRole   │      │ BankBPayRole    │
    │  │  └─────────────────┘      └─────────────────┘
    │  │          │                        │
    │  │          ▼                        ▼
    │  │  ┌─────────────────┐      ┌─────────────────┐
    │  │  │ Account Service │      │ Ledger Service  │
    │  │  │ SPIFFE ID:      │      │ SPIFFE ID:      │
    │  │  │ bank-a/acct-svc │      │ bank-b/ledger   │
    │  │  │ IAM Role:       │      │ IAM Role:       │
    │  │  │ BankAAcctRole   │      │ BankBLedgerRole │
    │  │  └─────────────────┘      └─────────────────┘
    │  │          │                        │
    │  │          ▼                        ▼
    │  │  ┌─────────────────┐      ┌─────────────────┐
    │  │  │   RDS Database  │      │   RDS Database  │
    │  │  │ IAM Auth        │      │ IAM Auth        │
    │  │  │ + SPIFFE Verify │      │ + SPIFFE Verify │
    │  │  └─────────────────┘      └─────────────────┘
    │  └─────────────────────────────────────────────────────────────────┘
    │                            │
    │                            │ AWS Pod Identity + IAM
    │                            ▼
    │  ┌─────────────────────────────────────────────────────────────────┐
    │  │                  AWS NATIVE SECRETS                             │
    │  │                                                                 │
    │  │  ┌─────────────────────────────────────────────────────────────┐
    │  │  │              AWS POD IDENTITY + IAM                         │
    │  │  │  - SPIFFE ID → IAM Role Mapping                             │
    │  │  │  - AWS Secrets Manager integration                          │
    │  │  │  - RDS IAM database authentication                          │
    │  │  │  - Parameter Store for config                               │
    │  │  │  - KMS for encryption keys                                  │
    │  │  └─────────────────────────────────────────────────────────────┘
    │  └─────────────────────────────────────────────────────────────────┘
    │                                                                      
    │  ┌─────────────────────────────────────────────────────────────────┐
    │  │                    OBSERVABILITY LAYER                          │
    │  │                                                                 │
    │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐
    │  │  │ Prometheus  │ │  Grafana    │ │    Loki     │ │  Jaeger  │
    │  │  │ (Metrics)   │ │(Dashboards) │ │   (Logs)    │ │(Tracing) │
    │  │  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘
    │  │                                                                 
    │  │  ┌─────────────────────────────────────────────────────────────┐
    │  │  │           AUDIT & SECURITY MONITORING                       │
    │  │  │  - Falco (Runtime Security)                                 │
    │  │  │  - OPA Violations                                           │
    │  │  │  - SPIFFE Identity Trails                                   │
    │  │  │  - AWS CloudTrail integration                               │
    │  │  │  - AWS Security Hub findings                                │
    │  │  └─────────────────────────────────────────────────────────────┘
    │  └─────────────────────────────────────────────────────────────────┘
    └──────────────────────────────────────────────────────────────────────┘
