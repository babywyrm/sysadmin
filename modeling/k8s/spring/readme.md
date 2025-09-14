

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

```
##
##
```


External User/API Client                    EKS Cluster
          │                                      │
          │ 1. HTTPS Request                     │
          │    + OAuth2 JWT                      │
          ▼                                      │
 ┌──────────────────┐                            │
 │    AWS ALB       │                            │
 │  - TLS Term      │                            │
 │  - WAF Rules     │                            │
 └─────────┬────────┘                            │
           │ 2. Forward                          │
           ▼                                     │
 ┌────────────────────────────────────────────────-─────────┐
 │ AMBASSADOR EDGE STACK                                    │
 │                                                          │
 │ ┌─────────────────┐  3. Validate JWT                     │
 │ │   Auth Filter   │  4. Extract user identity            │
 │ │                 │  5. Map to SPIFFE ID                 │
 │ │  OAuth2 JWT     │     user@bank-a →                    │
 │ │      ▼          │     spiffe://bank-a/user/12345       │
 │ │  SPIFFE Map     │                                      │
 │ └─────────────────┘                                      │
 │          │ 6. Issue Internal JWT                         │
 │          │    with SPIFFE claims                         │
 │          ▼                                               │
 │ ┌─────────────────┐                                      │
 │ │ Internal Token  │  {                                   │
 │ │    Generator    │    "sub": "spiffe://bank-a/user/12345", 
 │ │                 │    "aud": "bank-a",                  │
 │ │                 │    "scope": ["read", "transfer"],    │
 │ │                 │    "tenant": "bank-a"                │
 │ │                 │  }                                   │
 │ └─────────────────┘                                      │
 └─────────────────────────┬──────────────────────────────-─┘
                           │ 7. Forward with                
                           │    Internal JWT +               
                           │    X-Spiffe-ID header          
                           ▼                                
 ┌─────────────────────────────────────────────────────────┐
 │ ISTIO INGRESS GATEWAY                                   │
 │                                                         │
 │ ┌─────────────────┐  8. Validate Internal JWT           │
 │ │  JWT Validator  │  9. Extract SPIFFE ID               │
 │ │                 │ 10. Request SPIFFE SVID             │
 │ │  SPIFFE ID:     │     from SPIRE Agent                │
 │ │  ingress-gw     │                                     │
 │ │  AWS Pod ID:    │                                     │
 │ │  EKSIngressRole │                                     │
 │ └─────────────────┘                                     │
 │          │ 11. Establish mTLS                           │
 │          │     with target service                      │
 │          ▼                                              │
 └─────────────────────────┬───────────────────────────────┘
                           │ 12. mTLS Connection            
                           │     Gateway SVID ←→            
                           │     Service SVID               
                           ▼                                
 ┌─────────────────────────────────────────────────────────┐
 │ SPRING SERVICE (API GATEWAY)                            │
 │ SPIFFE ID: spiffe://bank-a/api-gateway                  │
 │ AWS Pod Identity: BankAGatewayRole                      │
 │                                                         │
 │ ┌─────────────────┐ 13. Verify peer SPIFFE ID           │
 │ │@PreAuthorize    │ 14. Check authorization             │
 │ │                 │     - Extract user context          │
 │ │ Security        │     - Validate tenant boundary      │
 │ │ Context         │     - Check method permissions      │
 │ └─────────────────┘                                     │
 │          │ 15. Call downstream service                  │
 │          ▼                                              │
 └─────────────────────────┬───────────────────────────────┘
                           │ 16. Service-to-Service         
                           │     mTLS call with             
                           │     SPIFFE context             
                           ▼                                
 ┌─────────────────────────────────────────────────────────┐
 │ SPRING SERVICE (USER SERVICE)                           │
 │ SPIFFE ID: spiffe://bank-a/user-service                 │
 │ AWS Pod Identity: BankAUserServiceRole                  │
 │                                                         │
 │ ┌─────────────────┐ 17. Verify caller SPIFFE ID         │
 │ │@PreAuthorize    │     - Only bank-a/api-gateway       │
 │ │                 │       can call this                 │
 │ │ Method Security │ 18. Validate user context           │
 │ │                 │     - User can only access          │
 │ │                 │       their own data                │
 │ └─────────────────┘                                     │
 │          │ 19. Need database credentials                │
 │          ▼                                              │
 └─────────────────────────┬───────────────────────────────┘
                           │ 20. Use AWS Pod Identity       
                           │     for RDS IAM auth            
                           ▼                                
 ┌─────────────────────────────────────────────────────────┐
 │ AWS RDS + SECRETS MANAGER                               │
 │                                                         │
 │ ┌─────────────────┐ 21. Pod Identity Auth               │
 │ │  RDS Instance   │     - Verify IAM role               │
 │ │                 │     - SPIFFE ID → IAM mapping       │
 │ │ IAM Database    │ 22. Generate DB auth token          │
 │ │ Authentication  │     - Short-lived (15 min)          │
 │ │                 │     - Scoped to specific database   │
 │ │ + CloudTrail    │     - Logged in CloudTrail          │
 │ │   Logging       │                                     │
 │ └─────────────────┘                                     │
 │                                                         │
 │ ┌─────────────────┐ 23. Secrets Manager (optional)      │
 │ │ AWS Secrets     │     - API keys                      │
 │ │ Manager         │     - External service tokens       │
 │ │                 │     - Encryption keys               │
 │ │ KMS Integration │     - Auto-rotation                 │
 │ └─────────────────┘                                     │
 └─────────────────────────┬───────────────────────────────┘
                           │ 24. Return auth token           
                           ▼                                
 ┌─────────────────────────────────────────────────────────┐
 │ USER SERVICE (continued)                                │
 │                                                         │
 │ ┌─────────────────┐ 25. Connect to RDS                  │
 │ │   DataSource    │     with IAM auth token             │
 │ │                 │ 26. Execute query                   │
 │ │ AWS RDS Driver  │ 27. Return user data                │
 │ │ + IAM Auth      │                                     │
 │ │ Token: 15min    │                                     │
 │ │ TTL             │                                     │
 │ └─────────────────┘                                     │
 └─────────────────────────┬───────────────────────────────┘
                           │ 28. Response flows back        
                           │     through mTLS chain         
                           ▼                                
                    ┌──────────────┐                       
                    │   RESPONSE   │                       
                    │   - Signed   │                       
                    │   - Encrypted│                       
                    │   - Audited  │                       
                    │ - CloudTrail │                       
                    └──────────────┘
