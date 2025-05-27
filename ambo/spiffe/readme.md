# Enhanced Proposal: Zero Trust Architecture with Ambassador, SPIFFE/SPIRE, and Istio on EKS

## Executive Summary

This proposal outlines a comprehensive zero trust architecture for our SaaS platform using Ambassador API Gateway as the edge authentication point, 

integrated with SPIFFE/SPIRE for workload identity and Istio service mesh for secure service-to-service communication. 

This approach establishes a continuous identity chain from initial user authentication through all internal service interactions, eliminating implicit trust at every level.

## Enhanced Architecture with Ambassador Edge Stack

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                      EKS CLUSTER                                                          │
│                                                                                                                           │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐                   │
│  │                                       AMBASSADOR NAMESPACE                                         │                   │
│  │                                                                                                    │                   │
│  │    ┌─────────────────────────┐         ┌───────────────────────┐         ┌────────────────────┐   │                   │
│  │    │ Ambassador Edge Stack   │         │ JWT Auth Service      │         │ OAuth/OIDC         │   │                   │
│  │    │ (Ingress Gateway)       │◄────────┤ (Token Minting)       │◄────────┤ Integration        │   │                   │
│  │    │                         │         │                       │         │                    │   │                   │
│  │    └─────────────┬───────────┘         └───────────────────────┘         └────────────────────┘   │                   │
│  │                  │                                                                                 │                   │
│  │                  │ JWT Propagation (External User Identity)                                        │                   │
│  │                  │                                                                                 │                   │
│  └──────────────────┼────────────────────────────────────────────────────────────────────────────────┘                   │
│                     │                                                                                                     │
│  ┌──────────────────┼────────────────────────────────────────────────────────────────────────────────┐                   │
│  │                  │                               SPIRE NAMESPACE                                  │                   │
│  │                  │    ┌─────────────┐         ┌─────────────┐         ┌─────────────────┐        │                   │
│  │                  │    │ SPIRE       │         │ SPIRE       │         │ Kubernetes      │        │                   │
│  │                  └───►│ Server      │◄────────┤ Controller  │◄────────┤ API Server      │        │                   │
│  │                       │             │         │             │         │                 │        │                   │
│  │                       └──────┬──────┘         └─────────────┘         └─────────────────┘        │                   │
│  │                              │                                                                    │                   │
│  │                              │ mTLS                                                               │                   │
│  │                              │                                                                    │                   │
│  │                       ┌──────▼──────┐                                                             │                   │
│  │                       │ SPIRE Agent │                                                             │                   │
│  │                       │ DaemonSet   │                                                             │                   │
│  │                       └──────┬──────┘                                                             │                   │
│  │                              │                                                                    │                   │
│  └──────────────────────────────┼────────────────────────────────────────────────────────────────────┘                   │
│                                 │                                                                                         │
│  ┌──────────────────────────────┼────────────────────────────────────────────────────────────────────┐                   │
│  │                              │                         ISTIO NAMESPACE                            │                   │
│  │                              │    ┌────────────────┐      ┌────────────────┐                      │                   │
│  │                              │    │  Istio Control │      │  Istio Ingress │                      │                   │
│  │                              └───►│  Plane (istiod)│      │  Gateway       │                      │                   │
│  │                                   │                │      │                │                      │                   │
│  │                                   └────────┬───────┘      └───────┬────────┘                      │                   │
│  │                                            │                      │                               │                   │
│  └────────────────────────────────────────────┼──────────────────────┼───────────────────────────────┘                   │
│                                               │                      │                                                    │
│  ┌───────────┐      ┌──────────────────────────────────────────────────────┐      Internet                                │
│  │ External  │      │                                                      │         ▲                                    │
│  │ Client    │◄─────┤               AWS Load Balancer                     │         │                                    │
│  │           │      │                                                      │         │                                    │
│  └───────────┘      └──────────────────────────┬───────────────────────────┘         │                                    │
│                                                │                                      │                                    │
│                                                ▼                                      │                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                                         MICROSERVICES NAMESPACES                                             │        │
│  │                                                                                                              │        │
│  │   ┌────────────────────┐       ┌────────────────────┐       ┌────────────────────┐                          │        │
│  │   │   Frontend Service │       │   API Gateway      │       │   Backend Service  │                          │        │
│  │   │   Namespace        │       │   Namespace        │       │   Namespace        │                          │        │
│  │   │                    │       │                    │       │                    │                          │        │
│  │   │  ┌──────────────┐  │       │  ┌──────────────┐  │       │  ┌──────────────┐  │                          │        │
│  │   │  │ Java Service │  │       │  │ Java Service │  │       │  │ Java Service │  │                          │        │
│  │   │  │  Pod         │  │       │  │  Pod         │  │       │  │  Pod         │  │                          │        │
│  │   │  │              │  │       │  │              │  │       │  │              │  │                          │        │
│  │   │  │  ┌─────────┐ │  │       │  │  ┌─────────┐ │  │       │  │  ┌─────────┐ │  │                          │        │
│  │   │  │  │ Istio   │ │  │       │  │  │ Istio   │ │  │       │  │  │ Istio   │ │  │                          │        │
│  │   │  │  │ Sidecar │ │  │       │  │  │ Sidecar │ │  │       │  │  │ Sidecar │ │  │                          │        │
│  │   │  │  │(Envoy)  │ │  │       │  │  │(Envoy)  │ │  │       │  │  │(Envoy)  │ │  │                          │        │
│  │   │  │  └────┬────┘ │  │       │  │  └────┬────┘ │  │       │  │  └────┬────┘ │  │                          │        │
│  │   │  │       │      │  │       │  │       │      │  │       │  │       │      │  │                          │        │
│  │   │  │  ┌────▼────┐ │  │       │  │  ┌────▼────┐ │  │       │  │  ┌────▼────┐ │  │                          │        │
│  │   │  │  │ SPIFFE  │ │  │       │  │  │ SPIFFE  │ │  │       │  │  │ SPIFFE  │ │  │                          │        │
│  │   │  │  │ Workload│ │  │       │  │  │ Workload│ │  │       │  │  │ Workload│ │  │                          │        │
│  │   │  │  │ API     │ │  │       │  │  │ API     │ │  │       │  │  │ API     │ │  │                          │        │
│  │   │  │  └─────────┘ │  │       │  │  └─────────┘ │  │       │  │  └─────────┘ │  │                          │        │
│  │   │  │              │  │       │  │              │  │       │  │              │  │                          │        │
│  │   │  │  ┌─────────┐ │  │       │  │  ┌─────────┐ │  │       │  │  ┌─────────┐ │  │                          │        │
│  │   │  │  │User JWT │ │  │       │  │  │User JWT │ │  │       │  │  │User JWT │ │  │                          │        │
│  │   │  │  │+Service │ │  │       │  │  │+Service │ │  │       │  │  │+Service │ │  │                          │        │
│  │   │  │  │SVID     │ │  │       │  │  │SVID     │ │  │       │  │  │SVID     │ │  │                          │        │
│  │   │  │  └─────────┘ │  │       │  │  └─────────┘ │  │       │  │  └─────────┘ │  │                          │        │
│  │   │  └──────────────┘  │       │  └──────────────┘  │       │  └──────────────┘  │                          │        │
│  │   │                    │       │                    │       │                    │                          │        │
│  │   └────────────────────┘       └────────┬───────────┘       └────────────────────┘                          │        │
│  │                                          │                                                                   │        │
│  │                                          ▼                                                                   │        │
│  │   ┌────────────────────┐       ┌────────────────────┐       ┌────────────────────┐                          │        │
│  │   │   Database         │       │   Caching          │       │   Other            │                          │        │
│  │   │   Services         │       │   Services         │       │   Services         │                          │        │
│  │   └────────────────────┘       └────────────────────┘       └────────────────────┘                          │        │
│  │                                                                                                              │        │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘        │
│                                                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Complete End-to-End Authentication Flow

```
┌─────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────┐      ┌────────────┐      ┌────────────┐
│ End User    │      │ Ambassador     │      │ JWT Auth       │      │ SPIRE      │      │ Service A  │      │ Service B  │
│ (Browser)   │      │ Edge Stack     │      │ Service        │      │ System     │      │ (Java)     │      │ (Java)     │
└──────┬──────┘      └───────┬────────┘      └───────┬────────┘      └─────┬──────┘      └─────┬──────┘      └─────┬──────┘
       │                     │                       │                      │                   │                   │
       │  1. Login Request   │                       │                      │                   │                   │
       ├────────────────────►│                       │                      │                   │                   │
       │                     │                       │                      │                   │                   │
       │                     │  2. Auth Request      │                      │                   │                   │
       │                     ├──────────────────────►│                      │                   │                   │
       │                     │                       │                      │                   │                   │
       │                     │  3. Return JWT Token  │                      │                   │                   │
       │                     │◄──────────────────────┤                      │                   │                   │
       │                     │                       │                      │                   │                   │
       │  4. Return JWT      │                       │                      │                   │                   │
       │◄────────────────────┤                       │                      │                   │                   │
       │                     │                       │                      │                   │                   │
       │  5. API Request     │                       │                      │                   │                   │
       │  with JWT           │                       │                      │                   │                   │
       ├────────────────────►│                       │                      │                   │                   │
       │                     │                       │                      │                   │                   │
       │                     │  6. Validate JWT      │                      │                   │                   │
       │                     ├──────────────────────►│                      │                   │                   │
       │                     │                       │                      │                   │                   │
       │                     │  7. JWT is Valid      │                      │                   │                   │
       │                     │◄──────────────────────┤                      │                   │                   │
       │                     │                       │                      │                   │                   │
       │                     │  8. Forward Request to Service A             │                   │                   │
       │                     │  (with JWT in headers)                       │                   │                   │
       │                     ├──────────────────────────────────────────────┼──────────────────►│                   │
       │                     │                       │                      │                   │                   │
       │                     │                       │                      │  9. Get SVID      │                   │
       │                     │                       │                      │◄──────────────────┤                   │
       │                     │                       │                      │                   │                   │
       │                     │                       │                      │  10. Issue SVID   │                   │
       │                     │                       │                      ├──────────────────►│                   │
       │                     │                       │                      │                   │                   │
       │                     │                       │                      │                   │  11. Call Service B   │
       │                     │                       │                      │                   │  (SVID + User JWT)    │
       │                     │                       │                      │                   ├──────────────────────►│
       │                     │                       │                      │                   │                       │
       │                     │                       │                      │  12. Validate     │                       │
       │                     │                       │                      │  Service A SVID   │                       │
       │                     │                       │                      │◄──────────────────┼───────────────────────┤
       │                     │                       │                      │                   │                       │
       │                     │                       │                      │  13. SVID Valid   │                       │
       │                     │                       │                      ├──────────────────►┼───────────────────────┤
       │                     │                       │                      │                   │                       │
       │                     │                       │                      │                   │  14. Process Request  │
       │                     │                       │                      │                   │  (with User Context)  │
       │                     │                       │                      │                   │◄──────────────────────┤
       │                     │                       │                      │                   │                       │
       │                     │                       │                      │                   │  15. Return Response  │
       │                     │                       │                      │                   │◄──────────────────────┤
       │                     │                       │                      │                   │                       │
       │  16. Return API     │                       │                      │                   │                       │
       │  Response           │                       │                      │                   │                       │
       │◄────────────────────┼───────────────────────┼──────────────────────┼───────────────────┤                       │
       │                     │                       │                      │                   │                       │
```

## Ambassador JWT Minting and Identity Propagation

### Ambassador Edge Stack Configuration

Ambassador serves as the entry point to our system, handling initial authentication and JWT minting.

```yaml
# ambassador-auth-service.yaml
apiVersion: getambassador.io/v3alpha1
kind: AuthService
metadata:
  name: jwt-auth-service
  namespace: ambassador
spec:
  auth_service: "jwt-auth.ambassador:3000"
  proto: http
  path_prefix: "/auth"
  timeout_ms: 5000
  allowed_request_headers:
    - "authorization"
    - "cookie"
    - "from"
    - "x-forwarded-proto"
  allowed_authorization_headers:
    - "authorization"
    - "x-user-id"
    - "x-user-roles"
    - "x-allowed-origins"
```

### JWT Minting Service

This custom service authenticates users and mints JWTs with the following properties:

- Short-lived tokens (15 minutes)
- User identity information (id, email, name)
- Permissions/roles for authorization
- Unique session identifier for tracking
- Claims for allowed service access

```javascript
// Example JWT structure minted by Ambassador auth service
{
  "iss": "ambassador.example.com",
  "sub": "user-123456",
  "exp": 1625097600,  // 15 minutes from issuance
  "iat": 1625096700,
  "jti": "session-abc-123",  // Unique session ID
  "email": "user@example.com",
  "name": "Example User",
  "roles": ["user", "premium"],
  "permissions": ["read:data", "write:own-data"],
  "allowed_services": [
    "frontend-service", 
    "api-gateway", 
    "user-profile-service"
  ],
  "context": {
    "origin": "web",
    "device_id": "browser-fingerprint-xyz"
  }
}
```

### Ambassador Mapping with JWT Verification

```yaml
# service-mapping.yaml
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: frontend-service
  namespace: ambassador
spec:
  prefix: /
  service: frontend-service.frontend-namespace:3000
  host: app.example.com
  cors:
    origins:
      - "https://app.example.com"
    credentials: true
  # JWT validation for all requests
  jwt:
    requireToken: true
    injectRequestHeaders:
      - name: "X-User-ID"
        value: "{{ .token.sub }}"
      - name: "X-User-Roles"
        value: "{{ .token.roles }}"
      - name: "X-Session-ID"
        value: "{{ .token.jti }}"
```

## SPIFFE/SPIRE and Istio Integration

### Bridging External User Identity with Workload Identity

The key innovation in this architecture is how we bridge external user identity (JWT from Ambassador) with internal workload identity (SPIFFE SVIDs):

1. **User authentication** happens at Ambassador, resulting in a JWT
2. **JWT propagation** occurs through all service calls
3. **Workload authentication** uses SPIFFE/SPIRE and mTLS
4. **Combined identity context** is maintained throughout

### User Identity Correlation

```yaml
# istio-authorization-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: frontend-authz
  namespace: frontend-namespace
spec:
  selector:
    matchLabels:
      app: frontend-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/ambassador/sa/ambassador"]
    when:
    - key: request.headers[x-user-id]
      values: ["*"]
```

## Java Service Integration for Dual Identity Context

```java
@Service
public class SecureServiceClient {
    private final WebClient webClient;
    private final SpiffeIdentityProvider spiffeProvider;
    
    @Autowired
    public SecureServiceClient(WebClient.Builder webClientBuilder, 
                               SpiffeIdentityProvider spiffeProvider) {
        this.spiffeProvider = spiffeProvider;
        
        // Configure WebClient with SPIFFE workload identity
        X509Source x509Source = spiffeProvider.getX509Source();
        SslContext sslContext = GrpcSslContexts.forClient()
                .trustManager(x509Source.getTrustManager())
                .keyManager(x509Source.getKeyManager())
                .build();
                
        HttpClient httpClient = HttpClient.create()
                .secure(t -> t.sslContext(sslContext));
                
        this.webClient = webClientBuilder
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }
    
    public Mono<ResponseEntity<String>> callSecureService(String path, String userJwt) {
        // Propagate user JWT while using service SVID for mTLS
        return webClient.get()
                .uri("https://backend-service.backend-namespace:8080/" + path)
                .header("Authorization", "Bearer " + userJwt)
                .retrieve()
                .toEntity(String.class);
    }
}
```

## Implementation Phases with Ambassador Integration

### Phase 1: Ambassador and Auth Service (2-3 weeks)
- Deploy Ambassador Edge Stack
- Implement JWT authentication service
- Configure JWT minting and validation
- Set up initial API routes

### Phase 2: SPIRE Infrastructure (2-3 weeks)
- Deploy SPIRE Server and Agent components
- Integrate with EKS control plane
- Configure SPIRE Kubernetes attestor
- Set up SPIFFE Certificate Authority

### Phase 3: Istio Integration (2-3 weeks)
- Configure Istio to use SPIFFE identities
- Set up identity-aware routing
- Implement JWT forwarding through Istio mesh
- Bridge Ambassador and Istio security models

### Phase 4: Java Microservice Adaptation (3-4 weeks)
- Implement Java SPIFFE libraries
- Add JWT context propagation
- Modify service-to-service communication
- Set up combined identity verification

### Phase 5: Security Hardening and Validation (2-3 weeks)
- Implement network policies
- Configure comprehensive audit logging
- Conduct security testing
- Document identity flows

## Benefits of Ambassador + SPIFFE/SPIRE Architecture

1. **Complete Zero Trust Chain**: Identity verification at every hop from browser to database
2. **Unified Authentication**: Consistent handling of both user and service identities
3. **Defense in Depth**: Multiple identity verification points
4. **Security Context Propagation**: User context maintained throughout the entire request path
5. **Centralized Policy Enforcement**: Authentication policies defined at Ambassador
6. **Scalable Identity Model**: Works across any number of services and namespaces
7. **Operational Visibility**: Clear tracking of identity throughout the system

## Authentication and Authorization Capabilities

### User-Level Controls (Ambassador)
- Initial authentication with OAuth/OIDC providers
- JWT minting with fine-grained claims
- Rate limiting per user/client
- API request validation

### Service-Level Controls (SPIFFE/SPIRE + Istio)
- Workload identity verification via mTLS
- Service-to-service authorization based on SPIFFE ID
- Cryptographically verifiable service identity
- Automatic credential rotation

### Data-Level Controls (Application Layer)
- User context available for row-level security
- Permission-based access control using JWT claims
- Tenant isolation in shared services

## Monitoring and Observability

- JWT session tracking through Ambassador logs
- SPIFFE identity correlation in Istio telemetry
- End-to-end request tracing with identity context
- Security anomaly detection based on identity behavior

##
##


# Part Deux 
1. Summary
   
- Ambassador Edge Stack for edge authentication, JWT minting and API routing  
- SPIFFE/SPIRE for automatic, cryptographically verifiable workload identities  
- Istio service mesh for mTLS, authorization policies, observability  
- GitOps, Terraform, and CI/CD for automated, scalable operations  

This design establishes a continuous identity chain: end-user → Ambassador (JWT) → Istio/SPIFFE (workload SVID) → microservices, with no implicit trust at any layer.

2. CURRENT VS. SPIFFE-ENHANCED ARCHITECTURE

```
+----------------------+-----------------------------+-----------------------------+
|         Layer        |       Traditional          |       SPIFFE/SPIRE         |
+----------------------+-----------------------------+-----------------------------+
| Identity Format      | API keys, static certs     | SPIFFE ID URIs + SVIDs     |
| Credential Mgmt      | Manual rotation, vaults    | Automatic issuance/rotation|
| Service-to-Service   | Network-based trust        | mTLS + SPIFFE identity     |
| Cross-Env Consistency| Varies per env             | Uniform across clusters    |
| Zero-Trust Support   | Limited                    | Native                     |
+----------------------+-----------------------------+-----------------------------+
```

3. ENHANCED ARCHITECTURE (ASCII)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                         EKS CLUSTER                                        │
│ ┌─────────────────────┐      ┌───────────────────────┐      ┌───────────────────────────┐   │
│ │ AMBASSADOR NAMESPACE│      │   SPIRE NAMESPACE     │      │    ISTIO NAMESPACE         │   │
│ │                     │      │                       │      │                            │   │
│ │ ┌───────────────┐   │      │ ┌───────────────┐     │      │ ┌───────────────────────┐  │   │
│ │ │ Ambassador    │   │      │ │ SPIRE Server  │     │      │ │ istiod (Control Plane)│  │   │
│ │ │ Edge Stack    │◄─┐ │      │ └──────┬────────┘     │      │ └──────────┬────────────┘  │   │
│ │ └─────┬─────────┘  │ │      │        │ mTLS           │      │            │ mTLS           │   │
│ │       │ JWT Mint  │  │      │ ┌──────▼──────┐       │      │ ┌───────────▼──────────┐ │   │
│ │       │ & Validate│  │      │ │ SPIRE Agent  │       │      │ │ Istio Ingress Gateway │ │   │
│ │       ▼           │  │      │ │ DaemonSet    │       │      │ └───────────┬──────────┘ │   │
│ │ ┌───────────────┐ │  │      │ └──────────────┘       │      │             │            │   │
│ │ │ JWT Auth      │ │  │      │                       │      │             │            │   │
│ │ │ Service       │ │  │      │                       │      │             │            │   │
│ │ └───────────────┘ │  │      │                       │      │             │            │   │
│ └───────────────────┘  │      └───────────────────────┘      └─────────────┴────────────┘   │
│                        │                                                             ▲     │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │     │
│ │                                  AWS NLB/ALB                                     │◄┘     │
│ └────────────────────────────────────────────────────────────────────────────────────┘       │
│                        │                                                            ▲        │
│                        ▼                                                            │        │
│ ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │                              MICROSERVICES NAMESPACES                                │ │
│ │ ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐          │ │
│ │ │ Frontend │    │ API      │    │ Backend  │    │ Database │    │ Caching  │          │ │
│ │ │ Service  │    │ Gateway  │    │ Service  │    │ Service  │    │ Service  │          │ │
│ │ │ (Java)   │    │ (Java)   │    │ (Java)   │    │ (Mongo)  │    │ (Redis)  │          │ │
│ │ └───┬──────┘    └───┬──────┘    └───┬──────┘    └───┬──────┘    └───┬──────┘          │ │
│ │     │ mTLS + JWT       │ mTLS + JWT        │ mTLS + JWT        │ mTLS only      │     │ │
│ │     ▼                  ▼                  ▼                  ▼                 ▼     │ │
│ │ ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐ │ │
│ │ │ WebApp   │        │ Auth     │        │ Business │        │ MongoDB  │        │ Redis    │ │ │
│ │ │ Pod      │        │ Pod      │        │ Pod      │        │ Pod      │        │ Pod      │ │ │
│ │ └──────────┘        └──────────┘        └──────────┘        └──────────┘        └──────────┘ │ │
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

4. COMPLETE END-TO-END AUTHENTICATION FLOW

```
End-User (Browser)
     │
 1. Login (OIDC) → Ambassador Edge Stack (Ingress)
     │
 2. Ambassador ▶ JWT Auth Service (Token Minting)
     │    • Validates OIDC token
     │    • Mints short-lived JWT (jti=sessionID, roles, permissions)
     │
 3. Ambassador returns JWT to browser
     │
 4. Browser ▶ Ambassador with JWT
     │
 5. Ambassador validates JWT, injects X-User-ID, X-Session-ID headers
     │
 6. Ambassador ▶ Service A (WebApp) via Istio Ingress (mTLS + JWT)
     │
 7. Service A ▶ SPIRE Agent (→ SPIRE Server) to obtain SVID
     │
 8. Service A uses SPIFFE SVID for mTLS to Service B
     │
 9. Service A calls Service B, forwarding user JWT
     │
10. Service B validates mTLS identity & user JWT claims
     │
11. Service B processes request → responds back through the mesh
     │
12. Ambassador returns final response to user
```

5. Ambassador JWT MINTING AND ROUTING YAMLS

```yaml
# ambassador-auth-service.yaml
apiVersion: getambassador.io/v3alpha1
kind: AuthService
metadata:
  name: jwt-auth-service
  namespace: ambassador
spec:
  auth_service: "jwt-auth.ambassador:3000"
  proto: http
  path_prefix: "/auth"
  timeout_ms: 5000
  allowed_request_headers:
    - "authorization"
    - "cookie"
  allowed_authorization_headers:
    - "authorization"
    - "x-user-id"
    - "x-user-roles"
    - "x-session-id"
```

```yaml
# ambassador-mapping.yaml
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: frontend-service
  namespace: ambassador
spec:
  prefix: /
  host: app.example.com
  service: frontend-service.frontend-namespace:3000
  cors:
    origins: ["https://app.example.com"]
    credentials: true
  jwt:
    requireToken: true
    injectRequestHeaders:
      - name: "X-User-ID"       value: "{{ .token.sub }}"
      - name: "X-User-Roles"    value: "{{ .token.roles }}"
      - name: "X-Session-ID"    value: "{{ .token.jti }}"
```

6. SPIRE & ISTIO INTEGRATION YAMLS

```yaml
# spire-server.yaml (Helm or Kustomize)
apiVersion: v1
kind: Namespace
metadata:
  name: spire
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spire-server
  namespace: spire
spec:
  replicas: 3
  selector: { matchLabels: { app: spire-server } }
  template:
    metadata: { labels: { app: spire-server } }
    spec:
      containers:
      - name: spire-server
        image: spiffe/spire-server:latest
        args: ["-config", "/run/spire/config/server.hcl"]
        volumeMounts:
         - name: server-config
           mountPath: /run/spire/config
      volumes:
      - name: server-config
        configMap: { name: spire-server-config }
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  selector: { matchLabels: { app: spire-agent } }
  template:
    metadata: { labels: { app: spire-agent } }
    spec:
      containers:
      - name: spire-agent
        image: spiffe/spire-agent:latest
        args: ["-config", "/run/spire/config/agent.hcl"]
        volumeMounts:
         - name: agent-config
           mountPath: /run/spire/config
      volumes:
      - name: agent-config
        configMap: { name: spire-agent-config }
```

```yaml
# istio-authorization-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: user-context-policy
  namespace: frontend-namespace
spec:
  selector: { matchLabels: { app: frontend-service } }
  rules:
    - from:
      - source:
          principals: ["cluster.local/ns/ambassador/sa/ambassador"]
      when:
        - key: request.headers[x-user-id]
          values: ["*"]
```

7. COMBINED JAVA SPRING BOOT EXAMPLE

```java
package com.example;

import io.spiffe.workloadapi.DefaultWorkloadApiClient;
import io.spiffe.workloadapi.WorkloadApiClient;
import io.spiffe.workloadapi.X509Source;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

@SpringBootApplication
public class Application {
  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

  @Bean public WebClient.Builder webClientBuilder() { return WebClient.builder(); }

  @Component
  public static class SpiffeIdentityProvider {
    private static final Logger logger = LoggerFactory.getLogger(SpiffeIdentityProvider.class);
    private static final String SOCKET = System.getenv().getOrDefault(
      "SPIFFE_ENDPOINT_SOCKET","unix:///tmp/agent.sock");
    public X509Source getX509Source() throws Exception {
      WorkloadApiClient c = DefaultWorkloadApiClient.newClient(SOCKET);
      X509Source src = c.getX509Source();
      logger.info("SPIFFE ID: {}", src.getSpiffeId());
      return src;
    }
  }

  @RestController
  public static class SecureController {
    private static final Logger logger = LoggerFactory.getLogger(SecureController.class);
    private final WebClient webClient;

    @Autowired
    public SecureController(WebClient.Builder builder,
                            SpiffeIdentityProvider sp) throws Exception {
      X509Source src = sp.getX509Source();
      TrustManager[] t = src.getTrustManager();
      KeyManager[] k = src.getKeyManager();
      SslContext ssl = SslContextBuilder.forClient()
                        .trustManager(t).keyManager(k).build();
      HttpClient hc = HttpClient.create().secure(s -> s.sslContext(ssl));
      this.webClient = builder.clientConnector(
          new ReactorClientHttpConnector(hc)).build();
      logger.info("WebClient with SPIFFE mTLS configured");
    }

    @GetMapping("/secure-data")
    public Mono<ResponseEntity<String>> getSecure(
      @RequestHeader("Authorization") String auth) {
      logger.info("/secure-data call");
      return webClient.get()
        .uri("https://backend-service.backend-namespace:8080/secure")
        .header("Authorization", auth)
        .retrieve().toEntity(String.class)
        .doOnNext(r -> logger.info("Status: {}", r.getStatusCode()))
        .doOnError(e -> logger.error("Error", e));
    }
  }
}
```

8. IMPLEMENTATION PHASES & TIMELINE  
 • Phase 1 (2–3w): Ambassador & JWT Auth → deploy Edge Stack, OIDC integration, JWT minting, mappings  
 • Phase 2 (2–3w): SPIRE Infra → HA SPIRE server, agents, K8s attestor, CA  
 • Phase 3 (2–3w): Istio Integration → mTLS, SPIFFE identity, JWT forwarding, authorization policies  
 • Phase 4 (3–4w): Java Microservices → SPIFFE libraries, JWT propagation, dual-context calls  
 • Phase 5 (2–3w): Hardening & Testing → network policies, audit logging, security tests, DR drills  

9. ADDITIONAL RECOMMENDATIONS  
 • GitOps: ArgoCD/Flux for Ambassador, SPIRE, Istio manifests  
 • IaC: Terraform for EKS, VPC, load-balancers, SPIRE stateful sets  
 • HA & Autoscale: multi-AZ Istio, SPIRE server replicas, Ambassador HPA, Cluster-Autoscaler  
 • Multi-Cluster: Route53/Gateway, federated trust domains  
 • Multi-Tenancy: namespace or annotation isolation, tenant claims in JWT  
 • Policy-as-Code: OPA Gatekeeper or Istio CRDs for RBAC/ABAC  
 • Observability: Prometheus+Thanos, Grafana, Jaeger, Kiali with identity metadata  
 • Resilience: Ambassador canaries, Istio traffic splits, circuit breakers  
 • Secrets Mgmt: AWS KMS, IRSA, ExternalSecrets for app credentials  
 • Performance: right-size nodes, spot instances, Envoy caching  
 • CI/CD & Testing: vulnerability scans, integration/chaos tests, canary deployments  
 • Backup & DR: SPIRE datastore snapshots, restore drills, Git as config backup  
 • Continuous Improvement: periodic chaos, upgrade playbooks, incident runbooks  

10. BENEFITS  
 • End-to-End Zero Trust: user + service identity verified at every hop  
 • Simplified Credential Mgmt: no static secrets, automatic SVID issuance  
 • Scalable & Resilient: autoscaling, multi-AZ, multi-cluster support  
 • Rich Observability: identity-aware metrics, logs, traces  
 • Policy Flexibility: central policies at Ambassador + fine-grained mesh controls  

11. NEXT STEPS  
 • Form cross-functional team: platform, security, devs  
 • Prototype in dev cluster, validate flows end-to-end  
 • Iterate on policies, performance, and resilience  
 • Plan phased rollout to production with monitoring and rollback plans

