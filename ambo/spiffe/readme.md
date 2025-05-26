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

