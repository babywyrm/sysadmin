


# Zero Trust Architecture with JWT Authentication at Ambassador Ingress on EKS

```
                                                 ┌─────────────────────────────────────────────────────────────────────┐
                                                 │                       EKS Cluster                                    │
                                                 │                                                                     │
                                                 │  ┌───────────────────────────────────────────────────────────────┐  │
                                                 │  │                Ambassador Namespace                           │  │
 ┌─────────────┐    HTTPS    ┌──────────────┐   │  │                                                               │  │
 │             │─────────────►              │   │  │  ┌────────────┐   ┌─────────────┐    ┌───────────────────┐   │  │
 │   External  │◄─────────────  AWS ALB /   │   │  │  │            │   │             │    │                   │   │  │
 │   Clients   │   (w/JWT)   │  NLB / APIGW │   │  │  │ Ambassador │   │ JWT Auth    │    │ Rate Limiting/   │   │  │
 │             │             │              │◄──┼──┼──┤ Ingress    ├───► Service     │    │ Circuit Breaking  │   │  │
 └─────────────┘             └──────────────┘   │  │  │            │   │ (ext_auth)  │    │                   │   │  │
                                                │  │  │            │   │             │    │                   │   │  │
                                                │  │  └─────┬──────┘   └─────────────┘    └───────────────────┘   │  │
                                                │  │        │                                                     │  │
                                                │  └────────┼─────────────────────────────────────────────────────┘  │
                                                │           │                                                        │
                                                │           │ JWT Propagation                                        │
                                                │           │ (Service Mesh)                                         │
                                                │           ▼                                                        │
                                                │  ┌────────────────────┐  ┌────────────────────┐  ┌──────────────┐ │
                                                │  │  Service Namespace  │  │  Service Namespace │  │    Other     │ │
                                                │  │                     │  │                    │  │  Namespaces  │ │
                                                │  │  ┌───────────────┐  │  │  ┌──────────────┐ │  │              │ │
                                                │  │  │ Microservice A│  │  │  │Microservice B│ │  │  ┌────────┐  │ │
                                                │  │  │ ┌───────────┐ │  │  │  │┌────────────┐│ │  │  │Database│  │ │
                                                │  │  │ │Service Acct│ │  │  │  ││Service Acct││ │  │  │Cluster │  │ │
                                                │  │  │ └───────────┘ │  │  │  │└────────────┘│ │  │  └────────┘  │ │
                                                │  │  └───────────────┘  │  │  └──────────────┘ │  │              │ │
                                                │  │                     │  │                    │  │              │ │
                                                │  └────────────────────┘  └────────────────────┘  └──────────────┘ │
                                                │                                                                    │
                                                └────────────────────────────────────────────────────────────────────┘
```

## Core Components and Flow

### 1. Authentication and JWT Minting at Ingress

```yaml
apiVersion: getambassador.io/v3alpha1
kind: AuthService
metadata:
  name: jwt-auth-service
spec:
  auth_service: "jwt-auth:3000"
  proto: http
  path_prefix: "/auth"
  allowed_request_headers:
    - "authorization"
    - "origin"
    - "content-type"
```

The JWT Auth Service:
- Validates initial credentials (username/password, OAuth tokens, etc.)
- Mints new JWTs containing:
  - User identity
  - Permissions/scopes
  - Allowed origins
  - Service access rights
  - Short expiration time (5-15 min)

### 2. Zero Trust Network Controls

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-microservice-a
spec:
  podSelector:
    matchLabels:
      app: microservice-a
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ambassador
    ports:
    - protocol: TCP
      port: 8080
```

### 3. JWT Validation and Propagation

For each microservice mapping:

```yaml
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: service-a-mapping
spec:
  prefix: /api/service-a/
  service: service-a.service-namespace:8080
  cors:
    origins:
      - "https://app.example.com"
    methods:
      - GET
      - POST
    credentials: true
  jwt:
    requireToken: true
    injectRequestHeaders:
      - name: "X-User-ID"
        value: "{{ .token.sub }}"
      - name: "X-User-Permissions"
        value: "{{ .token.permissions }}"
```

## Implementation Steps

1. **Deploy Ambassador Edge Stack** in a dedicated namespace with proper RBAC

2. **Create JWT Auth Service**:
   - Implement token minting logic
   - Connect to your identity provider
   - Deploy in the Ambassador namespace

3. **Configure Ambassador Mappings**:
   - Add JWT validation requirements
   - Set up CORS policies
   - Enable header injection for downstream services

4. **Implement Network Policies**:
   - Isolate namespaces
   - Allow only specific traffic flows
   - Block pod-to-pod communication except where needed

5. **Set Up Monitoring and Audit**:
   - Log all authentication events
   - Monitor JWT usage patterns
   - Set up alerts for unusual behavior

## Security Enhancements

1. **Short-lived tokens**: Configure JWTs with 5-15 minute expiration

2. **Embedded context**: Include allowed services, origins, and IP ranges in tokens

3. **Secure token storage**: Use secure cookie settings or HTTP-only storage in browser

4. **Circuit breaking**: Configure Ambassador to prevent cascading failures

5. **Rate limiting**: Protect services from abuse with Ambassador rate limiters

```yaml
apiVersion: getambassador.io/v3alpha1
kind: RateLimit
metadata:
  name: basic-rate-limit
spec:
  domain: ambassador
  limits:
   - pattern: [{generic_key: default}]
     rate: 10
     unit: minute
```

