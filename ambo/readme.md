
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                             EKS CLUSTER                                                                 │
│                                                                                                                                         │
│  ┌─────────────────────┐    HTTPS     ┌──────────────────────┐                                                                          │
│  │                     │◄────────────►│                      │                                                                          │
│  │   External Clients  │   w/ OIDC    │      AWS ALB/NLB     │                                                                          │
│  │                     │   ID Tokens  │                      │                                                                          │
│  └─────────────────────┘              └──────────┬───────────┘                                                                          │
│                                                  │                                                                                      │
│                                                  ▼                                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐                                                                │
│  │                     AMBASSADOR NAMESPACE                            │                                                                │
│  │                                                                     │                                                                │
│  │  ┌─────────────────────────────────────────────┐                    │                                                                │
│  │  │         Ambassador Edge Stack Pods          │                    │                                                                │
│  │  │  ┌──────────┐  ┌─────────────┐  ┌────────┐  │                    │                                                                │
│  │  │  │ Ingress  │  │ Rate Limit  │  │ Filter │  │                    │                                                                │
│  │  │  │ Gateway  │  │ Controller  │  │ Policy │  │                    │                                                                │
│  │  │  └────┬─────┘  └─────────────┘  └────────┘  │                    │                                                                │
│  │  └──────┼──────────────────────────────────────┘                    │                                                                │
│  │         │                                                           │                                                                │
│  │         │ JWT Validation Request                                    │                                                                │
│  │         ▼                                                           │                                                                │
│  │  ┌──────────────────────┐  ┌───────────────────────────────────┐   │                                                                 │
│  │  │ JWT Auth Service     │  │ Istio Control Plane (istiod)      │   │                                                                 │
│  │  │ ┌──────────────────┐ │  │ ┌─────────────┐ ┌──────────────┐  │   │                                                                 │
│  │  │ │Token Validation  │ │  │ │  Pilot      │ │  Citadel     │  │   │                                                                 │
│  │  │ │& Minting Service │ │  │ │(Traffic Mgmt)│ │(Cert/Identity)│  │   │                                                               │
│  │  │ └──────────────────┘ │  │ └─────────────┘ └──────────────┘  │   │                                                                 │
│  │  └──────────────────────┘  └───────────────────────────────────┘   │                                                                 │
│  │                                                                     │                                                                │
│  └─────────────────────────────────────────────────────────────────────┘                                                                │
│                                                                                                                                         │
│                                     │ JWT Token + Identity Headers Propagation                                                          │
│                                     ▼                                                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────────┐                                                       │
│  │                       KUBERNETES SERVICE DISCOVERY                           │                                                       │
│  │                                                                              │                                                       │
│  │  ┌──────────────────────┐ ┌────────────────────────────────────────────────┐ │                                                       │
│  │  │ CoreDNS (kube-dns)   │ │ Istio Service Registry                         │ │                                                       │
│  │  │                      │ │                                                │ │                                                       │
│  │  │ webapp-svc.frontend  │ │ ┌────────────────────┐ ┌───────────────────┐  │ │                                                        │
│  │  │ api-svc.api          │ │ │ Service Endpoints  │ │ Identity Mapping  │  │ │                                                        │
│  │  │ db-svc.database      │ │ │ w/ Security Labels │ │ Service↔Account   │  │ │                                                        │
│  │  └──────────────────────┘ │ └────────────────────┘ └───────────────────┘  │ │                                                        │
│  │                           └────────────────────────────────────────────────┘ │                                                       │
│  └──────────────────────────────────────────────────────────────────────────────┘                                                       │
│                              │               │                │                                                                         │
│            ┌─────────────────┘               │                └─────────────────┐                                                       │
│            │                                 │                                  │                                                       │
│            ▼                                 ▼                                  ▼                                                       │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────────┐                                      │
│  │     FRONTEND NAMESPACE      │  │       API NAMESPACE         │  │    DATABASE NAMESPACE       │                                      │
│  │                             │  │                             │  │                             │                                      │
│  │  ┌─────────────────────┐    │  │  ┌─────────────────────┐    │  │  ┌─────────────────────┐    │                                      │
│  │  │ WebApp Service      │    │  │  │ API Service         │    │  │  │ Database Service    │    │                                      │
│  │  │ (ClusterIP)         │    │  │  │ (ClusterIP)         │    │  │  │ (ClusterIP)         │    │                                      │
│  │  └──────────┬──────────┘    │  │  └──────────┬──────────┘    │  │  └──────────┬──────────┘    │                                      │
│  │             │               │  │             │               │  │             │               │                                      │
│  │             ▼               │  │             ▼               │  │             ▼               │                                      │
│  │  ┌─────────────────────────┐  │  │  ┌─────────────────────────┐  │  │  ┌─────────────────────────┐  │                                    │
│  │  │ WebApp Pod              │  │  │  │ API Pod                │  │  │  │ Database Pod            │  │                                     │
│  │  │ ┌─────────┐ ┌─────────┐ │  │  │  │ ┌─────────┐ ┌─────────┐ │  │  │  │ ┌─────────┐ ┌─────────┐ │  │                                    │
│  │  │ │ App     │ │ Istio   │ │  │  │  │ │ App     │ │ Istio   │ │  │  │  │ │ DB      │ │ Istio   │ │  │                                    │
│  │  │ │ Container│ │ Sidecar │ │◄─┼──┼──┼─┤ Container│ │ Sidecar │ │◄─┼──┼──┼─┤ Container│ │ Sidecar │ │  │                                 │
│  │  │ │         │ │ (Envoy) │ │  │  │  │ │         │ │ (Envoy) │ │  │  │  │ │         │ │ (Envoy) │ │  │                                     │
│  │  │ └─────────┘ └─────────┘ │  │  │  │ └─────────┘ └─────────┘ │  │  │  │ └─────────┘ └─────────┘ │  │                                     │
│  │  │       JWT + Identity    │  │  │  │      JWT + Identity     │  │  │  │      JWT + Identity     │  │                                     │
│  │  │       ┌─────────────┐   │  │  │  │      ┌─────────────┐    │  │  │  │      ┌─────────────┐    │  │                                     │
│  │  │       │WorkloadID   │   │  │  │  │      │WorkloadID   │    │  │  │  │      │WorkloadID   │    │  │                                     │
│  │  │       │K8s SA Token│   │──┼──┼─┐│      │K8s SA Token│    │──┼──┼─┐│      │K8s SA Token│    │  │                                     │
│  │  │       │SPIFFE ID    │   │  │  │ ││      │SPIFFE ID    │    │  │  │ ││      │SPIFFE ID    │    │  │                                    │
│  │  │       └─────────────┘   │  │  │ │└─────────────────────────┘  │  │ │└─────────────────────────┘  │                                    │
│  │  └─────────────────────────┘  │  │ │                             │  │ │                             │                                    │
│  │                               │  │ │                             │  │ │                             │                                    │
│  └───────────────────────────────┘  │ │                             │  │ │                             │                                    │
│                                     │ │                             │  │ │                             │                                    │
│  ┌─────────────────────────────────┐ │                             │  │ │                             │                                     │
│  │        ISTIO MESH               │ │                             │  │ │                             │                                     │
│  │ ┌─────────────────────────────┐ │ │                             │  │ │                             │                                     │
│  │ │ mTLS Service Connections    │◄┼─┘                             │  │ │                             │                                     │
│  │ └─────────────────────────────┘ │                               │  │ │                             │                                     │
│  │ ┌─────────────────────────────┐ │                               │  │ │                             │                                     │
│  │ │ Authentication Policy       │ │                               │  │ │                             │                                     │
│  │ │ ┌─────────────────────────┐ │ │                               │  │ │                             │                                     │
│  │ │ │ JWT Validation Rules    │ │ │                               │  │ │                             │                                     │
│  │ │ └─────────────────────────┘ │ │                               │  │ │                             │                                     │
│  │ └─────────────────────────────┘ │                               │  │ │                             │                                     │
│  │ ┌─────────────────────────────┐ │                               │  │ │                             │                                     │
│  │ │ Authorization Policy        │ │                               │  │ │                             │                                     │
│  │ │ ┌─────────────────────────┐ │ │                               │  │ │                             │                                     │
│  │ │ │ RBAC & Identity Rules   │◄┼─┘                               │  │ │                             │                                     │
│  │ │ └─────────────────────────┘ │ │                               │  │ │                             │                                     │
│  │ └─────────────────────────────┘ │                               │  │ │                             │                                     │
│  │ ┌─────────────────────────────┐ │                               │  │ │                             │                                     │
│  │ │ Request Authentication      │ │                               │  │ │                             │                                     │
│  │ │ ┌─────────────────────────┐ │ │                               │  │ │                             │                                     │
│  │ │ │ Principal Identity      │◄┼─┴───────────────────────────────┴──┘ │                             │                                     │
│  │ │ │ Tracking & Enforcement  │ │                                      │                             │                                     │
│  │ │ └─────────────────────────┘ │                                      │                             │                                     │
│  │ └─────────────────────────────┘                                      │                             │                                     │
│  └─────────────────────────────────┘                                    │                             │                                     │
│                                                                         │                             │                                     │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐                                     │
│  │                                      OBSERVABILITY PLANE                                           │                                     │
│  │  ┌───────────────┐  ┌────────────────┐  ┌───────────────────┐  ┌────────────────────────────────┐ │                                      │
│  │  │ Prometheus    │  │ Grafana        │  │ Jaeger            │  │ Kiali                          │ │                                      │
│  │  │ ┌───────────┐ │  │ ┌────────────┐ │  │ ┌───────────────┐ │  │ ┌────────────────────────────┐ │ │                                      │
│  │  │ │ Metrics   │ │  │ │ Dashboards │ │  │ │ Distributed   │ │  │ │ Service Mesh Visualization │ │ │                                      │
│  │  │ │ Collection│ │  │ │ & Alerts   │ │  │ │ Tracing       │ │  │ │ Identity & Traffic Tracking│ │ │                                      │
│  │  │ └───────────┘ │  │ └────────────┘ │  │ └───────────────┘ │  │ └────────────────────────────┘ │ │                                      │
│  │  └───────────────┘  └────────────────┘  └───────────────────┘  └────────────────────────────────┘ │                                      │
│  └────────────────────────────────────────────────────────────────────────────────────────────────────┘                                     │
│                                                                                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐                                     │
│  │                                   NETWORK POLICIES & SECURITY                                      │                                     │
│  │  ┌────────────────────────────────┐  ┌────────────────────────────┐  ┌───────────────────────────┐ │                                     │
│  │  │ Ingress Network Policies       │  │ Egress Network Policies    │  │ Pod Security Policies     │ │                                     │
│  │  │ (Inter-namespace Communication) │  │ (External Communication)   │  │ (Runtime Security)        │ │                                    │
│  │  └────────────────────────────────┘  └────────────────────────────┘  └───────────────────────────┘ │                                     │
│  └────────────────────────────────────────────────────────────────────────────────────────────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘


##
#



# Zero Trust Architecture with JWT Authentication at Ambassador Ingress on EKS

```
                                                 ┌─────────────────────────────────────────────────────────────────────┐
                                                 │                       EKS Cluster                                   │
                                                 │                                                                     │ 
                                                 │  ┌───────────────────────────────────────────────────────────────┐  │
                                                 │  │                Ambassador Namespace                           │  │
 ┌─────────────┐    HTTPS    ┌──────────────┐   │  │                                                               │  │
 │             │─────────────►              │   │  │  ┌────────────┐   ┌─────────────┐    ┌───────────────────┐   │  │
 │   External  │◄─────────────  AWS ALB /   │   │  │  │            │   │             │    │                   │   │  │
 │   Clients   │   (w/JWT)   │  NLB / APIGW │   │  │  │ Ambassador │   │ JWT Auth    │    │ Rate Limiting/    │   │  │
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
                                                │  │  │ │Service Acct│ │  │  │  ││Service Acct││ │  │ │Cluster │  │ │
                                                │  │  │ └───────────┘ │  │  │  │└────────────┘│ │  │  └────────┘  │ │
                                                │  │  └───────────────┘  │  │  └──────────────┘ │  │              │ │
                                                │  │                     │  │                   │  │              │ │
                                                │  └────────────────────┘  └────────────────────┘  └──────────────┘ │
                                                │                                                                   │
                                                └───────────────────────────────────────────────────────────────────┘
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



# Zero Trust Architecture: Internal Service Communication in EKS

Let's dive deeper into how microservices communicate within an EKS cluster in a zero trust model, with proper service discovery and secure communication patterns.

## Kubernetes Service Discovery and Routing

```
                                     ┌───────────────────────────────────────────────────────────────┐
                                     │                      EKS Cluster                              │
                                     │                                                               │
  ┌──────────┐     HTTPS     ┌──────┴──────┐                                                         │
  │          │◄────────────► │ AWS ALB/NLB │                                                         │
  │ External │               └──────┬──────┘                                                         │
  │ Clients  │                      │                                                                │
  └──────────┘                      ▼                                                                │
                         ┌──────────────────────┐                                                    │
                         │  Ambassador Ingress  │                                                    │
                         │  ┌────────────────┐  │                                                    │
                         │  │  JWT Auth/Mint │  │                                                    │
                         │  └────────────────┘  │                                                    │
                         └──────────┬───────────┘                                                    │
                                    │                                                                │
                                    │ JWT Token Propagation                                          │
                                    ▼                                                                │
  ┌───────────────────────────────────────────────────┐                                              │
  │              CoreDNS (kube-dns)                   │                                              │
  │                                                   │                                              │
  │  Service Discovery for cluster.local domain       │                                              │
  │  webapp.namespace.svc.cluster.local ──────────┐   │                                              │
  │  api.namespace.svc.cluster.local      ────────┼───┼───┐                                          │
  │  db.namespace.svc.cluster.local       ────────┼───┼───┼──┐                                       │
  └───────────────────────────────────────────────┘   │   │  │                                       │
                                                      │   │  │                                       │
  ┌────────────────────────┐  ┌─────────────────────┐ │   │  │ ┌───────────────────────┐             │
  │ Frontend Namespace     │  │ API Namespace       │ │   │  │ │ Database Namespace    │             │
  │ ┌──────────────────┐  │  │ ┌─────────────────┐ │ │   │  │ │ ┌─────────────────┐   │              │
  │ │ WebApp Service   │◄─┼──┼─┼─────────────────┼─┼─┘   │  │ │ │                 │   │              │
  │ │ (ClusterIP)      │  │  │ │ API Service     │◄┼─────┘  │ │ │ Database Service│   │              │
  │ │                  │  │  │ │ (ClusterIP)     │ │        │ │ │ (ClusterIP)     │◄──┼────────┐     │
  │ └────────┬─────────┘  │  │ └────────┬────────┘ │        │ │ └────────┬────────┘   │        │     │
  │          │            │  │          │          │        │ │          │            │        │     │
  │          ▼            │  │          ▼          │        │ │          ▼            │        │     │
  │ ┌──────────────────┐  │  │ ┌─────────────────┐ │        │ │ ┌─────────────────┐   │        │     │
  │ │ WebApp Pods      │  │  │ │ API Pods        │ │        │ │ │ Database Pods   │   │        │     │
  │ │ ┌──────────────┐ │  │  │ │ ┌─────────────┐ │ │        └─┼─► ┌─────────────┐ │   │        │     │
  │ │ │Service Account│ │  │  │ │ │Service Acct │ │ │          │ │ │Service Acct │ │  │        │     │
  │ │ └──────────────┘ │  │  │ │ └─────────────┘ │ │          │ │ └─────────────┘ │   │        │     │
  │ └──────────────────┘  │  │ └─────────────────┘ │          │ └─────────────────┘   │        │     │
  │                       │  │                     │          │                       │        │     │
  └───────────────────────┘  └─────────────────────┘          └───────────────────────┘        │     │
                                                                                               │     │
  ┌─────────────────────────────────────────────────────────────────────────────────────────┐  │     │
  │                     Network Policies Controlling Pod-to-Pod Traffic                     │◄─┘     │
  └─────────────────────────────────────────────────────────────────────────────────────────┘        │
                                                                                                     │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## How Service Discovery Works in Kubernetes

### 1. Kubernetes Service Objects

Services in Kubernetes provide stable endpoints for groups of pods. Each service gets:

- A stable DNS name: `service-name.namespace.svc.cluster.local`
- A virtual IP (ClusterIP)
- Port mappings

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-service
  namespace: api-namespace
spec:
  selector:
    app: api
  ports:
  - port: 8080
    targetPort: 3000
```

### 2. DNS-Based Discovery

Your webapp doesn't need hardcoded IP addresses because:

- CoreDNS runs within the cluster and resolves service names
- A pod can reach another service with:
  - `api-service.api-namespace` (within the same cluster)
  - `api-service.api-namespace.svc.cluster.local` (fully qualified)
- Environment variables are also injected: `API_SERVICE_HOST` and `API_SERVICE_PORT`

### 3. Token Propagation for Zero Trust

When the webapp needs to call an API service:

```javascript
// In your webapp code
async function fetchFromApi(endpoint) {
  // Get the JWT token from the original request
  const jwtToken = req.headers.authorization;
  
  // Forward the token to the internal API service
  const response = await fetch(`http://api-service.api-namespace:8080${endpoint}`, {
    headers: {
      'Authorization': jwtToken,
      'Content-Type': 'application/json'
    }
  });
  
  return response.json();
}
```

## Securing Internal Service Communication

### 1. Service Account JWT for Service-to-Service Auth

For additional security, you can use service account tokens:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: webapp-service-account
  namespace: frontend-namespace
```

Each pod gets a mounted token that can be used for authenticated service calls:

```javascript
const k8sToken = fs.readFileSync(
  '/var/run/secrets/kubernetes.io/serviceaccount/token', 
  'utf8'
);

// Use this token for service-to-service calls
const response = await fetch('http://api-service.api-namespace:8080/data', {
  headers: {
    'Authorization': `Bearer ${k8sToken}`,
  }
});
```

### 2. Network Policies for Zero Trust

Enforce which pods can communicate with each other:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-service-policy
  namespace: api-namespace
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: frontend-namespace
      podSelector:
        matchLabels:
          app: webapp
    ports:
    - protocol: TCP
      port: 3000
```

### 3. Service Mesh for Advanced Zero Trust

For enhanced security, consider implementing a service mesh like Istio or AWS App Mesh:

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: api-service-authz
  namespace: api-namespace
spec:
  selector:
    matchLabels:
      app: api
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/frontend-namespace/sa/webapp-service-account"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/*"]
    when:
    - key: request.auth.claims[iss]
      values: ["ambassador-jwt-issuer"]
```

## Code Example for JWT Propagation

Here's how your webapp might handle JWT propagation:

```javascript
// server.js in the webapp
const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());

// Middleware to verify JWT from Ambassador
const verifyJwt = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  // JWT already verified by Ambassador, so we can trust it
  // You could add additional verification here
  next();
};

app.get('/dashboard-data', verifyJwt, async (req, res) => {
  try {
    // Forward the JWT to internal services
    const token = req.headers.authorization;
    
    // Call internal API service using Kubernetes DNS name
    const apiResponse = await axios.get(
      'http://api-service.api-namespace:8080/user-data',
      {
        headers: {
          Authorization: token,
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json(apiResponse.data);
  } catch (error) {
    console.error('Error calling API service:', error.message);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

app.listen(3000, () => {
  console.log('Webapp listening on port 3000');
});
```

## Configuration for Secure Service Communication

### 1. Service Configuration for API Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-service
  namespace: api-namespace
spec:
  selector:
    app: api
  ports:
  - port: 8080
    targetPort: 3000
```

### 2. Ambassador Filtering Configuration

```yaml
apiVersion: getambassador.io/v3alpha1
kind: FilterPolicy
metadata:
  name: secure-jwt-policy
  namespace: ambassador
spec:
  rules:
  - host: "*"
    path: /api/*
    filters:
    - name: jwt-filter
      arguments:
        jwksURI: "https://your-jwks-endpoint/.well-known/jwks.json"
        audience: "your-api-audience"
        propagateToken: true  # This passes the verified token to services
```

The JWT filter verifies the token and can propagate it to your backend services, allowing them to trust tokens that have already been validated at the edge.

