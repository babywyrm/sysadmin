# Ambassador Configuration for Project-X - ( Beta )

This directory contains Ambassador Edge Stack mappings and modules that:

1. Terminate TLS and route incoming traffic  
2. Handle user authentication (`/auth/*`) via Auth Service  
3. Mint and validate RS-256 JWTs using JWKS  
4. Rate-limit per user on the Challenge API  
5. Route SPA calls to `/api/challenges` → Challenge Controller  
6. Proxy live challenge UIs at `/challenge/{id}` → Challenge Router  

**Namespace**: `ambassador`

---

## Files

- **ambassador.yaml**  
  Consolidated Ambassador `Module`, `AuthService`, `RateLimitService`, and `Mapping` CRDs.

---

## 1. Ambassador Module

```yaml
apiVersion: getambassador.io/v3alpha1
kind: Module
metadata:
  name: ambassador
  namespace: ambassador
spec:
  config:
    use_remote_address: true
    xff_num_trusted_hops: 1
    enable_websocket: true
```

- **use_remote_address**: trusts client IP from ALB/NLB  
- **xff_num_trusted_hops**: number of trusted proxy hops  
- **enable_websocket**: allow WS if your challenges use it  

---

## 2. RateLimitService

```yaml
apiVersion: getambassador.io/v3alpha1
kind: RateLimitService
metadata:
  name: projectx-rate-limit
  namespace: ambassador
spec:
  service: "ratelimit.project-x-infra.svc.cluster.local:8081"
```

- Provides per-user request limiting by integrating with an external RLS (e.g. Ory, Envoy’s built-in).  
- Used by the `/api/challenges` mapping.

---

## 3. AuthService CRD

```yaml
apiVersion: getambassador.io/v3alpha1
kind: AuthService
metadata:
  name: projectx-authservice
  namespace: ambassador
spec:
  auth_service: "project-x-auth.project-x.svc.cluster.local:8080"
  path_prefix: "/auth/validate"
  timeout_ms: 5000
  allowed_request_headers: ["authorization","cookie"]
  allowed_authorization_headers: ["authorization","cookie"]
```

- Routes all authentication checks (`/auth/validate`) to your Auth Service.  
- Ensures each incoming request to protected endpoints carries a valid JWT.

---

## 4. /auth/login Mapping

```yaml
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: auth-login
  namespace: ambassador
spec:
  hostname: project-x.example.com
  prefix: /auth/login/
  service: project-x-auth.project-x.svc.cluster.local:8080
  timeout_ms: 15000
  cors:
    origins: ["https://project-x.example.com"]
    methods: ["POST","OPTIONS"]
    headers: ["Content-Type","Authorization"]
    credentials: true
```

- **Endpoint**: `POST https://project-x.example.com/auth/login`  
- **Body**: `{ "email": "...", "password": "..." }`  
- **Response**: `{ "token": "<JWT>", "expiresAt": "<ISO>" }`  
- CORS enabled for your SPA domain. Cookies or `Authorization` header allowed.

---

## 5. /.well-known/jwks.json Mapping

```yaml
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: auth-jwks
  namespace: ambassador
spec:
  hostname: project-x.example.com
  prefix: /.well-known/jwks.json
  service: project-x-auth.project-x.svc.cluster.local:8080
  timeout_ms: 5000
```

- Fetches the JWKS (public keys) used by Ambassador’s JWT filter.  
- Ambassador caches the JWKS to validate incoming tokens.

---

## 6. /api/challenges Mapping

```yaml
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: challenge-api
  namespace: ambassador
spec:
  hostname: project-x.example.com
  prefix: /api/challenges/
  service: project-x-challenge-api.project-x-infra.svc.cluster.local:8080
  timeout_ms: 30000

  # 1) External auth
  auth_service: "projectx-authservice"

  # 2) Ambassador built-in JWT validation
  filters:
  - name: jwt
    jwt:
      issuer: "project-x.auth"
      jwksURI: "https://project-x.example.com/.well-known/jwks.json"
      audiences: ["project-x"]
      authHeader: "authorization"
      cookie: "jwt"

  # 3) Rate limiting per user ID claim
  - name: rate-limiting
    rateLimit:
      domain: project-x
      service: projectx-rate-limit
      descriptors:
      - key: "user_id"
        value: "%JWT_claim_user_id%"

  cors:
    origins: ["https://project-x.example.com"]
    methods: ["GET","POST","DELETE","OPTIONS"]
    headers: ["Authorization","Content-Type"]
    credentials: true
```

1. **Authentication**  
   - Ambassador calls `/auth/validate` on your Auth Service (via `AuthService` CRD).  
2. **JWT Validation**  
   - Verifies RS-256 JWT against JWKS.  
   - Ensures `issuer` and `audience` match.  
   - Extracts `user_id` for logging/policy.  
3. **Rate Limiting**  
   - Uses the `user_id` claim to throttle per-user requests.  
4. **CORS**  
   - Allows your SPA to call this endpoint.

---

## 7. /challenge/ Router Mapping

```yaml
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: challenge-router
  namespace: ambassador
spec:
  hostname: project-x.example.com
  prefix: /challenge/
  service: challenge-router.project-x-infra.svc.cluster.local:3000
  rewrite: "/"         
  timeout_ms: 300000  

  # Enforce scoped JWT token
  filters:
  - name: jwt
    jwt:
      issuer: "project-x.auth"
      jwksURI: "https://project-x.example.com/.well-known/jwks.json"
      audiences: ["challenge:*"]
      authHeader: "authorization"
      cookie: "jwt"
```

- **Purpose**: proxies dynamic challenge UIs (hosted at `<challenge-id>.svc.cluster.local`) back into the SPA.  
- **Path**: `/challenge/{id}/...` → `challenge-router:3000` strips `/challenge/{id}` and forwards.  
- **JWT Filter**: validates a scoped JWT minted by the Challenge Controller (`scope=challenge_access`).

---

## Frontend Workflow

1. **Login**  
   ```js
   const res = await fetch("/auth/login", {
     method:'POST', headers:{'Content-Type':'application/json'},
     body:JSON.stringify({email, password})
   });
   const { token } = await res.json();
   localStorage.setItem("jwt", token);
   ```
   or store `token` in a Secure, HttpOnly cookie via Set-Cookie.

2. **Spawn Challenge**  
   ```js
   const res = await fetch("/api/challenges", {
     method:'POST',
     headers:{
       'Content-Type':'application/json',
       'Authorization':'Bearer '+localStorage.getItem('jwt')
     },
     body:JSON.stringify({challengeType:'web', tier:'tier-1'})
   });
   const { id, endpoint, token:chalToken } = await res.json();
   // Optionally store chalToken for UI
   ```

3. **Access Challenge UI**  
   Navigate to:
   ```
   https://project-x.example.com/challenge/{id}/
   ```
   Ambassador routes to your `challenge-router` which proxies to the actual Pod.  JWT (global or scoped) is re-validated by Ambassador before proxying.

---

## Deploying Ambassador Config

```bash
kubectl apply -f ambassador.yaml -n ambassador
```

- Ensure the `ambassador` namespace and Ambassador Edge Stack are installed.  
- Ambassador auto-discovers these CRDs and configures Envoy accordingly.

---

### Summary

This Ambassador config layer:

- Terminates TLS for `project-x.example.com`  
- Routes authentication and JWKS retrieval to your Auth Service  
- Validates JWTs and enforces per-user rate limits on API calls  
- Forwards SPA challenge UIs through a path-based proxy  
- Ensures only authorized JWTs (global or challenge-scoped) may interact with your cluster services

##
##
##
