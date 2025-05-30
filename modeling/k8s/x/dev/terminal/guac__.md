# Secure Workstation Access Flow - Detailed Security Analysis - Path Trace ( Proposed )

## Complete Security Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        USER AUTHENTICATION FLOW                                │
└─────────────────────────────────────────────────────────────────────────────────┘

1. User Login:
   Browser → https://project-x.example.com/auth/login
   ├── POST: {username: "alice", password: "***"}
   └── Response: JWT + Set-Cookie: jwt=<token>; HttpOnly; Secure

2. JWT Contains:
   {
     "iss": "project-x.auth",
     "sub": "alice",
     "aud": ["project-x"],
     "iat": 1234567890,
     "exp": 1234571490,
     "user_id": "alice",
     "session_id": "sess_abc123def456",
     "tier": "tier-2",
     "scope": ["workstation_access", "challenge_access"],
     "workstation_authorized": true
   }

┌─────────────────────────────────────────────────────────────────────────────────┐
│                      WORKSTATION ACCESS REQUEST                                │
└─────────────────────────────────────────────────────────────────────────────────┘

3. User navigates to: https://project-x.example.com/workstation/alice
   ├── Browser sends: Cookie: jwt=<token>
   └── Or: Authorization: Bearer <token>

┌─────────────────────────────────────────────────────────────────────────────────┐
│                        AMBASSADOR EDGE SECURITY                                │
└─────────────────────────────────────────────────────────────────────────────────┘

4. Ambassador Edge Stack Processing:
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ STEP 1: Route Matching                                                     │
   │ ─────────────────────────                                                  │
   │ URL: /workstation/alice                                                    │
   │ Matches: prefix: /workstation/(.+)                                         │
   │ Extracted user_from_url: "alice"                                           │
   └─────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ STEP 2: JWT Validation Filter                                              │
   │ ──────────────────────────                                                 │
   │ 1. Extract JWT from Cookie or Authorization header                         │
   │ 2. Validate signature against JWKS from /.well-known/jwks.json            │
   │ 3. Check expiration (exp claim)                                            │
   │ 4. Verify issuer: "project-x.auth"                                         │
   │ 5. Verify audience: ["project-x"]                                          │
   │ 6. Check required scopes: ["workstation_access"]                           │
   │                                                                             │
   │ ❌ FAIL → 401 Unauthorized                                                  │
   │ ✅ PASS → Extract claims to headers                                         │
   └─────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ STEP 3: User ID Authorization Check                                        │
   │ ───────────────────────────────────                                        │
   │ URL user_id: "alice"                                                       │
   │ JWT user_id: "alice"                                                       │
   │                                                                             │
   │ ❌ MISMATCH → 403 Forbidden                                                 │
   │ ✅ MATCH → Continue                                                         │
   └─────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ STEP 4: Rate Limiting                                                      │
   │ ─────────────────                                                          │
   │ Key: user_id="alice"                                                       │
   │ Check Redis: workstation:alice:requests                                    │
   │                                                                             │
   │ ❌ RATE LIMITED → 429 Too Many Requests                                    │
   │ ✅ WITHIN LIMITS → Continue                                                 │
   └─────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ STEP 5: Forward to Service                                                 │
   │ ──────────────────────                                                     │
   │ Target: workstation-router.project-x-infra.svc.cluster.local:3000         │
   │ Headers Added:                                                              │
   │   X-User-ID: alice                                                          │
   │   X-Session-ID: sess_abc123def456                                           │
   │   X-Tier: tier-2                                                           │
   │   X-JWT-Claims: <base64-encoded-claims>                                    │
   └─────────────────────────────────────────────────────────────────────────────┘
```

## Detailed Ambassador Mapping Configuration

```yaml
apiVersion: x.getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: workstation-access
  namespace: project-x-infra
spec:
  hostname: project-x.example.com
  prefix: /workstation/(.+)
  prefix_regex: true
  service: workstation-router.project-x-infra.svc.cluster.local:3000
  rewrite: "/workstation/${1}"
  
  # Critical: JWT validation with user authorization
  filters:
  - name: jwt-validation
    jwt:
      issuer: "project-x.auth"
      jwksURI: "https://project-x.example.com/.well-known/jwks.json"
      audiences: ["project-x"]
      requiredClaims:
        scope: ["workstation_access"]
        workstation_authorized: [true]
      authHeader: "authorization"
      cookie: "jwt"
      leeway: 60s
      
  # User authorization filter (custom Envoy filter)
  - name: user-authorization
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
      inline_code: |
        function envoy_on_request(request_handle)
          -- Extract user ID from URL path
          local path = request_handle:headers():get(":path")
          local url_user_id = string.match(path, "/workstation/([^/]+)")
          
          -- Extract user ID from JWT claims
          local jwt_user_id = request_handle:headers():get("x-jwt-claim-user_id")
          
          -- Verify user can only access their own workstation
          if url_user_id ~= jwt_user_id then
            request_handle:respond(
              {[":status"] = "403"},
              "Access denied: Cannot access another user's workstation"
            )
            return
          end
          
          -- Add validated user headers
          request_handle:headers():add("x-validated-user-id", jwt_user_id)
          request_handle:headers():add("x-workstation-id", "ws-" .. jwt_user_id)
        end
      
  # Rate limiting per user
  - name: rate-limiting
    rateLimit:
      domain: project-x-workstation
      service: projectx-rate-limit.project-x-infra.svc.cluster.local:8080
      descriptors:
      - key: "user_id"
        value: "%JWT_claim_user_id%"
      - key: "session_id" 
        value: "%JWT_claim_session_id%"
      rateLimitedAsUnhealthy: true
      
  # Long timeouts for desktop sessions
  timeout_ms: 7200000      # 2 hours
  idle_timeout_ms: 1800000 # 30 minutes
  
  # WebSocket support for Guacamole
  upgrade_configs:
  - upgrade_type: websocket
    enabled: true
    
  cors:
    origins: ["https://project-x.example.com"]
    methods: ["GET", "POST", "OPTIONS"]
    headers: ["Authorization", "Content-Type", "Upgrade", "Connection"]
    credentials: true
    max_age: 86400
```

## Workstation Router Service Security

```go
// pkg/workstation-router/main.go
package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
    "time"
)

type WorkstationRouter struct {
    controller *Controller
}

type JWTClaims struct {
    UserID     string   `json:"user_id"`
    SessionID  string   `json:"session_id"`
    Tier       string   `json:"tier"`
    Scope      []string `json:"scope"`
    ExpiresAt  int64    `json:"exp"`
}

func (wr *WorkstationRouter) HandleWorkstation(w http.ResponseWriter, r *http.Request) {
    // Extract and validate user from path
    pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(pathParts) < 2 || pathParts[0] != "workstation" {
        http.Error(w, "Invalid workstation path", http.StatusBadRequest)
        return
    }
    requestedUserID := pathParts[1]
    
    // Validate JWT claims from Ambassador headers
    claims, err := wr.validateAmbassadorClaims(r)
    if err != nil {
        http.Error(w, fmt.Sprintf("Invalid claims: %v", err), http.StatusUnauthorized)
        return
    }
    
    // Critical security check: Ensure user can only access their own workstation
    if claims.UserID != requestedUserID {
        wr.logSecurityViolation(r, claims.UserID, requestedUserID)
        http.Error(w, "Access denied: Cannot access another user's workstation", http.StatusForbidden)
        return
    }
    
    // Verify session is still active in Redis
    if !wr.isSessionActive(claims.SessionID, claims.UserID) {
        http.Error(w, "Session expired or invalid", http.StatusUnauthorized)
        return
    }
    
    // Ensure user's workstation exists
    workstation, err := wr.controller.EnsureUserWorkstation(r.Context(), claims.UserID, claims.Tier)
    if err != nil {
        http.Error(w, fmt.Sprintf("Failed to ensure workstation: %v", err), http.StatusInternalServerError)
        return
    }
    
    // Wait for workstation to be ready
    if !wr.waitForWorkstationReady(workstation, 30*time.Second) {
        http.Error(w, "Workstation not ready", http.StatusServiceUnavailable)
        return
    }
    
    // Proxy to user's specific workstation
    wr.proxyToWorkstation(w, r, workstation)
}

func (wr *WorkstationRouter) validateAmbassadorClaims(r *http.Request) (*JWTClaims, error) {
    // Extract JWT claims from Ambassador-added headers
    userID := r.Header.Get("X-User-ID")
    sessionID := r.Header.Get("X-Session-ID")
    tier := r.Header.Get("X-Tier")
    claimsHeader := r.Header.Get("X-JWT-Claims")
    
    if userID == "" || sessionID == "" || claimsHeader == "" {
        return nil, fmt.Errorf("missing required headers from Ambassador")
    }
    
    // Decode and verify full claims
    claimsData, err := base64.StdEncoding.DecodeString(claimsHeader)
    if err != nil {
        return nil, fmt.Errorf("invalid claims encoding: %w", err)
    }
    
    var claims JWTClaims
    if err := json.Unmarshal(claimsData, &claims); err != nil {
        return nil, fmt.Errorf("invalid claims JSON: %w", err)
    }
    
    // Verify claims consistency
    if claims.UserID != userID || claims.SessionID != sessionID {
        return nil, fmt.Errorf("claims mismatch with headers")
    }
    
    // Verify token hasn't expired
    if time.Now().Unix() > claims.ExpiresAt {
        return nil, fmt.Errorf("token expired")
    }
    
    // Verify required scopes
    hasWorkstationScope := false
    for _, scope := range claims.Scope {
        if scope == "workstation_access" {
            hasWorkstationScope = true
            break
        }
    }
    if !hasWorkstationScope {
        return nil, fmt.Errorf("missing workstation_access scope")
    }
    
    return &claims, nil
}

func (wr *WorkstationRouter) proxyToWorkstation(w http.ResponseWriter, r *http.Request, workstation *UserWorkstation) {
    // Build target URL for user's specific workstation
    targetURL := fmt.Sprintf("http://ws-%s.project-x-users.svc.cluster.local:8080", workstation.UserID)
    target, err := url.Parse(targetURL)
    if err != nil {
        http.Error(w, "Invalid workstation URL", http.StatusInternalServerError)
        return
    }
    
    // Create reverse proxy with security headers
    proxy := &httputil.ReverseProxy{
        Director: func(req *http.Request) {
            req.URL.Scheme = target.Scheme
            req.URL.Host = target.Host
            req.Host = target.Host
            
            // Strip workstation prefix from path
            req.URL.Path = strings.TrimPrefix(req.URL.Path, fmt.Sprintf("/workstation/%s", workstation.UserID))
            if req.URL.Path == "" {
                req.URL.Path = "/"
            }
            
            // Add security headers for Guacamole
            req.Header.Set("X-Forwarded-User", workstation.UserID)
            req.Header.Set("X-Workstation-ID", workstation.WorkstationID)
            req.Header.Set("X-Session-ID", workstation.SessionID)
            req.Header.Set("X-Tier", workstation.Tier)
            
            // Remove sensitive headers
            req.Header.Del("X-JWT-Claims")
            req.Header.Del("Authorization")
        },
        ModifyResponse: func(resp *http.Response) error {
            // Add security headers to response
            resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
            resp.Header.Set("X-Content-Type-Options", "nosniff")
            resp.Header.Set("Content-Security-Policy", "frame-ancestors 'self'")
            resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            return nil
        },
    }
    
    // Update last activity
    wr.updateWorkstationActivity(workstation)
    
    // Proxy the request
    proxy.ServeHTTP(w, r)
}
```

## Istio Service Mesh Security Layer

```yaml
# VirtualService: Routes to specific user workstation
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: workstation-{userID}
  namespace: project-x-users
  labels:
    project-x/user-id: "{userID}"
spec:
  hosts:
  - "ws-{userID}.project-x-users.svc.cluster.local"
  http:
  - match:
    - headers:
        x-forwarded-user:
          exact: "{userID}"        # CRITICAL: Must match user
        x-workstation-id:
          exact: "ws-{userID}"     # CRITICAL: Must match workstation
    route:
    - destination:
        host: "ws-{userID}.project-x-users.svc.cluster.local"
        port:
          number: 8080
    fault:
      abort:
        percentage:
          value: 0.001
        httpStatus: 500
    timeout: 1800s  # 30 minute timeout

---
# AuthorizationPolicy: Only allow authenticated users to their workstation
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: workstation-{userID}-authz
  namespace: project-x-users
  labels:
    project-x/user-id: "{userID}"
spec:
  selector:
    matchLabels:
      project-x/user-id: "{userID}"
      project-x/component: workstation
  action: ALLOW
  rules:
  # RULE 1: Only workstation-router can access workstation
  - from:
    - source:
        principals:
        - "cluster.local/ns/project-x-infra/sa/workstation-router"
    when:
    - key: request.headers[x-forwarded-user]
      values: ["{userID}"]
    - key: request.headers[x-workstation-id] 
      values: ["ws-{userID}"]
    - key: request.headers[x-session-id]
      values: ["{sessionID}"]  # Dynamic per session
      
  # RULE 2: Allow SPIRE agent communication (for mTLS)
  - from:
    - source:
        principals:
        - "spiffe://project-x.local/spire/agent/k8s_sat/ns:project-x-users"
        
  # RULE 3: Allow health checks from Istio
  - from:
    - source:
        principals:
        - "cluster.local/ns/istio-system/sa/istio-proxy"
    to:
    - operation:
        paths: ["/healthz", "/ready"]

---
# Deny all other access (default deny)
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: workstation-default-deny
  namespace: project-x-users
spec:
  action: DENY
  rules:
  - {}  # Deny everything not explicitly allowed above
```

## SPIRE Workload Identity Verification

```yaml
# SPIRE Registration Entry for user workstation
apiVersion: spiffeid.spiffe.io/v1beta1
kind: SpiffeID
metadata:
  name: workstation-{userID}
  namespace: project-x-users
spec:
  spiffeId: "spiffe://project-x.local/user/{userID}/workstation"
  parentId: "spiffe://project-x.local/spire/agent/k8s_sat/ns:project-x-users"
  selector:
    k8s:
      namespace: "project-x-users"
      podLabel:
        project-x/user-id: "{userID}"
        project-x/component: "workstation"
  ttl: 3600  # 1 hour
  federatesWith: []
  downstream: true
```

## NetworkPolicy Enforcement

```yaml
# CRITICAL: User workstation isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: workstation-{userID}-isolation
  namespace: project-x-users
  labels:
    project-x/user-id: "{userID}"
spec:
  podSelector:
    matchLabels:
      project-x/user-id: "{userID}"
      project-x/component: workstation
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # ONLY allow traffic from workstation-router with correct user headers
  - from:
    - namespaceSelector:
        matchLabels:
          name: project-x-infra
    - podSelector:
        matchLabels:
          app: workstation-router
    ports:
    - protocol: TCP
      port: 8080
      
  # Allow Istio sidecar communication
  - from:
    - podSelector:
        matchLabels:
          app: istio-proxy
    ports:
    - protocol: TCP
      port: 15090
    - protocol: TCP
      port: 15021
      
  egress:
  # Allow access to user's challenges ONLY
  - to:
    - namespaceSelector:
        matchLabels:
          name: project-x-challenges
    - podSelector:
        matchLabels:
          project-x/user-id: "{userID}"  # CRITICAL: Same user only
    ports:
    - protocol: TCP   # All TCP ports
    - protocol: UDP   # All UDP ports
    
  # Standard infrastructure access
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
  - to:
    - podSelector:
        matchLabels:
          app: spire-agent
  - to:
    - namespaceSelector:
        matchLabels:
          name: istio-system

---
# Global NetworkPolicy: Prevent cross-user access
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: global-user-isolation
  namespace: project-x-users
spec:
  podSelector: {}  # All pods in namespace
  policyTypes:
  - Ingress
  - Egress
  
  # Default DENY all cross-user communication
  ingress: []  # Empty = deny all except what's explicitly allowed above
  egress: []   # Empty = deny all except what's explicitly allowed above
```

## Guacamole-Level Security

```javascript
// Custom Guacamole authentication extension
// /etc/guacamole/extensions/project-x-auth/
public class ProjectXAuthenticationProvider implements AuthenticationProvider {
    
    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser) 
            throws GuacamoleException {
        
        // Extract user information from headers set by workstation-router
        String userID = authenticatedUser.getCredentials().getRequest()
            .getHeader("X-Forwarded-User");
        String workstationID = authenticatedUser.getCredentials().getRequest()
            .getHeader("X-Workstation-ID");
        String sessionID = authenticatedUser.getCredentials().getRequest()
            .getHeader("X-Session-ID");
            
        // Validate user can only access their own desktop
        if (!workstationID.equals("ws-" + userID)) {
            throw new GuacamoleUnauthorizedException("Access denied");
        }
        
        // Verify session is still active
        if (!isSessionActive(sessionID, userID)) {
            throw new GuacamoleSessionClosedException("Session expired");
        }
        
        // Create user context with restricted permissions
        return new ProjectXUserContext(userID, workstationID, sessionID);
    }
}
```

## Attack Surface Analysis

### ❌ Attack Scenarios That Are Blocked:

1. **JWT Manipulation:**
   ```
   User alice tries: /workstation/bob
   With JWT: {user_id: "alice"}
   → Ambassador blocks at Step 3 (user_id mismatch)
   ```

2. **Direct Pod Access:**
   ```
   Attacker tries: http://ws-bob.project-x-users.svc.cluster.local:8080
   → NetworkPolicy blocks (no ingress from external)
   ```

3. **Cross-User Challenge Access:**
   ```
   Alice's workstation tries to connect to Bob's challenge
   → NetworkPolicy blocks (user_id label mismatch)
   ```

4. **Session Hijacking:**
   ```
   Stolen JWT with expired session_id
   → Redis check fails at workstation-router
   ```

5. **Pod Impersonation:**
   ```
   Malicious pod tries to access workstation
   → SPIRE SVID validation fails
   → Istio AuthorizationPolicy denies
   ```

### ✅ Only Allowed Access Path:

```
Authenticated User (alice) 
→ JWT with valid session + workstation_access scope
→ Ambassador validates JWT + user_id match
→ Workstation-router validates session + claims
→ Istio validates mTLS + AuthorizationPolicy
→ NetworkPolicy allows alice → ws-alice only
→ Guacamole validates headers match user
→ Desktop access granted
```

