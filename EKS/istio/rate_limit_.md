# Istio/Envoy Rate Limiting Implementation ..beta..

## Overview

Session-based rate limiting for cross-namespace requests in EKS using Istio/Envoy.
Addresses scenarios where authenticated users with sticky sessions can traverse
multiple namespaces without rate limiting controls.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EKS Cluster                                 │
│                                                                     │
│  ┌──────────────────┐              ┌──────────────────┐            │
│  │  frontend-apps   │              │  backend-svcs    │            │
│  │  Namespace       │              │  Namespace       │            │
│  │                  │              │                  │            │
│  │  ┌────────────┐  │              │  ┌────────────┐  │            │
│  │  │   Pod A    │  │   Request    │  │   Pod B    │  │            │
│  │  │            │  │   with       │  │            │  │            │
│  │  │ ┌────────┐ │  │   JSESSIONID │  │ ┌────────┐ │  │            │
│  │  │ │  App   │ │  │──────────────┼─>│ │ Envoy  │ │  │            │
│  │  │ └────────┘ │  │              │  │ │ Sidecar│ │  │            │
│  │  │            │  │              │  │ └───┬────┘ │  │            │
│  │  │ ┌────────┐ │  │              │  │     │      │  │            │
│  │  │ │ Envoy  │ │  │              │  │     │ Lua  │  │            │
│  │  │ │ Sidecar│ │  │              │  │     │ Extract              │
│  │  │ └────────┘ │  │              │  │     │ Session              │
│  │  └────────────┘  │              │  │     v      │  │            │
│  │                  │              │  │ ┌────────┐ │  │            │
│  └──────────────────┘              │  │ │ Rate   │ │  │            │
│                                    │  │ │ Limit  │ │  │            │
│                                    │  │ │ Filter │ │  │            │
│                                    │  │ └───┬────┘ │  │            │
│                                    │  │     │ gRPC │  │            │
│                                    │  └─────┼──────┘  │            │
│                                    │        │         │            │
│                                    │  ┌─────v──────┐  │            │
│                                    │  │ Rate Limit │  │            │
│                                    │  │  Service   │  │            │
│                                    │  │ ┌────────┐ │  │            │
│                                    │  │ │RateLimit│ │  │            │
│                                    │  │ │ Server │◄┼──┼─ gRPC :8081│
│                                    │  │ └────┬───┘ │  │            │
│                                    │  │      v     │  │            │
│                                    │  │ ┌────────┐ │  │            │
│                                    │  │ │ Redis  │ │  │            │
│                                    │  │ │ :6379  │ │  │            │
│                                    │  │ └────────┘ │  │            │
│                                    │  └────────────┘  │            │
│                                    └──────────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
```

## Request Flow

```
1. POST /api/v1/data/process
   Cookie: JSESSIONID=abc123
   │
   v
2. Envoy Sidecar (Inbound :15006)
   │
   ├─> Lua Filter
   │   └─> Extracts JSESSIONID → x-session-token header
   │
   ├─> Rate Limit Filter
   │   ├─> Builds descriptor: {"jsessionid": "abc123"}
   │   └─> gRPC call to Rate Limit Service
   │
   v
3. Rate Limit Service
   │
   ├─> Redis key: backend-ratelimit_jsessionid_abc123_{timestamp}
   ├─> INCRBY + EXPIRE (1800s TTL)
   ├─> Check: count <= 10/min?
   │
   ├─> YES → Return OK → Request continues
   └─> NO  → Return OVER_LIMIT → Return 429
```

## Configuration

**Policy:**
- Endpoint: `POST /api/v1/data/process`
- Limit: 10 requests/minute per JSESSIONID
- Block Duration: 30 minutes (Redis TTL)
- Scope: Cluster-wide (shared Redis state)

## Deployment Files

### 1. Rate Limit Service

**File**: `ratelimit-deployment.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ratelimit-config
  namespace: backend-svcs
data:
  config.yaml: |
    domain: backend-ratelimit-domain
    descriptors:
      - key: jsessionid
        rate_limit:
          unit: minute
          requests_per_unit: 10
---
apiVersion: v1
kind: Service
metadata:
  name: ratelimit
  namespace: backend-svcs
spec:
  ports:
  - name: http
    port: 8080
  - name: grpc
    port: 8081
  - name: debug
    port: 6070
  selector:
    app: ratelimit
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ratelimit
  namespace: backend-svcs
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ratelimit
  template:
    metadata:
      labels:
        app: ratelimit
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
    spec:
      containers:
      - name: ratelimit
        image: envoyproxy/ratelimit:master
        ports:
        - containerPort: 8080
        - containerPort: 8081
        - containerPort: 6070
        env:
        - name: USE_STATSD
          value: "false"
        - name: LOG_LEVEL
          value: "info"
        - name: REDIS_SOCKET_TYPE
          value: "tcp"
        - name: REDIS_URL
          value: "localhost:6379"
        - name: RUNTIME_ROOT
          value: "/data"
        - name: RUNTIME_SUBDIRECTORY
          value: "ratelimit"
        volumeMounts:
        - name: config
          mountPath: /data/ratelimit/config
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /healthcheck
            port: 8080
        readinessProbe:
          httpGet:
            path: /healthcheck
            port: 8080
      
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        command:
        - redis-server
        - --maxmemory
        - "256mb"
        - --maxmemory-policy
        - "allkeys-lru"
        - --save
        - ""
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      
      volumes:
      - name: config
        configMap:
          name: ratelimit-config
```

### 2. EnvoyFilter

**File**: `envoyfilter-ratelimit.yaml`

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: session-ratelimit
  namespace: backend-svcs
spec:
  workloadSelector:
    labels:
      app: backend-service
  
  configPatches:
  # Add rate limit cluster
  - applyTo: CLUSTER
    patch:
      operation: ADD
      value:
        name: rate_limit_cluster
        type: STRICT_DNS
        connect_timeout: 0.25s
        lb_policy: ROUND_ROBIN
        http2_protocol_options: {}
        load_assignment:
          cluster_name: rate_limit_cluster
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: ratelimit.backend-svcs.svc.cluster.local
                    port_value: 8081

  # Lua filter: extract JSESSIONID
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
            subFilter:
              name: "envoy.filters.http.router"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.lua
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
          inline_code: |
            function envoy_on_request(request_handle)
              local path = request_handle:headers():get(":path")
              local method = request_handle:headers():get(":method")
              
              if method == "POST" and path == "/api/v1/data/process" then
                local cookie = request_handle:headers():get("cookie")
                if cookie then
                  local jsessionid = cookie:match("JSESSIONID=([^;]+)")
                  if jsessionid then
                    request_handle:headers():add("x-session-token", jsessionid)
                  end
                end
              end
            end

  # Rate limit filter
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
            subFilter:
              name: "envoy.filters.http.router"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.ratelimit
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
          domain: backend-ratelimit-domain
          failure_mode_deny: false
          timeout: 0.5s
          rate_limit_service:
            grpc_service:
              envoy_grpc:
                cluster_name: rate_limit_cluster
            transport_api_version: V3

  # Route rate limit actions
  - applyTo: HTTP_ROUTE
    match:
      context: SIDECAR_INBOUND
      routeConfiguration:
        vhost:
          route:
            action: ANY
    patch:
      operation: MERGE
      value:
        route:
          rate_limits:
          - actions:
            - request_headers:
                header_name: "x-session-token"
                descriptor_key: "jsessionid"
```

## Installation

```bash
# Create namespace
kubectl create namespace backend-svcs
kubectl label namespace backend-svcs istio-injection=enabled

# Deploy rate limit service
kubectl apply -f ratelimit-deployment.yaml

# Wait for ready
kubectl wait --for=condition=ready pod \
  -l app=ratelimit -n backend-svcs --timeout=300s

# Deploy EnvoyFilter
kubectl apply -f envoyfilter-ratelimit.yaml

# Verify
kubectl get pods -n backend-svcs -l app=ratelimit
kubectl get envoyfilter -n backend-svcs
```

## Testing

**File**: `test-ratelimit.sh`

```bash
#!/bin/bash

SESSION_ID="${1:-test-session-$(date +%s)}"
SERVICE_URL="backend-service.backend-svcs.svc.cluster.local:8080"
ENDPOINT="/api/v1/data/process"

echo "Testing rate limiting"
echo "Session: $SESSION_ID"
echo "Limit: 10 requests/minute"
echo ""

for i in {1..15}; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Cookie: JSESSIONID=$SESSION_ID" \
    -H "Content-Type: application/json" \
    "http://${SERVICE_URL}${ENDPOINT}")
  
  if [ "$HTTP_CODE" == "200" ]; then
    echo "✓ Request $i: SUCCESS (200)"
  elif [ "$HTTP_CODE" == "429" ]; then
    echo "✗ Request $i: RATE LIMITED (429)"
  else
    echo "? Request $i: UNEXPECTED ($HTTP_CODE)"
  fi
  
  sleep 1
done
```

**Expected Output:**
```
✓ Request 1-10: SUCCESS (200)
✗ Request 11-15: RATE LIMITED (429)
```

## Monitoring

### Prometheus Metrics

```bash
kubectl port-forward -n backend-svcs svc/ratelimit 8080:8080
curl http://localhost:8080/metrics
```

**Key Metrics:**
- `ratelimit_service_total_hits` - Total requests evaluated
- `ratelimit_service_rate_limit_over_limit_total` - Blocked requests
- `ratelimit_service_cache_hit_total` - Redis hits

### Redis Inspection

```bash
POD=$(kubectl get pod -n backend-svcs -l app=ratelimit -o jsonpath='{.items[0].metadata.name}')

# List keys
kubectl exec -n backend-svcs $POD -c redis -- redis-cli KEYS "*"

# Check specific session
kubectl exec -n backend-svcs $POD -c redis -- \
  redis-cli GET "backend-ratelimit-domain_jsessionid_test123_*"

# Check TTL
kubectl exec -n backend-svcs $POD -c redis -- \
  redis-cli TTL "backend-ratelimit-domain_jsessionid_test123_*"
```

### Envoy Stats

```bash
POD=$(kubectl get pod -n backend-svcs -l app=backend-service -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n backend-svcs $POD -c istio-proxy -- \
  curl -s localhost:15000/stats | grep ratelimit
```

## Troubleshooting

### Rate Limiting Not Working

```bash
# Check EnvoyFilter applied
kubectl get envoyfilter -n backend-svcs session-ratelimit -o yaml

# Check Envoy config has rate limit filter
kubectl exec -n backend-svcs $POD -c istio-proxy -- \
  curl -s localhost:15000/config_dump | \
  jq '.. | select(.name? == "envoy.filters.http.ratelimit")'

# Check Lua filter logs
kubectl logs -n backend-svcs $POD -c istio-proxy | grep -i lua

# Restart pods
kubectl rollout restart deployment -n backend-svcs backend-service
```

### Rate Limit Service Issues

```bash
# Check service health
kubectl get pods -n backend-svcs -l app=ratelimit
kubectl logs -n backend-svcs -l app=ratelimit -c ratelimit

# Test gRPC connectivity
kubectl run grpcurl --rm -it --image=fullstorydev/grpcurl --restart=Never -- \
  -plaintext ratelimit.backend-svcs.svc.cluster.local:8081 list

# Should show: pb.lyft.ratelimit.RateLimitService
```

### Redis Issues

```bash
# Check Redis health
kubectl exec -n backend-svcs $POD -c redis -- redis-cli PING

# Check memory
kubectl exec -n backend-svcs $POD -c redis -- \
  redis-cli INFO memory | grep used_memory_human

# Check key count
kubectl exec -n backend-svcs $POD -c redis -- redis-cli DBSIZE
```

## Customization

### Change Rate Limit

Edit `ratelimit-config` ConfigMap:

```yaml
descriptors:
  - key: jsessionid
    rate_limit:
      unit: minute        # second, minute, hour, day
      requests_per_unit: 20  # Increase limit
```

Apply:
```bash
kubectl apply -f ratelimit-deployment.yaml
kubectl rollout restart deployment/ratelimit -n backend-svcs
```

### Multiple Endpoints

Modify Lua filter:

```lua
local protected_paths = {
  "/api/v1/data/process",
  "/api/v1/expensive-op",
  "/api/v1/sensitive-data"
}

local function is_protected(path)
  for _, p in ipairs(protected_paths) do
    if path == p then return true end
  end
  return false
end

function envoy_on_request(request_handle)
  local path = request_handle:headers():get(":path")
  local method = request_handle:headers():get(":method")
  
  if method == "POST" and is_protected(path) then
    -- Extract JSESSIONID
  end
end
```

### Different HTTP Methods

```lua
-- For all methods
if is_protected(path) then

-- For specific methods
local methods = {POST = true, PUT = true, DELETE = true}
if methods[method] and is_protected(path) then
```

## Performance Impact

- **Latency**: ~3-10ms additional per request
- **Memory**: Rate limit service ~128MB, Redis ~256MB
- **CPU**: Minimal (<0.1% per core for Lua, <100m for service)

## Security Considerations

- **Session validation**: No format validation on JSESSIONID
- **Redis security**: No auth (localhost-only in sidecar)
- **Bypass risk**: Requests without cookies not rate limited
- **Recommendation**: Add IP-based fallback rate limiting

## References

- [Istio Rate Limiting](https://istio.io/latest/docs/tasks/policy-enforcement/rate-limit/)
- [Lyft Rate Limit Service](https://github.com/envoyproxy/ratelimit)

- [Envoy Rate Limit Service](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ratelimit/v3/rls.proto)
- [Envoy Rate Limit Filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rate_limit_filter)
```

