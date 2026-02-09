# Istio/Envoy Rate Limiting Implementation

## Overview

This document describes the implementation of session-based rate limiting for
cross-namespace requests in an EKS cluster using Istio and Envoy.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EKS Cluster                                 │
│                                                                     │
│  ┌──────────────────┐              ┌──────────────────┐            │
│  │  webapps NS      │              │  integrations NS │            │
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
│                                    │  │     │      │  │            │
│                                    │  │     v gRPC │  │            │
│                                    │  └─────┼──────┘  │            │
│                                    │        │         │            │
│                                    │  ┌─────v──────┐  │            │
│                                    │  │ Rate Limit │  │            │
│                                    │  │  Service   │  │            │
│                                    │  │            │  │            │
│                                    │  │ ┌────────┐ │  │            │
│                                    │  │ │ Envoy  │ │  │            │
│                                    │  │ │RateLimit│◄─┼─┐           │
│                                    │  │ └────┬───┘ │  │ │           │
│                                    │  │      │     │  │ │           │
│                                    │  │      v     │  │ │           │
│                                    │  │ ┌────────┐ │  │ │           │
│                                    │  │ │ Redis  │ │  │ │  Tracks  │
│                                    │  │ │In-Mem  │ │  │ │  Session │
│                                    │  │ │Backend │ │  │ │  Counts  │
│                                    │  │ └────────┘ │  │ │           │
│                                    │  └────────────┘  │ │           │
│                                    │                  │ │           │
│                                    └──────────────────┘ │           │
│                                                         │           │
│  Response Flow:                                         │           │
│  - Allow (200) if under limit                           │           │
│  - Block (429) if over limit ─────────────────────────────           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Request Flow

```
1. User Request (POST /api/critical-endpoint)
   │
   ├─> Cookie: JSESSIONID=abc123
   │
   v
2. Envoy Sidecar (Inbound)
   │
   ├─> Lua Filter extracts JSESSIONID from cookie
   │   └─> Sets header: x-jsessionid: abc123
   │
   v
3. Rate Limit Filter
   │
   ├─> Builds descriptor: { "jsessionid": "abc123" }
   │
   ├─> Sends gRPC request to Rate Limit Service
   │
   v
4. Rate Limit Service
   │
   ├─> Checks Redis for key: jsessionid:abc123
   │
   ├─> Increments counter
   │
   ├─> Compares: count <= 10 per minute?
   │
   v
5. Decision
   │
   ├─> YES: Return OK → Request continues to app
   │
   └─> NO:  Return OVER_LIMIT → Return 429 to client
            └─> Redis TTL: 30 minutes
```

## Configuration

### Rate Limiting Policy

- **Endpoint**: `POST /api/critical-endpoint`
- **Limit**: 10 requests per minute per JSESSIONID
- **Block Duration**: 30 minutes (Redis TTL)
- **Scope**: Cluster-wide (all pods share state via Redis)

## Deployment Files

### 1. Rate Limit Service Deployment

**File**: `ratelimit-deployment.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ratelimit-config
  namespace: integrations
data:
  config.yaml: |
    domain: integration-posts
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
  namespace: integrations
spec:
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: grpc
    port: 8081
    targetPort: 8081
  - name: debug
    port: 6070
    targetPort: 6070
  selector:
    app: ratelimit
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ratelimit
  namespace: integrations
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ratelimit
  template:
    metadata:
      labels:
        app: ratelimit
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
        - name: RUNTIME_WATCH_ROOT
          value: "false"
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
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /healthcheck
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
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
        livenessProbe:
          tcpSocket:
            port: 6379
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: ratelimit-config
```

### 2. EnvoyFilter Configuration

**File**: `envoyfilter-ratelimit.yaml`

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: session-ratelimit
  namespace: integrations
spec:
  workloadSelector:
    labels:
      app: integration-service
  configPatches:
  # Add rate limit service cluster
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
                    address: ratelimit.integrations.svc.cluster.local
                    port_value: 8081

  # Lua filter to extract JSESSIONID from cookie
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
              
              -- Only apply to POST requests to critical endpoint
              if method == "POST" and path == "/api/critical-endpoint" then
                local cookie = request_handle:headers():get("cookie")
                if cookie then
                  -- Extract JSESSIONID from cookie string
                  local jsessionid = cookie:match("JSESSIONID=([^;]+)")
                  if jsessionid then
                    -- Add as header for rate limiting
                    request_handle:headers():add("x-jsessionid", jsessionid)
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
          domain: integration-posts
          failure_mode_deny: false
          timeout: 0.5s
          rate_limit_service:
            grpc_service:
              envoy_grpc:
                cluster_name: rate_limit_cluster
            transport_api_version: V3

  # Configure rate limit descriptors on routes
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
                header_name: "x-jsessionid"
                descriptor_key: "jsessionid"
```

## Installation

### Prerequisites

- Kubernetes cluster (EKS)
- Istio installed with sidecar injection enabled
- Namespace `integrations` exists
- Application labeled with `app: integration-service`

### Deploy Rate Limit Service

```bash
# Create namespace if it doesn't exist
kubectl create namespace integrations

# Enable Istio injection
kubectl label namespace integrations istio-injection=enabled

# Deploy rate limit service
kubectl apply -f ratelimit-deployment.yaml

# Verify deployment
kubectl get pods -n integrations -l app=ratelimit
kubectl logs -n integrations -l app=ratelimit -c ratelimit
```

### Deploy EnvoyFilter

```bash
# Apply EnvoyFilter configuration
kubectl apply -f envoyfilter-ratelimit.yaml

# Verify filter is applied
kubectl get envoyfilter -n integrations

# Check if sidecar picked up configuration
kubectl logs -n integrations <integration-pod-name> -c istio-proxy
```

### Verify Configuration

```bash
# Check rate limit service health
kubectl port-forward -n integrations svc/ratelimit 8080:8080
curl http://localhost:8080/healthcheck

# Should return: OK

# Check rate limit service stats
curl http://localhost:6070/stats
```

## Testing

### Test Script

```bash
#!/bin/bash

ENDPOINT="http://integration-service.integrations.svc.cluster.local/api/critical-endpoint"
SESSION_ID="test-session-123"

echo "Testing rate limiting with JSESSIONID: $SESSION_ID"
echo "Limit: 10 requests per minute"
echo ""

for i in {1..15}; do
  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Cookie: JSESSIONID=$SESSION_ID" \
    "$ENDPOINT")
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  BODY=$(echo "$RESPONSE" | head -n-1)
  
  if [ "$HTTP_CODE" == "200" ]; then
    echo "✓ Request $i: SUCCESS ($HTTP_CODE)"
  elif [ "$HTTP_CODE" == "429" ]; then
    echo "✗ Request $i: RATE LIMITED ($HTTP_CODE)"
  else
    echo "? Request $i: UNEXPECTED ($HTTP_CODE)"
  fi
  
  sleep 1
done
```

### Expected Output

```
Testing rate limiting with JSESSIONID: test-session-123
Limit: 10 requests per minute

✓ Request 1: SUCCESS (200)
✓ Request 2: SUCCESS (200)
✓ Request 3: SUCCESS (200)
✓ Request 4: SUCCESS (200)
✓ Request 5: SUCCESS (200)
✓ Request 6: SUCCESS (200)
✓ Request 7: SUCCESS (200)
✓ Request 8: SUCCESS (200)
✓ Request 9: SUCCESS (200)
✓ Request 10: SUCCESS (200)
✗ Request 11: RATE LIMITED (429)
✗ Request 12: RATE LIMITED (429)
✗ Request 13: RATE LIMITED (429)
✗ Request 14: RATE LIMITED (429)
✗ Request 15: RATE LIMITED (429)
```

## Monitoring

### Prometheus Metrics

The rate limit service exposes metrics on port 8080:

```bash
kubectl port-forward -n integrations svc/ratelimit 8080:8080
curl http://localhost:8080/metrics
```

Key metrics:
- `ratelimit_service_rate_limit_over_limit_total`: Count of rate limited requests
- `ratelimit_service_rate_limit_near_limit_total`: Count of requests near limit
- `ratelimit_service_rate_limit_total_hits`: Total requests evaluated
- `ratelimit_service_cache_hit_total`: Redis cache hits

### Redis Monitoring

```bash
# Connect to Redis
kubectl exec -it -n integrations \
  $(kubectl get pod -n integrations -l app=ratelimit -o jsonpath='{.items[0].metadata.name}') \
  -c redis -- redis-cli

# Check keys
127.0.0.1:6379> KEYS *

# Check specific session
127.0.0.1:6379> GET "integration-posts_jsessionid_test-session-123_1234567890"

# Check TTL (time remaining in seconds)
127.0.0.1:6379> TTL "integration-posts_jsessionid_test-session-123_1234567890"
```

### Envoy Proxy Stats

```bash
# Get rate limit stats from envoy sidecar
kubectl exec -it -n integrations <integration-pod-name> -c istio-proxy -- \
  curl -s localhost:15000/stats | grep ratelimit
```

## Customization

### Change Rate Limit Threshold

Edit `ratelimit-config` ConfigMap:

```yaml
descriptors:
  - key: jsessionid
    rate_limit:
      unit: minute        # Options: second, minute, hour, day
      requests_per_unit: 20  # Change from 10 to 20
```

Apply changes:

```bash
kubectl apply -f ratelimit-deployment.yaml
kubectl rollout restart deployment/ratelimit -n integrations
```

### Change Block Duration

The block duration is controlled by Redis TTL. To change from 30 minutes to
60 minutes, you need to modify the rate limit service configuration.

Update ConfigMap:

```yaml
descriptors:
  - key: jsessionid
    rate_limit:
      unit: minute
      requests_per_unit: 10
      unlimited: false
      # Add shadow mode for testing
      shadow_mode: false
```

For custom TTL, you'll need to use descriptors with different configurations
or modify the rate limit service source code.

### Apply to Multiple Endpoints

Modify the Lua filter to match multiple paths:

```lua
local protected_paths = {
  "/api/critical-endpoint",
  "/api/sensitive-data",
  "/api/expensive-operation"
}

local function is_protected(path)
  for _, p in ipairs(protected_paths) do
    if path == p then
      return true
    end
  end
  return false
end

function envoy_on_request(request_handle)
  local path = request_handle:headers():get(":path")
  local method = request_handle:headers():get(":method")
  
  if method == "POST" and is_protected(path) then
    -- Extract JSESSIONID logic here
  end
end
```

### Apply to Different HTTP Methods

Change the method check in Lua filter:

```lua
-- For all methods
if is_protected(path) then

-- For specific methods
local protected_methods = {["POST"] = true, ["PUT"] = true, ["DELETE"] = true}
if protected_methods[method] and is_protected(path) then
```

## Troubleshooting

### Rate Limiting Not Working

1. Check EnvoyFilter is applied:
```bash
kubectl get envoyfilter -n integrations session-ratelimit -o yaml
```

2. Check sidecar logs for errors:
```bash
kubectl logs -n integrations <pod-name> -c istio-proxy | grep -i error
```

3. Verify rate limit service is healthy:
```bash
kubectl get pods -n integrations -l app=ratelimit
kubectl logs -n integrations -l app=ratelimit -c ratelimit
```

4. Check if Lua filter is extracting session:
```bash
# Add debug logging to Lua script
request_handle:logInfo("JSESSIONID: " .. jsessionid)
```

### Rate Limit Service Connection Issues

1. Check service DNS resolution:
```bash
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- \
  nslookup ratelimit.integrations.svc.cluster.local
```

2. Test gRPC connectivity:
```bash
kubectl run -it --rm grpcurl --image=fullstorydev/grpcurl --restart=Never -- \
  -plaintext ratelimit.integrations.svc.cluster.local:8081 list
```

### Redis Issues

1. Check Redis connectivity:
```bash
kubectl exec -n integrations <ratelimit-pod> -c redis -- redis-cli PING
```

2. Check memory usage:
```bash
kubectl exec -n integrations <ratelimit-pod> -c redis -- \
  redis-cli INFO memory
```

3. Check eviction policy:
```bash
kubectl exec -n integrations <ratelimit-pod> -c redis -- \
  redis-cli CONFIG GET maxmemory-policy
```

### 429 Responses Not Being Returned

1. Check `failure_mode_deny` setting in EnvoyFilter (set to `false` for testing)

2. Verify rate limit response:
```bash
kubectl port-forward -n integrations svc/ratelimit 8081:8081

# Use grpcurl to test directly
grpcurl -plaintext -d @ localhost:8081 pb.lyft.ratelimit.RateLimitService/ShouldRateLimit <<EOF
{
  "domain": "integration-posts",
  "descriptors": [
    {
      "entries": [
        {"key": "jsessionid", "value": "test123"}
      ]
    }
  ]
}
EOF
```

## Security Considerations

### Session ID Extraction

- **Cookie parsing is basic**: Only handles simple JSESSIONID format
- **No validation**: Session IDs are used as-is without validation
- **Consider**: Adding session ID format validation in Lua

### Redis Security

- **No authentication**: Redis is localhost-only in sidecar
- **No encryption**: Data is stored unencrypted
- **For production**: Consider using managed Redis with auth/TLS

### Rate Limit Bypass

- **Missing cookie**: Requests without JSESSIONID are not rate limited
- **Modified cookies**: Users could potentially rotate session IDs
- **Consider**: Adding IP-based rate limiting as fallback

## Performance Considerations

### Resource Usage

- **Rate Limit Service**: ~128MB RAM, ~100m CPU per replica
- **Redis**: ~256MB RAM, ~100m CPU
- **Envoy overhead**: Minimal (~1-2ms latency per request)

### Scaling

For high-traffic scenarios (millions of requests):

1. **Scale rate limit service horizontally**:
```bash
kubectl scale deployment ratelimit -n integrations --replicas=5
```

2. **Use external Redis cluster** instead of sidecar:
```yaml
env:
- name: REDIS_URL
  value: "redis-cluster.integrations.svc.cluster.local:6379"
```

3. **Enable connection pooling** in EnvoyFilter

4. **Monitor Redis memory** and adjust maxmemory settings

### Latency Impact

- Rate limit check: ~1-5ms overhead
- Redis lookup: ~1ms (localhost)
- gRPC call: ~1-3ms
- Total: ~3-10ms additional latency per request

## References

- [Istio Rate Limiting](https://istio.io/latest/docs/tasks/policy-enforcement/rate-limit/)
- [Envoy Rate Limit Service](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ratelimit/v3/rls.proto)
- [Envoy Rate Limit Filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rate_limit_filter)
- [Lyft Rate Limit Service](https://github.com/envoyproxy/ratelimit)
```

This markdown file is ready for your GitHub repo. Save it as `RATE_LIMITING.md` or similar. Would you like me to add any additional sections like incident response procedures or runbook examples?
