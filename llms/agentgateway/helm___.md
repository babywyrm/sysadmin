# Agentgateway + Helm Reference Guide

A standalone reference for deploying agentgateway as a DPoP-authenticated
MCP/API proxy on Kubernetes using a custom Helm chart.

---

## What is Agentgateway?

- Open source Rust-based data plane for AI agent connectivity
- Proxies MCP (Model Context Protocol) and A2A (Agent-to-Agent) traffic
- Built-in JWT authentication, RBAC, CORS, rate limiting, TLS
- Repo: https://github.com/agentgateway/agentgateway
- Docs: https://agentgateway.dev/docs/
- Container: `ghcr.io/agentgateway/agentgateway:latest` (~68MB)

## What is DPoP?

- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession
- Binds tokens to a specific client keypair
- JWT proof contains `htu` (target URI) and `htm` (HTTP method)
- Prevents token replay across different endpoints
- Agentgateway enforces DPoP via its `jwtAuth` policy with JWKS verification

---

## Standalone Binary (no K8s)

```bash
# Install
curl -sL https://agentgateway.dev/install | bash
agentgateway --version

# Run with config
agentgateway -f config.yaml

# UI available at http://localhost:15000/ui
```

---

## Custom Helm Chart Structure

```
chart/agentgateway/
├── Chart.yaml              # Chart metadata
├── values.yaml             # Default values (customize per deployment)
├── files/
│   └── jwks.json           # RSA public key in JWKS format
└── templates/
    ├── configmap.yaml      # Gateway config + JWKS
    ├── deployment.yaml     # Pod spec with env var token injection
    ├── rbac.yaml           # ServiceAccount + Role + RoleBinding + token Secret
    └── service.yaml        # ClusterIP service
```

### Chart.yaml

```yaml
apiVersion: v2
name: agentgateway
description: AI-Ops Agent Gateway with DPoP authentication
type: application
version: 1.0.0
appVersion: "0.12.0"
```

### values.yaml

```yaml
replicaCount: 1

image:
  repository: ghcr.io/agentgateway/agentgateway
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8080

resources:
  requests:
    memory: "32Mi"
    cpu: "50m"
  limits:
    memory: "64Mi"
    cpu: "200m"

gateway:
  issuer: my-app-aiops        # JWT issuer claim to validate
  audience: mcp-gateway        # JWT audience claim to validate

  routes:
    mcp:
      enabled: true
      backend: my-mcp-server.default.svc.cluster.local:5000
    secrets:
      enabled: true
      backend: kubernetes.default:443

# Custom values that get stored in the Helm release secret
myApp:
  someCredential: "sensitive-value-here"
```

---

## JWKS Format

Generate from an RSA public key:

```python
import json, base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key

with open('public.pem', 'rb') as f:
    pub_key = load_pem_public_key(f.read())

numbers = pub_key.public_numbers()

def int_to_base64url(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

jwks = {"keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "my-key-1",
    "n": int_to_base64url(numbers.n),
    "e": int_to_base64url(numbers.e),
}]}

with open('jwks.json', 'w') as f:
    json.dump(jwks, f, indent=2)
```

Place in `chart/agentgateway/files/jwks.json`.

---

## Agentgateway Config (config.yaml)

### Basic structure

```yaml
binds:
- port: 8080
  listeners:
  - protocol: HTTP
    routes:
    - name: my-route
      matches:
      - path:
          pathPrefix: /api
        method: POST
      policies:
        jwtAuth:
          mode: strict                    # strict | optional | permissive
          issuer: my-app-aiops           # required iss claim
          audiences: [mcp-gateway]       # required aud claim
          jwks:
            file: /etc/agentgateway/jwks.json
        urlRewrite:
          path:
            full: "/new-path"            # replace entire path
            # OR
            prefix: /new-prefix          # replace matched prefix
      backends:
      - host: my-backend:5000
```

### JWT Authentication modes

| Mode | Behavior |
|---|---|
| `strict` | Valid JWT required. Rejects all unauthenticated requests. |
| `optional` | Validates JWT if present. Allows unauthenticated requests. |
| `permissive` | Never rejects. JWT claims available for downstream use. |

### Required JWT claims for strict mode

| Claim | Description |
|---|---|
| `iss` | Must match configured `issuer` |
| `aud` | Must match one of configured `audiences` |
| `exp` | Must be present and not expired |
| `iat` | Should be present (issued-at timestamp) |
| Signature | Must verify against JWKS public key |

### Additional DPoP claims (application-level, not enforced by gateway)

| Claim | Description |
|---|---|
| `jti` | Unique token ID (prevents replay) |
| `htm` | HTTP method the token is bound to |
| `htu` | HTTP target URI the token is bound to |

### Backend TLS (for HTTPS backends like K8s API)

```yaml
policies:
  backendTLS:
    insecure: true          # skip TLS verification
    # OR
    root: /path/to/ca.crt   # custom CA for verification
```

### Request/Response header modification

```yaml
policies:
  requestHeaderModifier:
    set:
      Authorization: "Bearer ${MY_ENV_VAR}"   # inject from env var
      X-Custom: "static-value"
    add:
      X-Request-Id: '${uuid()}'
    remove:
    - X-Internal-Header
```

### URL rewriting

```yaml
policies:
  urlRewrite:
    path:
      full: "/api/v1/resources"    # replace entire path
      # OR
      prefix: /api/v1              # replace the matched prefix portion
```

### Direct response (no backend)

```yaml
- name: health
  matches:
  - path:
      exact: /healthz
  policies:
    directResponse:
      body: '{"status":"ok"}'
      status: 200
```

### Rate limiting

```yaml
policies:
  localRateLimit:
  - maxTokens: 100
    tokensPerFill: 10
    fillInterval: 1s
```

### Path/header/method matching

```yaml
matches:
- path:
    pathPrefix: /api          # prefix match
    exact: /health            # exact match
    regex: "/users/[0-9]+"    # regex match
  method: GET                 # HTTP method
  headers:
  - name: x-api-key
    value:
      exact: "my-key"
      regex: "key-[a-z0-9]+"
  query:
  - name: version
    value:
      exact: "v2"
```

---

## Environment Variable Substitution

Agentgateway natively supports `${ENV_VAR}` in config files:

```yaml
requestHeaderModifier:
  set:
    Authorization: "Bearer ${SECRETS_TOKEN}"
```

Set the env var in the pod spec:

```yaml
env:
- name: SECRETS_TOKEN
  valueFrom:
    secretKeyRef:
      name: my-sa-token-secret
      key: token
```

---

## Helm Commands

```bash
# Install
helm install agentgateway ./chart/agentgateway -n my-namespace

# Upgrade (after changing values or templates)
helm upgrade agentgateway ./chart/agentgateway -n my-namespace

# Uninstall
helm uninstall agentgateway -n my-namespace

# Check release
helm list -n my-namespace
helm get values agentgateway -n my-namespace
helm get manifest agentgateway -n my-namespace

# Debug template rendering
helm template agentgateway ./chart/agentgateway -n my-namespace

# Show what Helm would do
helm upgrade --dry-run agentgateway ./chart/agentgateway -n my-namespace
```

---

## Helm Release Secrets

When Helm installs a chart, it creates a Secret:

```
sh.helm.release.v1.<release-name>.v<revision>
```

This secret contains the full release data including chart values.

### Decode a Helm release secret

```bash
# From kubectl
kubectl get secret sh.helm.release.v1.agentgateway.v1 \
  -n my-namespace -o jsonpath='{.data.release}' \
  | base64 -d | base64 -d | gunzip \
  | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['chart']['values'], indent=2))"

# From Python
import base64, gzip, json
release_b64 = "<base64 from secret>"
decoded = gzip.decompress(base64.b64decode(base64.b64decode(release_b64)))
release = json.loads(decoded)
values = release["chart"]["values"]
```

### Security note

Helm release secrets contain ALL values passed during install, including
any credentials embedded in values.yaml. This is a known attack surface:
- An attacker with K8s secret read access can decode release secrets
- Sensitive values should use external secret managers, not values.yaml
- In CTF/HTB context, this is an intentional vulnerability to exploit

---

## Forging DPoP JWTs (Python)

```python
import jwt, uuid, time

private_key = open("private.pem").read()

def forge_dpop(method, target_url):
    now = int(time.time())
    return jwt.encode(
        {
            "jti": str(uuid.uuid4()),
            "iss": "my-app-aiops",
            "aud": "mcp-gateway",
            "htm": method,
            "htu": target_url,
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "my-key-1"},
    )

# Usage
token = forge_dpop("GET", "http://gateway:8080/secrets")
# Send: curl -H "Authorization: Bearer <token>" http://gateway:8080/secrets
```

Install: `pip install pyjwt[crypto]`

---

## Quick Deploy Checklist

1. Generate RSA keypair: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem`
2. Extract public key: `openssl rsa -in private.pem -pubout -out public.pem`
3. Generate JWKS from public key (Python script above)
4. Create Helm chart with templates
5. Set values.yaml with routes, issuer, audience
6. `helm install agentgateway ./chart -n my-namespace`
7. Verify: `curl http://<gateway>/healthz`
8. Test auth: `curl -H "Authorization: Bearer <jwt>" http://<gateway>/my-route`

##
##
