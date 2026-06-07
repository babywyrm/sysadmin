# Agentgateway DPoP-Authenticated MCP/API Proxy on Kubernetes 

## Hardened Reference Architecture

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Threat Model & Security Posture](#2-threat-model--security-posture)
3. [Prerequisites & Dependencies](#3-prerequisites--dependencies)
4. [PKI & Key Management](#4-pki--key-management)
5. [Helm Chart Structure (Hardened)](#5-helm-chart-structure-hardened)
6. [Agentgateway Configuration](#6-agentgateway-configuration)
7. [DPoP Token Lifecycle](#7-dpop-token-lifecycle)
8. [Kubernetes Security Hardening](#8-kubernetes-security-hardening)
9. [Observability & Audit](#9-observability--audit)
10. [Secret Management Strategy](#10-secret-management-strategy)
11. [Operational Runbook](#11-operational-runbook)
12. [Known Attack Surfaces & Mitigations](#12-known-attack-surfaces--mitigations)

---

## 1. Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                        │
│                                                                  │
│  ┌──────────────┐    DPoP JWT     ┌────────────────────────┐     │
│  │   AI Agent   │ ─────────────► │    Agentgateway Pod    │      │
│  │  (client)    │                 │                        │     │
│  └──────────────┘                 │  ┌──────────────────┐  │     │
│                                   │  │  jwtAuth policy  │  │     │
│  ┌──────────────┐                 │  │  - iss/aud/exp   │  │     │
│  │  JWKS source │ ◄── verify ──── │  │  - JWKS verify   │  │     │
│  │ (file/https) │                 │  │  - DPoP claims   │  │     │
│  └──────────────┘                 │  └──────────────────┘  │     │
│                                   │           │            │     │
│                                   │    ┌──────▼──────┐     │    │
│                                   │    │Route + Rewrite    │    │
│                                   │    │+ Header Inject│   │    │
│                                   │    └──────┬──────┘     │    │
│                                   └───────────┼────────────┘    │
│                                               │                 │
│          ┌──────────────────────┬─────────────┘                 │
│          │                      │                               │
│  ┌───────▼──────┐    ┌──────────▼──────┐                        │
│  │  MCP Server  │    │  Kubernetes API  │                       │
│  │  :5000       │    │  (secrets route) │                       │
│  └──────────────┘    └─────────────────┘                        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  External Secret Operator → Vault/AWS SM → K8s Secrets   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```text
1. Client generates ephemeral keypair (per session or per request)
2. Client mints DPoP JWT: signs {jti, iss, aud, htm, htu, iat, exp}
   with private key → sends as Authorization: Bearer <token>
3. Agentgateway validates:
   a. JWT signature against JWKS
   b. iss matches configured issuer
   c. aud matches configured audience
   d. exp not elapsed
   e. (app-layer) htm/htu match incoming request
4. Gateway rewrites headers, injects backend credentials from env
5. Request forwarded to backend over mTLS or TLS-verified channel
6. Response returned; audit log emitted
```

---

## 2. Threat Model & Security Posture

### Assets Being Protected

| Asset | Classification | Notes |
|---|---|---|
| Backend service credentials | Critical | Injected via env, never in transit |
| JWKS private key | Critical | Never enters cluster; offline storage |
| Kubernetes ServiceAccount tokens | High | Short-lived, projected volumes |
| Helm release secrets | High | Known leakage vector — see §12 |
| Gateway config (routes, policies) | Medium | ConfigMap; no secrets in plaintext |

### Trust Boundaries

```text
Untrusted:  Client → Gateway (enforced by DPoP/JWT)
Semi-trusted: Gateway → MCP backend (network policy scoped)
Trusted:    Gateway → K8s API (SA token, RBAC scoped to minimum)
Out of scope: Node-level compromise, etcd access
```

### STRIDE Summary

| Threat | Control |
|---|---|
| Spoofing (token replay) | DPoP jti + htm/htu binding |
| Tampering (header injection) | Gateway rewrites; upstream headers stripped |
| Repudiation | Structured audit log with jti per request |
| Info disclosure | Helm values exfil → external secrets (§10) |
| DoS | Rate limiting policy + resource limits |
| Elevation of privilege | RBAC least-privilege SA; network policies |

---

## 3. Prerequisites & Dependencies

### Toolchain

```bash
# Required
kubectl >= 1.28
helm >= 3.12
openssl >= 3.0
python >= 3.10      # for JWKS generation and token tooling

# Optional but recommended
vault >= 1.15       # or AWS SM / GCP SM
external-secrets-operator >= 0.9
cert-manager >= 1.14
```

### Cluster Requirements

- Network policy enforcement enabled (Calico, Cilium, or equivalent)
- Pod Security Admission: `restricted` or `baseline` at minimum
- Audit logging enabled at the API server level
- RBAC enabled (default on all modern distributions)

### Python Dependencies

```bash
pip install pyjwt[crypto] cryptography
```

---

## 4. PKI & Key Management

### 4.1 Generate RSA Keypair (Offline)

Perform this on an air-gapped or secure workstation. The private key must **never** enter the cluster.

```bash
# Generate 2048-bit RSA private key (use 4096 for long-lived prod keys)
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out private.pem

# Extract public key
openssl rsa \
  -in private.pem \
  -pubout \
  -out public.pem

# Verify
openssl rsa -in public.pem -pubin -text -noout
```

**Storage rules:**
- `private.pem` → HSM, Vault Transit, or encrypted offline storage
- `public.pem` → Used to generate JWKS; can be committed to chart `files/`
- Never commit `private.pem` to version control

### 4.2 Generate JWKS from Public Key

```python
#!/usr/bin/env python3
"""
generate_jwks.py
Converts an RSA public key PEM to JWKS format.
Usage: python3 generate_jwks.py --key public.pem --kid my-key-1 --out jwks.json
"""

import argparse
import base64
import json
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def int_to_base64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    b = n.to_bytes(length, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def generate_jwks(key_path: str, kid: str) -> dict:
    with open(key_path, "rb") as f:
        pub_key = load_pem_public_key(f.read())

    numbers = pub_key.public_numbers()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": int_to_base64url(numbers.n),
                "e": int_to_base64url(numbers.e),
            }
        ]
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True, help="Path to RSA public PEM")
    parser.add_argument("--kid", default="my-key-1", help="Key ID")
    parser.add_argument("--out", default="jwks.json", help="Output path")
    args = parser.parse_args()

    jwks = generate_jwks(args.key, args.kid)

    with open(args.out, "w") as f:
        json.dump(jwks, f, indent=2)

    print(f"JWKS written to {args.out}")
    print(f"Key ID: {args.kid}")
    print(f"Key type: {jwks['keys'][0]['kty']}")


if __name__ == "__main__":
    main()
```

```bash
python3 generate_jwks.py \
  --key public.pem \
  --kid my-key-1 \
  --out chart/agentgateway/files/jwks.json
```

### 4.3 Key Rotation Procedure

```text
1. Generate new keypair (new-private.pem / new-public.pem)
2. Generate new JWKS with new kid (e.g., my-key-2)
3. Merge both keys into jwks.json (dual-key JWKS for zero-downtime rotation)
4. helm upgrade → gateway now accepts both keys
5. Roll all clients to new private key
6. After all clients rotated, remove old kid from jwks.json
7. helm upgrade → old key no longer accepted
8. Securely destroy old private key material
```

Dual-key JWKS during rotation:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "my-key-1",
      "n": "<old-modulus>",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "my-key-2",
      "n": "<new-modulus>",
      "e": "AQAB"
    }
  ]
}
```

---

## 5. Helm Chart Structure (Hardened)

```text
chart/agentgateway/
├── Chart.yaml
├── values.yaml                   # No secrets; references only
├── files/
│   └── jwks.json                 # RSA public key only
└── templates/
    ├── _helpers.tpl               # Common label/name helpers
    ├── configmap.yaml             # Gateway config + JWKS mount
    ├── deployment.yaml            # Pod spec; hardened security context
    ├── externalsecret.yaml        # ESO ExternalSecret (if using ESO)
    ├── networkpolicy.yaml         # Ingress/egress restrictions
    ├── poddisruptionbudget.yaml   # HA guard
    ├── rbac.yaml                  # SA + Role + RoleBinding (minimal)
    └── service.yaml               # ClusterIP only
```

### Chart.yaml

```yaml
apiVersion: v2
name: agentgateway
description: >
  AI-Ops Agent Gateway with DPoP authentication.
  Proxies MCP and API traffic with JWT/DPoP enforcement.
type: application
version: 1.1.0
appVersion: "0.12.0"
keywords:
  - agentgateway
  - mcp
  - dpop
  - ai-ops
maintainers:
  - name: platform-team
```

### values.yaml

```yaml
replicaCount: 2  # >=2 for PDB to be meaningful

image:
  repository: ghcr.io/agentgateway/agentgateway
  # Pin to a digest in production; never use `latest` in prod
  tag: "0.12.0"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8080
  # Expose metrics on a separate port; do not expose externally
  metricsPort: 9090

resources:
  requests:
    memory: "64Mi"
    cpu: "100m"
  limits:
    memory: "128Mi"
    cpu: "500m"

# Pod disruption budget
pdb:
  enabled: true
  minAvailable: 1

# Security context applied at pod and container level
securityContext:
  pod:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  container:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]

gateway:
  issuer: "my-app-aiops"
  audience: "mcp-gateway"
  dpop:
    # Application-level DPoP validation settings
    # Agentgateway enforces iss/aud/exp; htu/htm validated in strict mode
    enforceHtuHtm: true
    maxTokenAgeSeconds: 300

  routes:
    mcp:
      enabled: true
      backend: "my-mcp-server.default.svc.cluster.local:5000"
      pathPrefix: "/mcp"
      rateLimit:
        maxTokens: 100
        tokensPerFill: 10
        fillInterval: "1s"
    secrets:
      enabled: true
      backend: "kubernetes.default.svc.cluster.local:443"
      pathPrefix: "/secrets"
      backendTLS:
        # Use CA verification, not insecure: true
        rootCA: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# External secret configuration (External Secrets Operator)
externalSecret:
  enabled: true
  refreshInterval: "1h"
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: agentgateway-backend-creds
  data:
    - secretKey: BACKEND_TOKEN
      remoteRef:
        key: secret/aiops/agentgateway
        property: backend_token

# Network policy
networkPolicy:
  enabled: true
  # Namespaces/pods allowed to reach the gateway
  allowedIngress:
    - podSelector:
        matchLabels:
          app: ai-agent
  # Backends the gateway is allowed to reach
  allowedEgressPorts:
    - 5000   # MCP server
    - 443    # K8s API
```

### templates/\_helpers.tpl

```yaml
{{/*
Expand the name of the chart.
*/}}
{{- define "agentgateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "agentgateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "agentgateway.labels" -}}
helm.sh/chart: {{ include "agentgateway.chart" . }}
{{ include "agentgateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "agentgateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentgateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "agentgateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "agentgateway.serviceAccountName" -}}
{{- printf "%s-sa" (include "agentgateway.fullname" .) }}
{{- end }}
```

### templates/configmap.yaml

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "agentgateway.fullname" . }}-config
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "agentgateway.labels" . | nindent 4 }}
data:
  config.yaml: |
    binds:
    - port: 8080
      listeners:
      - protocol: HTTP
        routes:

        # Health check — no auth required
        - name: health
          matches:
          - path:
              exact: /healthz
          policies:
            directResponse:
              body: '{"status":"ok"}'
              status: 200

        {{- if .Values.gateway.routes.mcp.enabled }}
        # MCP backend route — DPoP/JWT required
        - name: mcp-proxy
          matches:
          - path:
              pathPrefix: {{ .Values.gateway.routes.mcp.pathPrefix }}
            method: POST
          policies:
            jwtAuth:
              mode: strict
              issuer: {{ .Values.gateway.issuer | quote }}
              audiences:
                - {{ .Values.gateway.audience | quote }}
              jwks:
                file: /etc/agentgateway/jwks.json
            localRateLimit:
            - maxTokens: {{ .Values.gateway.routes.mcp.rateLimit.maxTokens }}
              tokensPerFill: {{ .Values.gateway.routes.mcp.rateLimit.tokensPerFill }}
              fillInterval: {{ .Values.gateway.routes.mcp.rateLimit.fillInterval | quote }}
            requestHeaderModifier:
              remove:
              - X-Forwarded-For
              - X-Real-IP
              - X-Original-Authorization
          backends:
          - host: {{ .Values.gateway.routes.mcp.backend }}
        {{- end }}

        {{- if .Values.gateway.routes.secrets.enabled }}
        # Kubernetes secrets proxy — DPoP/JWT required; SA token injected
        - name: secrets-proxy
          matches:
          - path:
              pathPrefix: {{ .Values.gateway.routes.secrets.pathPrefix }}
            method: GET
          policies:
            jwtAuth:
              mode: strict
              issuer: {{ .Values.gateway.issuer | quote }}
              audiences:
                - {{ .Values.gateway.audience | quote }}
              jwks:
                file: /etc/agentgateway/jwks.json
            backendTLS:
              root: {{ .Values.gateway.routes.secrets.backendTLS.rootCA | quote }}
            requestHeaderModifier:
              set:
                Authorization: "Bearer ${BACKEND_TOKEN}"
              remove:
              - X-Forwarded-For
          backends:
          - host: {{ .Values.gateway.routes.secrets.backend }}
        {{- end }}

  jwks.json: |
{{ .Files.Get "files/jwks.json" | indent 4 }}
```

### templates/deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "agentgateway.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "agentgateway.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "agentgateway.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "agentgateway.selectorLabels" . | nindent 8 }}
      annotations:
        # Force pod restart when config changes
        checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
    spec:
      serviceAccountName: {{ include "agentgateway.serviceAccountName" . }}

      # Do not automount SA token; we use projected volume instead
      automountServiceAccountToken: false

      securityContext:
        {{- toYaml .Values.securityContext.pod | nindent 8 }}

      # No privilege escalation via init containers either
      initContainers: []

      containers:
      - name: agentgateway
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}

        args:
        - -f
        - /etc/agentgateway/config.yaml

        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP

        securityContext:
          {{- toYaml .Values.securityContext.container | nindent 10 }}

        resources:
          {{- toYaml .Values.resources | nindent 10 }}

        env:
        - name: BACKEND_TOKEN
          valueFrom:
            secretKeyRef:
              # Populated by ExternalSecret or projected SA token
              name: agentgateway-backend-creds
              key: BACKEND_TOKEN

        volumeMounts:
        - name: config
          mountPath: /etc/agentgateway
          readOnly: true
        - name: tmp
          mountPath: /tmp
        # Projected SA token for K8s API calls (short-lived, audience-scoped)
        - name: sa-token
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true

        livenessProbe:
          httpGet:
            path: /healthz
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
          failureThreshold: 3

        readinessProbe:
          httpGet:
            path: /healthz
            port: http
          initialDelaySeconds: 3
          periodSeconds: 5

      volumes:
      - name: config
        configMap:
          name: {{ include "agentgateway.fullname" . }}-config
      - name: tmp
        emptyDir: {}
      - name: sa-token
        projected:
          sources:
          - serviceAccountToken:
              path: token
              # Short expiry; kubelet rotates automatically
              expirationSeconds: 3600
              audience: https://kubernetes.default.svc.cluster.local
          - configMap:
              name: kube-root-ca.crt
              items:
              - key: ca.crt
                path: ca.crt
```

### templates/rbac.yaml

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "agentgateway.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "agentgateway.labels" . | nindent 4 }}
  annotations:
    # If using IRSA (AWS) or Workload Identity (GCP), add annotations here
    # eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/agentgateway
automountServiceAccountToken: false
---
# Minimal RBAC: read-only access to secrets in this namespace only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "agentgateway.fullname" . }}-role
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "agentgateway.labels" . | nindent 4 }}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  # Scope to specific secrets by name if possible
  resourceNames: ["agentgateway-backend-creds"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "agentgateway.fullname" . }}-rolebinding
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "agentgateway.labels" . | nindent 4 }}
subjects:
- kind: ServiceAccount
  name: {{ include "agentgateway.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
roleRef:
  kind: Role
  apiGroup: rbac.authorization.k8s.io
  name: {{ include "agentgateway.fullname" . }}-role
```

### templates/networkpolicy.yaml

```yaml
{{- if .Values.networkPolicy.enabled }}
# Deny all ingress/egress by default; then explicitly allow
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "agentgateway.fullname" . }}-deny-all
  namespace: {{ .Release.Namespace }}
spec:
  podSelector:
    matchLabels:
      {{- include "agentgateway.selectorLabels" . | nindent 6 }}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "agentgateway.fullname" . }}-allow
  namespace: {{ .Release.Namespace }}
spec:
  podSelector:
    matchLabels:
      {{- include "agentgateway.selectorLabels" . | nindent 6 }}
  policyTypes:
  - Ingress
  - Egress

  ingress:
  # Allow from authorized agent pods only
  {{- range .Values.networkPolicy.allowedIngress }}
  - from:
    - podSelector:
        {{- toYaml .podSelector | nindent 8 }}
    ports:
    - port: 8080
      protocol: TCP
  {{- end }}
  # Allow metrics scraping from monitoring namespace
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
    ports:
    - port: 9090
      protocol: TCP

  egress:
  # Allow DNS
  - to: []
    ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  # Allow configured backend ports
  {{- range .Values.networkPolicy.allowedEgressPorts }}
  - ports:
    - port: {{ . }}
      protocol: TCP
  {{- end }}
{{- end }}
```

### templates/externalsecret.yaml

```yaml
{{- if .Values.externalSecret.enabled }}
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ include "agentgateway.fullname" . }}-ext-secret
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "agentgateway.labels" . | nindent 4 }}
spec:
  refreshInterval: {{ .Values.externalSecret.refreshInterval }}
  secretStoreRef:
    name: {{ .Values.externalSecret.secretStoreRef.name }}
    kind: {{ .Values.externalSecret.secretStoreRef.kind }}
  target:
    name: {{ .Values.externalSecret.target.name }}
    creationPolicy: Owner
    # Annotate the resulting secret to prevent Helm from managing it
    template:
      metadata:
        annotations:
          helm.sh/resource-policy: keep
  data:
    {{- toYaml .Values.externalSecret.data | nindent 4 }}
{{- end }}
```

### templates/poddisruptionbudget.yaml

```yaml
{{- if .Values.pdb.enabled }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "agentgateway.fullname" . }}-pdb
  namespace: {{ .Release.Namespace }}
spec:
  minAvailable: {{ .Values.pdb.minAvailable }}
  selector:
    matchLabels:
      {{- include "agentgateway.selectorLabels" . | nindent 6 }}
{{- end }}
```

### templates/service.yaml

```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "agentgateway.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "agentgateway.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  selector:
    {{- include "agentgateway.selectorLabels" . | nindent 4 }}
  ports:
  - name: http
    port: {{ .Values.service.port }}
    targetPort: http
    protocol: TCP
  - name: metrics
    port: {{ .Values.service.metricsPort }}
    targetPort: metrics
    protocol: TCP
```

---

## 6. Agentgateway Configuration

### Full Reference config.yaml

```yaml
# Full config reference — rendered by configmap.yaml template
# Shown here as a standalone reference

binds:
- port: 8080
  listeners:
  - protocol: HTTP
    routes:

    # ── Health ────────────────────────────────────────────────────
    - name: health
      matches:
      - path:
          exact: /healthz
      policies:
        directResponse:
          body: '{"status":"ok"}'
          status: 200

    # ── MCP proxy ─────────────────────────────────────────────────
    - name: mcp-proxy
      matches:
      - path:
          pathPrefix: /mcp
        method: POST
      policies:
        jwtAuth:
          mode: strict
          issuer: "my-app-aiops"
          audiences:
            - "mcp-gateway"
          jwks:
            file: /etc/agentgateway/jwks.json
        localRateLimit:
        - maxTokens: 100
          tokensPerFill: 10
          fillInterval: 1s
        requestHeaderModifier:
          remove:
          - X-Forwarded-For
          - X-Real-IP
          - X-Original-Authorization
      backends:
      - host: my-mcp-server.default.svc.cluster.local:5000

    # ── K8s secrets proxy ─────────────────────────────────────────
    - name: secrets-proxy
      matches:
      - path:
          pathPrefix: /secrets
        method: GET
      policies:
        jwtAuth:
          mode: strict
          issuer: "my-app-aiops"
          audiences:
            - "mcp-gateway"
          jwks:
            file: /etc/agentgateway/jwks.json
        backendTLS:
          root: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        requestHeaderModifier:
          set:
            Authorization: "Bearer ${BACKEND_TOKEN}"
          remove:
          - X-Forwarded-For
      backends:
      - host: kubernetes.default.svc.cluster.local:443
```

### JWT Auth Mode Decision Table

| Scenario | Mode | Rationale |
|---|---|---|
| Production MCP/API proxy | `strict` | All traffic must be authenticated |
| Dev/debug endpoint | `optional` | Validate if present; allow otherwise |
| Audit-only (no enforcement) | `permissive` | Log claims; never block |
| Internal health checks | No jwtAuth block | Route matched before auth |

### Path Matching Precedence

```text
Agentgateway evaluates routes top-to-bottom; first match wins.
Always place exact and specific matches BEFORE prefix matches.

Correct:
  1. exact: /healthz        ← matched first, no auth
  2. exact: /mcp/v1/call    ← specific; auth applied
  3. pathPrefix: /mcp       ← catch-all for MCP; auth applied

Incorrect:
  1. pathPrefix: /mcp       ← would swallow /mcp/v1/call
  2. exact: /mcp/v1/call    ← never reached
```

---

## 7. DPoP Token Lifecycle

### 7.1 DPoP Token Minting (Client-Side)

```python
#!/usr/bin/env python3
"""
dpop_client.py
Mints DPoP-compliant JWTs for use with agentgateway.

DPoP (RFC 9449) binds a token to:
  - A specific HTTP method (htm)
  - A specific target URI (htu)
  - A unique token ID (jti) — prevents replay
  - A short expiry (exp) — limits window of misuse

Usage:
    from dpop_client import DPoPClient
    client = DPoPClient("private.pem", kid="my-key-1")
    token = client.mint("POST", "http://gateway:8080/mcp")
    # curl -H "Authorization: Bearer <token>" -X POST http://gateway:8080/mcp
"""

import time
import uuid
from pathlib import Path

import jwt


class DPoPClient:
    def __init__(
        self,
        private_key_path: str,
        issuer: str = "my-app-aiops",
        audience: str = "mcp-gateway",
        kid: str = "my-key-1",
        ttl_seconds: int = 300,
    ):
        self.private_key = Path(private_key_path).read_text()
        self.issuer = issuer
        self.audience = audience
        self.kid = kid
        self.ttl_seconds = ttl_seconds

    def mint(self, method: str, target_url: str) -> str:
        """
        Mint a DPoP JWT bound to the given HTTP method and target URL.

        Args:
            method: HTTP method (GET, POST, etc.) — must match request method
            target_url: Full target URL — must match request URL exactly

        Returns:
            Signed JWT string
        """
        now = int(time.time())

        payload = {
            # Standard claims
            "jti": str(uuid.uuid4()),  # Unique; enables server-side replay detection
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "exp": now + self.ttl_seconds,
            # DPoP-specific claims (RFC 9449)
            "htm": method.upper(),
            "htu": target_url,
        }

        return jwt.encode(
            payload,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.kid},
        )

    def mint_headers(self, method: str, target_url: str) -> dict:
        """Returns a dict of headers ready for use with requests/httpx."""
        return {
            "Authorization": f"Bearer {self.mint(method, target_url)}",
            "Content-Type": "application/json",
        }
```

### 7.2 Token Validation Checklist (Application Layer)

Agentgateway enforces `iss`, `aud`, `exp`, and signature. The following **must be validated by your application** if enforcing full RFC 9449 DPoP:

```text
Gateway enforces:
  ✅ iss matches configured issuer
  ✅ aud matches configured audience
  ✅ exp not elapsed
  ✅ Signature verifies against JWKS kid

Application must enforce:
  ⚠️  htm matches HTTP method of incoming request
  ⚠️  htu matches HTTP target URI of incoming request
  ⚠️  jti has not been seen before (replay prevention)
  ⚠️  iat is recent (clock skew tolerance: ±5s recommended)
```

### 7.3 Token Replay Prevention

For production, implement a jti store:

```python
import redis
from datetime import timedelta


class JtiStore:
    """
    Redis-backed jti replay prevention.
    Stores seen jti values for the duration of their token's TTL.
    """

    def __init__(self, redis_client: redis.Redis):
        self.r = redis_client

    def check_and_consume(self, jti: str, exp: int) -> bool:
        """
        Returns True if jti is new (not seen before).
        Returns False if jti was already used (replay detected).
        """
        ttl = max(exp - int(__import__("time").time()), 0)
        if ttl == 0:
            return False  # Already expired

        key = f"dpop:jti:{jti}"
        # SET NX: only set if not exists; atomic
        result = self.r.set(key, "1", ex=ttl, nx=True)
        return result is True
```

---

## 8. Kubernetes Security Hardening

### 8.1 Pod Security Standards

Apply at the namespace level:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aiops
  labels:
    # Enforce restricted PSS; pods violating will be rejected
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

### 8.2 Security Context Requirements (restricted PSS)

```text
Required for restricted Pod Security Standard:
  ✅ runAsNonRoot: true
  ✅ runAsUser: non-zero (we use 65534 = nobody)
  ✅ allowPrivilegeEscalation: false
  ✅ capabilities.drop: [ALL]
  ✅ seccompProfile.type: RuntimeDefault (or Localhost)
  ✅ readOnlyRootFilesystem: true
  ✅ volumes: emptyDir for /tmp (writable scratch)
```

### 8.3 Image Pinning

```bash
# Never use :latest in production
# Get the digest for a specific tag
docker pull ghcr.io/agentgateway/agentgateway:0.12.0
docker inspect ghcr.io/agentgateway/agentgateway:0.12.0 \
  --format='{{index .RepoDigests 0}}'
# → ghcr.io/agentgateway/agentgateway@sha256:abc123...

# Use in values.yaml:
# image:
#   repository: ghcr.io/agentgateway/agentgateway
#   tag: "sha256:abc123..."
```

### 8.4 Projected ServiceAccount Tokens

Avoid `automountServiceAccountToken: true` (mounts a non-expiring token). Use projected volumes with explicit expiry and audience:

```yaml
# In deployment.yaml (shown in §5)
volumes:
- name: sa-token
  projected:
    sources:
    - serviceAccountToken:
        path: token
        expirationSeconds: 3600      # kubelet rotates before expiry
        audience: https://kubernetes.default.svc.cluster.local
    - configMap:
        name: kube-root-ca.crt
        items:
        - key: ca.crt
          path: ca.crt
```

---

## 9. Observability & Audit

### 9.1 Structured Logging

Agentgateway emits structured logs. Capture and forward with a sidecar or DaemonSet log shipper:

```text
Fields to index/alert on:
  - jwt.jti       → enable per-request tracing and replay detection
  - jwt.iss       → verify only known issuers are calling
  - jwt.aud       → detect audience mismatches
  - route.name    → traffic distribution per route
  - response.status → 401/403 spikes indicate auth failures or attack
  - dpop.htm      → method binding violations
  - dpop.htu      → URI binding violations
```

### 9.2 Prometheus Metrics

Expose on `:9090/metrics`. Key metrics to alert on:

```text
# Auth failures — alert if rate > threshold
agentgateway_jwt_auth_failure_total{route, reason}

# Rate limit hits — alert if sustained
agentgateway_rate_limit_triggered_total{route}

# Request latency
agentgateway_request_duration_seconds{route, status}

# Active connections
agentgateway_active_connections{backend}
```

### 9.3 Kubernetes Audit Policy

Ensure API server audit policy captures secret access through the gateway:

```yaml
# audit-policy.yaml (applied to API server)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all secret reads by the agentgateway SA
- level: Request
  users:
    - "system:serviceaccount:aiops:agentgateway-sa"
  resources:
  - group: ""
    resources: ["secrets"]
  verbs: ["get", "list"]

# Log all auth failures cluster-wide
- level: Metadata
  omitStages: [RequestReceived]
  nonResourceURLs: ["/apis/*"]
```

---

## 10. Secret Management Strategy

### The Problem with Helm Values

```text
RISK: helm install -f values.yaml stores ALL values in:
  sh.helm.release.v1.<release>.v<n>  (K8s Secret)

Any principal with `get secrets` in that namespace can decode:
  kubectl get secret sh.helm.release.v1.agentgateway.v1 \
    -o jsonpath='{.data.release}' \
    | base64 -d | base64 -d | gunzip \
    | python3 -c "
        import sys, json
        print(json.dumps(
          json.load(sys.stdin)['chart']['values'], indent=2
        ))"

RESULT: Any credential in values.yaml is recoverable by
  anyone with secret read access in that namespace.
```

### Recommended Secret Management Matrix

| Credential | Storage | Access Method |
|---|---|---|
| Backend API tokens | Vault / AWS SM | External Secrets Operator → K8s Secret |
| JWKS private key | HSM / Vault Transit | Never enters cluster |
| JWKS public key | `files/jwks.json` in chart | Safe to version control |
| SA token (K8s API) | Projected volume | Auto-rotated by kubelet |
| TLS certs | cert-manager | CertificateRequest → Secret |

### External Secrets Operator Setup

```bash
# Install ESO
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets \
  external-secrets/external-secrets \
  -n external-secrets-system \
  --create-namespace

# Create a ClusterSecretStore pointing to Vault
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.internal:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "agentgateway"
          serviceAccountRef:
            name: agentgateway-sa
            namespace: aiops
EOF
```

With ESO enabled, `externalSecret.enabled: true` in values.yaml causes the chart to create an `ExternalSecret` resource that syncs credentials from Vault into a K8s Secret — **without those credentials ever appearing in Helm release secrets**.

---

## 11. Operational Runbook

### Deploy

```bash
# 1. Generate keypair (once, offline)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -in private.pem -pubout -out public.pem

# 2. Generate JWKS
python3 generate_jwks.py \
  --key public.pem \
  --kid my-key-1 \
  --out chart/agentgateway/files/jwks.json

# 3. Create namespace with PSS labels
kubectl create namespace aiops
kubectl label namespace aiops \
  pod-security.kubernetes.io/enforce=restricted

# 4. Lint chart
helm lint ./chart/agentgateway

# 5. Dry run
helm upgrade --install agentgateway ./chart/agentgateway \
  -n aiops \
  --dry-run \
  --debug

# 6. Install
helm upgrade --install agentgateway ./chart/agentgateway \
  -n aiops \
  --wait \
  --timeout 2m
```

### Verify Deployment

```bash
# Pod running and ready
kubectl get pods -n aiops -l app.kubernetes.io/name=agentgateway

# Health check (from within cluster)
kubectl run curl-test --image=curlimages/curl --rm -it --restart=Never \
  -- curl -s http://agentgateway.aiops.svc.cluster.local:8080/healthz

# Check logs
kubectl logs -n aiops -l app.kubernetes.io/name=agentgateway -f

# Check RBAC
kubectl auth can-i get secrets \
  --as=system:serviceaccount:aiops:agentgateway-sa \
  -n aiops \
  --resource-name=agentgateway-backend-creds
```

### Test DPoP Auth Flow

```python
#!/usr/bin/env python3
"""
test_auth.py — Smoke test for gateway DPoP auth.
Run from outside the cluster with port-forward or from a test pod inside.
"""

import httpx
from dpop_client import DPoPClient

GATEWAY = "http://localhost:8080"  # or internal svc URL
client = DPoPClient("private.pem", kid="my-key-1")

# Should succeed: valid DPoP token, matching method and URL
response = httpx.post(
    f"{GATEWAY}/mcp",
    headers=client.mint_headers("POST", f"{GATEWAY}/mcp"),
    json={"test": True},
)
print(f"MCP (should be 200 or 502): {response.status_code}")

# Should fail: no token
response = httpx.post(f"{GATEWAY}/mcp", json={"test": True})
print(f"No token (should be 401): {response.status_code}")

# Should fail: wrong method in token
response = httpx.post(
    f"{GATEWAY}/mcp",
    headers=client.mint_headers("GET", f"{GATEWAY}/mcp"),  # wrong method
    json={"test": True},
)
print(f"Wrong htm (behaviour depends on gateway version): {response.status_code}")
```

### Upgrade

```bash
# Upgrade after config or values change
helm upgrade agentgateway ./chart/agentgateway -n aiops --wait

# Helm will trigger a rolling update because of the config checksum annotation
# Verify rollout
kubectl rollout status deployment/agentgateway -n aiops
```

### Rotate Keys

```bash
# 1. Generate new keypair
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out new-private.pem
openssl rsa -in new-private.pem -pubout -out new-public.pem

# 2. Generate new JWKS entry and merge with existing
python3 generate_jwks.py \
  --key new-public.pem \
  --kid my-key-2 \
  --out new-key.json

# 3. Manually merge jwks.json (both keys present)
# Edit chart/agentgateway/files/jwks.json to include both key entries

# 4. Deploy dual-key JWKS
helm upgrade agentgateway ./chart/agentgateway -n aiops --wait

# 5. Roll clients to new private key (my-key-2)
# ... client-specific procedure ...

# 6. Remove old key from jwks.json
# Edit chart/agentgateway/files/jwks.json to remove my-key-1

# 7. Deploy single-key JWKS (new key only)
helm upgrade agentgateway ./chart/agentgateway -n aiops --wait

# 8. Securely destroy old private key
shred -u private.pem
```

### Rollback

```bash
# View release history
helm history agentgateway -n aiops

# Rollback to previous revision
helm rollback agentgateway -n aiops

# Rollback to specific revision
helm rollback agentgateway 2 -n aiops
```

---

## 12. Known Attack Surfaces & Mitigations

| Attack Surface | Risk | Mitigation |
|---|---|---|
| Helm release secrets | Credentials in values.yaml recoverable by anyone with secret read in namespace | Use External Secrets Operator; never put credentials in values.yaml |
| JWKS private key | Compromise allows forging any token | Store offline/HSM; never enter cluster; rotate on suspected exposure |
| Token replay | Stolen token reused within its TTL | Short TTL (≤300s) + jti store (Redis) for replay detection |
| htm/htu bypass | Gateway validates iss/aud/exp but not htm/htu at transport layer | Enforce htm/htu in application layer; log mismatches |
| Lateral movement via MCP backend | Compromised gateway reaches other services | NetworkPolicy restricts egress to explicit backends only |
| SA token abuse | Gateway SA token used to list/modify other resources | RBAC scoped to single named secret; projected token (audience-scoped) |
| Image supply chain | Malicious image version | Pin image to digest; use admission controller (Kyverno/OPA) to enforce |
| Config injection via env | Env vars containing `${...}` could be abused | Validate all env var sources; use ESO for controlled injection |
| K8s audit log gaps | Secret access via proxy not logged at app level | Enable K8s audit policy for SA + structured gateway logs with jti |

---

## Quick Reference Card

```text
GENERATE KEYS
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
  openssl rsa -in private.pem -pubout -out public.pem
  python3 generate_jwks.py --key public.pem --kid my-key-1 --out files/jwks.json

DEPLOY
  helm upgrade --install agentgateway ./chart/agentgateway -n aiops --wait

MINT TOKEN (Python)
  from dpop_client import DPoPClient
  t = DPoPClient("private.pem").mint("POST", "http://gw:8080/mcp")

TEST
  curl -H "Authorization: Bearer <token>" -X POST http://gw:8080/mcp
  curl http://gw:8080/healthz          # no auth
  curl http://gw:8080/mcp              # should 401

ROTATE
  1. Generate new keypair
  2. Merge both keys into jwks.json (dual-key)
  3. helm upgrade → roll clients → remove old key → helm upgrade

DECODE HELM SECRET (audit/forensic only)
  kubectl get secret sh.helm.release.v1.agentgateway.v1 \
    -n aiops -o jsonpath='{.data.release}' \
    | base64 -d | base64 -d | gunzip \
    | python3 -c "import sys,json; d=json.load(sys.stdin);
        print(json.dumps(d['chart']['values'], indent=2))"

PRIVATE KEY: NEVER ENTERS CLUSTER. STORE OFFLINE OR IN HSM.
```
