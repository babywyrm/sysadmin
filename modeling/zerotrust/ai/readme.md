
 **Zero Trust Microservice Pattern**  (AI/ML/EKS)

- JWT-based user identity at ingress (Ambassador/Gateway)
- Service identity via IRSA (IAM Roles for Service Accounts)
- Sidecars for policy enforcement (Envoy + OPA/Gatekeeper)
- Guardrail configs as Infra-as-Code
- AWS Bedrock access (e.g., model inference)
- Integration with SaaS security tools (AI Defense)
- Logging/observability (SIEM-forwarding)
- PrivateLink for secure external access
- Istio/NetworkPolicies for service mesh control

---

## 🛡️ Zero Trust Microservice Pattern (Markdown Friendly)

```plaintext
┌────────────────────┐
│   User / Client    │
└────────┬───────────┘
         │ HTTPS + JWT
         ▼
┌──────────────────────────────┐
│    Ambassador / Ingress      │  ← JWT Validation + TLS Termination
│    (ExtAuth via OIDC/OAuth)  │
└────────┬─────────┬───────────┘
         │         │
         │         │ Authn Failure
         │         ▼
         │     401 Response
         ▼
┌──────────────────────────────────────────────┐
│ Kubernetes Service (e.g., `svc-brain-api`)  │
└────────┬─────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────────────────┐
│                             Pod (`brain-api`)                         │
│                                                                        │
│  ┌────────────────────┐   ┌──────────────────────────────┐             │
│  │ App Container       │   │ Envoy Sidecar                │             │
│  │ - Business logic    │   │ - mTLS for in-mesh traffic   │             │
│  │ - Reads configmap   │   │ - OPA/Gatekeeper Policy Enf. │             │
│  │ - Calls Bedrock     │   │ - Rate limiting/circuit brk  │             │
│  └────────────────────┘   └──────────────────────────────┘             │
│                                                                        │
│ IRSA (IAM Role for SA) → [ bedrock:InvokeModel + logs:PutLogEvents ]  │
│ Config/Secrets mounted (guardrails, tokens, env)                      │
└────────────────────────────────────────────────────────────────────────┘
         │
         │ PrivateLink
         ▼
┌──────────────────────────┐
│      AWS Bedrock         │
└──────────────────────────┘
         │
         ▼
┌────────────────────────────┐
│  AI Defense SaaS (Runtime) │ ← Optional, Detection/Protection
└────────────────────────────┘

        ┌──────────────────────┐
        │   Logging & SIEM     │ ← FluentBit/DaemonSet shipping to ELK, Splunk, etc.
        └──────────────────────┘
```

---

### 🧱 Core Components

| Component                | Description |
|-------------------------|-------------|
| **Ambassador/Gateway**  | External traffic ingress. Handles JWT validation, TLS, routing. |
| **Envoy Sidecar**       | Enforces mesh policy: mTLS, egress controls, rate limiting, etc. |
| **OPA/Gatekeeper**      | Custom runtime policies; validates requests, headers, context. |
| **IRSA**                | Grants Bedrock-specific IAM access to the pod securely. |
| **AWS Bedrock**         | Model invocation; private access via VPC endpoint. |
| **AI Defense SaaS**     | Optional layer for validation, discovery, protection. |
| **ConfigMap/Secrets**   | Store guardrail templates, policy configs, credentials. |
| **FluentBit/DaemonSet** | Logs collected and forwarded securely to central SIEM. |

---

### 🔁 Reusability Pattern

This Zero Trust setup can be **packaged into a Helm chart or Kustomize base**:

- `deployment.yaml` – app + envoy + annotations for IRSA
- `service.yaml` – internal cluster routing
- `gateway.yaml` – Ambassador or Istio Gateway definition
- `configmap.yaml` – guardrail and OPA policy templates
- `networkpolicy.yaml` – restricts intra-cluster traffic
- `serviceaccount.yaml` – annotated with IRSA role ARN
- `opa-policy.rego` – Zero trust access policy module

---

### 🧪 Security Testing Flow

1. **JWT validation** – malformed/invalid JWTs rejected at ingress.
2. **mTLS enforced** – all in-cluster service comms are encrypted & authenticated.
3. **Policy enforcement** – OPA/Gatekeeper stops unexpected behavior.
4. **Egress control** – only Bedrock and AI Defense endpoints reachable.
5. **IRSA scoping** – pods can't escalate AWS privileges.
6. **SIEM logging** – everything is observable and auditable.

---


# Zero Trust Microservice Pattern for AI/ML on EKS

A fully “zero trust” blueprint for deploying an AI/ML inference microservice (`brain-api`) on Amazon EKS, with secure ingress, service identity, policy enforcement, and observability.

---

## 1. Architecture Diagram

```text
User / Client
     │ HTTPS + JWT
     ▼
┌─────────────────────────────────┐
│ Ambassador / API Gateway       │  ← JWT validation, TLS termination
│ • ExtAuth → OIDC/OAuth         │
└──────────────┬──────────────────┘
               │
               ▼
┌───────────────────────────────────────────┐
│ kubernetes Service: svc‑brain‑api        │
└──────────────┬────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Pod: brain‑api                                                         │
│                                                                         │
│ ┌─────────────────────┐   ┌───────────────────────────────────────────┐  │
│ │ App Container       │   │ Envoy Sidecar                           │  │
│ │ • Business logic    │   │ • mTLS for in‑mesh traffic              │  │
│ │ • Bedrock client    │   │ • OPA/Gatekeeper policy enforcement     │  │
│ │ • Reads ConfigMap   │   │ • Rate limiting / circuit breaking      │  │
│ └─────────────────────┘   └───────────────────────────────────────────┘  │
│                                                                         │
│ IRSA → IAM role grants: ["bedrock:InvokeModel", "logs:PutLogEvents"]   │
│ ConfigMaps & Secrets → guardrails, OPA policies, tokens & certs        │
└─────────────────────────────────────────────────────────────────────────┘
               │
               │ PrivateLink
               ▼
┌───────────────────────────┐
│ AWS Bedrock (VPC endpoint)│
└───────────────────────────┘
               │
               ▼
┌───────────────────────────┐
│ AI Defense SaaS (Opt.)    │  ← Runtime anomaly detection / ML‑powered WAF
└───────────────────────────┘
               │
               ▼
┌───────────────────────────┐
│ Logging & SIEM            │  ← Fluent Bit → ELK / Splunk / Datadog
└───────────────────────────┘
```

---

## 2. Core Components

| Component             | Purpose                                                                                 | Open‑Source / AWS                                                        |
|-----------------------|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| Ambassador / Gateway  | Ingress JWT validation, TLS termination, routing                                        | Ambassador Edge Stack                                                   |
| Envoy Sidecar         | mTLS, egress control, rate‑limit, circuit breaker, observability                        | Envoy                                                                     |
| OPA / Gatekeeper      | Fine‑grained policy enforcement (e.g. “only allow calls to Bedrock endpoint”)           | Open Policy Agent                                                        |
| IRSA                  | Pod‑bound IAM role for Bedrock invocation + CloudWatch Logs                             | AWS IRSA                                                                 |
| AWS Bedrock           | Private model inference endpoint via VPC endpoint                                      | AWS Bedrock                                                              |
| AI Defense SaaS       | Optional runtime protection/insights (e.g. ML WAF, anomaly detection)                   | e.g. Datadog AI Security                                                 |
| ConfigMap / Secrets   | Guardrail configs (OPA policies, rate limits), tokens, certs                            | Kubernetes ConfigMaps                                                    |
| NetworkPolicy         | Restrict pod‑to‑pod traffic by namespace, label                                         | Calico / Kubernetes NetworkPolicy                                        |
| Fluent Bit / DaemonSet| Collect & forward logs / metrics to SIEM                                                | Fluent Bit                                                               |

---

## 3. Reusability Pattern (Helm / Kustomize)

Package this pattern into a chart or base with the following manifests:

### `serviceaccount.yaml`
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: brain-api-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/BrainApiRole
```

### `deployment.yaml`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: brain-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: brain-api
  template:
    metadata:
      labels:
        app: brain-api
    spec:
      serviceAccountName: brain-api-sa
      containers:
        - name: brain-api
          image: myrepo/brain-api:latest
          envFrom:
            - configMapRef:
                name: brain-api-config
            - secretRef:
                name: brain-api-secrets
      # Envoy sidecar injection via Istio or manual YAML
```

### `configmap.yaml`
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: brain-api-config
data:
  opa-policy.rego: |
    package zt
    default allow = false
    allow {
      input.method == "POST"
      input.path == "/predict"
    }
```

### `networkpolicy.yaml`
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: brain-api-policy
spec:
  podSelector:
    matchLabels:
      app: brain-api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ambassador
      ports:
        - protocol: TCP
          port: 80
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: ai-defense
        - namespaceSelector:
            matchLabels:
              name: logging
```

### `gateway.yaml` (Ambassador Mapping)
```yaml
apiVersion: getambassador.io/v2
kind: Mapping
metadata:
  name: brain-api-mapping
spec:
  prefix: /brain/
  host: ai.example.com
  service: brain-api.default.svc.cluster.local:80
  timeout_ms: 30000
```

---

## 4. Security Testing Flow

1. **Ingress JWT Validation**  
   - _Test:_ Send requests with invalid JWT → Ambassador returns `401`.  
   - _Tools:_ `curl -H "Authorization: Bearer invalid" https://ai.example.com/brain/health`

2. **mTLS Enforcement**  
   - _Test:_ Pod‑to‑pod HTTP without Envoy → connection refused.  
   - _Tools:_ `openssl s_client -connect pod-ip:port`

3. **OPA/Gatekeeper Policies**  
   - _Test:_ Deploy a pod violating the Rego policy → admission denied.  
   - _Tools:_ `kubectl apply -f invalid-deployment.yaml`

4. **Egress Control**  
   - _Test:_ Attempt external API call from pod → should be blocked.  
   - _Tools:_ `kubectl exec -it brain-api -- curl http://example.com`

5. **IRSA Scoping**  
   - _Test:_ Within `brain-api` pod, `aws s3 ls` → `AccessDenied`.  
   - _Tools:_ AWS CLI inside pod

6. **SIEM Logging**  
   - _Test:_ Simulate failed login → verify log in ELK/Splunk.  
   - _Tools:_ Search `ERROR` entries in SIEM dashboard

---

## 5. Recommended Open‑Source & AWS Tools

| Purpose              | Tool                                    | Link                                               |
|----------------------|-----------------------------------------|----------------------------------------------------|
| Ingress Gateway      | Ambassador Edge Stack                   | https://www.getambassador.io                       |
| Service Mesh         | Envoy / Istio / AWS App Mesh            | https://www.envoyproxy.io                          |
| Policy Enforcement   | Open Policy Agent / Gatekeeper          | https://www.openpolicyagent.org                    |
| IAM Pod Roles        | AWS IRSA                                | https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html |
| Secret Management    | Kubernetes Secrets / HashiCorp Vault    | https://www.vaultproject.io                        |
| Model Inference      | AWS Bedrock                             | https://aws.amazon.com/bedrock/                    |
| Runtime Protection   | Falco / Datadog AI Security             | https://falco.org, https://www.datadoghq.com       |
| Logging & Metrics    | Fluent Bit / Prometheus / Grafana       | https://fluentbit.io, https://prometheus.io        |
| Network Policy       | Calico                                  | https://projectcalico.org                          |

---
