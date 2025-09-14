```
src/
├── main/
│   ├── java/
│   │   └── com/
│   │       └── mycompany/
│   │           └── banking/
│   │               ├── UserServiceApplication.java
│   │               ├── config/
│   │               │   ├── ZeroTrustSecurityConfig.java
│   │               │   ├── ServiceClientConfig.java
│   │               │   └── AwsConfig.java
│   │               ├── controller/
│   │               │   ├── UserController.java
│   │               │   └── AccountController.java
│   │               ├── service/
│   │               │   ├── UserService.java
│   │               │   ├── ZeroTrustValidator.java
│   │               │   └── AwsCredentialsService.java
│   │               ├── security/
│   │               │   ├── SpiffeJwtDecoder.java
│   │               │   ├── SessionLifecycleManager.java
│   │               │   └── SpiffeX509ContextHolder.java
│   │               ├── dto/
│   │               │   ├── UserDto.java
│   │               │   ├── TransferRequest.java
│   │               │   ├── TransferResponse.java
│   │               │   └── RequestContext.java
│   │               ├── entity/
│   │               │   └── User.java
│   │               ├── repository/
│   │               │   └── UserRepository.java
│   │               └── exception/
│   │                   ├── UserNotFoundException.java
│   │                   ├── InsufficientFundsException.java
│   │                   └── TransferException.java
│   └── resources/
│       ├── application.yml
│       ├── application-k8s.yml
│       └── application-local.yml
└── test/
    └── java/
        └── com/
            └── mycompany/
                └── banking/
                    ├── integration/
                    │   └── UserControllerIntegrationTest.java
                    └── unit/
                        ├── UserServiceTest.java
                        └── ZeroTrustValidatorTest.java


```



Perfect — let’s write your **README SPIFFE setup section** as if a new team member is coming in fresh, so they clearly know how to enable SPIFFE/SPIRE for their Spring Boot microservices inside **AWS EKS**. 🚀  

---

# 🔑 Setting Up **SPIFFE/SPIRE** in EKS for Spring Microservices

This section explains how to configure **SPIFFE identities** for your services in an EKS cluster.  
It walks through **why**, **what**, and **how** so that new engineers don’t drown in YAML.  

---

## 🌍 What is SPIFFE/SPIRE?

- **SPIFFE (Secure Production Identity Framework for Everyone)**: A standard that defines how workloads get cryptographically verifiable identities (SPIFFE IDs like `spiffe://bank-a/user-service`)
- **SPIRE (SPIFFE Runtime Environment)**: The implementation of SPIFFE we deploy in Kubernetes. It:
  - Issues **short-lived certificates (SVIDs)** to workloads
  - Attests workloads using Kubernetes "selectors" (namespace, service account, pod labels)
  - Rotates and manages keys transparently
  - Acts as the **root of trust** in your cluster

Together, SPIFFE/SPIRE replaces **static service accounts, secrets, or tokens** — giving us **zero trust identity** at runtime.

---

## 🧠 Logical Flow of Identities

1. **SPIRE Server**: root authority (the Cluster CA for workload identities)  
2. **SPIRE Agent**: runs as a DaemonSet on every node, talks to SPIRE Server  
3. **Pod**: talks to its local SPIRE Agent over a Unix domain socket  
4. **Agent issues SVID** = X.509 certificate bound to a SPIFFE ID (like `spiffe://bank-a/user-service`)  
5. **Sidecars** (Istio Envoy, Spring mTLS client) use this SVID for:  
   - Mutual TLS between services  
   - Authenticating to AWS services (via IRSA mapping)  
   - Enforcing access policies  

---

## ⚙️ Setup in AWS EKS (Step-by-Step)

### 1. **Install SPIRE Server & Agent**

Apply Helm charts or YAML manifests from SPIRE’s release. Example:

```bash
kubectl create namespace spire

helm repo add spiffe https://spiffe.github.io/helm-charts
helm install spire spiffe/spire --namespace spire
```

This deploys:
- `spire-server`: StatefulSet (holds trust domain, root keypair)
- `spire-agent`: DaemonSet (runs on all worker nodes, issues SVIDs)

### 2. **Define the Trust Domain**

Every cluster needs a trust domain (like an email domain for services).

In `spire-server` ConfigMap:

```yaml
trust_domain: "mycompany.internal"
server:
  bind_address: "0.0.0.0"
  bind_port: "8081"
  data_dir: "/run/spire/data"
```

This means all workload IDs will look like:

```
spiffe://mycompany.internal/<namespace>/<service>
```

### 3. **Register Workload Identities**

Each service needs a **SPIFFE ID binding** to *selectors* (namespace, service account, labels):

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: SpiffeID
metadata:
  name: user-service
  namespace: bank-a
spec:
  spiffeId: spiffe://mycompany.internal/bank-a/user-service
  parentId: spiffe://mycompany.internal/spire/agent/k8s-workload
  selector:
    - k8s:ns:bank-a
    - k8s:sa:user-service
    - k8s:pod-label:app:user-service
```

> 👆 This says: *Any pod in namespace `bank-a` using ServiceAccount `user-service` with label `app=user-service` will automatically get the identity `spiffe://mycompany.internal/bank-a/user-service`.*

---

### 4. **Mount the SPIRE Agent Socket in Pods**

In your Kubernetes **Deployment**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
  namespace: bank-a
spec:
  template:
    spec:
      serviceAccountName: user-service
      containers:
      - name: user-service
        image: 123456789012.dkr.ecr.us-west-2.amazonaws.com/user-service:1.0.0
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /tmp/spire-agent/public
          readOnly: true
      volumes:
      - name: spire-agent-socket
        csi:
          driver: "csi.spiffe.io"
          readOnly: true
```

This mounts the SPIRE agent’s Unix socket, allowing the Spring Boot service (and Istio sidecar) to fetch its SVID.

---

### 5. **Configure Spring Boot to Use SPIFFE**

In `application-k8s.yml`:

```yaml
spiffe:
  trust-domain: mycompany.internal
  socket-path: /tmp/spire-agent/public/api.sock
```

Your Spring app picks its SPIFFE ID and certs at runtime for:
- **Inbound requests**: Verify caller SPIFFE ID  
- **Outbound calls**: Authenticate with its own SPIFFE mTLS cert  

---

### 6. **Integrate with Istio**

Tell Istio to use SPIRE:
- Configure Istio CA to plug into SPIRE Agent
- All sidecars get SVIDs as their cert source
- Enforce **mTLS mesh-wide**:
  ```bash
  istioctl install -f istio-spire-config.yaml
  kubectl apply -f peer-authentication.yaml
  ```
- Now **service-to-service calls require SPIFFE certs**

---

### 7. **Tie to AWS Pod Identities (IRSA Integration)**

- SPIFFE ID → IAM Role mapping (via custom webhook or OPA policy)
- Example: `spiffe://mycompany.internal/bank-a/user-service` ↔ `arn:aws:iam::123456789012:role/BankAUserServiceRole`
- This IAM Role then grants:
  - RDS IAM authentication
  - Secrets Manager / Parameter Store access
- **No static AWS keys inside pods.**

---

## 🔑 Day-in-the-life of a Request

1. User hits API → Ambassador validates → attaches internal JWT with SPIFFE claim  
2. Istio sidecar on `user-service` pod requests SVID from SPIRE Agent  
3. SPIRE Agent verifies pod selectors → issues short-lived cert for `spiffe://bank-a/user-service`  
4. UserService sidecar connects to AccountService → both present SPIFFE IDs → Istio verifies mTLS handshake  
5. If UserService needs DB creds → it presents its SPIFFE ID → Pod Identity maps it to IAM → RDS IAM token issued → DB access granted  

All without a **single static password** 👌

---

## ✅ Key Takeaways for Developers

- **You don’t create keys** → SPIRE handles certs and rotation  
- **SPIFFE IDs replace usernames/passwords** → treat them like “service emails”  
- **Namespace + ServiceAccount + label = Identity**  
- **Spring Security + SPIFFE** → lets you write simple `@PreAuthorize` rules against cryptographic identities  

---

📘 Short version for README:

> **SPIFFE/SPIRE gives each Spring service a real, cryptographic identity inside EKS.**  
> We deploy SPIRE server/agents, register each workload with selectors, mount the SPIRE agent socket into pods, and configure Spring Boot + Istio to use those identities for mTLS and authorization.  
> This removes all static creds and makes service-to-service trust based solely on SPIFFE IDs.

---
