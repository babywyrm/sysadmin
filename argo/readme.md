
# ArgoCD & Kubernetes CLI Cheat Sheet (..Extended..)

This cheat sheet covers common ArgoCD operations and complementary Kubernetes commands.
It includes **application lifecycle, troubleshooting, security, GitOps patterns, and useful scripts**.

---

## ArgoCD CLI Commands

### Application Management

* **Create an Application (with auto-sync & pruning):**

  ```bash
  argocd app create wordpress-beta \
    --repo https://github.com/zzzz/argocd-example-apps.git \
    --path wordpress-beta \
    --dest-server https://kubernetes.default.svc \
    --dest-namespace wordpress \
    --sync-policy automated \
    --auto-prune
  ```

* **Update Application Source (change branch or path):**

  ```bash
  argocd app set wordpress-beta \
    --repo https://github.com/zzzz/argocd-example-apps.git \
    --revision main \
    --path wordpress-prod
  ```

* **Refresh Application Cache:**

  ```bash
  argocd app refresh wordpress-beta
  ```

* **Rollback to Previous Revision:**

  ```bash
  argocd app rollback wordpress-beta 2
  ```

* **Force Sync (ignores differences, replaces resources):**

  ```bash
  argocd app sync wordpress-beta --force
  ```

---

## ArgoCD User & Cluster Management

* **Login to ArgoCD:**

  ```bash
  argocd login argocd.example.com --username admin --password <password>
  ```

* **List ArgoCD Clusters:**

  ```bash
  argocd cluster list
  ```

* **Add New Cluster:**

  ```bash
  argocd cluster add my-cluster-context
  ```

* **Add User (local account):**

  Edit `argocd-cm` ConfigMap:

  ```bash
  kubectl -n argocd edit cm argocd-cm
  ```

  Add:

  ```yaml
  accounts.myuser: apiKey, login
  ```

  Then set password:

  ```bash
  argocd account update-password
  ```

---

## Troubleshooting & Maintenance

* **View Application Diff:**

  ```bash
  argocd app diff wordpress-beta
  ```

* **Check App Health & Sync Status:**

  ```bash
  argocd app get wordpress-beta
  ```

* **Check ArgoCD Logs:**

  ```bash
  kubectl -n argocd logs deploy/argocd-server
  kubectl -n argocd logs deploy/argocd-repo-server
  ```

* **Remove Stuck Finalizers (scripted):**

  ```bash
  kubectl patch app <app-name> \
    --type json -p='[{"op": "remove", "path": "/metadata/finalizers"}]'
  ```

---

## Kubernetes (`kubectl`) Cheat Sheet

### Pod Management

* **Exec into Pod:**

  ```bash
  kubectl exec -it <pod> -- /bin/sh
  ```

* **Stream Logs (follow, all containers):**

  ```bash
  kubectl logs -f <pod> --all-containers
  ```

* **Restart All Pods in a Deployment:**

  ```bash
  kubectl rollout restart deployment <deployment-name>
  ```

### Deployment & Rollouts

* **Check Rollout Status:**

  ```bash
  kubectl rollout status deployment <deployment-name>
  ```

* **Undo Deployment:**

  ```bash
  kubectl rollout undo deployment <deployment-name>
  ```

* **Pause / Resume Rollout:**

  ```bash
  kubectl rollout pause deployment <deployment-name>
  kubectl rollout resume deployment <deployment-name>
  ```

### Security & RBAC

* **Check What a User Can Do:**

  ```bash
  kubectl auth can-i list pods --as user@example.com
  ```

* **Impersonate ServiceAccount:**

  ```bash
  kubectl auth can-i get pods --as system:serviceaccount:default:my-sa
  ```

* **View ClusterRoles:**

  ```bash
  kubectl get clusterrole | grep admin
  ```

### Debugging

* **Run Debug Pod with BusyBox:**

  ```bash
  kubectl run tmp-shell --rm -i --tty \
    --image=busybox -- /bin/sh
  ```

* **Port-Forward a Service:**

  ```bash
  kubectl port-forward svc/argocd-server -n argocd 8080:443
  ```

* **Describe Events for a Pod:**

  ```bash
  kubectl describe pod <pod-name>
  kubectl get events --sort-by=.metadata.creationTimestamp
  ```

---

## GitOps Best Practices

* **Label Applications with Owner:**

  ```bash
  argocd app set wordpress-beta --label owner=team-a
  ```

* **Sync Wave Ordering (in manifests):**

  ```yaml
  metadata:
    annotations:
      argocd.argoproj.io/sync-wave: "1"
  ```

* **Ignore Differences (ConfigMap, Secrets):**

  ```yaml
  argocd.argoproj.io/compare-options: IgnoreExtraneous
  argocd.argoproj.io/sync-options: Prune=false
  ```

---

## Advanced Scripts

### Backup ArgoCD Config & Apps

```bash
#!/usr/bin/env bash
kubectl -n argocd get secrets,cm,apps -o yaml > argocd-backup-$(date +%F).yaml
```

### Bulk Sync All Apps

```bash
#!/usr/bin/env bash
for app in $(argocd app list -o name); do
  argocd app sync "$app"
done
```

---

## Useful Resources

* **ArgoCD Docs:** [https://argo-cd.readthedocs.io](https://argo-cd.readthedocs.io)
* **ArgoCD GitHub:** [https://github.com/argoproj/argo-cd](https://github.com/argoproj/argo-cd)
* **Kubectl Reference:** [https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)
* **Krew Plugins:** [https://krew.sigs.k8s.io/plugins/](https://krew.sigs.k8s.io/plugins/)


##
##



# 🚀 ArgoCD & Kubernetes CLI Cheat Sheet (Production + SecOps)

This cheat sheet covers **ArgoCD operations**, **Kubernetes essentials**, **Day-2 ops incident response**, and **security hardening & compliance**.
Think of it as a **field playbook** for running ArgoCD safely in production.

---


## 🔧 Day-2 Operations & Incident Response  (..Beta..)

### Sync & Drift Recovery

* **Force Re-Sync All Apps:**

  ```bash
  for app in $(argocd app list -o name); do
    argocd app sync "$app" --force
  done
  ```

* **Detect Drift:**

  ```bash
  argocd app diff <app-name>
  ```

* **Clear Stuck Syncs (restart controller):**

  ```bash
  kubectl -n argocd delete pod -l app.kubernetes.io/name=argocd-application-controller
  ```

---

### ArgoCD Component Recovery

* **Restart Core Components:**

  ```bash
  kubectl -n argocd rollout restart deploy argocd-server
  kubectl -n argocd rollout restart deploy argocd-repo-server
  kubectl -n argocd rollout restart deploy argocd-application-controller
  ```

* **Check Git Repo Health:**

  ```bash
  argocd repo list
  argocd repo validate-revision https://github.com/org/repo.git HEAD
  ```

---

### Secrets & Credential Rotation

* **Rotate Admin Password:**

  ```bash
  kubectl -n argocd delete secret argocd-initial-admin-secret
  kubectl -n argocd rollout restart deploy argocd-server
  ```

* **Rotate ServiceAccount Tokens:**

  ```bash
  kubectl delete secret $(kubectl get sa my-sa -o jsonpath='{.secrets[0].name}') -n <namespace>
  ```

* **Update Git Repo Credentials:**

  ```bash
  argocd repo add https://github.com/org/repo.git --username <user> --password <token>
  ```

---

### Incident Playbook

* **Cluster Node Down:**

  ```bash
  kubectl cordon <node>
  kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
  ```

* **CrashLoopBackOff Debug:**

  ```bash
  kubectl describe pod <pod>
  kubectl logs <pod> -c <container>
  ```

* **API Server Down (bypass ingress):**

  ```bash
  kubectl -n argocd port-forward svc/argocd-server 8080:443
  ```

---

### Observability & Audit

* **Audit App History:**

  ```bash
  argocd app history <app>
  ```

* **Audit Logs:**

  ```bash
  kubectl -n argocd logs deploy/argocd-server | grep "audit"
  ```

* **Get All Errors:**

  ```bash
  argocd app list | grep -E "OutOfSync|Degraded"
  ```

---

### Backup & Disaster Recovery

* **Backup All ArgoCD State:**

  ```bash
  kubectl -n argocd get cm,secrets,apps -o yaml > argocd-backup.yaml
  ```

* **Restore:**

  ```bash
  kubectl apply -f argocd-backup.yaml
  ```

* **Remove Stuck Finalizers:**

  ```bash
  kubectl patch app <app> --type=json \
    -p='[{"op":"remove","path":"/metadata/finalizers"}]'
  ```

---

## 🔐 Security & Compliance Hardening

### Access Control & RBAC

* **Check User Permissions:**

  ```bash
  kubectl auth can-i list pods --as user@example.com
  ```

* **Limit ArgoCD ServiceAccounts:**

  * Bind only **namespaces it manages**.
  * Avoid `cluster-admin` unless absolutely necessary.

* **Impersonate for Testing:**

  ```bash
  kubectl auth can-i get pods --as system:serviceaccount:argocd:argocd-server
  ```

---

### ArgoCD Authentication

* **SSO Integration (Dex / OIDC / SAML):**
  In `argocd-cm` ConfigMap:

  ```yaml
  dex.config: |
    connectors:
    - type: oidc
      id: okta
      name: Okta
      config:
        issuer: https://<okta-domain>/oauth2/default
        clientID: $OKTA_CLIENT_ID
        clientSecret: $OKTA_CLIENT_SECRET
        redirectURI: https://argocd.example.com/api/dex/callback
  ```

* Disable local admin after onboarding SSO:

  ```bash
  kubectl -n argocd patch secret argocd-secret -p '{"stringData": {"admin.password": null}}'
  ```

---

### GitOps Security

* **Least Privilege Git Repos:**

  * Use **deploy keys** (read-only).
  * Separate staging vs production repos.
  * Avoid using personal access tokens (PATs).

* **Enforce Signed Commits / Tags:**

  ```bash
  git config --global commit.gpgsign true
  ```

* **Pin App Revisions:**

  ```bash
  argocd app set <app> --revision v1.2.3
  ```

---

### Cluster & Network Security

* **Namespace Isolation:**
  Deploy ArgoCD in its own namespace with strict NetworkPolicies:

  ```yaml
  kind: NetworkPolicy
  apiVersion: networking.k8s.io/v1
  metadata:
    name: argocd-deny-all
    namespace: argocd
  spec:
    podSelector: {}
    policyTypes:
    - Ingress
    - Egress
  ```

* **TLS Enforcement:**

  * Use cert-manager with Let’s Encrypt or internal CA.
  * Disable `--insecure` flags in production.

* **Audit Logs Enabled:**
  Forward logs to **SIEM** for compliance.

---

### Compliance Best Practices

* **CIS Benchmark Alignment:**

  * Ensure ArgoCD pods don’t run as root.
  * Apply PodSecurity or PSPs.

* **Secret Management:**

  * Integrate with **Vault** or **Sealed Secrets**.
  * Avoid plaintext Git secrets.

* **RBAC Reviews (Quarterly):**

  ```bash
  kubectl get clusterrolebindings -o wide
  kubectl get rolebindings -A -o wide
  ```

* **Multi-Tenancy:**

  * Use `appProject` objects to limit what teams can deploy.
  * Example:

    ```yaml
    kind: AppProject
    metadata:
      name: team-a
    spec:
      destinations:
      - namespace: team-a
        server: https://kubernetes.default.svc
      sourceRepos:
      - https://github.com/org/team-a-apps.git
    ```




## 📊 ArgoCD + Kubernetes Playbook (All-in-One Mermaid Diagram)

```mermaid
flowchart LR
  classDef argo fill:#e3f2fd,stroke:#1e88e5,color:#0d47a1,stroke-width:1.5px;
  classDef k8s fill:#e8f5e9,stroke:#43a047,color:#1b5e20,stroke-width:1.5px;
  classDef sec fill:#ffebee,stroke:#e53935,color:#b71c1c,stroke-width:1.5px;
  classDef infra fill:#ede7f6,stroke:#5e35b1,color:#311b92,stroke-width:1.5px;
  classDef svc fill:#fff3e0,stroke:#ef6c00,color:#e65100,stroke-width:1.5px;
  classDef obs fill:#e0f7fa,stroke:#00838f,color:#004d40,stroke-width:1.5px;
  classDef store fill:#f1f8e9,stroke:#33691e,color:#1b5e20,stroke-width:1.5px;
  classDef decision fill:#fff,stroke:#616161,color:#212121,stroke-dasharray:4 2;

  subgraph DEV[Developer Workflow]
    C[Code change] --> PR[Open PR]
    PR --> CI[CI checks]
    CI --> M[Merge/Tag]
  end

  subgraph GIT[Git Repository]
    M --> REV[Release/Revision]
  end

  subgraph ARGO[ArgoCD Control Plane]
    S[ArgoCD API/Server]:::argo
    R[Repo Server]:::argo
    AC[Application Controller]:::argo
  end

  subgraph NET[Ingress / SSO]
    ING[Ingress Controller]:::infra
    IdP[(OIDC/SAML IdP)]:::sec
  end
  user[User]:::infra -->|/argocd TLS| ING --> S
  S -->|SSO AuthN| IdP

  REV --> R -->|Render Helm/Kustomize/Plain| AC
  S --> AC
  AC -->|Diff desired vs live| L1([ ]):::decision

  subgraph K8S[Kubernetes Cluster]
    API[apiserver]:::k8s
    subgraph TEN[Multi-Tenancy (AppProjects)]
      P[AppProject: team-a]:::svc
      A1[App: service-x]:::k8s --> P
      A2[App: service-y]:::k8s --> P
    end
  end

  L1 -->|OutOfSync| APPLY[Apply/Prune manifests]:::k8s
  L1 -->|InSync| NOOP[No-op]:::k8s

  subgraph POLICY[Admission / Supply Chain]
    OPA[Gatekeeper/OPA<br/>Policies]:::sec
    SIG[Image/Commit Signing<br/>(Cosign/GPG)]:::sec
  end

  APPLY --> API --> OPA
  SIG -. verify .- OPA
  OPA -->|deny if non-compliant| DENY((DENY)):::sec
  OPA -->|admit if compliant| OK((ADMIT)):::k8s
  OK --> RUN[Workloads running]:::k8s
  RUN --> AC
  AC --> S

  subgraph DAY2[Day-2 Ops & Incident Response]
    D0[Detect: Degraded/OutOfSync]:::obs
    D1{Render OK?<br/>helm/kustomize}:::decision
    D2{CRD/Dependency missing?}:::decision
    D3{RBAC forbidden?}:::decision
    D4{Rollout failing?}:::decision
    D5{Manual drift?}:::decision
    FIX_RENDER[Fix values/templates<br/>Update Git & retry]:::svc
    FIX_ORDER[Use sync-waves / install CRDs]:::svc
    FIX_RBAC[Adjust Roles/Projects<br/>kubectl auth can-i ...]:::svc
    FIX_ROLLOUT[Describe/logs/undo<br/>Update img/config]:::svc
    FORCE[Force sync / prune]:::svc
    RESTART[Restart components:<br/>server/repo/controller]:::svc
  end

  AC --> D0
  D0 --> D1
  D1 -- No --> FIX_RENDER --> AC
  D1 -- Yes --> D2
  D2 -- Yes --> FIX_ORDER --> AC
  D2 -- No --> D3
  D3 -- Yes --> FIX_RBAC --> AC
  D3 -- No --> D4
  D4 -- Yes --> FIX_ROLLOUT --> AC
  D4 -- No --> D5
  D5 -- Yes --> FORCE --> AC
  D5 -- No --> RESTART --> AC

  subgraph OBS[Observability & Audit]
    H[App history<br/>argocd app history]:::obs
    E[Events/logs<br/>kubectl logs/get events]:::obs
    SIEM[(SIEM / Audit sink)]:::obs
  end
  S --> H
  K8S --> E
  H --> SIEM
  E --> SIEM

  subgraph BDR[Backup & Disaster Recovery]
    BK[Backup cm,secrets,apps<br/>kubectl get ... > backup.yaml]:::store
    RS[Restore apply -f backup.yaml]:::store
  end
  S --> BK
  BK --> RS
  RS --> AC

  subgraph ROT[Secret & Credential Rotation]
    R0[Choose rotation window]:::svc
    R1{Type? Git / Cluster / App Secret}:::decision
    RG[New deploy key/token<br/>argocd repo add/replace]:::svc
    RK[New kubeconfig/SA<br/>argocd cluster add]:::svc
    RA[Update Vault/SealedSecret<br/>commit encrypted]:::svc
    RV[Validate access & sync]:::svc
    RAUD[Audit + close]:::obs
  end

  R0 --> R1
  R1 -- Git --> RG --> RV --> RAUD
  R1 -- Cluster --> RK --> RV --> RAUD
  R1 -- App Secret --> RA --> RV --> RAUD
  RV --> AC

  note over ARGO,NET: Ingress → argocd-server only\nSSO via IdP\nEgress limits: repo-server → Git, controller → apiserver
  note right of POLICY: Enforce image/commit signing\nBlock privileged pods / disallowed registries
  note bottom of TEN: AppProjects limit sourceRepos/destinations\nTeam blast radius control

```

##
##




## 🔧 Day-2 Operations & Incident Response

### Sync & Drift Recovery
```bash
# Force Re-Sync All Apps
for app in $(argocd app list -o name); do
  argocd app sync "$app" --force
done

# Detect Drift
argocd app diff <app-name>

# Clear Stuck Syncs (restart controller)
kubectl -n argocd delete pod -l app.kubernetes.io/name=argocd-application-controller
````

---

### ArgoCD Component Recovery

```bash
# Restart Core Components
kubectl -n argocd rollout restart deploy argocd-server
kubectl -n argocd rollout restart deploy argocd-repo-server
kubectl -n argocd rollout restart deploy argocd-application-controller

# Check Repo Health
argocd repo list
argocd repo validate-revision https://github.com/org/repo.git HEAD
```

---

### Secrets & Credential Rotation

```bash
# Rotate Admin Password
kubectl -n argocd delete secret argocd-initial-admin-secret
kubectl -n argocd rollout restart deploy argocd-server

# Rotate ServiceAccount Tokens
kubectl delete secret $(kubectl get sa my-sa -o jsonpath='{.secrets[0].name}') -n <namespace>

# Update Git Repo Credentials
argocd repo add https://github.com/org/repo.git --username <user> --password <token>
```

---

### Incident Playbook

```bash
# Cluster Node Down
kubectl cordon <node>
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data

# CrashLoopBackOff Debug
kubectl describe pod <pod>
kubectl logs <pod> -c <container>

# API Server Down (bypass ingress)
kubectl -n argocd port-forward svc/argocd-server 8080:443
```

---

### Observability & Audit

```bash
# Audit App History
argocd app history <app>

# Audit Logs
kubectl -n argocd logs deploy/argocd-server | grep "audit"

# Get All Errors Across Apps
argocd app list | grep -E "OutOfSync|Degraded"
```

---

### Backup & Disaster Recovery

```bash
# Backup All State
kubectl -n argocd get cm,secrets,apps -o yaml > argocd-backup.yaml

# Restore
kubectl apply -f argocd-backup.yaml

# Remove Stuck Finalizers
kubectl patch app <app> --type=json \
  -p='[{"op":"remove","path":"/metadata/finalizers"}]'
```

---

## 🔐 Security & Compliance Hardening

### Access Control & RBAC

```bash
# Check User Permissions
kubectl auth can-i list pods --as user@example.com

# Impersonate ServiceAccount for Testing
kubectl auth can-i get pods --as system:serviceaccount:argocd:argocd-server

# Review ClusterRoles
kubectl get clusterrole | grep admin
```

* Avoid `cluster-admin` for ArgoCD.
* Limit ArgoCD ServiceAccounts to only namespaces they manage.

---

### ArgoCD Authentication

**Enable SSO via Dex / OIDC / SAML:**

```yaml
dex.config: |
  connectors:
  - type: oidc
    id: okta
    name: Okta
    config:
      issuer: https://<okta-domain>/oauth2/default
      clientID: $OKTA_CLIENT_ID
      clientSecret: $OKTA_CLIENT_SECRET
      redirectURI: https://argocd.example.com/api/dex/callback
```

**Disable local admin after onboarding SSO:**

```bash
kubectl -n argocd patch secret argocd-secret -p '{"stringData": {"admin.password": null}}'
```

---

### GitOps Security

* Use **deploy keys** (read-only) for repos.
* Separate staging vs production repos.
* Avoid personal access tokens (PATs).
* Enforce signed commits/tags:

```bash
git config --global commit.gpgsign true
```

* Pin App Revisions:

```bash
argocd app set <app> --revision v1.2.3
```

---

### Cluster & Network Security

**Namespace Isolation (deny-all by default):**

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: argocd-deny-all
  namespace: argocd
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

* Enforce TLS with cert-manager (Let’s Encrypt or internal CA).
* Disable `--insecure` flags in production.
* Forward ArgoCD logs to a SIEM for compliance.

---

### Compliance Best Practices

* Align with **CIS Benchmarks** (no root pods, enforce PodSecurity).
* Manage secrets via **Vault** or **Sealed Secrets**.
* Audit RBAC quarterly:

```bash
kubectl get clusterrolebindings -o wide
kubectl get rolebindings -A -o wide
```

* Use **AppProjects** to restrict teams:

```yaml
kind: AppProject
metadata:
  name: team-a
spec:
  destinations:
  - namespace: team-a
    server: https://kubernetes.default.svc
  sourceRepos:
  - https://github.com/org/team-a-apps.git
```

---


### 📚 References

* [ArgoCD Docs](https://argo-cd.readthedocs.io)
* [ArgoCD GitHub](https://github.com/argoproj/argo-cd)
* [Kubectl CLI Reference](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)
* [Krew Plugins](https://krew.sigs.k8s.io/plugins/)

```



