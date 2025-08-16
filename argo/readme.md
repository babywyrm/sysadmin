
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

Excellent — let’s merge **Day-2 Operations** with a full **Security & Compliance Hardening** section.
This turns your cheat sheet into a **production + SecOps guide** that’s battle-ready for both operations and security teams.

---

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

---

# ✅ Wrap-Up

With this extension, your cheat sheet now includes:

* **ArgoCD & kubectl basics**
* **Day-2 ops & incident response**
* **Secrets rotation & disaster recovery**
* **Security hardening (RBAC, SSO, GitOps security)**
* **Compliance (CIS, Vault, appProjects, auditing)**


