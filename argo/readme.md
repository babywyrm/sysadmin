
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

