

# ArgoCD & Kubernetes CLI Cheat Sheet

This cheat sheet covers common ArgoCD operations as well as complementary Kubernetes commands useful during ArgoCD usage. 
It includes commands for creating, deleting, syncing, and listing ArgoCD applications along with helpful Kubernetes tips.

---

## ArgoCD CLI Commands

### Application Management

- **Create an Application**

  ```bash
  argocd app create wordpress-beta \
    --repo https://github.com/zzzz/argocd-example-apps.git \
    --path wordpress-beta \
    --dest-server https://kubernetes.default.svc \
    --dest-namespace wordpress \
    --sync-policy automated
  ```

- **List Applications**

  ```bash
  argocd app list
  ```

- **Sync an Application**

  ```bash
  argocd app sync wordpress-beta
  ```

- **Delete an Application**

  ```bash
  argocd app delete wordpress-beta --cascade
  ```

---

## Kubernetes (`kubectl`) Cheat Sheet

### Working with Pods

- **List Pod Names (using jsonpath and range):**

  ```bash
  kubectl get po -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
  ```

- **List Pods with Container Images:**

  ```bash
  kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}:{range .spec.containers[*]}{.image}{", "}{end}{"\n"}{end}'
  ```

- **Clean Up Pods That Are Not Running (e.g., Terminated):**

  ```bash
  kubectl get po --field-selector=status.phase!=Running \
    -o custom-columns=":metadata.name" --no-headers | xargs kubectl delete po
  ```

### Working with Nodes

- **List Node Names and CPU Capacity:**

  ```bash
  kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.capacity.cpu}{"\n"}{end}'
  ```

- **Custom Columns for Node Info:**

  ```bash
  kubectl get nodes -o custom-columns="NODE:.metadata.name,CPU:.status.capacity.cpu"
  ```

### Working with Services and Endpoints

- **Get Service External IP and Port:**

  ```bash
  EXT_IP=$(kubectl get svc hello-server -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')
  EXT_PORT=$(kubectl get svc hello-server -o=jsonpath='{.spec.ports[0].port}')
  echo "$EXT_IP:$EXT_PORT"
  ```

### Context and Namespace Commands

- **Get Current Context:**

  ```bash
  kubectl config view -o=jsonpath='{.current-context}'
  ```

- **List All Contexts:**

  ```bash
  kubectl config get-contexts -o=name | sort -n
  ```

- **Set Namespace for Current Context:**

  ```bash
  kubectl config set-context --current --namespace=kube-system
  ```

- **Switch Context:**

  ```bash
  kubectl config use-context <cluster_name_in_kubeconfig>
  ```

### API Resources and Discovery

- **List Supported API Versions:**

  ```bash
  kubectl api-versions | sort
  ```

- **List API Resources (Sorted by Name):**

  ```bash
  kubectl api-resources --sort-by=name
  ```

- **Explain Resource Details:**

  ```bash
  kubectl explain deployment --api-version=apps/v1 --recursive
  ```

- **List Resources Under a Specific API Group:**

  ```bash
  kubectl api-resources --api-group=networking.k8s.io
  ```

### Working with Metrics

- **Show Top Pods Sorted by CPU:**

  ```bash
  kubectl top pods --sort-by=cpu --no-headers
  ```

- **Show Top Pods (Container Memory Usage):**

  ```bash
  kubectl top pods --containers --sort-by=memory
  ```

- **Fetch Node Metrics (JSON):**

  ```bash
  kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes | jq -C .
  ```

### RBAC and Access Checks

- **Check Allowed Actions for a Service Account:**

  ```bash
  kubectl auth can-i --list --as system:serviceaccount:<namespace>:<serviceaccount>
  ```

- **List What a User/Group Can Do:**

  ```bash
  kubectl auth can-i get crd
  ```

- **Using Krew Plugins for RBAC Lookup (if installed):**

  ```bash
  kubectl rbac-lookup velero -o wide
  kubectl who-can create customresourcedefinition
  ```

---

## Script Examples

### Remove ArgoCD Applications Finalizer

Sometimes, a stuck finalizer can block deletion. Use the script below to remove finalizers from ArgoCD applications.

```bash
#!/usr/bin/env bash
APPS=$(kubectl -n argocd get app -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
for app in $APPS; do
  echo "Patching finalizers from app: $app"
  kubectl patch app/$app --type json \
    --patch='[{"op": "remove", "path": "/metadata/finalizers"}]'
done
```

### Deploying ArgoCD via Helm on a KIND Cluster

A sample script to deploy a KIND cluster, ingress-nginx, and ArgoCD using the `argo-helm` chart:

```bash
#!/usr/bin/env bash
set -e

# CONSTANTS
readonly KIND_IMAGE=kindest/node:v1.24.4
readonly CLUSTER_NAME=argo

# Create KIND Cluster
kind create cluster --name "$CLUSTER_NAME" --image "$KIND_IMAGE" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - containerPort: 80
        hostPort: 80
        protocol: TCP
      - containerPort: 443
        hostPort: 443
        protocol: TCP
EOF

# Deploy ingress-nginx
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

sleep 15

kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s

# Deploy ArgoCD using Helm
helm upgrade --install --wait --timeout 15m --atomic --namespace argocd \
  --create-namespace --repo https://argoproj.github.io/argo-helm \
  argocd argo-cd --values - <<EOF
dex:
  enabled: false
redis:
  enabled: true
redis-ha:
  enabled: false
repoServer:
  serviceAccount:
    create: true
server:
  config:
    resource.compareoptions: |
      ignoreAggregatedRoles: true
      ignoreResourceStatusField: all
    url: http://localhost/argocd
    application.instanceLabelKey: argocd.argoproj.io/instance
  extraArgs:
    - --insecure
    - --rootpath
    - /argocd
  ingress:
    annotations:
      kubernetes.io/ingress.class: nginx
      cert-manager.io/cluster-issuer: ca-issuer
    enabled: true
    paths:
      - /argocd
EOF

# Display ArgoCD Initial Admin Password
ARGOCD_PASSWORD=$(kubectl -n argocd get secret \
  argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)

echo "---------------------------------------------------------------------------------"
echo "ArgoCD is running and available at http://localhost/argocd"
echo "Log in with username: admin and password: $ARGOCD_PASSWORD"
```

---

## Useful Resources

- **ArgoCD Documentation:**  
  [https://argo-cd.readthedocs.io](https://argo-cd.readthedocs.io)

- **Kubernetes CLI Reference:**  
  [https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)

- **Kubectl Cheat Sheet:**  
  [Kubernetes Cheat Sheet](https://kubernetes.io/docs/user-guide/kubectl-cheatsheet/)

- **Krew Plugin Index:**  
  [https://krew.sigs.k8s.io/plugins/](https://krew.sigs.k8s.io/plugins/)

---

