
## GKE vs EKS Master Command Cheat Sheet

| Action | GKE | EKS |
|---|---|---|
| **CLUSTER MANAGEMENT** | | |
| List clusters | `gcloud container clusters list` | `aws eks list-clusters` |
| Create cluster | `gcloud container clusters create <name> --zone <zone>` | `eksctl create cluster --name <name> --region <region>` |
| Delete cluster | `gcloud container clusters delete <name>` | `eksctl delete cluster --name <name>` |
| Get cluster info | `gcloud container clusters describe <name>` | `aws eks describe-cluster --name <name>` |
| Get kubeconfig | `gcloud container clusters get-credentials <name> --zone <zone>` | `aws eks update-kubeconfig --name <name> --region <region>` |
| List available versions | `gcloud container get-server-config --zone <zone>` | `aws eks describe-addon-versions` |
| **NODE POOLS** | | |
| List node pools | `gcloud container node-pools list --cluster <name>` | `aws eks list-nodegroups --cluster-name <name>` |
| Create node pool | `gcloud container node-pools create <pool> --cluster <name>` | `eksctl create nodegroup --cluster <name>` |
| Delete node pool | `gcloud container node-pools delete <pool> --cluster <name>` | `eksctl delete nodegroup --cluster <name> --name <pool>` |
| Describe node pool | `gcloud container node-pools describe <pool> --cluster <name>` | `aws eks describe-nodegroup --cluster-name <name> --nodegroup-name <pool>` |
| **AUTH / IAM** | | |
| Login | `gcloud auth login` | `aws configure` |
| Set project | `gcloud config set project <project-id>` | `aws configure --profile <profile>` |
| Set default zone | `gcloud config set compute/zone <zone>` | `aws configure set region <region>` |
| Get current context | `kubectl config current-context` | `kubectl config current-context` |
| Switch context | `kubectl config use-context <context>` | `kubectl config use-context <context>` |
| List contexts | `kubectl config get-contexts` | `kubectl config get-contexts` |
| **IMAGES / REGISTRY** | | |
| Auth to registry | `gcloud auth configure-docker` | `aws ecr get-login-password \| docker login ...` |
| List repos | `gcloud artifacts repositories list` | `aws ecr describe-repositories` |
| Tag & push image | `docker tag <img> gcr.io/<project>/<img>` | `docker tag <img> <account>.dkr.ecr.<region>.amazonaws.com/<img>` |
| Create repository | `gcloud artifacts repositories create <name> --repository-format=docker` | `aws ecr create-repository --repository-name <name>` |
| **NETWORKING** | | |
| List firewall rules | `gcloud compute firewall-rules list` | `aws ec2 describe-security-groups` |
| Create firewall rule | `gcloud compute firewall-rules create <name> --allow tcp:<port>` | `aws ec2 authorize-security-group-ingress --group-id <id> ...` |
| List VPCs | `gcloud compute networks list` | `aws ec2 describe-vpcs` |
| List subnets | `gcloud compute networks subnets list` | `aws ec2 describe-subnets` |
| Enable Network Policy | `gcloud container clusters update <name> --enable-network-policy` | Done via `eksctl` config or Calico addon |
| List load balancers | `gcloud compute forwarding-rules list` | `aws elbv2 describe-load-balancers` |
| **STORAGE** | | |
| List disks | `gcloud compute disks list` | `aws ec2 describe-volumes` |
| Create disk | `gcloud compute disks create <name> --size <size>` | `aws ec2 create-volume --size <size> --availability-zone <az>` |
| List storage classes | `kubectl get storageclass` | `kubectl get storageclass` |
| Default storage class | `standard` (GCE Persistent Disk) | `gp2` / `gp3` (EBS) |
| **AUTOSCALING** | | |
| Enable cluster autoscaler | `gcloud container clusters update <name> --enable-autoscaling --min-nodes <n> --max-nodes <n>` | `eksctl scale nodegroup --cluster <name> --nodes-min <n> --nodes-max <n>` |
| Enable HPA | `kubectl autoscale deployment <name> --min <n> --max <n> --cpu-percent <n>` | `kubectl autoscale deployment <name> --min <n> --max <n> --cpu-percent <n>` |
| List HPA | `kubectl get hpa` | `kubectl get hpa` |
| Enable VPA | `kubectl apply -f vpa.yaml` | `kubectl apply -f vpa.yaml` |
| **WORKLOAD IDENTITY / IRSA** | | |
| Enable Workload Identity | `gcloud container clusters update <name> --workload-pool=<project>.svc.id.goog` | `eksctl utils associate-iam-oidc-provider --cluster <name>` |
| Create IAM service account | `gcloud iam service-accounts create <sa-name>` | `aws iam create-role --role-name <name> --assume-role-policy-document ...` |
| Bind IAM role to SA | `gcloud projects add-iam-policy-binding <project> --member serviceAccount:<sa> --role roles/<role>` | `aws iam attach-role-policy --role-name <name> --policy-arn <arn>` |
| Annotate k8s SA | `kubectl annotate serviceaccount <ksa> iam.gke.io/gcp-service-account=<gsa>@<project>.iam.gserviceaccount.com` | `kubectl annotate serviceaccount <ksa> eks.amazonaws.com/role-arn=arn:aws:iam::<account>:role/<role>` |
| Bind k8s SA to GCP SA | `gcloud iam service-accounts add-iam-policy-binding <gsa> --role roles/iam.workloadIdentityUser --member "serviceAccount:<project>.svc.id.goog[<ns>/<ksa>]"` | N/A (handled via OIDC trust policy) |
| **LOGGING / MONITORING** | | |
| View cluster logs | `gcloud logging read "resource.type=k8s_cluster"` | `aws logs describe-log-groups --log-group-name-prefix /aws/eks` |
| Stream pod logs | `kubectl logs -f <pod>` | `kubectl logs -f <pod>` |
| Open monitoring dashboard | GCP Console → Kubernetes Engine → Workloads | AWS Console → EKS → Cluster → Monitoring |
| **HELM** | | |
| Install Helm | `brew install helm` | `brew install helm` |
| Add repo | `helm repo add <name> <url>` | `helm repo add <name> <url>` |
| Update repos | `helm repo update` | `helm repo update` |
| Install chart | `helm install <release> <chart>` | `helm install <release> <chart>` |
| Upgrade release | `helm upgrade <release> <chart>` | `helm upgrade <release> <chart>` |
| Uninstall release | `helm uninstall <release>` | `helm uninstall <release>` |
| List releases | `helm list -A` | `helm list -A` |
| Override values | `helm install <release> <chart> -f values.yaml` | `helm install <release> <chart> -f values.yaml` |
| Dry run | `helm install <release> <chart> --dry-run` | `helm install <release> <chart> --dry-run` |
| **CERT-MANAGER** | | |
| Install cert-manager | `helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set installCRDs=true` | Same |
| List certificates | `kubectl get certificates -A` | `kubectl get certificates -A` |
| List certificate requests | `kubectl get certificaterequests -A` | `kubectl get certificaterequests -A` |
| List issuers | `kubectl get issuers -A` | `kubectl get issuers -A` |
| List cluster issuers | `kubectl get clusterissuers` | `kubectl get clusterissuers` |
| Describe cert (debug) | `kubectl describe certificate <name> -n <namespace>` | `kubectl describe certificate <name> -n <namespace>` |
| DNS01 challenge provider | Google Cloud DNS via Workload Identity | Route53 via IRSA |
| **INGRESS CONTROLLERS** | | |
| Install NGINX Ingress | `helm install ingress-nginx ingress-nginx/ingress-nginx` | Same |
| Native ingress class | `kubernetes.io/ingress.class: "gce"` (GCP HTTP(S) LB) | `kubernetes.io/ingress.class: "alb"` (AWS Load Balancer Controller) |
| List ingresses | `kubectl get ingress -A` | `kubectl get ingress -A` |
| Describe ingress | `kubectl describe ingress <name> -n <namespace>` | `kubectl describe ingress <name> -n <namespace>` |
| Get ingress IP/host | `kubectl get ingress <name> -n <ns> -o jsonpath='{.status.loadBalancer.ingress[0].ip}'` | `kubectl get ingress <name> -n <ns> -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'` |
| **PRIVATE CLUSTER SETUP** | | |
| Create private cluster | `gcloud container clusters create <name> --enable-private-nodes --enable-private-endpoint --master-ipv4-cidr 172.16.0.0/28` | `eksctl create cluster --name <name> --node-private-networking --vpc-private-subnets <subnet-ids>` |
| Authorize master access | `gcloud container clusters update <name> --enable-master-authorized-networks --master-authorized-networks <cidr>` | Done via Security Group rules on API server |
| Enable Cloud NAT (egress) | `gcloud compute routers create <router> --network <vpc>` then `gcloud compute routers nats create <nat> --router <router>` | Done via NAT Gateway in VPC config |
| Enable IAP for access | `gcloud compute backend-services update <svc> --global --iap=enabled` | Use AWS Systems Manager Session Manager or VPN |
| List authorized networks | `gcloud container clusters describe <name> --format='value(masterAuthorizedNetworksConfig)'` | `aws eks describe-cluster --name <name> --query 'cluster.resourcesVpcConfig'` |
| **NAMESPACES & RBAC** | | |
| List namespaces | `kubectl get namespaces` | `kubectl get namespaces` |
| Create namespace | `kubectl create namespace <name>` | `kubectl create namespace <name>` |
| Delete namespace | `kubectl delete namespace <name>` | `kubectl delete namespace <name>` |
| List roles | `kubectl get roles -A` | `kubectl get roles -A` |
| List cluster roles | `kubectl get clusterroles` | `kubectl get clusterroles` |
| List role bindings | `kubectl get rolebindings -A` | `kubectl get rolebindings -A` |
| List cluster role bindings | `kubectl get clusterrolebindings` | `kubectl get clusterrolebindings` |
| Create role binding | `kubectl create rolebinding <name> --clusterrole=<role> --user=<user> -n <ns>` | Same |
| Describe role binding | `kubectl describe rolebinding <name> -n <ns>` | Same |
| Check permissions | `kubectl auth can-i <verb> <resource> --as=<user> -n <ns>` | Same |
| GKE IAM cluster access | `gcloud projects add-iam-policy-binding <project> --member=user:<email> --role=roles/container.developer` | `aws eks create-access-entry --cluster-name <name> --principal-arn <arn>` |
| **SECRET MANAGEMENT** | | |
| List k8s secrets | `kubectl get secrets -A` | `kubectl get secrets -A` |
| Create k8s secret | `kubectl create secret generic <name> --from-literal=key=value` | Same |
| Describe secret | `kubectl describe secret <name> -n <ns>` | Same |
| Decode secret value | `kubectl get secret <name> -o jsonpath='{.data.<key>}' \| base64 -d` | Same |
| Create secret (cloud) | `gcloud secrets create <name> --data-file=<file>` | `aws secretsmanager create-secret --name <name> --secret-string <value>` |
| List secrets (cloud) | `gcloud secrets list` | `aws secretsmanager list-secrets` |
| Get secret value (cloud) | `gcloud secrets versions access latest --secret=<name>` | `aws secretsmanager get-secret-value --secret-id <name>` |
| Sync cloud secrets to k8s | External Secrets Operator or Secret Store CSI Driver | Same |
| **GITOPS — ARGOCD** | | |
| Install ArgoCD | `kubectl create namespace argocd && kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml` | Same |
| Get ArgoCD admin password | `kubectl get secret argocd-initial-admin-secret -n argocd -o jsonpath='{.data.password}' \| base64 -d` | Same |
| Port forward ArgoCD UI | `kubectl port-forward svc/argocd-server -n argocd 8080:443` | Same |
| Install ArgoCD CLI | `brew install argocd` | Same |
| Login via CLI | `argocd login localhost:8080` | Same |
| Add cluster to ArgoCD | `argocd cluster add <context>` | Same |
| Create ArgoCD app | `argocd app create <name> --repo <url> --path <path> --dest-server https://kubernetes.default.svc --dest-namespace <ns>` | Same |
| Sync app | `argocd app sync <name>` | Same |
| List apps | `argocd app list` | Same |
| Get app status | `argocd app get <name>` | Same |
| **GITOPS — FLUX** | | |
| Install Flux CLI | `brew install fluxcd/tap/flux` | Same |
| Bootstrap Flux (GitHub) | `flux bootstrap github --owner=<org> --repository=<repo> --branch=main --path=clusters/<name>` | Same |
| Check Flux status | `flux check` | Same |
| List Flux sources | `flux get sources git` | Same |
| List Flux kustomizations | `flux get kustomizations` | Same |
| List Flux helm releases | `flux get helmreleases -A` | Same |
| Reconcile manually | `flux reconcile kustomization <name>` | Same |
| Suspend reconciliation | `flux suspend kustomization <name>` | Same |
| Resume reconciliation | `flux resume kustomization <name>` | Same |

---

## Key Conceptual Differences

| Concept | GKE | EKS |
|---|---|---|
| Pod identity | Workload Identity (GCP SA annotation) | IRSA (IAM Role via OIDC) |
| Managed node option | Autopilot (fully managed) | Fargate (serverless pods) |
| Native ingress | GCE HTTP(S) Load Balancer | AWS Load Balancer Controller (ALB) |
| Ingress IP format | IP address | Hostname |
| Firewall model | VPC-wide Firewall Rules | Per-resource Security Groups |
| Default storage | GCE Persistent Disk (`standard`) | EBS (`gp2`/`gp3`) |
| Private node egress | Cloud NAT | NAT Gateway |
| Private cluster access | Identity-Aware Proxy (IAP) | SSM Session Manager / VPN |
| DNS01 cert-manager | Cloud DNS via Workload Identity | Route53 via IRSA |
| Secret sync to k8s | External Secrets Operator / CSI Driver | Same |
| Cluster IAM access | `roles/container.developer` etc. | EKS Access Entries + IAM |
| GitOps | ArgoCD or Flux (same on both) | ArgoCD or Flux (same on both) |

---

##
##
