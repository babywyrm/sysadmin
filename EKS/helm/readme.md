# Amazon EKS Helm Guide: Modern and Secure Usage Patterns

## 1. Introduction

Helm is the package manager for Kubernetes that helps you install and manage applications on your Amazon EKS cluster.
This guide provides modern, security-focused instructions for using Helm with Amazon EKS.

## 2. Installation and Setup

### Prerequisites

- A functioning Amazon EKS cluster
- `kubectl` configured for your EKS cluster
- AWS CLI installed and configured

Verify your kubectl configuration:

```bash
kubectl get svc
```

### Installing Helm

#### macOS
```bash
brew install helm
```

#### Windows
```bash
choco install kubernetes-helm
```

#### Linux
```bash
curl -fsSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 > get_helm.sh
chmod 700 get_helm.sh
./get_helm.sh
```

Verify installation:
```bash
helm version --short
```

Expected output (version may vary):
```
v3.14.2
```

## 3. Security Configuration

### RBAC Setup for Helm

Create a dedicated service account for Helm operations:

```bash
kubectl create namespace helm-system
kubectl create serviceaccount helm-user -n helm-system

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: helm-role
  namespace: default
rules:
- apiGroups: ["", "apps", "batch", "extensions"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: helm-role-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: helm-user
  namespace: helm-system
roleRef:
  kind: Role
  name: helm-role
  apiGroup: rbac.authorization.k8s.io
EOF
```

### Configuring Helm to Use Service Account Tokens

```bash
SA_NAME="helm-user"
SA_NAMESPACE="helm-system"

# Get the token secret name
SECRET_NAME=$(kubectl get serviceaccount $SA_NAME -n $SA_NAMESPACE -o jsonpath='{.secrets[0].name}')

# Get the token
TOKEN=$(kubectl get secret $SECRET_NAME -n $SA_NAMESPACE -o jsonpath='{.data.token}' | base64 --decode)

# Create a Helm values file using this token
echo "serviceAccount:
  create: false
  name: $SA_NAME
  namespace: $SA_NAMESPACE
  annotations:
    eks.amazonaws.com/role-arn: <IAM-ROLE-ARN-IF-NEEDED>" > helm-values.yaml
```

### Securing Helm Repositories

Add trusted repositories only:

```bash
# Add official stable repository
helm repo add stable https://charts.helm.sh/stable

# Add EKS charts repository
helm repo add eks https://aws.github.io/eks-charts

# Update repositories
helm repo update
```

## 4. AWS ECR for Private Helm Charts

### Setting Up ECR for Helm Charts

```bash
# Create an ECR repository for Helm charts
aws ecr create-repository --repository-name helm-charts --region us-west-2

# Login to ECR
aws ecr get-login-password --region us-west-2 | helm registry login --username AWS --password-stdin <AWS_ACCOUNT_ID>.dkr.ecr.us-west-2.amazonaws.com
```

### Pushing Charts to ECR

```bash
# Package a chart
helm package ./my-chart

# Push to ECR
helm push my-chart-1.0.0.tgz oci://<AWS_ACCOUNT_ID>.dkr.ecr.us-west-2.amazonaws.com/helm-charts
```

### Installing from ECR

```bash
# Pull and install from ECR
helm install my-release oci://<AWS_ACCOUNT_ID>.dkr.ecr.us-west-2.amazonaws.com/helm-charts/my-chart --version 1.0.0
```

## 5. Secure Chart Installation Practices

### Validating Chart Signatures

```bash
# Install the helm-gpg plugin
helm plugin install https://github.com/technosophos/helm-gpg

# Verify a chart
helm gpg verify my-chart-1.0.0.tgz
```

### Setting Resource Limits

Always set resource limits in your values files:

```yaml
resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi
```

### Scan Charts for Vulnerabilities

```bash
# Install kubeaudit
helm plugin install https://github.com/Shopify/kubeaudit/releases/latest/download/helm-kubeaudit_linux_amd64.tar.gz

# Audit a chart
helm kubeaudit all my-chart
```

## 6. Integrating with AWS Services

### Using AWS Secrets Manager with Helm

Create a Kubernetes secret from AWS Secrets Manager:

```bash
# Get secret from AWS Secrets Manager
SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id my-secret --query SecretString --output text)

# Create Kubernetes secret
kubectl create secret generic my-k8s-secret --from-literal=secret-key="$SECRET_VALUE"

# Reference in values.yaml
secretRef:
  name: my-k8s-secret
  key: secret-key
```

### IAM Roles for Service Accounts (IRSA)

Enable IRSA and use it with Helm:

```bash
# Create an IAM policy
aws iam create-policy --policy-name my-policy --policy-document file://policy.json

# Create an IAM role for service account
eksctl create iamserviceaccount \
    --name my-service-account \
    --namespace default \
    --cluster my-cluster \
    --attach-policy-arn arn:aws:iam::<AWS_ACCOUNT_ID>:policy/my-policy \
    --approve

# Install chart using the service account
helm install my-release my-chart --set serviceAccount.create=false --set serviceAccount.name=my-service-account
```

## 7. GitOps Integration

### Setting Up Flux for Helm

```bash
# Install Flux v2
flux install

# Create a Helm repository source
flux create source helm my-repo \
  --url=https://charts.my-company.com \
  --interval=10m

# Create a HelmRelease
flux create helmrelease my-release \
  --source=HelmRepository/my-repo \
  --chart=my-chart \
  --target-namespace=default \
  --interval=1h \
  --values=values.yaml
```

## 8. Best Practices

### Version Pinning

Always pin versions in production:

```bash
helm install my-release my-chart --version 1.2.3
```

### Using Custom Values Files

Maintain different values files for different environments:

```bash
helm install my-release my-chart -f values-prod.yaml
```

### Rollback Strategy

Always have a rollback plan:

```bash
# List revisions
helm history my-release

# Rollback to a specific revision
helm rollback my-release 2
```

### Regular Auditing

Schedule regular security audits:

```bash
# List all releases
helm list --all-namespaces

# Check for outdated charts
helm list --all-namespaces | grep -v UPDATED
```

## 9. Troubleshooting

### Common Issues

1. **Connection issues to EKS**:
   Verify AWS credentials and kubectl context:
   ```bash
   aws sts get-caller-identity
   kubectl config current-context
   ```

2. **Permission errors**:
   Check RBAC settings:
   ```bash
   kubectl auth can-i create deployments --as=system:serviceaccount:helm-system:helm-user
   ```

3. **Chart not found**:
   Update repositories:
   ```bash
   helm repo update
   ```

4. **ECR access issues**:
   Verify IAM permissions and re-login:
   ```bash
   aws ecr get-login-password --region us-west-2 | helm registry login --username AWS --password-stdin <AWS_ACCOUNT_ID>.dkr.ecr.us-west-2.amazonaws.com
   ```

## 10. Helm with EKS Upgrades

When upgrading EKS, ensure Helm compatibility:

1. Check Helm version compatibility with new Kubernetes version
2. Backup all Helm releases:
   ```bash
   helm list -A -o json > helm-releases-backup.json
   ```
3. After upgrade, verify all charts are functional:
   ```bash
   for release in $(helm list -A -o json | jq -r '.[] | .name + "," + .namespace'); do
     name=$(echo $release | cut -d, -f1)
     namespace=$(echo $release | cut -d, -f2)
     echo "Testing $name in namespace $namespace"
     helm test $name -n $namespace
   done
   ```

## 11. Advanced Configuration

### Using Helm diff plugin

```bash
# Install the diff plugin
helm plugin install https://github.com/databus23/helm-diff

# Preview an upgrade
helm diff upgrade my-release my-chart
```

### Automatic Chart Updates with AWS Lambda

Create a Lambda function that:
1. Monitors ECR for new chart versions
2. Updates Helm releases automatically
3. Notifies via SNS on success/failure

## 12. Resources

- [Official Helm Documentation](https://helm.sh/docs/)
- [EKS Workshop](https://www.eksworkshop.com/)
- [AWS Containers Blog](https://aws.amazon.com/blogs/containers/)
- [Artifact Hub](https://artifacthub.io/) for discovering charts
- [EKS Best Practices Guide](https://aws.github.io/aws-eks-best-practices/)

---

