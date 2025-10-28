# Teleport Enterprise - Modern Installation Guide ..(2025,beta)..

**Gravitational Teleport** is a modern SSH/Kubernetes API proxy server for remotely accessing clusters of Linux containers and servers via SSH, HTTPS, or Kubernetes API.

## Prerequisites

- **Kubernetes**: 1.24+ (recommended 1.28+)
- **Helm**: 3.12+ 
- **kubectl**: Configured and connected to your cluster
- **Teleport Enterprise License**: Downloaded from your Teleport dashboard

## Installation

### 1. Add the Helm Repository

```bash
helm repo add cloudposse https://charts.cloudposse.com/incubator/
helm repo update
```

### 2. Create a Namespace

```bash
kubectl create namespace teleport
```

### 3. Prepare the License File

Download your `license.pem` from the Teleport dashboard and create a Kubernetes secret:

```bash
# Rename the license file
cp ~/Downloads/license.pem license-enterprise.pem

# Create the secret in the teleport namespace
kubectl create secret generic license \
  --from-file=license-enterprise.pem \
  --namespace=teleport
```

### 4. Configure TLS Certificates

#### Option A: Let Teleport Generate Self-Signed Certificates (Development)

Skip this step - Teleport will auto-generate certificates.

#### Option B: Use Your Own TLS Certificates (Production)

Prepare your certificate files:
- `ca.pem` - Your CA certificate
- `proxy-server.pem` - Your proxy server certificate
- `proxy-server-key.pem` - Your proxy server private key

Create the secrets:

```bash
# Create TLS secret
kubectl create secret tls tls-web \
  --cert=proxy-server.pem \
  --key=proxy-server-key.pem \
  --namespace=teleport

# Create CA configmap
kubectl create configmap ca-certs \
  --from-file=ca.pem \
  --namespace=teleport
```

### 5. Install the Chart

#### Basic Installation

```bash
helm install teleport cloudposse/teleport \
  --namespace=teleport \
  --version=0.0.2 \
  --create-namespace
```

#### Production Installation with Custom Values

Create a `values.yaml` file:

```yaml
replicaCount: 3

config:
  teleport:
    auth_service:
      enabled: true
      cluster_name: "production.example.com"
      listen_addr: 0.0.0.0:3025
    
    proxy_service:
      enabled: true
      listen_addr: 0.0.0.0:3023
      web_listen_addr: 0.0.0.0:3080
      public_addr: "teleport.example.com:443"
      kubernetes:
        enabled: true
        public_addr: ["teleport.example.com:443"]
    
    ssh_service:
      enabled: true

# Use custom TLS certificates
tls:
  existingSecretName: "tls-web"
  existingCAConfigMap: "ca-certs"

# Resource limits
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"

# Storage for session recordings
persistence:
  enabled: true
  storageClass: "standard"
  size: 10Gi

# Ingress configuration (optional)
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: teleport.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: teleport-tls
      hosts:
        - teleport.example.com
```

Install with custom values:

```bash
helm install teleport cloudposse/teleport \
  --namespace=teleport \
  --version=0.0.2 \
  --values=values.yaml
```

## Accessing Teleport

### Internal Cluster Access (Port Forward)

```bash
kubectl port-forward -n teleport svc/teleport 3080:3080
```

Access at: `https://localhost:3080`

### External Access (with Ingress)

Access at: `https://teleport.example.com`

## Initial Setup

### Create Admin User

```bash
# Get the pod name
POD=$(kubectl get pods -n teleport -l app=teleport -o jsonpath='{.items[0].metadata.name}')

# Create admin user
kubectl exec -n teleport $POD -- tctl users add admin \
  --roles=editor,access \
  --logins=root,ubuntu,ec2-user
```

This will output a signup link - open it in your browser to set up MFA and password.

## Using the Teleport CLI (`tsh`)

### Install tsh

```bash
# macOS
brew install teleport

# Linux
curl https://goteleport.com/static/install.sh | bash -s 14.0.0
```

### Login

```bash
# Using local auth
tsh login --proxy=teleport.example.com:443 --auth=local --user=admin

# Using SSO (if configured)
tsh login --proxy=teleport.example.com:443 --auth=github --user=your-username
```

### Common Commands

```bash
# List available servers
tsh ls

# SSH into a node
tsh ssh user@hostname

# List Kubernetes clusters
tsh kube ls

# Login to a Kubernetes cluster
tsh kube login my-cluster

# View recorded sessions
tsh play <session-id>
```

## Local Development with Kind

### Setup Script

```bash
#!/bin/bash
set -e

# Create kind cluster
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: teleport-dev
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 3080
    hostPort: 3080
    protocol: TCP
EOF

# Install Teleport
kubectl create namespace teleport

# Create license secret (replace with your license)
kubectl create secret generic license \
  --from-file=license-enterprise.pem \
  --namespace=teleport

# Install with development values
helm install teleport cloudposse/teleport \
  --namespace=teleport \
  --set config.teleport.proxy_service.public_addr="localhost:3080" \
  --set service.type=NodePort \
  --set service.ports.web.nodePort=30080

# Wait for deployment
kubectl wait --for=condition=ready pod \
  -l app=teleport \
  -n teleport \
  --timeout=300s

# Create admin user
POD=$(kubectl get pods -n teleport -l app=teleport -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n teleport $POD -- tctl users add admin \
  --roles=editor,access \
  --logins=root

echo "Teleport is ready at https://localhost:3080"
```

Save as `setup-teleport-dev.sh` and run:

```bash
chmod +x setup-teleport-dev.sh
./setup-teleport-dev.sh
```

## Upgrading

```bash
# Update repository
helm repo update

# Upgrade release
helm upgrade teleport cloudposse/teleport \
  --namespace=teleport \
  --values=values.yaml
```

## Verification

```bash
# Check deployment status
kubectl get all -n teleport

# Check logs
kubectl logs -n teleport -l app=teleport --tail=100 -f

# Verify license
POD=$(kubectl get pods -n teleport -l app=teleport -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n teleport $POD -- tctl get license
```

## Troubleshooting

### Check Pod Status

```bash
kubectl describe pod -n teleport -l app=teleport
```

### View Detailed Logs

```bash
kubectl logs -n teleport -l app=teleport --previous
```

### Common Issues

1. **License not found**: Ensure the secret is created in the correct namespace
2. **TLS errors**: Verify certificate files and secret names match configuration
3. **Pod not starting**: Check resource limits and persistent volume claims

## Production Recommendations

1. **High Availability**: Set `replicaCount: 3` or higher
2. **Persistent Storage**: Enable persistence for session recordings
3. **Resource Limits**: Set appropriate CPU/memory limits
4. **TLS Certificates**: Use cert-manager for automatic certificate management
5. **Monitoring**: Integrate with Prometheus/Grafana
6. **Backup**: Regularly backup the audit log and session recordings
7. **Security**: Enable RBAC and network policies

## Additional Resources

- [Teleport Documentation](https://goteleport.com/docs/)
- [Teleport GitHub](https://github.com/gravitational/teleport)
- [Helm Chart Repository](https://charts.cloudposse.com/incubator/)
- [Teleport Community](https://github.com/gravitational/teleport/discussions)

## Contributing

To build the Teleport CLI from source:

```bash
# Clone repository
git clone https://github.com/gravitational/teleport.git
cd teleport

# Build all components
make full

# Build only tsh client
make build/tsh

# Use locally built tsh
./build/tsh --proxy=teleport.example.com:443 --auth=local --user=admin login
```

## Uninstallation

```bash
helm uninstall teleport --namespace=teleport
kubectl delete namespace teleport
```
