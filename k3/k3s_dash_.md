# K3s Dashboard Installation Guide

Modern installation guide for Kubernetes Dashboard on K3s clusters.

## Prerequisites

- K3s cluster installed and running
- `kubectl` configured to access your cluster
- Master node access

## Installation

### 1. Create Dashboard Directory

```bash
mkdir ~/k3s-dashboard
cd ~/k3s-dashboard
```

### 2. Deploy Kubernetes Dashboard

Get the latest version and deploy:

```bash
GITHUB_URL=https://github.com/kubernetes/dashboard/releases
VERSION_KUBE_DASHBOARD=$(curl -w '%{url_effective}' -I -L -s -S ${GITHUB_URL}/latest -o /dev/null | sed -e 's|.*/||')
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/${VERSION_KUBE_DASHBOARD}/aio/deploy/recommended.yaml
```

### 3. Create Service Account and RBAC

Create `dashboard-admin.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kubernetes-dashboard
```

Apply the configuration:

```bash
kubectl apply -f dashboard-admin.yaml
```

## Access Methods

### Method 1: Traefik Ingress (Recommended)

Create `dashboard-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
  annotations:
    kubernetes.io/ingress.class: "traefik"
    traefik.ingress.kubernetes.io/router.tls: "true"
    traefik.ingress.kubernetes.io/router.tls.options: "default"
spec:
  tls:
  - hosts:
    - k3s-dashboard.example.org
    secretName: dashboard-tls
  rules:
  - host: k3s-dashboard.example.org
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes-dashboard
            port:
              number: 443
```

Apply the ingress:

```bash
kubectl apply -f dashboard-ingress.yaml
```

**For test environments without certificates:**

Edit Traefik config to skip SSL verification:

```bash
kubectl -n kube-system edit configmap traefik
```

Add `insecureSkipVerify = true` to the TOML configuration, then restart Traefik:

```bash
kubectl -n kube-system rollout restart deployment traefik
```

Access at: `https://k3s-dashboard.example.org`

### Method 2: kubectl proxy

Start the proxy:

```bash
kubectl proxy
```

Create SSH tunnel from your local machine:

```bash
ssh -N -L localhost:8001:localhost:8001 pi@your-k3s-master-ip
```

Access at: `http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/`

### Method 3: NodePort (Alternative)

Create `dashboard-nodeport.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard-nodeport
  namespace: kubernetes-dashboard
spec:
  type: NodePort
  ports:
  - port: 443
    targetPort: 8443
    nodePort: 32443
    protocol: TCP
  selector:
    k8s-app: kubernetes-dashboard
```

Apply and access at: `https://your-node-ip:32443`

## Authentication

### Get Login Token

```bash
kubectl -n kubernetes-dashboard create token admin-user
```

Or for longer-lived tokens, create a secret:

```bash
kubectl -n kubernetes-dashboard apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: admin-user-token
  namespace: kubernetes-dashboard
  annotations:
    kubernetes.io/service-account.name: admin-user
type: kubernetes.io/service-account-token
EOF
```

Then retrieve the token:

```bash
kubectl -n kubernetes-dashboard get secret admin-user-token -o jsonpath='{.data.token}' | base64 -d
```

## Troubleshooting

### Fix Permission Issues

If you encounter permission errors:

```bash
kubectl create clusterrolebinding kubernetes-dashboard \
  --clusterrole=cluster-admin \
  --serviceaccount=kubernetes-dashboard:kubernetes-dashboard
```

### Check Dashboard Status

```bash
kubectl -n kubernetes-dashboard get pods,services
```

## Cleanup

To remove the dashboard:

```bash
kubectl delete namespace kubernetes-dashboard
```

## Security Notes

- The admin-user has cluster-admin privileges - use carefully in production
- Consider creating more restrictive RBAC policies for production environments
- Always use TLS in production deployments
- Regularly update the dashboard to the latest version for security patches

## Key Improvements Made

1. **Modernized YAML**: Updated from deprecated `extensions/v1beta1` to `networking.k8s.io/v1`
2. **Combined Files**: Merged ServiceAccount and ClusterRoleBinding into single file
3. **Better Organization**: Clearer sections and improved formatting
4. **Multiple Access Methods**: Added NodePort option
5. **Security Enhancements**: Added TLS configuration and security notes
6. **Improved Commands**: Used `kubectl rollout restart` instead of manual scaling
7. **Token Management**: Added both temporary and persistent token options
8. **Troubleshooting**: Added common debugging steps



## Installation steps for K3s dashboard (..legacy..)

##
#
https://gist.github.com/jannegpriv/06427e4ecc2a17f317a4bebc32b6445c
#
##
 
The steps below requires that you have followed the installation steps for [installing K3s on RPIs](https://gist.github.com/jannegpriv/c8227de6fe46c1eb7e214ac3c6b7b283).

*NOTE*: The following files can be found in the following [repository](https://github.com/jannegpriv/k3s-dashboard).


Installation steps for K3s dashboard. On master node, create a folder called dashboard:

```
mkdir ~/k3s-dashboard
cd ~/k3s-dashboard
GITHUB_URL=https://github.com/kubernetes/dashboard/releases
VERSION_KUBE_DASHBOARD=$(curl -w '%{url_effective}' -I -L -s -S ${GITHUB_URL}/latest -o /dev/null | sed -e 's|.*/||')
sudo k3s kubectl create -f https://raw.githubusercontent.com/kubernetes/dashboard/${VERSION_KUBE_DASHBOARD}/aio/deploy/recommended.yaml
```


Then create a file named `service-account.yaml` with the following content:

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
```

Then create a file named `cluster-role.yaml` with the following content:

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kubernetes-dashboard
```

Then apply the 2 yaml-files:

```
k apply -f service-account.yaml
k apply -f cluster-role-binding.yaml
```

### Access the Kubernetes Dashboard using ingress controller Traefik

The easiest way to access the dashboard is by creating an ingress controller using the Traefik load balancer.

Create a file named `dashboard-trafik.yaml`:

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
  labels:
    app: kubernetes-dashboard
  annotations:
    kubernetes.io/ingress.class: "traefik"
spec:
  rules:
  - host: k3s-dashboard.example.org
    http:
      paths:
      - path: /
        backend:
          serviceName: kubernetes-dashboard
          servicePort: 443          
```

Then apply the yaml-file:

```
k apply -f dashboard-trafik.yaml
```

If you run without certificates, e.g. in a test environment, you then need to configure traefik to skip certificate checks by adding the following line to the config map for traefik, first launch the config map editor:

```
kubectl -n kube-system edit cm traefik
```

Then add the following line to the top of the toml part:

```insecureSkipVerify = true```

like this:

```
# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
  traefik.toml: |
    # traefik.toml
    logLevel = "debug"
    insecureSkipVerify = true
    defaultEntryPoints = ["http","https"]
```

Then relaunch the traefik pod by scaling down/up:

```
kubectl -n kube-system scale deploy traefik --replicas 0
kubectl -n kube-system scale deploy traefik --replicas 1
```



Then surf to:

https://k3s-dashboard.example.org/#/login

### Access the Kubernetes Dashboard using Kube Proxy

Start kube proxy to export port 8001 to dashboard. **NOTE**: The prompt will hang!:

```
sudo k3s kubectl proxy
Starting to serve on 127.0.0.1:8001
```
 
Then depending on your local computer's OS, create a SSH tunnel to k3s-master-1 using either ssh (Linux/MacOS) or e.g. MobaXterm using Windows, below shows Linux/MacOS configuration. **NOTE**: If you have not configured k3s-master-1n /etc/hosts on your local computer, you will need to use the IP address of the master node:

```
ssh -N -L localhost:8001:localhost:8001 pi@k3s-master-1
```

Using your favourite browser on tour local computer, surf to the following URL:
http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#/login

### Login to the Kubernetes Dashboard

To login you will need a Token, use the following command to find it:

```
sudo k3s kubectl -n kubernetes-dashboard describe secret admin-user-token | grep ^token
```

Copy&paste the token listed above and log in to the dashboard.

If you have problems with dashboard complaining about user rights, then issue the following command on the master node:

`kubectl create clusterrolebinding kubernetes-dashboard --clusterrole=cluster-admin --serviceaccount=kube-system:kubernetes-dashboard `

### Delete the Dashboard

To delete the dashboard:

```
sudo k3s kubectl delete -n kubernetes-dashboard
```

