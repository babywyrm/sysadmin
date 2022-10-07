istio install steps
create-services.sh
#!/bin/bash

for count in {1..770}
do
    kubectl -n istio-test apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: reg${count}
spec:
  ports:
  - name: tcp
    port: 12111
    protocol: TCP
    targetPort: 12111
  selector:
    app: reg${count}
  type: ClusterIP
EOF
done
install-istio.md
Install istio 1.1.1
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.1.1 sh -
cd istio-1.1.1/
export PATH=$PWD/bin:$PATH
kubectl create namespace istio-system
helm template install/kubernetes/helm/istio-init --name istio-init --namespace istio-system | kubectl apply -f -
kubectl get crds | grep 'istio.io\|certmanager.k8s.io' | wc -l
>>53
helm template install/kubernetes/helm/istio --name istio --namespace istio-system | kubectl apply -f -

# edit istio-sidecar-injector config map to include `--proxy-level error` in the args and restart the sidecar injector pod
Apply workload
kubectl apply -f https://gist.githubusercontent.com/gotwarlost/e50efe260448f1f1c21d38060c6e56ef/raw/e673a835b6952edfd7197dc3e9479b5357124807/workloads.yaml

The above creates an istio-test namespace, a deployment, service and sidecar that only cares about services in the current namespace.

workloads.yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    istio-injection: enabled
  name: istio-test
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: reg
  namespace: istio-test
---
apiVersion: extensions/v1beta1
kind: PodSecurityPolicy
metadata:
  name: istio-pod-network-controller
spec:
  allowedCapabilities:
    - NET_ADMIN
  fsGroup:
    rule: RunAsAny
  hostIPC: true
  hostNetwork: true
  hostPID: true
  hostPorts:
    - max: 65535
      min: 1
  privileged: true
  runAsUser:
    rule: RunAsAny
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  volumes:
    - '*'
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
  name: istio-pod-network-controller
rules:
  - apiGroups:
      - extensions
    resourceNames:
      - istio-pod-network-controller
    resources:
      - podsecuritypolicies
    verbs:
      - use

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: istio-pod-network-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: istio-pod-network-controller
subjects:
  - kind: ServiceAccount
    name: reg
    namespace: istio-test
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  labels:
    app: reg
    version: v1
  name: reg-v1
  namespace: istio-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: reg
      version: v1
  template:
    metadata:
      labels:
        app: reg
        version: v1
    spec:
      serviceAccount: reg
      containers:
      - image: pstauffer/curl
        command: ["/bin/sleep", "3650d"]
        name: sleep
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: reg
  name: reg
  namespace: istio-test
spec:
  ports:
  - name: http-web
    port: 80
    protocol: TCP
    targetPort: 8080
  selector:
    app: reg
  type: ClusterIP

---
apiVersion: networking.istio.io/v1alpha3
kind: Sidecar
metadata:
  name: reg
  namespace: istio-test
spec:
  egress:
  - hosts:
    - istio-test/*
  workloadSelector:
    labels:
      app: reg
  
