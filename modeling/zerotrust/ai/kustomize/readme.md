

```
kustomize/
├── base/
│   ├── deployment.yaml
│   ├── serviceaccount.yaml
│   ├── configmap.yaml
│   ├── networkpolicy.yaml
│   ├── mapping-ambassador.yaml
│   └── kustomization.yaml
└── overlays/
    └── prod/
        ├── kustomization.yaml
        └── patch‑deployment.yaml
```


```
```
base/kustomization.yaml

```
resources:
  - deployment.yaml
  - serviceaccount.yaml
  - configmap.yaml
  - networkpolicy.yaml
  - mapping-ambassador.yaml

```
overlays/prod/kustomization.yaml

```
resources:
  - ../../base
patchesStrategicMerge:
  - patch-deployment.yaml




```
overlays/prod/patch-deployment.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: brain-api
spec:
  replicas: 4                # override to 4 in prod
  template:
    spec:
      containers:
      - name: brain-api
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "1"
            memory: "2Gi"
