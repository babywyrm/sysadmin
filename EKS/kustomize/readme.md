```

+-------------------+                +-------------------+
| Input: Base YAMLs |                | Input: Patches    |
| & Customizations  |                | & Overlays        |
+-------------------+                +-------------------+
         |                                   |
         v                                   v
     +---------------------------------------------+
     |              Kustomize Process              |
     |                                             |
     | 1. Read base resources                      |
     | 2. Apply patches and overlays               |
     | 3. Apply common transformations             |
     |    (namespace, labels, name prefixes)       |
     | 4. Output combined Kubernetes manifests     |
     +---------------------------------------------+
                         |
                         v
               +-------------------+
               | Output: Complete  |
               | K8s YAML Manifests|
               +-------------------+


##
##


+-----------------------------------+
|         Kustomize Process         |
+-----------------------------------+

  +------------------------+
  |        base/           |
  |                        |
  | kustomization.yaml     |<------+  References Helm chart
  | - helmCharts:          |       |  and base values
  |   - name: wordpress    |       |
  |     version: 15.2.5    |       |
  |     valuesFile: values |       |
  |                        |       |
  | values.yaml            |       |
  | - wordpressUsername    |       |
  | - persistence: 10Gi    |       |
  +------------------------+       |
             |                     |
             | kustomize combines  |
             v                     |
  +------------------------+       |
  |      overlays/dev/     |       |
  |                        |       |
  | kustomization.yaml     |       |
  | - resources:           |       |
  |   - ../../base         |<------+  Extends base and
  | - patches:             |          applies specific changes
  |   - values-patch.yaml  |
  |                        |
  | values-patch.yaml      |
  | - resources:           |
  |   cpu: 500m            |
  | - replicaCount: 1      |
  +------------------------+
             |
             | kustomize build
             v
  +------------------------+
  |   Generated Output     |
  |   (Final K8s YAML)     |
  |                        |
  | - Namespace            |
  | - Secret               |
  | - Deployment           |<----- Complete set of K8s resources
  | - Service              |       with all values merged
  | - PVC                  |
  | - ConfigMap            |
  | - etc...               |
  +------------------------+


  +----------------------+    +----------------------+
|     Base Values      |    |   Overlay Patches    |
|                      |    |                      |
| wordpressUsername:   |    | replicaCount: 1      |
|   user               |    | resources:           |
| persistence:         |    |   cpu: 500m          |
|   size: 10Gi         |    |   memory: 512Mi      |
| service:             |    | service:             |
|   type: ClusterIP    |    |   type: LoadBalancer |
+----------------------+    +----------------------+
           |                           |
           |                           |
           v                           v
      +------------------------------------+
      |       Kustomize Build Engine       |
      |                                    |
      | 1. Loads base configuration        |
      | 2. Applies patches from overlay    |
      | 3. Processes Helm chart template   |
      | 4. Generates final K8s manifests   |
      +------------------------------------+
                      |
                      v
     +-------------------------------------+
     |         Final Configuration         |
     |                                     |
     | wordpressUsername: user             |
     | persistence:                        |
     |   size: 10Gi                        |
     | service:                            |
     |   type: LoadBalancer  <-- Overridden|
     | replicaCount: 1       <-- Added     |
     | resources:            <-- Added     |
     |   cpu: 500m                         |
     |   memory: 512Mi                     |
     +-------------------------------------+


+-----------------+    +----------------+    +------------------+
| Kustomize Base  |    | Helm Template  |    | Values Override  |
| (References     |    | (WordPress     |    | (Environment     |
|  Helm Chart)    |    |  Chart)        |    |  Specific)       |
+-----------------+    +----------------+    +------------------+
        |                      |                     |
        |                      |                     |
        +----------+-----------+---------------------+
                   |
                   | Kustomize processes Helm charts when using
                   | "helmCharts:" directive in kustomization.yaml
                   v
      +--------------------------------+
      |     Rendered K8s Resources     |
      |                                |
      | apiVersion: apps/v1            |
      | kind: Deployment               |
      | metadata:                      |
      |   name: wordpress              |
      | spec:                          |
      |   replicas: 1                  |
      |   ...                          |
      +--------------------------------+

```
# wordpress/applications/app-template.yaml
```
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: wordpress-environments
  namespace: argocd
spec:
  generators:
  - git:
      repoURL: https://github.com/your-organization/wordpress-gitops.git
      revision: HEAD
      directories:
      - path: wordpress/overlays/*
  template:
    metadata:
      name: "wordpress-{{path.basename}}"
    spec:
      project: default
      source:
        repoURL: https://github.com/your-organization/wordpress-gitops.git
        targetRevision: HEAD
        path: "{{path}}"
      destination:
        server: https://kubernetes.default.svc
        namespace: "wordpress-{{path.basename}}"
      syncPolicy:
        automated:
          prune: true
          selfHeal: true

```
# Helm
```

apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: wordpress-helm-environments
  namespace: argocd
spec:
  generators:
  - list:
      elements:
      - name: dev
        namespace: wordpress-dev
        valueFiles: values-dev.yaml
        replicas: 1
      - name: staging
        namespace: wordpress-staging
        valueFiles: values-staging.yaml
        replicas: 2
      - name: production
        namespace: wordpress-prod
        valueFiles: values-prod.yaml
        replicas: 3
  template:
    metadata:
      name: wordpress-{{name}}
    spec:
      project: default
      source:
        repoURL: https://github.com/your-organization/wordpress-gitops.git
        targetRevision: HEAD
        path: wordpress/helm
        helm:
          releaseName: wordpress-{{name}}
          valueFiles:
          - {{valueFiles}}
          values: |
            replicaCount: {{replicas}}
            environment: {{name}}
      destination:
        server: https://kubernetes.default.svc
        namespace: "{{namespace}}"
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true



