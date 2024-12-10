##
#
https://gist.github.com/harrywm/6a80b6dc355f20595b002734559d4a15
#
##

ArgoCD Helm Secrets
1helm-plugin.md
Install the Helm Secrets Plugin to ArgoCD using initContainers. This example is using the Helm Chart.

2values.yaml
```
repoServer:
  initContainers:
  - name: download-tools
    image: alpine:latest
    imagePullPolicy: IfNotPresent
    command: [sh, -ec]
    env:
    - name: HELM_SECRETS_VERSION
      value: "4.4.2"
    - name: KUBECTL_VERSION
      value: "1.26.1"
    - name: VALS_VERSION
      value: "0.24.0"
    - name: SOPS_VERSION
      value: "3.7.3"
    args:
    - |
      mkdir -p /custom-tools/helm-plugins
      wget -qO- https://github.com/jkroepke/helm-secrets/releases/download/v${HELM_SECRETS_VERSION}/helm-secrets.tar.gz | tar -C /custom-tools/helm-plugins -xzf-;
      wget -qO /custom-tools/curl https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64
      wget -qO /custom-tools/sops https://github.com/mozilla/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux
      wget -qO /custom-tools/kubectl https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl
      wget -qO- https://github.com/helmfile/vals/releases/download/v${VALS_VERSION}/vals_${VALS_VERSION}_linux_amd64.tar.gz | tar -xzf- -C /custom-tools/ vals;
      cp /custom-tools/helm-plugins/helm-secrets/scripts/wrapper/helm.sh /custom-tools/helm
      chmod +x /custom-tools/*
    volumeMounts:
    - mountPath: /custom-tools
      name: custom-tools
```
      
3applications.md
We use ApplicationSets, but you could use Applications as well. The helm-secrets plugin allows you to use the secrets:// qualifier.

Using a "SubChart" method, we can pull remote charts, while using local Values and Secrets files.

You can then reference secrets like below.

Note line 40.

4applicationset.yaml

```
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: apps
  namespace: argo
  annotations:
    type: application
spec:
  generators:
  - matrix:
      generators:
      - scmProvider:
          cloneProtocol: https
          github:
            organization: org
            appSecretName: github-app-repo-creds
            allBranches: false
      - git:
          repoURL: '{{ url }}'
          revision: '{{ branch }}'
          files:
          - path: helm/**/config/env.json
          values:
            env: env
  template:
    metadata:
      annotations:
        argocd.argoproj.io/manifest-generate-paths: .
      name: '{{ path[1] }}'
    spec:
      project: default
      source:
        repoURL: '{{ url }}'
        targetRevision: '{{ branch }}'
        path: 'helm/{{ path[1] }}'
        helm:
          valueFiles:
          - 'values.common.yaml'
          - 'values.{{values.env}}.yaml'
          - 'secrets://secrets.{{values.env}}.yaml'
      destination:
        server: https://kubernetes.default.svc
        namespace: '{{namespace}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
        - ServerSideApply=true
        - PrunePropagationPolicy=foreground
```

5app.md
The path that the ApplicationSet is looking for, and will generate Apps for, is laid out like so:
```
├── helm
│   └── app-name
│       ├── Chart.yaml
│       ├── config
│       │   └── env.json
│       ├── secrets.env.yaml
│       ├── values.common.yaml
│       ├── values.env.yaml
```

Where Chart.yaml contains a SubChart dependency like below:

6Chart.yaml
```
apiVersion: v2
description: Honeycomb
name: honeycomb
version: 1.0.0
type: application
dependencies:
  - name: honeycomb
    version: 1.7.1
    repository: https://honeycombio.github.io/helm-charts

    
