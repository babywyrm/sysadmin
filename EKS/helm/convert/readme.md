
## ( BETA ) 


1. Helm-template your chart into raw YAML  
   ```bash
   helm template my-release path/to/chart \
     --namespace your-ns \
     > base/all-resources.yaml
   ```  
   This inlines all your templates + values into one big file.

2. Split into logical pieces under `base/`  
   Create separate files (you can use `csplit`, `yq` or manual cuts):  
   – `namespace.yaml`  
   – `serviceaccount.yaml`, `roles.yaml`, `rolebindings.yaml`  
   – `configmap.yaml`  
   – `secret.yaml`  
   – `deployment.yaml` / `statefulset.yaml`  
   – `service.yaml` / `ingress.yaml`  

3. Create your `base/kustomization.yaml`  
   ```yaml
   apiVersion: kustomize.config.k8s.io/v1beta1
   kind: Kustomization

   namespace: your-ns
   resources:
     - namespace.yaml
     - serviceaccount.yaml
     - roles.yaml
     - rolebindings.yaml
     - configmap.yaml
     - secret.yaml
     - deployment.yaml
     - service.yaml
     - ingress.yaml
   ```

4. Parameterize with patches or generators  
   – Secrets: replace hard-coded values with a `SecretGenerator`  
     ```yaml
     secretGenerator:
       - name: my-app-creds
         literals:
           - USERNAME=$(USERNAME)
           - PASSWORD=$(PASSWORD)
     generatorOptions:
       disableNameSuffixHash: true
     ```  
   – ConfigMaps: likewise with `configMapGenerator`  
   – Images, replica counts, resource limits: use patches under `overlays/`  

5. Define overlays per environment  
   Directory layout:  
   ```
   base/
     kustomization.yaml
     *.yaml
   overlays/
     dev/
       kustomization.yaml
       patch-deployment.yaml
     prod/
       kustomization.yaml
       patch-deployment.yaml
   ```  
   Example `overlays/dev/kustomization.yaml`:  
   ```yaml
   apiVersion: kustomize.config.k8s.io/v1beta1
   kind: Kustomization
   bases:
     - ../../base
   patchesStrategicMerge:
     - patch-deployment.yaml
   configMapGenerator:
     - name: my-app-config
       files:
         - config.properties=dev.properties
   secretGenerator:
     - name: my-app-creds
       literals:
         - USERNAME=devuser
         - PASSWORD=devpass
   ```

6. Write strategic-merge patches  
   E.g. `overlays/dev/patch-deployment.yaml`:  
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: my-app
   spec:
     replicas: 1
     template:
       spec:
         containers:
         - name: my-app
           image: my-app:dev-tag
           env:
           - name: LOG_LEVEL
             value: DEBUG
   ```

7. Reference secrets/configmaps in your base manifests  
   In `base/deployment.yaml`, refer to generated secrets:  
   ```yaml
   env:
     - name: USERNAME
       valueFrom:
         secretKeyRef:
           name: my-app-creds
           key: USERNAME
     - name: PASSWORD
       valueFrom:
         secretKeyRef:
           name: my-app-creds
           key: PASSWORD
   ```

8. Validate & test locally  
   For each overlay:  
   ```bash
   kustomize build overlays/dev | kubectl apply --dry-run=client -f -
   kustomize build overlays/prod | kubeval --strict -
   ```

9. Hook into Argo CD  
   Create an Argo Application pointing at your Git repo and the desired overlay path:  
   ```yaml
   apiVersion: argoproj.io/v1alpha1
   kind: Application
   metadata:
     name: my-app-dev
   spec:
     project: default
     source:
       repoURL: https://git.example.com/your-repo.git
       targetRevision: HEAD
       path: overlays/dev
     destination:
       server: https://kubernetes.default.svc
       namespace: your-ns
     syncPolicy:
       automated:
         prune: true
         selfHeal: true
   ```

10. Keep DRY and iterate  
   – Extract common patches into `base`  
   – Only environment-specific bits live under overlays  
   – Rotate secrets with SealedSecrets or ExternalSecrets if you don’t want raw creds in Git  

With this pattern you can take any Helm chart, turn it into a Kustomize “base,” then overlay per-env customizations, and let Argo CD handle sync.
