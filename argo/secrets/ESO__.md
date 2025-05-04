

## 1. Using External Secrets with AWS Secrets Manager

The [External Secrets Operator](https://external-secrets.io/) lets you declaratively fetch secrets from AWS Secrets Manager (as well as other external providers) and turn them into native Kubernetes secrets. This avoids storing plaintext secrets in Git.

### Example: ExternalSecret CRD for AWS Secrets Manager

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: my-app-secrets
  namespace: my-app
spec:
  refreshInterval: "1h" # How frequently to re-fetch the secret from AWS
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: my-app-secrets # Name of the Kubernetes Secret to be created
    creationPolicy: Owner
  data:
    - secretKey: DB_PASSWORD
      remoteRef:
        key: /prod/db/password
    - secretKey: API_KEY
      remoteRef:
        key: /prod/api/key
```

In this example:
- AWS Secrets Manager stores the database password under `/prod/db/password` and the API key under `/prod/api/key`.
- The ExternalSecrets Operator reconciles the `ExternalSecret` and creates/updates a Kubernetes secret named `my-app-secrets` in the `my-app` namespace.

---

## 2. Incorporating Secrets into Kustomize Overlays

Using Kustomize, you can overlay your base configurations with patches that reference your secrets.

### Base Deployment (base/deployment.yaml)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  labels:
    app: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
        - name: my-app
          image: my-image:latest
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: placeholder-secret  # This will be patched later!
                  key: DB_PASSWORD
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: placeholder-secret  # This will be patched later!
                  key: API_KEY
```

### Base Kustomization File (base/kustomization.yaml)

```yaml
resources:
  - deployment.yaml
```

### Overlay for Production (overlays/prod/kustomization.yaml)

```yaml
resources:
  - ../../base

patchesStrategicMerge:
  - secret-patch.yaml
```

### Kustomize Patch to Reference the External Secret (overlays/prod/secret-patch.yaml)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: placeholder-secret  # Matches the reference in the deployment
stringData:
  # These values are not kept here; they indicate that this secret will be superseded by the
  # ExternalSecret reconciliation process. When the ExternalSecret is reconciled, it creates
  # a secret matching a predetermined structure.
  DB_PASSWORD: "REPLACED_BY_EXTERNAL_SECRET"
  API_KEY: "REPLACED_BY_EXTERNAL_SECRET"
```

**Note:**  
In this workflow, the external secret created by the External Secrets Operator (e.g., `my-app-secrets`) can be referenced or mapped within your application. You might choose between using different names or directly referencing the external secret. The Kustomize overlay here shows how you might patch in a placeholder secret so that your base manifests are complete; however, in production you can directly use the name from the ExternalSecret.

---

## 3. Using Helm for Secrets

When using Helm, you can parameterize the secret names and values with your `values.yaml` file, ensuring that your templates refer to the pre-created or dynamically managed secrets.

### Example: Deployment Template in a Helm Chart

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "myapp.fullname" . }}
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: {{ include "myapp.name" . }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.secrets.k8sSecretName }}
                  key: DB_PASSWORD
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.secrets.k8sSecretName }}
                  key: API_KEY
```

### Example: values.yaml

```yaml
image:
  repository: my-image
  tag: latest

secrets:
  # This can be the same name as the ExternalSecret target, thus linking Helm deployments to the secret
  k8sSecretName: "my-app-secrets"
```

With this approach, your Helm release through ArgoCD will refer to the secret that the External Secrets Operator creates. This separation allows you to update the secret in AWS (and have it sync to Kubernetes) without requiring changes to your Helm charts.

---

## 4. Advanced: Dynamic Secret Injection with Sidecars

Another strategy for handling secrets securely is to use an _init container_ or a _sidecar container_ that pulls secrets directly from AWS Secrets Manager at pod startup, then writes them to an in-memory volume. This avoids disk storage of secrets on the container’s filesystem.

### Example: Pod Spec with an Init Container

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      # Define an emptyDir volume that is stored in memory
      volumes:
        - name: secrets-volume
          emptyDir:
            medium: Memory
      initContainers:
        - name: fetch-secrets
          image: amazon/aws-cli:2.7.0
          command:
            - "sh"
            - "-c"
            - |
              # Fetch secrets and write them to a file in the shared volume
              aws secretsmanager get-secret-value --secret-id /prod/app/config --region us-west-2 \
                --query 'SecretString' --output text > /tmp/secrets.json && \
              cp /tmp/secrets.json /mounted/secrets/secrets.json
          volumeMounts:
            - name: secrets-volume
              mountPath: /mounted/secrets
      containers:
        - name: my-app
          image: my-app-image:latest
          env:
            - name: APP_CONFIG_FILE
              value: /secrets/secrets.json
          volumeMounts:
            - name: secrets-volume
              mountPath: /secrets
```

In this configuration:
- An **init container** runs before the main app container. It uses the AWS CLI to fetch the secret and write it to a shared volume.
- The **emptyDir** volume is used with `medium: Memory` to keep the secret out of disk storage.
- The main application then reads the secret from the shared volume.

---

## Final Recommendations

- **Separate Deployment of Secrets:**  
  Always strive for separation of concerns. Use operators or init containers for secret retrieval and make sure your application solely consumes the injected secrets.
  
- **Audit and Monitor:**  
  Log secret fetch attempts and monitor AWS Secrets Manager access. Use Kubernetes audit logs to keep track of secret updates and accesses.
  
- **Rotate Secrets:**  
  Ensure that secrets in AWS are rotated regularly. The External Secrets Operator can help automatically pull in updated secrets and trigger redeployments, if needed.

