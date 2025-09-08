

# 🔐 Using Bitnami Sealed Secrets with Helm

This workflow ensures you can manage secrets **safely in Git**, while keeping a **regular Helm workflow**.
Developers never need to run `kubeseal` manually, and CI/CD can deploy seamlessly.

---

## ✅ Definition of Done

* A **single `SealedSecret` per release/namespace** with all secret variables
* Works with the **regular Helm workflow** (no manual `kubeseal` steps)
* **Encrypted secrets** are committed to Git
* **Plaintext secrets never leave local/dev machines** (`.gitignore`d)
* **SealedSecret objects are managed by Helm**

---

## 📂 Folder Structure

```
app/templates/sealedsecret.yaml
env/ci.values.yaml
env/ci.secrets.yaml   # ignored
env/qa.values.yaml
env/qa.secrets.yaml   # ignored
env/prod.values.yaml
env/prod.secrets.yaml # ignored
```

`.gitignore`:

```
env/*.secrets.yaml
```

---

## 📜 Helm Template (`app/templates/sealedsecret.yaml`)

```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: {{ include "app.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "app.labels" . | nindent 4 }}
spec:
  encryptedData:
    {{- range $key, $val := .Values.secret }}
    {{ $key }}: {{ $val | quote }}
    {{- end }}
```

---

## ⚙️ Example Environment Values

`./env/ci.values.yaml`

```yaml
env:
  NODE_ENV: production
  AWS_BUCKET: xyz
secret: {}
```

`./env/ci.secrets.yaml` (**ignored by Git**)

```yaml
AWS_ACCESS_KEY_ID: abc123
AWS_SECRET_ACCESS_KEY: xyz
```

---

## 🪝 Pre-Commit Hook (`.git/hooks/pre-commit`)

```bash
#!/usr/bin/env bash
# Dependencies:
#   - yq (>= v4)
#   - jq
#   - kubeseal
set -euo pipefail

fullname="your-app"                # must match helm release fullname
controller_name="sealed-secrets"
controller_namespace="kube-system" # adjust to your cluster

encrypt_namespace() {
    namespace=$1
    secrets_file="env/${namespace}.secrets.yaml"
    values_file="env/${namespace}.values.yaml"
    tmp_secret_file="$(mktemp)"

    if [[ ! -f "$secrets_file" ]]; then
        echo "⚠️  No secrets file found for $namespace. Skipping."
        return
    fi

    echo "🔐 Encrypting secrets for $namespace ..."

    # iterate over keys in secrets file
    for key in $(yq e 'keys | .[]' "$secrets_file"); do
        val=$(yq e ".${key}" "$secrets_file")
        echo -n "$val" >"$tmp_secret_file"

        encrypted=$(kubeseal \
            --raw \
            --name="$fullname" \
            --namespace="$namespace" \
            --controller-name="$controller_name" \
            --controller-namespace="$controller_namespace" \
            --from-file="$tmp_secret_file")

        yq e -i ".secret.${key} = \"$encrypted\"" "$values_file"
    done

    rm -f "$tmp_secret_file"
    echo "✅ Updated $values_file"
}

for ns in ci qa prod; do
    encrypt_namespace "$ns"
done

git add env
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

---

## 🚀 Workflow

1. Developer edits **plaintext secrets** in `env/<ns>.secrets.yaml`.
2. On `git commit`, pre-commit hook:

   * Reads each key/value
   * Encrypts with `kubeseal`
   * Writes ciphertext into `env/<ns>.values.yaml`
   * Adds the file to the commit
3. Git contains only **encrypted values**:

Example `env/ci.values.yaml` after commit:

```yaml
env:
  NODE_ENV: production
  AWS_BUCKET: xyz
secret:
  AWS_ACCESS_KEY_ID: AgD8...
  AWS_SECRET_ACCESS_KEY: AgDl...
```

---

## 🎯 Helm Deployment

```bash
helm upgrade --install myapp ./app -f env/prod.values.yaml
```

This uses the sealed, committed values. No access to raw secrets is required in CI/CD.

---

## 🔧 Extras & Improvements

* Add a `make encrypt` target for CI jobs, so pipelines can regenerate encrypted values if needed.
* Add `--dry-run` flag support in the script for testing.
* Validate `env/*.values.yaml` with your **audit script** (schema + cluster comparison).
* If you run multiple apps/teams, wrap this into a reusable tool (Docker image or Python helper).



##
##


Perfect — let’s **extend the workflow with a Makefile-based approach** so that:

* Developers still get the **pre-commit safety net**.
* CI/CD pipelines can run the same logic via `make`.
* Everything stays **DRY** (shared encrypt logic, no duplication).

---

# 🔨 Makefile for Sealed Secrets

Here’s a `Makefile` that wraps the encryption process:

```makefile
SHELL := /bin/bash
APP_NAME := your-app
CONTROLLER_NAME := sealed-secrets
CONTROLLER_NAMESPACE := kube-system
ENVS := ci qa prod

encrypt:
	@for ns in $(ENVS); do \
	  echo "🔐 Encrypting secrets for $$ns..."; \
	  ./scripts/encrypt.sh $$ns $(APP_NAME) $(CONTROLLER_NAME) $(CONTROLLER_NAMESPACE); \
	done

audit:
	@./audit_sealed_secrets.py --dir ./env --report --format table --exit-nonzero-on-issues

deploy:
	@for ns in $(ENVS); do \
	  echo "🚀 Deploying $$ns..."; \
	  helm upgrade --install $(APP_NAME)-$$ns ./app -f env/$$ns.values.yaml --namespace $$ns; \
	done
```

---

# 📜 `scripts/encrypt.sh`

Instead of duplicating logic between hook & CI, move the encryption logic into a single script (`scripts/encrypt.sh`):

```bash
#!/usr/bin/env bash
# Usage: ./scripts/encrypt.sh <namespace> <app-name> <controller-name> <controller-namespace>
set -euo pipefail

namespace=$1
fullname=$2
controller_name=$3
controller_namespace=$4

secrets_file="env/${namespace}.secrets.yaml"
values_file="env/${namespace}.values.yaml"
tmp_secret_file="$(mktemp)"

if [[ ! -f "$secrets_file" ]]; then
    echo "⚠️  No secrets file found for $namespace. Skipping."
    exit 0
fi

# iterate over keys in secrets file
for key in $(yq e 'keys | .[]' "$secrets_file"); do
    val=$(yq e ".${key}" "$secrets_file")
    echo -n "$val" >"$tmp_secret_file"

    encrypted=$(kubeseal \
        --raw \
        --name="$fullname" \
        --namespace="$namespace" \
        --controller-name="$controller_name" \
        --controller-namespace="$controller_namespace" \
        --from-file="$tmp_secret_file")

    yq e -i ".secret.${key} = \"$encrypted\"" "$values_file"
done

rm -f "$tmp_secret_file"
echo "✅ Updated $values_file"
```

Make it executable:

```bash
chmod +x scripts/encrypt.sh
```

---

# 🪝 Updated Pre-Commit Hook

Now the hook just calls the script (no duplicated logic):

```bash
#!/usr/bin/env bash
set -euo pipefail

APP_NAME="your-app"
CONTROLLER_NAME="sealed-secrets"
CONTROLLER_NAMESPACE="kube-system"
ENVS="ci qa prod"

for ns in $ENVS; do
    ./scripts/encrypt.sh $ns $APP_NAME $CONTROLLER_NAME $CONTROLLER_NAMESPACE
done

git add env
```

---

# 🚀 Usage

### Developer Workflow

```bash
# Encrypt secrets and stage changes
git commit -m "Update secrets"
```

### CI/CD Workflow

```bash
# Encrypt secrets (regenerate values files)
make encrypt

# Audit for correctness
make audit

# Deploy across environments
make deploy
```

---

# 🧩 Benefits

* **Single source of truth** (`scripts/encrypt.sh`) for both dev hooks and CI.
* **Audit step** ensures only valid sealed secrets exist before deploy.
* Easy `make encrypt && make deploy` workflow in pipelines.
* Developers don’t need to know `kubeseal` details — automation does the work.

##

