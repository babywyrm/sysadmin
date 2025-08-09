


### 🐙 The GitOps Upgrade: Managing Helm with Kustomize ..beta..

When your Helm chart is not managed by direct `helm` commands but is instead part of a declarative GitOps workflow (using tools like Argo CD or Flux), the entire upgrade paradigm shifts. Your Git repository becomes the single source of truth. You no longer *tell* the cluster what to do; you *declare* the desired state in Git, and a controller in the cluster works to make it so.

This approach is more robust, repeatable, and auditable, but it requires a different set of procedures for an upgrade.

#### 🏛️ Understanding the Declarative Structure

Your repository is likely organized with a `bases` and `overlays` (or `environments`) structure. This allows you to define the core application once and then apply environment-specific tweaks.

```
.
├── bases/
│   └── wordpress/
│       ├── kustomization.yaml  # <-- Defines the Helm chart source, version, and base values.
│       └── values.yaml         # <-- Base values shared by all environments.
└── environments/
    ├── staging/
    │   ├── kustomization.yaml  # <-- Points to the base, adds staging-specific patches.
    │   └── patch-values.yaml   # <-- Overrides for staging (e.g., lower replica count, debug flags).
    └── production/
        ├── kustomization.yaml  # <-- Points to the base, adds production-specific patches.
        └── patch-values.yaml   # <-- Overrides for production (e.g., higher replicas, custom domain).
```

The upgrade process primarily involves modifying files in the `bases/wordpress` directory and then promoting those changes through your environments.

---

### 📝 Step-by-Step Kustomize Upgrade Process

#### 1. Pre-Flight: Research and Local Validation

Before touching any files, do your homework.

*   **Identify Target Versions:** Go to the chart source (e.g., Artifact HUB for Bitnami charts) and find the target chart version and the corresponding application version (the image tag).
    *   **Target Chart Version:** `24.2.11`
    *   **Target App Version (Image Tag):** `6.8.1-debian-12-r6`

*   **Review Chart Changes:** Read the changelog between your current chart version and the target version. Look for breaking changes, such as renamed values in `values.yaml` or significant architectural shifts.

*   **Local Validation (Highly Recommended):** Use the `kustomize` CLI to render the final YAML manifests locally. This allows you to catch syntax errors or templating issues *before* you commit.
    ```bash
    # Install kustomize if you haven't already
    # From the root of your git repo:
    kustomize build environments/staging > staging-manifests.yaml
    ```
    Inspect the output file `staging-manifests.yaml` to see what Kustomize *would* apply to the cluster.

#### 2. Declarative Upgrade: Modifying the Base

You will now edit the core definition of your WordPress application.

*   **File to Edit:** `bases/wordpress/kustomization.yaml`
    *   **Action:** Update the `version` field under `helmCharts` to the new target chart version.

    **Before:**
    ```yaml
    # bases/wordpress/kustomization.yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization
    helmCharts:
      - name: wordpress
        repo: https://charts.bitnami.com/bitnami
        version: 23.1.16 # <-- OLD CHART VERSION
        releaseName: wordpress-release
        valuesFile: values.yaml
    ```

    **After:**
    ```yaml
    # bases/wordpress/kustomization.yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization
    helmCharts:
      - name: wordpress
        repo: https://charts.bitnami.com/bitnami
        version: 24.2.11 # <-- NEW CHART VERSION
        releaseName: wordpress-release
        valuesFile: values.yaml
    ```

*   **File to Edit:** `bases/wordpress/values.yaml`
    *   **Action:** Update the `image.tag` to the new application version that corresponds with the new chart version. This is the most common step people forget.

    **Before:**
    ```yaml
    # bases/wordpress/values.yaml
    image:
      registry: docker.io
      repository: bitnami/wordpress
      tag: 6.6.2-debian-12-r4 # <-- OLD APP VERSION
    # ... other base values
    ```

    **After:**
    ```yaml
    # bases/wordpress/values.yaml
    image:
      registry: docker.io
      repository: bitnami/wordpress
      tag: 6.8.1-debian-12-r6 # <-- NEW APP VERSION
    # ... other base values
    ```

#### 3. The Trigger: Commit and Push to Git

This is the declarative equivalent of `helm upgrade`. By pushing to the branch your GitOps controller is watching, you initiate the process. Best practice is to upgrade `staging` first.

```bash
# Create a new branch for the upgrade
git checkout -b feat/upgrade-wordpress-to-24.2.11

# Add your changes
git add bases/wordpress/kustomization.yaml bases/wordpress/values.yaml

# Commit with a descriptive message
git commit -m "feat(wordpress): Upgrade chart to 24.2.11 and app to 6.8.1"

# Push the branch and create a Pull Request
git push origin feat/upgrade-wordpress-to-24.2.11
```
After the PR is reviewed and merged into your `staging` or `main` branch, the GitOps controller takes over.

#### 4. The Reconciliation Loop: Monitor the GitOps Controller

Your GitOps tool will detect the change and start the reconciliation process.

*   **Argo CD:** In the UI, the application will show as `OutOfSync`. Click the "Sync" button (or wait for auto-sync) and watch the resources update. The logs for the `argocd-application-controller` pod will provide detailed information.
*   **Flux:** The `Kustomization` object will be reconciled automatically. You can watch the progress with `flux get kustomizations --watch` and check logs with `flux logs deployment/kustomize-controller`.

#### 5. Post-Flight: Verification

Once the sync is complete, use `kubectl` to verify the upgrade was successful, just as you would in the imperative guide. Check pod versions, service endpoints, and application functionality.

---

### 🚨 Handling Issues in a Kustomize Workflow

The underlying Kubernetes issues are the same, but how you see and solve them is different.

**Issue 1: StatefulSet Immutability Error**

*   **Symptom:** The GitOps sync will fail repeatedly. The controller's logs or the Argo CD UI will clearly show the `StatefulSet.apps ... is invalid` error. The system is stuck because it cannot apply the change.
*   **Solution:** This requires a temporary manual intervention to unblock the declarative process.
    1.  **Pause Reconciliation:** In your GitOps tool, temporarily disable auto-sync for the application to prevent the controller from fighting you.
    2.  **Perform Manual Deletion:** Run the `kubectl delete` command on your workstation to remove the blocking resource while leaving its pods running.
        ```bash
        kubectl delete statefulset [RELEASE_NAME]-mariadb --cascade=orphan
        ```
    3.  **Trigger Manual Sync:** Go back to your GitOps tool and trigger a manual sync.
        *   **Argo CD:** Click the "Sync" button.
        *   **Flux:** Run `flux reconcile kustomization [kustomization-name]`.
    4.  **Resume Reconciliation:** Once the sync succeeds, re-enable auto-sync.

**Issue 2: The "Nuclear Option" in GitOps**

You don't run `helm uninstall`. Instead, you declaratively state that the application should no longer exist for a given environment.

*   **Action:** Edit the `kustomization.yaml` for the specific environment (e.g., `environments/staging/kustomization.yaml`) and remove the WordPress base from its `resources` list.

    **Before:**
    ```yaml
    # environments/staging/kustomization.yaml
    resources:
      - ../../bases/wordpress # <-- WordPress is a resource
    # ... patches
    ```

    **After:**
    ```yaml
    # environments/staging/kustomization.yaml
    resources:
      # - ../../bases/wordpress # <-- Comment out or delete this line
    # ... patches
    ```
*   **Result:** When you commit and push this change, the GitOps controller will see that all the WordPress resources are no longer in the desired state and will perform a `kubectl delete` on all of them (respecting the default behavior of leaving PVCs intact).

### 📊 Comparison: Imperative vs. Declarative Workflow

| Task | Imperative (`helm`) | Declarative (`kustomize` + GitOps) |
| :--- | :--- | :--- |
| **Trigger Upgrade** | Run `helm upgrade ...` command from your terminal. | `git commit` and `git push` changes to the repository. |
| **Update Chart Version** | Use the `--version` flag in the `helm` command. | Edit the `version` field in `kustomization.yaml`. |
| **Update Image Tag** | Use the `--set image.tag=...` flag. | Edit the `tag` field in `values.yaml`. |
| **View Changes** | Use `helm diff` plugin or `--dry-run --debug`. | Create a Pull Request to review changes before merging. |
| **Troubleshooting** | Check `helm history` and `kubectl` events. | Check GitOps controller logs and UI for sync errors. |
| **Rollback** | Run `helm rollback [RELEASE_NAME] [REVISION]`. | `git revert` the commit and push again. |
| **Source of Truth** | The live state of the Helm release in the cluster. | The state of the YAML files in the Git repository. |
