# Installing ECK Using Helm Charts (Updated)



## Prerequisites

- Helm version 3.2.0 or later
- Kubernetes cluster access with appropriate permissions

## Adding the Elastic Helm Repository

Add the Elastic Helm repository to your Helm configuration:

```bash
helm repo add elastic https://helm.elastic.co
helm repo update
```

## Installation Options

### Cluster-Wide Installation

This is the default installation mode, equivalent to using the stand-alone YAML manifests:

```bash
helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace
```

### Restricted Installation

This mode avoids installing cluster-scoped resources and restricts the operator to manage only specified namespaces.

First, an administrator must install the CRDs (which are global resources):

```bash
helm install elastic-operator-crds elastic/eck-operator-crds
```

Then, users with appropriate permissions can install the operator with restricted settings:

```bash
helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace \
  --set=installCRDs=false \
  --set=managedNamespaces='{namespace-a, namespace-b}' \
  --set=createClusterScopedResources=false \
  --set=webhook.enabled=false \
  --set=config.validateStorageClass=false
```

### Using Pre-defined Profiles

The eck-operator chart includes pre-defined profiles for different configurations. For example, you can use the restricted profile:

```bash
helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace \
  --values="${CHART_DIR}/profile-restricted.yaml" \
  --set=managedNamespaces='{namespace-a, namespace-b}'
```

You can find profile files in the Helm cache directory or the ECK source repository.

## Viewing Configuration Options

To view all configurable values:

```bash
helm show values elastic/eck-operator
```

## Migrating an Existing Installation to Helm

Migrating from an existing installation is essentially an upgrade operation. Review the upgrade documentation before proceeding.

To migrate, you need to add Helm-specific annotations and labels to resources for Helm to manage them properly, particularly the Elastic Custom Resource Definitions (CRDs).

### Migration Steps

1. Annotate and label ECK CRDs to preserve existing Elastic applications:

```bash
for CRD in $(kubectl get crds --no-headers -o custom-columns=NAME:.metadata.name | grep k8s.elastic.co); do
    kubectl annotate crd "$CRD" meta.helm.sh/release-name="$RELEASE_NAME"
    kubectl annotate crd "$CRD" meta.helm.sh/release-namespace="$RELEASE_NAMESPACE"
    kubectl label crd "$CRD" app.kubernetes.io/managed-by=Helm
done
```

2. Uninstall the current ECK operator:

```bash
kubectl delete -n elastic-system \
    serviceaccount/elastic-operator \
    secret/elastic-webhook-server-cert \
    clusterrole.rbac.authorization.k8s.io/elastic-operator \
    clusterrole.rbac.authorization.k8s.io/elastic-operator-view \
    clusterrole.rbac.authorization.k8s.io/elastic-operator-edit \
    clusterrolebinding.rbac.authorization.k8s.io/elastic-operator \
    service/elastic-webhook-server \
    configmap/elastic-operator \ 
    statefulset.apps/elastic-operator \
    validatingwebhookconfiguration.admissionregistration.k8s.io/elastic-webhook.k8s.elastic.co
```

3. If you had customized the operator configuration in the ConfigMap, note that you'll need to re-apply these configurations after reinstallation.

4. Install the ECK operator using the Helm chart as described in the installation sections above.

A sample migration script is available in the ECK source repository that demonstrates migration from version 1.7.1 to Helm.
