
Install ECK using the Helm chart

##
#
https://www.elastic.co/guide/en/cloud-on-k8s/master/k8s-install-helm.html
#
##

Starting from ECK 1.3.0, a Helm chart is available to install ECK. It is available from the Elastic Helm repository and can be added to your Helm repository list by running the following command:

helm repo add elastic https://helm.elastic.co
helm repo update

The minimum supported version of Helm is 3.2.0.
Cluster-wide (global) installation
edit

This is the default mode of installation and is equivalent to installing ECK using the stand-alone YAML manifests.

helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace

Restricted installation
edit

This mode avoids installing any cluster-scoped resources and restricts the operator to manage only a set of pre-defined namespaces.

Since CRDs are global resources, they still need to be installed by an administrator. This can be achieved by:

helm install elastic-operator-crds elastic/eck-operator-crds

The operator can be installed by any user who has full access to the set of namespaces they wish to manage. The following example installs the operator to elastic-system namespace and configures it to manage only namespace-a and namespace-b:

helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace \
  --set=installCRDs=false \
  --set=managedNamespaces='{namespace-a, namespace-b}' \
  --set=createClusterScopedResources=false \
  --set=webhook.enabled=false \
  --set=config.validateStorageClass=false

The eck-operator chart contains several pre-defined profiles to help you install the operator in different configurations. These profiles can be found in the root of the chart directory, prefixed with profile-. For example, the restricted configuration illustrated in the previous code extract is defined in the profile-restricted.yaml file, and can be used as follows:

helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace \
  --values="${CHART_DIR}/profile-restricted.yaml" \
  --set=managedNamespaces='{namespace-a, namespace-b}'

You can find the profile files in the Helm cache directory or from the ECK source repository.
View available configuration options
edit

You can view all configurable values by running the following:

helm show values elastic/eck-operator

Migrate an existing installation to Helm
edit

Migrating an existing installation to Helm is essentially an upgrade operation and any caveats associated with normal operator upgrades are applicable. Check the upgrade documentation before proceeding.

You can migrate an existing operator installation to Helm by adding the meta.helm.sh/release-name, meta.helm.sh/release-namespace annotations and the app.kubernetes.io/managed-by label to all the resources you want to be adopted by Helm. You must do this for the Elastic Custom Resource Definitions (CRD) because deleting them would trigger the deletion of all deployed Elastic applications as well. All other resources are optional and can be deleted.

A shell script is available in the ECK source repository to demonstrate how to migrate from version 1.7.1 to Helm. You can modify it to suit your own environment.

For example, an ECK 1.2.1 installation deployed using the quickstart guide can be migrated to Helm as follows:

    Annotate and label all the ECK CRDs with the appropriate Helm annotations and labels. CRDs need to be preserved to retain any existing Elastic applications deployed using the operator.

    for CRD in $(kubectl get crds --no-headers -o custom-columns=NAME:.metadata.name | grep k8s.elastic.co); do
        kubectl annotate crd "$CRD" meta.helm.sh/release-name="$RELEASE_NAME"
        kubectl annotate crd "$CRD" meta.helm.sh/release-namespace="$RELEASE_NAMESPACE"
        kubectl label crd "$CRD" app.kubernetes.io/managed-by=Helm
    done

    Uninstall the current ECK operator. You can do this by taking the operator.yaml file you used to install the operator and running kubectl delete -f operator.yaml. Alternatively, you could delete each resource individually.

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

    	

    If you have previously customized the operator configuration in this ConfigMap, you will have to repeat the configuration once the operator has been reinstalled in the next step.
    Install the ECK operator using the Helm chart as described in Install ECK using the Helm chart.

