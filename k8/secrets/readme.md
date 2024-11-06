
##
#
https://medium.com/@abdullah.devops.91/how-to-use-sealed-secrets-in-kubernetes-b6c69c84d1c2
#
##

# How to use Kubernetes Secrets
### Create Kubernetes secrets using kubectl and --from-literal
The easiest ways to create the Kubernetes secret is by using the kubectl command and --from-literal flag. For example to understand Kubernetes secret creation we need three things.

- secret-name - test-secret
- username - test-user
- password - testP@ssword

```sh
kubectl create secret generic test-secret --from-literal=username=test-user --from-literal=password=testP@ssword
```
### Verify the secret using the following command
```sh
kubectl get secret test-secret
```
### Describe The Secret
```sh
kubectl describe secret test-secret
```
### Base64 Encoded Kubernetes Secrets
```sh
echo -n ‘test-user’ | base64
```
### Using Kubernetes Secrets In A Deployment (mysql)
Create a secret
```sh
apiVersion: v1
kind: Secret
metadata:
  name: mysql-test-secret
type: kubernetes.io/basic-auth
stringData:
  password: test1234
```
Create a deployment
```sh
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mysql
spec:
  selector:
    matchLabels:
      app: mysql
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: mysql
    spec:
      containers:
        - image: mysql
          name: mysql
          env:
            - name: MYSQL_ROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mysql-test-secret
                  key: password
          ports:
            - containerPort: 3306
              name: mysql
```

Secret Management

Kubernetes is un-opinionated about how secrets are managed. There's many ways to do it and there's no one-size-fits-all solution. Here's some ways people are doing GitOps secrets:

    Bitnami Sealed Secrets
    GoDaddy Kubernetes External Secrets
    External Secrets Operator
    Hashicorp Vault
    Banzai Cloud Bank-Vaults
    Helm Secrets
    Kustomize secret generator plugins
    secret-manager-operator
    KSOPS
    secrets-store-csi-driver-provider-gcp


##
#
https://gist.github.com/StevenACoffman/1f540900560af2878d4e24c914bd0224
#
##

    

External Secrets Operator (ESO) vs Secrets Store Container Storage Interface (CSI) Driver (SSCSID):

    ESO synchronizes secrets from a cloud provider to secrets in k8s, so you can keep using k8s secrets if you are used to that.
    SSCSID mounts the external secret as a volume in a pod directly, and having a k8s secret in the cluster is optional
    ESO focuses on having configuration on the CRD, what you create on the secret store in the provider is only the secret value itself
    SSCSID requires the entire config/secret to be stored in the provider directly as the application will need to consume it. This may be too difficult to use with larger configurations that have some secrets embedded.
    ESO secrets can be used with any resource in k8s natively, that's obvious, but 👇
    SSCSID needs a pod webhook to really have it work well. You can not easily use SSCSID secrets to reference them in ingress, or dockerconfig for pulling images, since their goal is just to mount to a pod. Even if you want to enable k8s secret sync, you need to first mount the secret to a pod to sync it.
    In ESO, Since we sync secrets with k8s native secrets, if you have connectivity problems, you can still access the secret that is present in your cluster, when you re-connect, it will just continue to re-sync
    with SSCSID, if you loose connectivity, your csi driver mounts stop working if you get some restarts and all that. They are thinking about that, not sure what is the progress there: doc. You would need to check with them.
    ESO will be just one operator deployment in your cluster
    SSCSID will have a privileged provider daemonset that will be responsible to make the mounts in your pods

If you need to follow any compliance and need to avoid having kubernetes native secrets in your cluster, you need to go with SSCSID, then you can mount secrets from external provider directly as volumes in your pods. If you don't need that, you can probably give ESO a go.

We have in our roadmap the plan to integrate with them: #336

We have some discussions going: #461

For discussion, see #1364 It is at least also perhaps noting in that document that the argoproj-labs/argocd-vault-plugin supports not only HashiCorp Vault, but also GCP Secret Manager, AWS Secrets Manager, Azure Key Vault, and IBM Cloud Secrets Manager.

I found that there was a pretty good write up on using external secrets with ArgoCD in this Kubernetes External Secrets article. It also had a few helpful opinions based on their experience with other solutions:

    There were some minor disadvantages:

        We can’t install ArgoCD via the operator because we need a customized image that includes KSOPS, so we have to maintain our own ArgoCD image.

    And there was one major problem:

        Using GPG-encrypted secrets in a git repository makes it effectively impossible to recover from a key compromise. Once a private key is compromised, anyone with access to that key and the git repository will be able to decrypt data in historical commits, even if we re-encrypt all the data with a new key.

    Because of these security implications, we decided we would need a different solution (it’s worth noting here that Bitnami Sealed Secrets suffers from effectively the same problem).

Both external secrets and argoproj-labs/argocd-vault-plugin tools are looking to solve the same problem but in different ways.

    argoproj-labs/argocd-vault-plugin works as plugin to Argo CD or CLI tool to help inject secrets into Kubernetes Secret manifests with special annotations so it can find them and then update the manifests in place using a templating system.

    external secrets makes use of Custom Resources and an Operator to generate a Kubernetes Secret from the provided Custom Resource.

