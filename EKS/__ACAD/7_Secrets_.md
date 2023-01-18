# Secret Management
Kubernetes is un-opinionated about how secrets are managed. There's many ways to do it and there's no one-size-fits-all solution. Here's some ways people are doing GitOps secrets:

* [Bitnami Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
* [GoDaddy Kubernetes External Secrets](https://github.com/godaddy/kubernetes-external-secrets)
* [External Secrets Operator](https://github.com/external-secrets/external-secrets)
* [Hashicorp Vault](https://www.vaultproject.io)
* [Banzai Cloud Bank-Vaults](https://github.com/banzaicloud/bank-vaults)
* [Helm Secrets](https://github.com/jkroepke/helm-secrets)
* [Kustomize secret generator plugins](https://github.com/kubernetes-sigs/kustomize/blob/fd7a353df6cece4629b8e8ad56b71e30636f38fc/examples/kvSourceGoPlugin.md#secret-values-from-anywhere)
* [secret-manager-operator](https://github.com/endclothing/secret-manager-operator)
* [KSOPS](https://github.com/viaduct-ai/kustomize-sops#argo-cd-integration)
* [secrets-store-csi-driver-provider-gcp](https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp) 

[External Secrets Operator (ESO) vs Secrets Store Container Storage Interface (CSI) Driver (SSCSID)](https://github.com/external-secrets/external-secrets/issues/478#issuecomment-964413129):

* ESO synchronizes secrets from a cloud provider to secrets in k8s, so you can keep using k8s secrets if you are used to that.
* SSCSID mounts the external secret as a volume in a pod directly, and having a k8s secret in the cluster is optional
* ESO focuses on having configuration on the CRD, what you create on the secret store in the provider is only the secret value itself
* SSCSID requires the entire config/secret to be stored in the provider directly as the application will need to consume it. This may be too difficult to use with larger configurations that have some secrets embedded.
* ESO secrets can be used with any resource in k8s natively, that's obvious, but 👇
* SSCSID  needs a pod webhook to really have it work well. You can not easily use SSCSID secrets to reference them in ingress, or dockerconfig for pulling images, since their goal is just to mount to a pod. Even if you want to enable k8s secret sync, you need to first mount the secret to a pod to sync it.
* In ESO, Since we sync secrets with k8s native secrets, if you have connectivity problems, you can still access the secret that is present in your cluster, when you re-connect, it will just continue to re-sync
* with SSCSID, if you loose connectivity, your csi driver mounts stop working if you get some restarts and all that. They are thinking about that, not sure what is the progress there: [doc](https://docs.google.com/document/d/1qAm_D3UflpmSn7J8QV1gxvbmv5RDX6hw8v2mvYfKBfc/edit#heading=h.1a54pwicbu4n). You would need to check with them.
* ESO will be just one operator deployment in your cluster
* SSCSID will have a privileged provider daemonset that will be responsible to make the mounts in your pods

If you need to follow any compliance and need to avoid having kubernetes native secrets in your cluster, you need to go with SSCSID, then you can mount secrets from external provider directly as volumes in your pods. If you don't need that, you can probably give ESO a go.

We have in our roadmap the plan to integrate with them: #336

We have some discussions going: #461

---

For discussion, see [#1364](https://github.com/argoproj/argo-cd/issues/1364)
It is at least also perhaps noting in that document that the [argoproj-labs/argocd-vault-plugin](https://github.com/argoproj-labs/argocd-vault-plugin) supports not only HashiCorp Vault, but also GCP Secret Manager, AWS Secrets Manager, Azure Key Vault, and IBM Cloud Secrets Manager.

I found that there was a pretty good write up on using [external secrets](https://external-secrets.io/) with ArgoCD in this [Kubernetes External Secrets](https://blog.oddbit.com/post/2021-09-03-kubernetes-external-secrets/) article. It also had a few helpful opinions based on their experience with other solutions:

> There were some minor disadvantages:
> 
> - We can’t install ArgoCD via the operator because we need a customized image that includes KSOPS, so we have to maintain our own ArgoCD image.
> 
> And there was one major problem:
> 
> - Using GPG-encrypted secrets in a git repository makes it effectively impossible to recover from a key compromise.
> Once a private key is compromised, anyone with access to that key and the git repository will be able to decrypt data in historical commits, even if we re-encrypt all the data with a new key.
> 
> Because of these security implications, we decided we would need a different solution (it’s worth noting here that Bitnami Sealed Secrets suffers from effectively the same problem).
> 

Both [external secrets](https://external-secrets.io/) and [argoproj-labs/argocd-vault-plugin](https://github.com/argoproj-labs/argocd-vault-plugin) tools are looking to solve the same problem but in different ways. 

+ [argoproj-labs/argocd-vault-plugin](https://github.com/argoproj-labs/argocd-vault-plugin) works as plugin to Argo CD or CLI tool  to help inject secrets into Kubernetes Secret manifests with special annotations so it can find them and then update the manifests in place using a templating system.

+ [external secrets](https://external-secrets.io/) makes use of Custom Resources and an Operator to generate a Kubernetes Secret from the provided Custom Resource.






How to keep your Kubernetes secrets secure in Git

Published in September 2019
How to keep your Kubernetes secrets secure in Git

Welcome to Bite-sized Kubernetes learning — a regular column on the most interesting questions that we see online and during our workshops answered by a Kubernetes expert.

    Today's answers are curated by Omer Levi Hevroni. DevSecOps engineer at Soluto Engineering. OWASP member.

If you wish to have your question featured on the next episode, please get in touch via email or you can tweet us at @learnk8s.

Did you miss the previous episodes? You can find them here.

Kubernetes secrets hold the most sensitive information of your application - API keys, tokens, database passwords, etc.

If a hacker can retrieve one of these secrets, they could connect to your database without you even noticing it.

It's crucial to ensure that those secrets are stored as securely as possible.

Let's recap on how secrets work in Kubernetes.
Secrets in Kubernetes

Secrets are objects that contain key-value pairs and some metadata.

Secrets are similar to ConfigMaps and share the same limitations (1MB in size — as an example).

The main differences are the security protections added to Secrets.

This is how a secret looks like in the YAML representation:

secret.yaml

apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=
  password: MWYyZDFlMmU2N2Rm

You can create a secret like any other Kubernetes object (usually with kubectl).

The manifest will be sent to the server that will proceed it and store it in etcd - similarly to all Kubernetes objects.

So why did the Kubernetes team decided to "encrypt" the secrets using base64?

As you might already know, base64 is an encoding, not an encryption.

Encoding allows you to represent binary data in a secret manifest.

Imagine storing a certificate in Kubernetes without base64: a lot of "���" — unrecognised characters.

Base64 translates those binaries files in standard strings such as aGVsbG8gdGhlcmUh==.

But we still haven't answered how to secure those secrets properly.

In Kubernetes, you can opt-in to encryption at rest: by enabling this feature, Kubernetes API encrypts the secrets (optionally, using an external KMS system) before storing them in etcd.

    When you create a Secret with kubectl create -f secret.yaml, Kubernetes stores it in etcd.
    1/4

    When you create a Secret with kubectl create -f secret.yaml, Kubernetes stores it in etcd.
    Next 

You solved the issue of storing sensitive files such as certificates inside the cluster.

You also protected your secrets at rest with a suitable encryption provider.

Is your cluster finally secure?

Perhaps.

However, the secrets that you load into the cluster must exist somewhere.

Do you keep a copy or rely on Kubernetes to be the only source of truth?

How do you back them up?

What if you keep a copy and they go out of sync?
Storing secrets in Git

You could store the secrets with the other manifests files - for example, in Git.

That could solve most of the challenges related to secret management:

    You get a full audit history for free thanks to Git
    You can reuse the same merging strategy and approve changes to your secrets as you do with the rest of the code
    Your code and your secrets are kept in sync at all times

But can you secure the secrets in Git?

Can anyone who has access to the repository run away with your precious credentials?

Some existing tools let you create "encrypted secrets" that can be stored on Git alongside the rest of the deployment files.

The tools also provide a mechanism to decrypt back to regular secrets so your app can consume them seamlessly.

Let's discuss some of them.
Sealed Secretes

A successful project in this space is Sealed Secrets.

Sealed secrets has two parts: an operator deployed into your cluster and a command-line tool designed to interact with it called kubeseal.

You can install the operator with:

bash

kubectl apply -f \
  https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.8.1/controller.yaml

You can install the command-line tool (on macOS) with:

bash

brew install kubeseal

    For other operating systems, use the releases pages and download the relevant executable.

When the operator starts, it generates a private and public key.

The private key stays in the cluster, but you can retrieve the public key with the kubeseal CLI:

bash

kubeseal --fetch-cert > mycert.pem

Once you have the public key, you can encrypt all your secrets.

Storing the public key and the secrets in the repository are safe, even if the repo is public, as the public key is used only for encryption.

The mechanism described above is usually called asymmetric encryption.

If you're interested in learning more about it, you can do so here.

Assuming you have a secret in JSON format like this:

mysecret.json

{
    "kind": "Secret",
    "apiVersion": "v1",
    "metadata": {
        "name": "mysecret",
        "creationTimestamp": null
    },
    "data": {
        "foo": "YmFy"
    }
}

You can encrypt the secret with:

bash

kubeseal <mysecret.json >mysealedsecret.json

The new file contains a Custom Resourced Definition (CRD):

mysealedsecret.json

{
  "kind": "SealedSecret",
  "apiVersion": "bitnami.com/v1alpha1",
  "metadata": {
    "name": "mysecret",
    "namespace": "default",
    "creationTimestamp": null
  },
  "spec": {
    "template": {
      "metadata": {
        "name": "mysecret",
        "namespace": "default",
        "creationTimestamp": null
      }
    },
    "encryptedData": {
      "foo": "<encrypted data here>"
    }
  }
}

You can use the above file to create a SealedSecret in your cluster.

bash

kubectl create -f mysealedsecret.json

The operator is watching for resources.

As soon as it finds a SealedSecret, it uses the private key to decrypt the values and create a standard Kubernetes secret.

You can verify that the secret was created successfully with:

bash

kubectl get secrets mysecret -o yaml

    Please notice that the secret created by the operator has the same name as the SealedSecret.

You can use the Secrets in your Pods to inject environment variables or mount them as files.

Since you can only decrypt the secrets with the private key (and that is safely stored in the cluster), you can sleep sweet dreams.

Also, Kubeseal supports secrets rotation.

You can generate a new public and private key and re-encrypt your secrets.

There are some downsides to consider, though:

    First, you can't see what's inside the secret. Every time you want to add a new value, you might need to re-encrypt all values or create a separate secret. In Git, you will see the content of the secret changed in full. It's hard to tell if a single entry or all them changed.
    Second, Sealed Secret use one key pair to encrypt all your secrets. Also, the key is kept inside the cluster - without any additional protection (for example, using Hardware Security Model).

There are alternative tools to Sealed Secrets that address those two shortcomings.
Helm Secrets

While the underlying mechanism to secure the secrets is similar to Sealed Secrets, there are some noteworthy differences.

Helm secrets is capable of leveraging Helm to template secrets resources.

If you work in a large team with several namespaces and you use Helm already, you might find Helm secrets more convenient than Sealed secrets.

Helm secret has another advantage over Sealed Secrets - it's using the popular open-source project SOPS (developed by Mozilla) for encrypting secrets.

SOPS supports external key management systems, like AWS KMS, making it more secure as it's a lot harder to compromise the keys.

With that said, Helm Secrets and Sealed Secrets share the same issues - to use them, you must have permissions to decrypt the secrets.

If you work as part of a small team this could be a minor issue.

However, if you want to reduce your blast radius, you might not want to hand over the keys to your secrets to every DevOps and Developer in your team.

Also, Helm Secrets is a Helm plugin, and it is strongly coupled to Helm, making it harder to change to other templating mechanisms such as kustomize.

You can learn more about Helm secrets on the official project page.
Kamus

    Full disclosure - the author is the lead developer.

The architecture is similar to Sealed Secrets and Helm Secrets. However, Kamus lets you encrypt a secret for a specific application, and only this application can decrypt it.

The more granular permissions make Kamus more suitable to zero-trust environments with a high standard of security.

Kamus works by associating a service account to your secrets.

Only applications running with this service account are allowed to decrypt it.

You can install Kamus in your cluster with the official Helm chart:

bash

helm repo add soluto https://charts.soluto.io
helm upgrade --install kamus soluto/kamus

And you can install the Kamus CLI with:

bash

npm install -g @soluto-asurion/kamus-cli

You can create a secret with the Kamus CLI:

bash

kamus-cli encrypt \
  --secret super-secret \
  --sa kamus-example-sa \
  --namespace default \
  --kamus-url <Kamus URL>

The output is the encrypted secret.

You can store the value safely your repository even if public.

Only the Kamus API has the private key to decrypt it.

To use the secret in your app, you need to add a particular init container to your pod.

The init container is responsible for reading the secrets, decrypting them and producing files in various formats.

Your application can then consume this file to consume the decrypted secrets.

Being able to encrypt and store one secret at the time is convenient if you gradually need to add more secrets to your app.

You can find more examples of how to use Kamus on the official project page.
Summary

Storing and managing secrets in Kubernetes isn't only about enabling encryption at rest.

You should have a strategy for

    Loading secrets into the cluster safely and securely. After all, the secrets are created externally and then migrated to the cluster.
    Keeping a single and trusted source of truth for your secrets. So you don't risk having secrets out of sync.
    Having an audit history of who changed the secret and for what reason.

Tools such as Sealed Secrets, Helm Secrets and Kamus are designed to help you keep your secrets in Git so that you can leverage existing coding practices without compromising on security.
