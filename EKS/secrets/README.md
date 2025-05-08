
# Bitnami Sealed Secrets Guide

This guide explains how to use Bitnami Sealed Secrets to store Kubernetes secrets in Git repositories without directly exposing sensitive data. 
Refactored and enhanced with additional options and examples.

> **Warning:** Storing secrets in Git repositories is generally not advised—use Sealed Secrets to safely encrypt them before committing.

---

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Sealing Secrets](#sealing-secrets)
- [Options and Variations](#options-and-variations)
- [Reporting and Verification](#reporting-and-verification)
- [Further Reading](#further-reading)

---

## Introduction

Bitnami Sealed Secrets lets you safely commit encrypted Kubernetes secrets to Git. In a GitOps workflow, your CI/CD tool (like Argo CD or Flux) then applies these secrets to your cluster while keeping the original secret values hidden.

---

## Prerequisites

- **Kubernetes Cluster**: Have a running cluster (local or cloud).
- **kubectl CLI**: Installed and configured to interact with your cluster.
- **kubeseal CLI**: Download from [Bitnami Sealed Secrets Releases](https://github.com/bitnami-labs/sealed-secrets/releases).

---

## Setup

1. **Deploy the Sealed Secrets Controller**

   Apply the Sealed Secrets controller YAML to your cluster:

   ```bash
   kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.13.1/controller.yaml
   ```

2. **Verify the Controller Deployment**

   Verify that the controller is running:

   ```bash
   kubectl get pods -n kube-system -l app=sealed-secrets-controller
   ```

---

## Sealing Secrets

### Create and Seal a Secret

Use `kubectl` to create your secret locally and output it as JSON:

```bash
kubectl --namespace default create secret generic mysecret \
    --dry-run=client \
    --from-literal foo=bar \
    --output json
```

Pipe the JSON output to `kubeseal` to create the sealed secret YAML:

```bash
kubectl --namespace default create secret generic mysecret \
    --dry-run=client \
    --from-literal foo=bar \
    --output json | kubeseal | tee mysecret.yaml
```

Finally, create the sealed secret in your cluster:

```bash
kubectl create -f mysecret.yaml
```

---

## Options and Variations

You can customize various parameters when creating and sealing secrets:

### 1. Specify a Different Namespace

When creating a secret, adjust the namespace:

```bash
kubectl --namespace my-namespace create secret generic mysecret \
    --dry-run=client \
    --from-literal foo=bar \
    --output json | kubeseal --namespace my-namespace | tee mysecret.yaml
```

### 2. Using Multiple Literals or Files

To add multiple key/value pairs or load data from a file:

```bash
kubectl --namespace default create secret generic mysecret \
    --dry-run=client \
    --from-literal foo=bar \
    --from-file=password=./secret.txt \
    --output json | kubeseal | tee mysecret.yaml
```

### 3. Output Options

You can save the output to a file with a name you choose:

```bash
kubectl --namespace default create secret generic mysecret --dry-run=client \
    --from-literal foo=bar \
    --output json | kubeseal > sealed-mysecret.yaml
```

### 4. Fetching the Sealed Secrets Certificate

Sometimes you may need the controller's public certificate (to use in your CI/CD pipelines):

```bash
kubeseal --fetch-cert > pub-cert.pem
```

---

## Reporting and Verification

After deploying a sealed secret, you can verify and report its status:

### Verify the Secret in the Cluster

Get the secret in YAML format:

```bash
kubectl get secret mysecret --output yaml
```

Or in JSONPath to decode a base64-encoded value:

```bash
kubectl get secret mysecret --output jsonpath="{.data.foo}" | base64 --decode && echo
```

### Integration with GitOps / CI/CD

- **GitOps**: Commit the sealed secret YAML files to your repository. Tools like Argo CD or Flux CD will sync them with your cluster.
- **CI/CD**: Use the above commands as part of your automation pipeline to generate sealed secrets from plain-text values without manual intervention.

---

## Further Reading

- **Bitnami Sealed Secrets GitHub**: [https://github.com/bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)
- **GitOps Principles**: [What Is GitOps and Why Do We Want It?](https://youtu.be/qwyRJlmG5ew)
- **Argo CD Overview**: [Argo CD: Managing Production with GitOps](https://youtu.be/vpWQeoaiRM4)
- **Flux CD v2 with GitOps Toolkit**: [Flux CD v2 GitOps](https://youtu.be/R6OeIgb7lUI)

---



##
#
https://dev.to/stack-labs/store-your-kubernetes-secrets-in-git-thanks-to-kubeseal-hello-sealedsecret-2i6h
#
##

Store your Kubernetes Secrets in Git thanks to Kubeseal. Hello SealedSecret!
#kubernetes
#devops
#security
#git

In the Kubernetes world when we want to handle sensitive data the usage is to store it in a Secret in a Kubernetes cluster. Cool, but when we want to save our Secrets in our source code (Git) repositories, a security problem appears.
We will see in this article, a solution that can helps us ;-).
Kubernetes Secrets

Secrets in Kubernetes are used to store sensitive data, like password, keys, certificates and token. Secrets are encoded in base64 and automatically decoded when they are attached and read by a Pod.

Alt Text

Cool, so what's the problem?

/!\ Be careful:

Alt Text

A secret in Kubernetes cluster is encoded in base64 but not encrypted!

Theses data are "only" encoded so if a user have access to your secrets, he can simply base64 decode to see your sensitive data (kubectl get secret my-secret -o jsonpath="{.data.password}" | base64 -D for Mac and --decode instead of -D for Linux platform).

And suddenly, since the secrets aren't encrypted, it can be unsecure to commit them to your Git repository :-(.

In the DevOps world, we can build, test, package and deploy our applications and infrastructure through a CI (Continuous Integration) & CD (Continuous Delivery) pipeline but we can also handle this through GitOps (a way of managing all our configurations and infrastructure through code in Git repositories).

So if we want to store in Git repositories our Kubernetes manifests, a problem appears. And as usual, several solutions exists , and today in this article we will see one of them: kubeseal.
Encrypt/Seal your Secrets with Kubeseal

Secrets are cool but what about encrypted secrets with kubeseal?
The goal of kubeseal, a bitnami tool, is to encrypt your Kubernetes Secret into a SealedSecret.
Thanks to that, it will be safe to store in public Git repository.
The SealedSecret can be decrypted only by the controller running in the target cluster and nobody else.
Overview

Alt Text

As you can see in the schema, a sealed-secret-controller run in the Kubernetes cluster. He listens when a new SealedSecret object appears, unsealed it (thanks to known certificates) and create a Kubernetes secret in the same namespace as the SealedSecret.

Be careful, if you delete the SealedSecret in your cluster, the linked Secret will be deleted too.
Usage - Step by step

After the theory, it's time to see all the steps.
Let's split the steps in two parts: server and client part.
Server part

We will:

    deploy the sealed-secrets-controller in the cluster
    retrieve generated certificate keypair

1. Install SealedSecret CRD, server-side controller into kube-system namespace

$ kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.15.0/controller.yaml

NOTE: If you can't (or don't want) to use the kube-system namespace, please consider this approach.

NOTE: if you want to install it on a GKE cluster for which your user account doesn't have admin rights, please read this guide.

Once you deploy the YAML Kubernetes manifest file, it will create the SealedSecret resource and install the controller into kube-system namespace, create a service account and necessary RBAC roles.

After a few moments, the controller will start, generate a key pair, and be ready for operation.

Resources created:

$ kubectl get all -n kube-system
NAME                                             READY   STATUS    RESTARTS   AGE
...           1/1     Running   63         2d
pod/sealed-secrets-controller-123456-abcdef   1/1     Running   2          4d

NAME                                TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
service/sealed-secrets-controller   ClusterIP   xxx.xxx.xxx.xxx   <none>        8080/TCP   4d

NAME                                        DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/sealed-secrets-controller   1         1         1            1           4d

NAME                                                   DESIRED   CURRENT   READY   AGE
replicaset.apps/sealed-secrets-controller-123abc456def   1         1         1       4d

If the controller Pod is not in Running state, check its logs:

$ kubectl logs sealed-secrets-controller-123456-abcdef -n kube-system

2. Retrieves the certificate keypair generated by the controller at start:

$ kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secrets-key
NAME                       TYPE                DATA   AGE
sealed-secrets-key<ID>     kubernetes.io/tls   2      4d

$ kubectl get secret sealed-secrets-key<ID> -o yaml -n kube-system

apiVersion: v1
data:
  tls.crt: <encoded_crt>
  tls.key: <encoded_key>
kind: Secret
metadata:
  creationTimestamp: "2021-02-20T20:37:11Z"
  generateName: sealed-secrets-key
  labels:
    sealedsecrets.bitnami.com/sealed-secrets-key: active
  name: sealed-secrets-key<ID>
  namespace: kube-system
  resourceVersion: "123456"
  selfLink: /api/v1/namespaces/kube-system/secrets/sealed-secrets-key<ID>
  uid: abc123-45def-67gh-89ij-687vf6
type: kubernetes.io/tls

Here you can see tls.crt and tls.key data that you can base64 decode and store in your Vault or in your secret management tool.
Client part

We will:

    install needed CLI tools
    create a Kubernetes Secret
    seal it into a SealedSecret
    convert JSON to YAML file and clean it
    deploy it in the Kubernetes cluster
    check if everything have been deployed & created

0. Pre-requisites

Install following tools:

    Kubeseal

For MacOS you can install it via Brew:

$ brew install kubeseal

For others platform you can follow the installation guide.

    kubectl-neat (via Krew)

$ kubectl krew install neat

1. Create Kubernetes secret

$ kubectl create secret generic my-token --from-literal=my_token='123456789abc123def456ghi789' --dry-run=client -o yaml -n my-namespace > my-token.yaml

The YAML file should be like this:

$ cat my-token.yaml

apiVersion: v1
data:
  my_token: <a_token>
kind: Secret
metadata:
  creationTimestamp: null
  name: my-token
  namespace: my-namespace

Or you can create it also with Kustomize:

$ vi kustomization.yaml

namespace: my-namespace
secretGenerator:
- name: my-token
  literals:
  - my_token=<a_token>
generatorOptions:
  disableNameSuffixHash: true

$ kubectl kustomize . > my-token.yaml

2. Seal the secret (with the retrieved certificate)

$ kubeseal --cert tls.crt --format=yaml < my-token.yaml > mysealedtoken.yaml

The sealed YAML file should be like this:

apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  creationTimestamp: null
  name: my-token
  namespace: my-namespace
spec:
  encryptedData:
    my_token: <encrypted_token>
  template:
    metadata:
      creationTimestamp: null
      name: my-token
      namespace: my-namespace

3. Clean the YAML manifest file with "kubectl neat" command

$ kubectl neat -f mysealedtoken.yaml > mycleanedsealedtoken.yaml

The cleaned sealed secret YAML file should be like this:

apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-token
  namespace: my-namespace
spec:
  encryptedData:
    my_token: <encrypted_token>
  template:
    metadata:
      creationTimestamp: null
      name: my-token
      namespace: my-namespace
    type: Opaque

4. Deploy SealedSecret in the cluster

$ kubectl apply -f mycleanedsealedtoken.yaml -n my-namespace

5. Check in your cluster

You can check/verify in your Kubernetes cluster if the SealedSecret and Secret have been correctly deployed:

$ kubectl get sealedsecret -n my-namespace
NAME           TYPE       DATA    AGE
my-token      Opaque       1      4d

$ kubectl get secret -n my-namespace
NAME          AGE
my-token    4d

Ok, my Secret have been successfully created by the controller! :-)
Details

Be careful, the SealedSecret and Secret resources must have the same namespace and name. This is a feature to prevent other users on the same cluster from re-using your sealed secrets.
Debug

As you know, some issues can appear, so in order to debug/troubleshoot the behavior of the controller, you can watch their logs:

$ kubectl logs sealed-secrets-controller-<podID> -n kube-system

A possible issue is that you sealed the secret with another certificate than the ones the controller know ;-).
Conclusion

Store your sensitive data in a Kubernetes Secret object is a common practice, but don't forget that a Secret is only encoded and not encrypted. So if you want to store them in a Git Repository (in GitHub or Gitlab repositories for example), you'll need to find a secure solution. Kubeseal is one of them and I hope this article helps you to see that it can be a solution that you can try in your side.
