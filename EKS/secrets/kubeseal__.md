

Kubeseal & SealedSecret: Make your ‘secrets’ secure in SCM by using ‘sealed secret’
Sandeep Kumar

·
Follow
##
#
https://siddhivinayak-sk.medium.com/kubeseal-sealedsecret-make-your-secrets-secure-in-scm-by-using-sealed-secret-4631bcb39bf8
#
##




Introduction
In applications, a ‘secret’ is a sensitive data which has been used in application and it requires ‘implied level of security’ to protect the secrets for example: passwords, keys and token etc. Almost every web application needs secrets to perform business cases. From application development perspective, usually some design principal followed; most advocated design principal is “Keep low degree of coupling and high degree of cohesion” means reduce dependencies while write code among components. To adopt this design principal, the configurations are externalized from the code and kept in separate flat files called ‘configuration files’ like: YAML, properties, conf files etc. This externalization of configuration also brings idea of storing secrets apart from the code.

There are several ways of storing such secrets e.g. for Java based application ‘Key Stores’ can be used to store secrets, Key Vaults can be used in Cloud, Encrypted configurations can be used. Below are important ways to store secrets:

Flat File based Configuration: It is very conventional way of storing secrets, keys in flat file based configuration files like conf, YAML, properties files etc. In this way of storing secrets are highly prone to attack as secrets are stored in plain flat file based configuration files.
Encrypted Configuration: It adds just an additional process over Flat File based configuration. The content stored in configuration file is encrypted which implements the security for secrets, keys, certs stored in configuration file. There are certain frameworks available for implementing encrypted configuration like Jsypt. Read more about Jsypt implementation.
Keystore: Java provides a local storage of secrets, keys, certificates by using a file based secure storage mechanism called ‘keystore’. It allows to store secrets, keys, certificates very easily with keytool and Java APIs.
Key Vaults: A specialized application build only for storing secrets, keys, certificates called ‘Key Vaults’. Key Vaults are available from different vendors. Each Cloud provider has a Key Vault product which provides secure storage for secrets e.g. Azure provides ‘Azure Key Vault’. Some Vaults also supports hardware backed data encryption security mechanism (called Hardware Security Module — HSM) to provide additional security level for secrets and keys.
Similar to Vaults, Kubernetes (also called K8s) also provides an object to store opaque secrets, certs and private keys. However, it is not considered much secure compared to specialized vaults because Kubernetes secrets are by default stored unencrypted in API server’s underlying data store (etcd). Anyone with API access can retrieve and modify a Kubernetes secret. Also, these secrets can be used in by different objects like Pods (by mounting to path similar to Kubernetes ConfigMap).

In Kubernetes, the objects (K8s objects like ConfigMap, Secrets, Deployment, Pod etc.) created by YAML based declarative configuration. And Source Code Management (SCM) tools like Git, SVN etc. are used to store the source codes & declarative configurations (e.g. K8s YAMLs) for the application source code to maintain the version control, code sharing, release & tagging. In this case, the declarative configuration (K8s YAML) for creating Kubernetes Secrets also need to be stored in SCM. This will expose the ‘secret’ to all the users who have access to code in SCM.


Figure 1: Depicts Secret stored in SCM as declarative YAML which is used to create Secrets in K8s Cluster
Although, this is not problem in case of lower environments (like Development, SIT, UAT) but for higher environment like Production this also need to be protected from everyone (including developers, testers etc.). This will create a requirement of having a mechanism to protect the secrets stored in SCMs.

To solve this requirement, Bitnami Lab provides a utility called ‘SealedSecret & Kubeseal’. SealedSecret / Kubeseal & its use case has been discussed in subsequent section.

About SealedSecret & Kubeseal
SealedSecret & Kubeseal is an extension on Kubernetes Secret by Bitnami Labs as Sealed-Secret component. It adds an additional encryption layer on secret declarative YAML configuration which then can stored to any SCM. The immediate accessor will not get the actual secret’s value by reading it.

The Sealed-Secret is installed in K8s cluster and serve the secret encryption flow. The flow is very simple, encrypt the secret and create a new K8s object called SealedSecret.

SealedSecret: A SealedSecret is an object in Kubernetes (available once Bitnami Labs Sealed-Secret installed) which is extension on K8s Secret and which stores encrypted Secrets.

The Kubeseal has below two major components:

kubeseal Utility: It is an utility which is used for creating SealedSecret declarative YAML form K8s Secret declarative YAML. It is distributed for different OSs and used as client while creating SealedSecret YAML.
sealed-secret-controller Server-Side Component: It is a server-side component which is installed on Kubernetes cluster. Normally, it is installed in kube-system namespace but can be installed on other namespaces as well. It can be installed by using Helm. When it is installed, other K8s components are also created e.g. A K8s deployment, replicaset, service and pod.
Below diagram covers the complete flow of Kubeseal / SealedSecret:


Figure 2: Complete Flow of SealedSecret / Kubeseal
Below are steps involved in creating SealedSecret and store in Source Code Management (SCM) tool:

First K8s Secret declarative YAML is created -> Then Kubeseal utility is used to encrypt it (it internally fetch the public key from sealed-secret-controller and encrypt the values in YAML) and create a new format called SealedSecret -> This SealedSecret declarative YAML is stored in SCM.

Whenever Secret need to be created at the K8s Cluster, need to perform below steps:

The declarative YAML for SealedSecret is checked out from SCM -> Create object in Cluster using kubectl create -f <YAML file> -> A sealedsecret object is created (using kubectl get sealedsecret command, it can be enquired) -> When it is created in K8s, the sealed-secret-controller decrypt the SealedSecret and create K8s Secret with original values (in decrypted form).

Since encrypted Secret values (in form of SealedSecret) stored in SCM, if anyone accessed the SCM, no problem he/she does not have the actual secret value.

Here, sealed-secret is using Public/Private key for encryption and decryption of secret values. Which is created as Secret in K8s and used in Sealed-Secret-Controller.

Additionally, the sealing key rotation is also supported in SealedSecret.

SealedSecret can also support scopes:

cluster-wide — It defines the scope of sealedsecret wheresealedsecret can be used across the namespaces in cluster
namespace-wide — It defines the scope of sealedsecret where sealedsecret for namespaces. sealedsecret created for one namespace cannot be used to another namespace.
The implementation has been discussed in subsequent section.

Use Case
To create a use case of SealedSecret & Kubeseal, we need to have a Kubenetes (k8s) Cluster. If you have a full-fledged cluster then ok else can install Docker Desktop or minikube to spin off single node cluster for testing purpose. So ensure you have a cluster and kubectl installed and targeting to the cluster.

Kubeseal

Install the kubeseal utility from where you wanted to connect to the K8s Cluster. Ideally same machine where kubectl installed.

Kubeseal is available for multiple platforms like:

Download kubeseal from Link which is appropriate to you machine. [Note: Download latest release]
Place at the path so that it can be accessible form command prompt. [Note: environment variables can be used to set path]
Apart from binary download, it can be installed from:

Using Homebrew:

brew install kubeseal
Using MacPorts on MacOS:

port install kubeseal
Using NixPkgs on Nix environment:

nix-env -iA nixpkgs.kubeseal
On Linux:

wget https://github.com/bitnami-labs/sealed-secrets/releases/download/<release-tag>/kubeseal-<version>-linux-amd64.tar.gz
tar -xvzf kubeseal-<version>-linux-amd64.tar.gz kubeseal
sudo install -m 755 kubeseal /usr/local/bin/kubeseal
Sealed-Secret

The Bitnami Labs has provided Helm package to install SealedSecret. To install SealedSecret on K8s cluster, we will be using Helm package manager.

First check the latest release of Sealed-Secret from release page: https://github.com/bitnami-labs/sealed-secrets/releases

Add Bitnami Labs’s Helm chart repository to your local helm:

helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm repo update
Install Sealed-Secret by running below Helm command:

helm install sealed-secrets -n kube-system --set-string fullnameOverride=sealed-secrets-controller sealed-secrets/sealed-secrets
The above command will install the Sealed-Secret. After installation, below command can be used to check the deployment status:

helm list -n kube-system
or
helm status -n kube-system sealed-secrets
It will show result like:

NAME: sealed-secrets
LAST DEPLOYED: Thu Oct  6 12:52:20 2022
NAMESPACE: kube-system
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
** Please be patient while the chart is being deployed **
You should now be able to create sealed secrets.
1. Install the client-side tool (kubeseal) as explained in the docs below:
https://github.com/bitnami-labs/sealed-secrets#installation-from-source
2. Create a sealed secret file running the command below:
```
kubectl create secret generic secret-name --dry-run=client --from-literal=foo=bar -o [json|yaml] | \
    kubeseal \
      --controller-name=sealed-secrets-controller \
      --controller-namespace=kube-system \
      --format yaml > mysealedsecret.[json|yaml]
The file mysealedsecret.[json|yaml] is a commitable file.
If you would rather not need access to the cluster to generate the sealed secret you can run:
kubeseal \
      --controller-name=sealed-secrets-controller \
      --controller-namespace=kube-system \
      --fetch-cert > mycert.pem
to retrieve the public cert used for encryption and store it locally. You can then run 'kubeseal --cert mycert.pem' instead to use the local cert e.g.
kubectl create secret generic secret-name --dry-run=client --from-literal=foo=bar -o [json|yaml] | \
    kubeseal \
      --controller-name=sealed-secrets-controller \
      --controller-namespace=kube-system \
      --format [json|yaml] --cert mycert.pem > mysealedsecret.[json|yaml]
4. Apply the sealed secret
kubectl create -f mysealedsecret.[json|yaml]
Running 'kubectl get secret secret-name -o [json|yaml]' will show the decrypted secret that was generated from the sealed secret.
Both the SealedSecret and generated Secret must have the same name and namespace.
Now Sealed-Secret and Kubectl installed. Next need to create SealedSecret on the K8s cluster.

Create a K8s Secret declarative YAML. Run below command to create it:
kubectl create secret generic mysecret-1 --dry-run=client --from-literal=dbpassword=password -o yaml
It will generate content which need to be saved in a YAML file:

apiVersion: v1
data:
  dbpassword: cGFzc3dvcmQ=
kind: Secret
metadata:
  creationTimestamp: null
  name: mysecret-1
Note: Mark the value of secret in previous command, it was a literal ‘password’ but when Secret YAML is generated value is encoded in Base64. When creating manually, make sure the value is in Base64 in Secret declarative YAML.

2. Generate SealedSecret YAML using SecretYAML by using kubeseal utility. Below command can be run to generate SealedSecret YAML:

kubeseal --controller-name=sealed-secrets-controller --controller-namespace=kube-system --format yaml --secret-file mysecret-1.yaml > mysealedsecret-1.yaml
Or

kubeseal --controller-name=sealed-secrets-controller --controller-namespace=kube-system --format yaml --secret-file mysecret-1.yaml --sealed-secret-file mysealedsecret-1.yaml
It will create a file named mysealedsecret-1.yaml with below content (the declarative YAML for SealedSecret):

apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  creationTimestamp: null
  name: mysecret-1
  namespace: default
spec:
  encryptedData:
    dbpassword: AgATNyCUi2FN59/bjWVc+KoWwZ97RPaYvQU/UWny02Ucjuhkrb8bC27ans9Q3eqFQwcQ3YOw5LcPA/H3tej5Bh2C+bHybkqH5uVW6I+zSQlsgsbhJ6M2aMxPC5kC0X5NFNcOjqwg7C0HNFcO5ri0y9TiTnRYKEpPNDC6aIEQPgAAzO8hxznPfjTnIZUNkHHlyIMfWTZ3fxylkDApLRkE7yyTcAkpt3ahOyOUNBu/Q6uoFRjYawFDZnzmkuCLElBnCNvXUgrEHKHLzyVXgH2eohf3H6mDqwEYw531o+qDHMd4B7UwWMQxcYajrV9GNpNxy6Or1cSNBm8D1Z4JnJCRQoMOYoh4NF+R9HxOLD24Pv8gyNQ/HFpCdimm9YKd0MlYfmgGasRFIX/q1lfTkzIhdb+J4LvQTcRkvB6JzPwB9YDGlRgSsoYBoDAMGx8Ehl2pxFymWn79A8WrfYABYFW+wo6W5xCVszr6nc1MGHwS2P+chKtRF0vpYbNW70ShO55HE8a9IlGZG6xTHtPA4WoCKvcy1TEuwuwq1KuWxzoMHSqvNbmnKB2Kj68W7+nn+sXEnJDC1h8AAUYVnnq8TUVgJUjaJ4Dc/9D6u7pdxuMl9McYfpnwSl3EGjT+CmlP6ps8AZokTKCZl+ZsBXScLrvdAZLobYeESW5UxczdBwcCVpBN9L+kmfn+E3uNVnlSNAc9hxggxW7PfQLYGQ==
  template:
    data: null
    metadata:
      creationTimestamp: null
      name: mysecret-1
      namespace: default
You can see the value has been encrypted using public key available in Cluster and it will only be decrypted by cluster so it is safe to store in SCM.

Now, we have SealedSecret declarative YAML file which can be used to create SealedSecret in K8s.
```
3. Create SealedSecret in K8s. Run below command to create Sealed Secret in K8s:
```
kubectl create -f mysealedsecret-1.yaml
Note: Sealed-Secret-Controller has been created in kube-system namespace but SealedSecret has been created without namespace explicitly means it has been created for default namespace.

Along with SealedSecret creation in K8s, the controller also created Secret with original value.

Let’s enquire the SealedSecret by below command:

kubectl get sealedsecret
Result:
NAME         AGE
mysecret-1   3m26s
Enquire K8s Secret by below command:

kubectl get secret
Result:
NAME         TYPE     DATA   AGE
mysecret-1   Opaque   1      4m16s
Check the content of mysecret-1 K8s Secret by running below command:

kubectl get secret mysecret-1 -o yaml
It will result:

apiVersion: v1
data:
  dbpassword: cGFzc3dvcmQ=
kind: Secret
metadata:
  creationTimestamp: "2022-10-06T07:44:38Z"
  name: mysecret-1
  namespace: default
  ownerReferences:
  - apiVersion: bitnami.com/v1alpha1
    controller: true
    kind: SealedSecret
    name: mysecret-1
    uid: e5606492-a8e3-449b-a9c5-9a1e27685f74
  resourceVersion: "797829"
  uid: 2af5efd6-d076-4ad5-91ec-b697fe8af110
type: Opaque
```

Now this Secret can be used in application’s Pod.

Additionally, one can fetch the cert using kubeseal :

kubeseal --controller-name=sealed-secrets-controller --controller-namespace=kube-system --fetch-cert > mycert.pem
It will generate a file named mycert.pem whcih contains Base64 version of certificate. It can also be used to generated SealedSecret from K8s secrets by using kubeseal :

kubeseal --controller-name=sealed-secrets-controller --controller-namespace=kube-system --format yaml --secret-file mysecret-1.yaml --sealed-secret-file mysealedsecret-1.yaml --cert mycert.pem
That’s all!

Conclusion
Security is a collective responsibility so each stakeholder should think by keeping security in mind. So even the source code repository is private for developers it should not contain secrets in plain text (un-encrypted).

SealedSecret is a good extension on Kubernetes Secret which make the secret’s values encrypted which can be stored easily in any Source Code Management (SCM) tool like GitHub, BitBucket, GitLab, SVN etc. Since values are encrypted and can only be decrypted by the Cluster’s sealed-secret-controller it is also possible to make source repository as public.

Reference
SealedSecret GitHub — https://github.com/bitnami-labs/sealed-secrets
Download Kubeseal — https://github.com/bitnami-labs/sealed-secrets/releases/tag/v0.18.5
