

Kubeseal & SealedSecret: Make your ‘secrets’ secure in SCM by using ‘sealed secret’
Sandeep Kumar

·
Follow
##
#
https://siddhivinayak-sk.medium.com/kubeseal-sealedsecret-make-your-secrets-secure-in-scm-by-using-sealed-secret-4631bcb39bf8
#
https://medium.com/@josephsims1/secure-your-kubernetes-cluster-e2ddc3a09eb0
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



###
###



Securing Your Kubernetes Cluster’s Secrets With Sealed Secrets
Joseph Whiteaker
Joseph Whiteaker

·
Follow

8 min read
·
Jul 21, 2024





Sealed Secrets offer a practical solution for managing Kubernetes secrets in a GitOps workflow. Storing secrets directly in Git poses significant security risks, whereas manually adding secrets to the cluster undermines the benefits of GitOps — where the goal is to avoid imperative commands, whether during initial setup or ongoing operations.


Bitnami Labs — Creators of Sealed Secrets
The Sealed Secrets resource allows you to safely store secrets in Git. When you apply a “SealedSecret” custom resource to the cluster, it converts into a standard Kubernetes secret. This approach ensures that your secrets are managed declaratively, maintaining the integrity and principles of GitOps.

Before diving into a simple demo of Sealed Secrets, it’s crucial to ensure your environment is properly set up, especially if you’re using Windows. Here are the steps to get started:

Enable WSL: If you are on Windows, make sure you are running your commands in Windows Subsystem for Linux (WSL). You will also need to enable Docker for wsl within Rancher Desktop or Docker Desktop.

2. Kubernetes Setup: Ensure Kubernetes is active. You could have a local cluster running through Rancher Desktop, Docker Desktop, or a kind cluster.

Now, let’s proceed with the installation of Sealed Secrets:

Open Your Linux Distro: Use PowerShell to switch to your default Linux distribution:
wsl ~
2. Create a Directory: This directory will be used for our project files:

mkdir SealedSecretSpike
3. Add Helm Repository: Add the Sealed Secrets Helm repository to your Helm configuration:

helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
4. Install Sealed Secrets: Install the Sealed Secrets Helm chart into the sealed-secrets namespace with a custom name for the controller:

helm install sealed-secrets -n sealed-secrets --set-string fullnameOverride=sealed-secrets-controller sealed-secrets/sealed-secrets
These steps set the stage for working with Sealed Secrets in your Kubernetes environment.

With the Sealed Secrets controller installed in your Kubernetes cluster, the next step is to install the kubeseal CLI on your local machine. Since kubeseal does not run natively on Windows, we'll use WSL (Windows Subsystem for Linux) for this setup. Here’s how to install kubeseal:

Create an Installation Script: Below is a script to install the kubeseal CLI. Save it as install-sealedsecret.sh:
```
#!/bin/bash

# Set the version of kubeseal
KUBESEAL_VERSION='0.27.0'
INSTALL_DIR="$HOME/bin"

# Check if kubeseal is already installed
if [ -x "$INSTALL_DIR/kubeseal" ]; then
  echo "kubeseal is already installed in $INSTALL_DIR"
  exit 0
fi

# Create the installation directory if it doesn't exist
mkdir -p "$INSTALL_DIR"

# Download the specified version of kubeseal
curl -OL "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz"

# Extract the kubeseal binary from the downloaded tar.gz file
tar -xvzf kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz kubeseal

# Move the kubeseal binary to the installation directory
mv kubeseal "$INSTALL_DIR/kubeseal"

# Clean up the downloaded tar.gz file
rm kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz

# Confirm installation
kubeseal --version

# Add the installation directory to the PATH in .bashrc if it's not already there
if ! grep -q "$INSTALL_DIR" ~/.bashrc; then
  echo "export PATH=\$PATH:$INSTALL_DIR" >> ~/.bashrc
fi

# Set environment variables for Sealed Secrets
if ! grep -q "export SEALED_SECRETS_CONTROLLER_NAME=" ~/.bashrc; then
  echo "export SEALED_SECRETS_CONTROLLER_NAME=sealed-secrets" >> ~/.bashrc
fi

if ! grep -q "export SEALED_SECRETS_CONTROLLER_NAMESPACE=" ~/.bashrc; then
  echo "export SEALED_SECRETS_CONTROLLER_NAMESPACE=sealed-secrets" >> ~/.bashrc
fi
```
# Refresh the bash session to apply changes
source ~/.bashrc
2. Run the Script: Make the script executable and run it:

chmod +x install-sealedsecret.sh
./install-sealedsecret.sh
Once you have kubeseal installed, you can create a Sealed Secret from a Kubernetes secret as follows:

Create a Secret File: Save the following YAML to a file named secret.yaml:
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: secret-namespace
type: Opaque
data:
  username: dXNlcm5hbWU=   # Base64 encoded 'username'
  password: cGFzc3dvcmQ=   # Base64 encoded 'password'
2. Seal the Secret: Use kubeseal to create a Sealed Secret:

kubeseal -f secret.yaml -w sealed-secret.yaml
This creates a file named sealed-secret.yaml, which you can safely store in your Git repository. The contents of this file include encrypted data, ensuring that your sensitive information remains secure while still adhering to GitOps principles.

---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  creationTimestamp: null
  name: my-secret
  namespace: secret-namespace
spec:
  encryptedData:
    password: AgAshIeLGpn2B3c9ktWq2CLMBRMlyiH/3sZ8/8se8ZAsRqmr5zOs11kE4jWBsA288kAWiYVBNYjJbSNgg4VFRGsAn0MeRIT3eaEkNf/zzVJXeiLozc68JBLJSpJ60hD+2C6Vy5ah2sNPtnuPftosu3+MNuj9MGgKdm9ruJ2CvdGj25eDT6rxTrE6HWMnziOz+vXXZsEX7I7el/fAIwiDLDC/QftqPtlfHa7XDGSNOx/HAa7Ci18u2nji31GueqKW77ZwllaqMcjyTmN/MZ7Z+J8ATFJUwQHIjeuFdzXjMfrn2054T4MaC+FfJSW/EnlLE68NnCmgvTe/FF9WXfqGPYg16EDlfTLGEpIXyACqskBOaflLh1Q/b+nbFPkE2uzm+59/i5DmXBu4jPiiATvDqyjr5yHjGoxSKDteTIUojndYjOGEfU0mdRKQAdnBTWtMpWteuWGEWTNqyRekHi16Vyei8QeAiwjdKCSxMXEhVP3AOrdj4E3bcZ5q5Oq5yNSFhJEgzdopESGqTbpwwo0AqQ7nkU3ZpwL+Bsp2wc4XLQXag34n1O0iBiqz/hjxKznvYRiWAaI3oY1kxY5H4EIPsMaBnakZDRKYBt6+rmkOZ5VNJcngch9rCcjZv2qPiVyRJ7Yj2q2HQQXpANwqndXFlgoiZA1ReW5VkUn7craE6hw686tSuioFa1QbGwTxhunf0u7NJZfgP9Lv/g==
    username: AgAaxACRmL8qy6NE9EKf/SCPwwoaK8VYH/soOxOvswRhWOJtfiJBDeIGqrTk8ve+um4HQ4rQmpO0XQz/Bs7783i0C03VlPALgHGLaQZxrxa8CLgQ7jM7n7pMZEikAnEs7fzKsdOFvD5tTQAd/IPMW+jcI6Y+0ETOAMvpyTjk2+5XZz6pxZS7PEzTD/xoZImEissS8J/kEPd/eOZTpxue5Pa1AS5SMJoyhSr94ukKhCTEpIyTzLVrx24pDPDymYxNMcNEPWv/wNSn9QmG1Efy4azvKFxg4UYEQIec7208HZfAj2u3x36ir3G6TkQK2d5bXmqF62GCnQzhl1+cLNxRUBuIVB4DgxbCTggs04d9t5uGoUruzdBU/voGQCe60mCYWUe2ETky9P5U5RYCtkYWwFRWBbrATXIWwkwO8NRS24zYGFJhAGD4pYZsZ3KztrPbLd7YOH+dlc+ITIrIO2QgfzmeYmbrkfInqzD5s3Ofj7L4gqABsNjBD5rwknxD89Ct3dlC5R87/p2tmniMTGsvy1Pr3Kwv18rSnZchjJMNA9opFRmit08qBnDBy54lSsiMz3UcB1FT61Sz3XjeFCvVhXIxbXKxpja7b07gBKTjPJlsvP3I1pxBo+Z6EEhJ8WT/Sa/jOOhWgDEmKY3lHx8joPAUlrw66VMQ7AT0UGVwUv4sGm0eDuAgZxbbTZBR2nH0rebmecItEmrJSA==
  template:
    metadata:
      creationTimestamp: null
      name: my-secret
      namespace: secret-namespace
    type: Opaque
To convert a Sealed Secret back to a regular Kubernetes Secret, you can use the following script, which makes the process smooth and efficient:

Create the Script: Save the following script as unseal-secret.sh to automate the extraction and conversion process:
#!/bin/bash

# Define file paths
SEALED_SECRET_FILE="sealed-secret.yaml"
RECOVERED_SECRET_FILE="recovered-secret.yaml"
SEALED_SECRETS_KEY_YAML_FILE="sealed-secrets-key.yaml"
SEALED_SECRETS_KEY_PEM_FILE="sealed-secrets-key.pem"

# Extract the Sealed Secrets private key (requires admin privileges)
kubectl get secret -n sealed-secrets -l sealedsecrets.bitnami.com/sealed-secrets-key -o yaml > $SEALED_SECRETS_KEY_YAML_FILE

# Verify the key file was created
if [ ! -s $SEALED_SECRETS_KEY_YAML_FILE ]; then
    echo "Failed to extract the Sealed Secrets private key"
    exit 1
fi

# Decode the base64-encoded private key to a PEM file
KEY=$(kubectl get secret -n sealed-secrets -l sealedsecrets.bitnami.com/sealed-secrets-key -o jsonpath="{.items[0].data['tls\.key']}")
echo $KEY | base64 --decode > $SEALED_SECRETS_KEY_PEM_FILE

# Verify the PEM file was created
if [ ! -s $SEALED_SECRETS_KEY_PEM_FILE ]; then
    echo "Failed to create the PEM file from the extracted key"
    exit 1
fi

# Optional: Output the extracted PEM key for debugging
echo "Extracted PEM key:"
cat $SEALED_SECRETS_KEY_PEM_FILE

# Recover the original secret from the sealed secret using the private key
kubeseal --recovery-unseal --recovery-private-key $SEALED_SECRETS_KEY_PEM_FILE -f $SEALED_SECRET_FILE -o yaml > $RECOVERED_SECRET_FILE

# Verify the recovered secret was created
if [ ! -s $RECOVERED_SECRET_FILE ]; then
    echo "Failed to recover the original secret"
    exit 1
fi

# Output the recovered secret
echo "Recovered Secret:"
cat $RECOVERED_SECRET_FILE

# Clean up private key files
rm $SEALED_SECRETS_KEY_YAML_FILE $SEALED_SECRETS_KEY_PEM_FILE
2. Execute the Script: Make the script executable and run it:

chmod +x unseal-secret.sh
./unseal-secret.sh
This script extracts the private key used by the Sealed Secrets controller, decodes it, and then uses it to recover the original secret from the sealed secret file, resulting in a recovered-secret.yaml. This file will contain the original secret data, like so:

---
apiVersion: v1
data:
  password: cGFzc3dvcmQ=
  username: dXNlcm5hbWU=
kind: Secret
metadata:
  creationTimestamp: null
  name: my-secret
  namespace: secret-namespace
  ownerReferences:
  - apiVersion: bitnami.com/v1alpha1
    controller: true
    kind: SealedSecret
    name: my-secret
    uid: ""
type: Opaque
Now, your secrets can be stored and managed in Git without exposing sensitive information, thanks to the encryption provided by Sealed Secrets. This approach significantly enhances security in a GitOps workflow.

While Sealed Secrets offers a robust way to manage secrets within a GitOps workflow, it’s true that it might not be the ideal solution for every scenario. Here are some considerations and an alternative approach that might better suit certain environments:

Challenges with Sealed Secrets
Cluster Dependency: Sealed Secrets are inherently tied to the cluster because each cluster has its unique key pair. In a fleet of clusters, managing and synchronizing these keys across multiple clusters can become complex.
Key Rotation: If there is a need to rotate the private keys, all Sealed Secrets must be re-encrypted with the new key. This adds operational overhead and could potentially lead to errors or downtime.
Alternative: External Secrets Operator
An alternative to using Sealed Secrets is the External Secrets Operator. This operator allows Kubernetes to automatically inject secrets into your pods from external secret management systems like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault. This method avoids storing secrets in Git, even in an encrypted form, and reduces the dependency on cluster-specific keys.

How External Secrets Operator Works:
Secret Management: Secrets are managed externally and pulled into the Kubernetes environment as needed, without ever being stored in Git.
Reduced Coupling: The solution is less coupled to the specific cluster’s encryption keys, making it easier to manage in a fleet of clusters.
Dynamic Secret Rotation: Secrets can be rotated in the external system without any changes to the Kubernetes resources. (No overhead of managing sealed secrets manually)
Example Configuration:
Defining the Secret Store
First, you define a SecretStore that specifies how to connect to the external secrets provider, in this case, a Vault server:
```
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "http://my.vault.server:8200"
      path: "secret"
      version: "v2"
      auth:
        tokenSecretRef:
          name: "vault-token"
          key: "token"
Creating the Authentication Token
To authenticate with Vault, you create a Kubernetes Secret containing the Vault token:

apiVersion: v1
kind: Secret
metadata:
  name: vault-token
data:
  token: cm9vdA==  # Base64-encoded 'root'
Defining the External Secret
Then, you define an ExternalSecret which tells the operator what external data to fetch and how to present it as a Kubernetes Secret:

apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-example
spec:
  refreshInterval: "15s"
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: example-sync
  data:
  - secretKey: foobar
    remoteRef:
      key: foo
      property: my-value
  - secretKey: tags
    remoteRef:
      metadataPolicy: Fetch
      key: foo
  - secretKey: developer
    remoteRef:
      metadataPolicy: Fetch
      key: foo
      property: dev
```
This will create a Kubernetes Secret named example-sync:

kind: Secret
metadata:
  name: example-sync
data:
  foobar: czNjcjN0  # Base64-encoded secret data
This solution, while effective, isn’t without its imperfections. Notably, the secret store definition relies on vault credentials, which necessitates creating a secret that isn’t included in the repository. However, if the objective is to minimize the number of resources that aren’t defined within the cluster, maintaining just the essential credentials for the vault or a service principal to access Key Vault outside the repo is a manageable compromise.

What if we use Sealed Secrets to manage the Vault or Azure credentials and store them in the repository?
While this approach could be feasible, it’s important to remember the limitations of Sealed Secrets I mentioned earlier. Sealed Secrets are specific to a single cluster and don’t translate well across a fleet of clusters. Therefore, this method doesn’t fully address the underlying issue.

Don’t forget a backup strategy for the manually created secrets
When using Sealed Secrets, it’s crucial to back up the secrets created by the tool. A recommended practice is to use a backup solution like Velero to save these secrets to a storage account. This approach ensures that if your cluster goes down and you need to create a new one, you will have access to the original private key. This key is essential for decrypting and resealing the secrets in the new cluster.

Similarly, if you’re using the External Secrets Operator, it’s wise to also use Velero to back up the cloud credentials used by your secret store to a storage account. In the event that your cluster is wiped, you can quickly restore functionality by extracting and reapplying the secret files from the storage account. Once the credentials are restored in the cluster, you can use tools like Helm and Argo to reconnect to your original repository and resume operations.

In Conclusion, sealed Secrets provide a robust framework for managing Kubernetes secrets within a GitOps workflow. This method not only enhances security by enabling secrets to be stored in Git repositories without compromising sensitive information but also aligns with the principles of declarative configuration and automated management. By integrating Sealed Secrets into your Kubernetes setup, you ensure that all aspects of your environment, including secret management, remain within the realm of version-controlled and automated processes. Whether you choose to stick strictly with Sealed Secrets or incorporate the External Secrets Operator for broader secret management strategies, the foundation laid out in this introduction will help maintain the security and integrity of your cluster. Remember, regardless of the method, backing up your secrets is critical to avoid potential disruptions and ensure a smooth recovery process when needed.

Sealed Secret

