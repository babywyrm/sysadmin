
##
#
https://github.com/gravitational/teleport/discussions/13850#discussion-4171002
##
https://artifacthub.io/packages/helm/teleport-agent-kube/teleport-cluster
#
##



Teleport Cluster

This chart sets up a single node Teleport cluster. It uses a persistent volume claim for storage. Great for getting started with Teleport.

Important Notices
The chart version follows the Teleport version. e.g. chart v10.x can run Teleport v10.x and v11.x, but is not compatible with Teleport 9.x
Teleport does mutual TLS to authenticate clients. It currently does not support running behind a L7 LoadBalancer, like a Kubernetes Ingress. It requires being exposed through a L4 LoadBalancer (Kubernetes Service).
Getting Started
Single-node example
To install Teleport in a separate namespace and provision a web certificate using Let's Encrypt, run:

$ helm install teleport/teleport-cluster \
    --set acme=true \
    --set acmeEmail=alice@example.com \
    --set clusterName=teleport.example.com\
    --create-namespace \
    --namespace=teleport-cluster \
    ./teleport-cluster/
Finally, configure the DNS for teleport.example.com to point to the newly created LoadBalancer.

Note: this guide uses the built-in ACME client to get certificates. In this setup, Teleport nodes cannot be replicated. If you want to run multiple Teleport replicas, you must provide a certificate through tls.existingSecretName or by installing  and setting the highAvailability.certManager.* values.

Replicated setup guides
Creating first user
The first user can be created by executing a command in one of the auth pods.

kubectl exec it -n teleport-cluster statefulset/teleport-cluster-auth -- tctl users add my-username --roles=editor,auditor,access
The command should output a registration link to finalize the user creation.

Uninstalling
helm uninstall --namespace teleport-cluster teleport-cluster
Documentation
See  for guides on setting up HA Teleport clusters in EKS or GKE, plus a comprehensive chart reference.


##
##
