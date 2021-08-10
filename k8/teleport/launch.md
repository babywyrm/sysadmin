
###############
###############

https://goteleport.com/docs/kubernetes-access/getting-started/

###############
###############

Step 1/3. Install Teleport
Let's start with a single-pod Teleport using persistent volume as a backend.

Open Source
Enterprise
helm repo add teleport https://charts.releases.teleport.dev

# Install a single node teleport cluster and provision a cert using ACME.
# Set clusterName to unique hostname, for example tele.example.com
# Set acmeEmail to receive correspondence from Letsencrypt certificate authority.
helm install teleport-cluster teleport/teleport-cluster --create-namespace --namespace=teleport-cluster \
  --set clusterName=${CLUSTER_NAME?} --set acme=true --set acmeEmail=${EMAIL?}
Teleport's helm chart uses an external load balancer to create a public IP for Teleport.

Open Source
Enterprise
# Set kubectl context to the namespace to save some typing
kubectl config set-context --current --namespace=teleport-cluster

# Service is up, load balancer is created
kubectl get services
# NAME               TYPE           CLUSTER-IP   EXTERNAL-IP      PORT(S)                        AGE
# teleport-cluster   LoadBalancer   10.4.4.73    104.199.126.88   443:31204/TCP,3026:32690/TCP   89s

# Save the pod IP. If the IP is not available, check the pod and load balancer status.
MYIP=$(kubectl get services teleport-cluster -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $MYIP
# 192.168.2.1
Set up two A DNS records - tele.example.com for UI and *.tele.example.com for web apps using application access.

GCP Cloud DNS
AWS Route 53
MYZONE="myzone"
MYDNS="tele.example.com"

gcloud dns record-sets transaction start --zone="${MYZONE?}"
gcloud dns record-sets transaction add ${MYIP?} --name="${MYDNS?}" --ttl="30" --type="A" --zone="${MYZONE?}"
gcloud dns record-sets transaction add ${MYIP?} --name="*.${MYDNS?}" --ttl="30" --type="A" --zone="${MYZONE?}"
gcloud dns record-sets transaction describe --zone="${MYZONE?}"
gcloud dns record-sets transaction execute --zone="${MYZONE?}"
The first request to Teleport's API will take a bit longer because it gets a cert from Let's Encrypt. Teleport will respond with discovery info:

curl https://tele.example.com/webapi/ping

# {"server_version":"6.0.0","min_client_version":"3.0.0"}
Step 2/3. Create a local admin
Local users are a reliable fallback for cases when the SSO provider is down. Let's create a local admin alice who has access to Kubernetes group system:masters.

Save this role as member.yaml:

kind: role
version: v3
metadata:
  name: member
spec:
  allow:
    # This field is used for SSH logins. You have to keep 'logins' as a non-empty random value
    # for Kubernetes to work until we fix it.
    logins: ['keep-this-value-here']
    kubernetes_groups: ["system:masters"]
Create the role and add a user:

# To create a local user, we are going to run Teleport's admin tool tctl from the pod.
POD=$(kubectl get po -l app=teleport-cluster -o jsonpath='{.items[0].metadata.name}')

# Create a role
kubectl exec -i ${POD?} -- tctl create -f < member.yaml

# Generate an invite link for the user.
kubectl exec -ti ${POD?} -- tctl users add alice --roles=member

# User "alice" has been created but requires a password. Share this URL with the user to
# complete user setup, link is valid for 1h:

# https://tele.example.com:443/web/invite/random-token-id-goes-here

# NOTE: Make sure tele.example.com:443 points at a Teleport proxy which users can access.
Let's install tsh and tctl on Linux. For other install options, check out install guide

Open Source
Enterprise
curl -L -O https://get.gravitational.com/teleport-v6.2.7-linux-amd64-bin.tar.gz
tar -xzf teleport-v6.2.7-linux-amd64-bin.tar.gz
sudo mv teleport/tsh /usr/local/bin/tsh
sudo mv teleport/tctl /usr/local/bin/tctl
Try tsh login with a local user. Use a custom KUBECONFIG to prevent overwriting the default one in case there is a problem.

KUBECONFIG=${HOME?}/teleport.yaml tsh login --proxy=tele.example.com:443 --user=alice
Teleport updated KUBECONFIG with a short-lived 12-hour certificate.

# List connected Kubernetes clusters
tsh kube ls

# Output
Kube Cluster Name Selected
----------------- --------
tele.example.com

# Login to Kubernetes by name
tsh kube login tele.example.com

# Output
Kube Cluster Name Selected
----------------- --------
tele.example.com  *

# Once working, remove the KUBECONFIG= override to switch to teleport
KUBECONFIG=${HOME?}/teleport.yaml kubectl get -n teleport-cluster pods
NAME                                READY   STATUS    RESTARTS   AGE
teleport-cluster-6c9b88fd8f-glmhf   1/1     Running   0          127m
Step 3/3. SSO for Kubernetes
We are going to setup Github connector for OSS and Okta for Enterprises version.

Open Source
Enterprise
Save the file below as github.yaml and update the fields. You will need to set up Github OAuth 2.0 Connector app. Any member belonging to the Github organization octocats and on team admin will be able to assume a built-in role access.

kind: github
version: v3
metadata:
  # connector name that will be used with `tsh --auth=github login`
  name: github
spec:
  # client ID of Github OAuth app
  client_id: client-id
  # client secret of Github OAuth app
  client_secret: client-secret
  # This name will be shown on UI login screen
  display: Github
  # Change tele.example.com to your domain name
  redirect_url: https://tele.example.com:443/v1/webapi/github/callback
  # Map github teams to teleport roles
  teams_to_logins:
    - organization: octocats # Github organization name
      team: admin            # Github team name within that organization
      # map github admin team to Teleport's "access" role
      logins: ["access"]
To create a connector, we are going to run Teleport's admin tool tctl from the pod.

Open Source
Enterprise
# To create a Github connector, we are going to run Teleport's admin tool tctl from the pod.
kubectl config set-context --current --namespace=teleport-cluster
POD=$(kubectl get po -l app=teleport-cluster -o jsonpath='{.items[0].metadata.name}')

kubectl exec -i ${POD?} -- tctl create -f < github.yaml
# authentication connector "github" has been created
Try tsh login with Github user. I am using a custom KUBECONFIG to prevent overwriting the default one in case there is a problem.

Open Source
Enterprise
KUBECONFIG=${HOME?}/teleport.yaml tsh login --proxy=tele.example.com:443 --auth=github
DEBUGGING SSO
If you are getting a login error, take a look at the audit log for details:

kubectl exec -ti "${POD?}" -- tail -n 100 /var/lib/teleport/log/events.log

# {"error":"user \"alice\" does not belong to any teams configured in \"github\" connector","method":"github","attributes":{"octocats":["devs"]}}


###########################
##
##
