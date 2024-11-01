How to register Rancher managed Kubernetes clusters in Argo CD
Registering Rancher managed clusters in Argo CD doesn't work out of the box unless the Authorized Cluster Endpoint is used.
Many users will prefer an integration of Argo CD via the central Rancher authentication proxy (which shares the network endpoint of the Rancher API/GUI). 
So let's find out why registering clusters via Rancher auth proxy fails and how to make it work.

##
#
https://gist.github.com/janeczku/b16154194f7f03f772645303af8e9f80
#
https://gist.github.com/devops-school/7dbba2adb3933071dc15d44a82c4cd5c
#
##

Hint: If you are just looking for the solution scroll to the bottom of this page.

Why do i get an error when running argocd cluster add?
Service Account tokens and the Rancher authentication proxy
Registering external clusters to an Argo CD instance is normally accomplished by invoking the command-line tool argocd like this:

$ argocd cluster add <context-name>
Here, context-name references a context in the command-line user's kubeconfig file (by default ~/.kube/config).
Running this command using a context that points to a Rancher authentication proxy endpoint (typically an URL in the form https://<rancher-server-endpoint>/k8s/clusters/<cluster-id>) will result in the following error:

FATA[0001] rpc error: code = Unknown desc = REST config invalid: the server has asked for the client to provide credentials 
Ref: GH ticket

Before getting to the solution let's understand why this happens.

By default, the kubeconfig files provided by Rancher specify the Rancher server network endpoint as the cluster API server endpoint. By doing so Rancher acts as an authentication proxy that validates the user identity and then proxies the request to the downstream cluster.

This generally has a number of advantages compared to having clients communicating directly with the downstream cluster API endpoint:One of the is that this provides a high available Kubernetes API endpoint for all clusters under Rancher's management, sparing the ops team from having to maintain a failover/load-balancing mechanism for each cluster's API servers.
An alternative authentication method avalaible in Rancher is the Authorized Cluster Endpoint which allows requests to be authenticated directly at the downstream cluster Kubernetes API server. See the documentation for details on these methods.

It is important to understand that only the Authorized Cluster Endpoint allows authentication based on K8s service account tokens. The authentication proxy endpoint requires usng a Rancher API token instead.

How can still use the central Rancher auth endpoint to integrate ArgoCD
To summarize: In order to integrate Argo CD via the Rancher server network endpoint, we will need to setup Argo CD with a Rancher API token in lieu of a Kubernetes Service Account token.

For now this can not be accomplished using the argocd command-line tool because it doesn't let the user specify a pre-existing API credential or custom kubeconfig.

Luckily, argocd is at the core just a Kubernetes client with syntactic sugar coating and therefore does most things by interacting with Kubernetes (CRD) resources under the hood. So whatever $ argocd cluster add does, we should be able to do this using kubectl and K8s manifests.

According to the documentation the "cluster add" command does the following:

The above command installs a ServiceAccount (argocd-manager), into the kube-system namespace of that kubectl context, and binds the service account to an admin-level ClusterRole. Argo CD uses this service account token to perform its management tasks (i.e. deploy/monitoring).

And in another place we find:

To manage external clusters, Argo CD stores the credentials of the external cluster as a Kubernetes Secret in the argocd namespace. This secret contains the K8s API bearer token associated with the argocd-manager ServiceAccount created during argocd cluster add, along with connection options to that API server

Futhermore, the format of that cluster secret is also described in detail on this page providing the following example:
```
apiVersion: v1
kind: Secret
metadata:
  name: mycluster-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: mycluster.com
  server: https://mycluster.com
  config: |
    {
      "bearerToken": "<authentication token>",
      "tlsClientConfig": {
        "insecure": false,
        "caData": "<base64 encoded certificate>"
      }
    }
```

Finally, the argocd CLI creates a RBAC role called argocd-manager-role which by default assigns clusteradmin privileges but can be narrowed down to implement a least-privilege concept.

tl;dr: Here are the steps to register Rancher managed clusters using the central Rancher API endpoint
So it appears that all we need to do is replace the argocd cluster add command with the following steps:

Create a local Rancher user account (e.g. service-argo)
Create a Rancher API token for that user account, either by logging in and using the GUI (API & Keys -> Add Key) or requesting the token via direct invocation of the /v3/tokens API resource.
Authorize that user account in the cluster (GUI: Cluster -> Members -> Add) and assign the cluster-member role (role should be narrowed down for production usage later).
Create a secret resource file (e.g. cluster-secret.yaml) based on the example above, providing a configuration reflecting the Rancher setup:
name: A named reference for the cluster, e.g. "prod".
server: The Rancher auth proxy endpoint for the cluster in the format: https://<rancher-server-endpoint>/k8s/clusters/<cluster-id>
config.bearerToken: The Rancher API token created above
config.tlsClientConfig.caData: PEM encoded CA certificate data for Rancher's SSL endpoint. Only needed if the server certificate is not signed by a public trusted CA.
Then apply the secret to the Argo CD namespace in the cluster where Argo CD is installed (by default argocd): $ kubectl apply -n argocd -f cluster-secret.yaml
Finally check that the cluster has been successfully registered in Argo CD:

argocd cluster list
SERVER                                                     NAME     VERSION  STATUS      MESSAGE
https://xxx.rancher.xxx/k8s/clusters/c-br1xm               vsphere  1.17     Successful
https://kubernetes.default.svc                                               Successful
Load earlier comments...
@mkolb-navican
mkolb-navican commented on Oct 6, 2020 • 
I am only able to get the https://kubernetes.default.svc in-cluster to work. It seems like the default install wants to add the in-cluster and https://<rancher-server-endpoint>/k8s/clusters/<cluster-id> for the cluster where ArgoCD is installed. I setup the secret, but I still get the credential error trying to add the local cluster https://<rancher-server-endpoint>/k8s/clusters/<cluster-id>.

@andrewcottle
andrewcottle commented on Oct 7, 2020
@mkolb-navican so you arent able to add additional clusters managed by Rancher to argocd?

@mkolb-navican
mkolb-navican commented on Oct 8, 2020
Yes, in-cluster works, but adding another cluster doesn't. I created two bearer tokens of cluster scope for a service-argocd local account. One for each cluster. The error events are definitely user permissions for the second cluster. I even get errors for the local cluster that is added at the same time as the in-cluster resource.

@andrewcottle
andrewcottle commented on Oct 8, 2020 • 
@mkolb-navican for me I didnt have to do anything to get in-cluster, e.g. the cluster where argocd is running to work. To get the second Rancher Cluster to be managed correctly by argocd I did the following:

Create a local Rancher user account (e.g. service-argo)

Login to rancher using the new user, create a Rancher API token for the new user account, either by logging in and using the GUI (API & Keys -> Add Key) or requesting the token via direct invocation of the /v3/tokens API resource.
-- The Rancher API token (Bearer) in format: token-abcded:abcde12345abcde12345abcde1234abcde1234abcde12345

Authorize that user account in ALL target clusters (GUI: Cluster -> Members -> Add) and assign the cluster-member role in ALL target clusters
-- The local user needs standard user global permissions and Cluster Member permissions on the cluster where ArgoCD is installed and on the clusters that it will deploy applications

Create a secret resource file (e.g. cluster-secret.yaml) based on the example above, providing a configuration reflecting the Rancher setup:
```
kind: Secret
metadata:
  name: dev-rke
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: dev-rke
  server: https://<rancher-server-endpoint>/k8s/clusters/<cluster-id>
  config: |
    {
      "bearerToken": "<The Rancher API token created above>",
      "tlsClientConfig": {
        "insecure": false,
        "caData": "<caData is the certificate-authority-data from the endpoint cluster>"
      }
    }
```

Then apply the secret to the Argo CD namespace in the cluster where Argo CD is installed (by default argocd): $ kubectl apply -n argocd -f cluster-secret.yaml
@mkolb-navican
mkolb-navican commented on Oct 8, 2020
@andrewcottle Did you select the API key scope as "no scope" vs. a specific cluster scope? If so, this would explain why my permissions are failing.

@andrewcottle
andrewcottle commented on Oct 8, 2020
No scope.

@mkolb-navican
mkolb-navican commented on Oct 8, 2020
I am not able to get this to work... Does anyone else have Rancher in an HA environment and able to add additional downstream clusters?

@ansilh
ansilh commented on Oct 16, 2020
Clone "Cluster Member" role and create a new one with below additional rule and then assign this role to the Rancher user.

image
(Caution: User will be able to "see" all Projects with this rule)
Add namespace list in the secret if you want to restrict ArgoCD to specific namespaces
```
apiVersion: v1
kind: Secret
metadata:
  name: mycluster-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: downstream1
  server: https://xxxx/k8s/clusters/c-xxxx
  namespaces: namespace1,namespace2
  config: |
    {
      "bearerToken": "token-xxx:xxxxxxxxxxxxxxxxxxxxxxxxxx",
      "tlsClientConfig": {
        "insecure": false
      }
    }
```

 
You may try to exclude unwanted resources using the ArgoCD's resource exclusion

@llienard
llienard commented on Feb 4, 2021
"Local user should have Cluster Member role in the target cluster AND the cluster where argocd is installed. "

I have 2 rancher servers, the first one where argocd is installed and the second one that it will deploy applications. How can I allow argocd to deploy to the remote k8s cluster if the 2 k8s clusters are not managed by the same rancher ?

@janeczku
Author
janeczku commented on Feb 4, 2021
I have 2 rancher servers, the first one where argocd is installed and the second one that it will deploy applications. How can I allow argocd to deploy to the remote k8s cluster if the 2 k8s clusters are not managed by the same rancher ?

By creating a local user and corresponding Rancher API token in the Rancher server managing the remote K8s cluster where the application will be deployed. And using that API Bearer Token and Rancher endpoint when creating the clusterSecret resource in the other cluster running ArgoCD. See https://gist.github.com/janeczku/b16154194f7f03f772645303af8e9f80#gistcomment-3482575

@sebastienroy-accelex
sebastienroy-accelex commented on Mar 11, 2021
Same issue for me.
No way to make it works until I grant the new user the "Cluster Owner" role on the remote cluster.
Before this action, the user was not able to list anything. Even in the GUI by the way.

@epacke
epacke commented on Mar 22, 2021 • 
Wrote a bit more verbose guide based on the instructions above:
https://loadbalancing.se/2022/07/08/argocd-behind-istio-on-rancher/

Would also like to add that even though argocd cluster list did not work for me after doing the steps ArgoCD still had access to the cluster. Recommending following the troubleshooting steps from this article to validate the credentials after creating the secret:

https://argoproj.github.io/argo-cd/operator-manual/troubleshooting/#cluster-credentials

Hopefully it helps someone else!

Edit: Updated the article to work with the latest version of ArgoCD.

@janeczku
Author
janeczku commented on Mar 22, 2021
Thanks for sharing this blog article @epacke !

@travisghansen
travisghansen commented on Oct 5, 2021
This is crude and makes assumptions which may not be applicable to everyone, but some may find it useful: https://github.com/travisghansen/rancher-to-argocd-controller

@ogontaro
ogontaro commented on Oct 21, 2021
The article was very helpful!

@lperrin-obs
lperrin-obs commented on Feb 4, 2022
Same issue for me as @sebastienroy-accelex, I got "failed to load initial state of resource IPAMBlock.crd.projectcalico " errors and I had to set cluster owner permission to the local user

@yidaqiang
yidaqiang commented on Mar 24, 2022
be careful. everything is ok in my cluster-secret.yaml, but there's an , after "insecure": false, It's not valid.
```
apiVersion: v1
kind: Secret
metadata:
  name: mycluster-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  config: |
    {
      "bearerToken": "token-xxx:xxxxxxxxxxxxxxxxxxxxxxxxxx",
      "tlsClientConfig": {
        "insecure": false,  # remove ','
      }
    }  
```
    
@Araoms
Araoms commented on Aug 14, 2022
@mkolb-navican for me I didnt have to do anything to get in-cluster, e.g. the cluster where argocd is running to work. To get the second Rancher Cluster to be managed correctly by argocd I did the following:

Create a local Rancher user account (e.g. service-argo)
Login to rancher using the new user, create a Rancher API token for the new user account, either by logging in and using the GUI (API & Keys -> Add Key) or requesting the token via direct invocation of the /v3/tokens API resource.
-- The Rancher API token (Bearer) in format: token-abcded:abcde12345abcde12345abcde1234abcde1234abcde12345
Authorize that user account in ALL target clusters (GUI: Cluster -> Members -> Add) and assign the cluster-member role in ALL target clusters
-- The local user needs standard user global permissions and Cluster Member permissions on the cluster where ArgoCD is installed and on the clusters that it will deploy applications
Create a secret resource file (e.g. cluster-secret.yaml) based on the example above, providing a configuration reflecting the Rancher setup:
```
kind: Secret
metadata:
  name: dev-rke
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: dev-rke
  server: https://<rancher-server-endpoint>/k8s/clusters/<cluster-id>
  config: |
    {
      "bearerToken": "<The Rancher API token created above>",
      "tlsClientConfig": {
        "insecure": false,
        "caData": "<caData is the certificate-authority-data from the endpoint cluster>"
      }
    }

```

Then apply the secret to the Argo CD namespace in the cluster where Argo CD is installed (by default argocd): $ kubectl apply -n argocd -f cluster-secret.yaml
I apply it,But it doesm't work ;The cluster's status is still Unknow ;

@andrewcottle
andrewcottle commented on Aug 15, 2022
I apply it,But it doesm't work ;The cluster's status is still Unknow ;

I believe even when it does work, it will still show as Unknown until you give argocd something to manage on the new cluster.

@Araoms
Araoms commented on Aug 15, 2022
I apply it,But it doesm't work ;The cluster's status is still Unknow ;

I believe even when it does work, it will still show as Unknown until you give argocd something to manage on the new cluster.

Yes,But I Can't deploy apps;The problems make me confused

@rahulsawra98
rahulsawra98 commented on Sep 21, 2022
hey @epacke your blog is not accessible ?

@epacke
epacke commented on Sep 21, 2022
It is. I refreshed the article and the URL changed:
https://loadbalancing.se/2022/07/08/argocd-behind-istio-on-rancher/

@sherkon18
sherkon18 commented on Oct 4, 2022
Would you have to create a secret for each cluster you're managing with Rancher or just add a service-argo user to each cluster?

@pwurbs
pwurbs commented on Jan 11, 2023
@janeczku Great work. Thx a lot for this guide.
For me it worked.
But I had to set the users role to Cluster Owner, Cluster Member was not sufficient (could not list some objects like cron, replicationController). Later on I check how to narrow down the permissions.

@leliyin
leliyin commented on Jan 11, 2023
We are automating managed cluster registration in ArgoCD with Rancher Proxy using the link: https://gist.github.com/janeczku/b16154194f7f03f772645303af8e9f80. We’re able to automate this programmatically by creating the k8s secret for cluster registration in ArgoCD. There was one incident during testing where I saw the cluster secret was created, but argocd CLI showed cluster registered, but with no ‘Successful’ status:
$ argocd cluster listWARN[0000] Failed to invoke grpc call. Use flag --grpc-web in grpc calls. To avoid this warning message, use flag --grpc-web.
SERVER NAME VERSION STATUS MESSAGE PROJECT
https://rancher.default.172.18.0.231.nip.io/k8s/clusters/c-qmfns demo
https://kubernetes.default.svc/ in-cluster in-cluster
When trying to deploy the app in UI, the cluster is populated which we could create the app, but syncing the app failed with error ‘https://rancher.default.172.18.0.231.nip.io/k8s/clusters/c-qmfns not configured’ error.
What resolved the issue is restarting all argocd pods. Has anyone run into this issue as well? I'm particularly concerned that the cluster secret was created and cluster was populated in UI, however the clue that the argocd CLI didn't show Successful statusseemed to indicate an error in cluster registration, and this could mislead the user to create the app in UI which failed as a result.

@leliyin
leliyin commented on Jan 23, 2023
@janeczku Great work. Thx a lot for this guide. For me it worked. But I had to set the users role to Cluster Owner, Cluster Member was not sufficient (could not list some objects like cron, replicationController). Later on I check how to narrow down the permissions.

+1. I also had to set the user role to cluster owner as cluster member role was insufficient that the rancher user needs to create deployment on the managed cluster.

@MaxAnderson95
MaxAnderson95 commented on May 25, 2023
For those here in 2023 not knowing what the "cluster id" is: It's the Mgmt Cluster name which is more of a unique ID and less of a name. You can find this by going to Cluster Management > Choose your downstream cluster > Related Resources > Find the object under "Refers To" with the type of Mgmt Cluster. The name should be something like c-m-abcdefghi. Use this in the URL to reference the cluster:

https://<rancher-server-endpoint>/k8s/clusters/c-m-abcdefghi

@alvrebac
alvrebac commented on Aug 10, 2023 • 
Hey,
am I missing something?
I did all of the steps to add a new cluster. But everytime I do a kubectl apply with the created secret it only creates the secret and does nothing else.

@ggogel
ggogel commented on Jan 5
This guide worked for me using Rancher 2.8.0. Thanks!

However, I had to give the user service-argo the cluster owner role. Giving the cluster member role wasn't sufficient in my case:

Failed to load live state: failed to get cluster info for "...": error synchronizing cache state : failed to sync cluster ... failed to load initial state of resource ServiceAccount: serviceaccounts is forbidden: User "u-h8njl" cannot list resource "serviceaccounts" in API group "" at the cluster scope
@virtualb0x
virtualb0x commented on Mar 18 • 
Can plz anyone help me?

I've make everything instruction says:

Created local user with cluster owner role on both clusters (where argocd is) and rancher-maanges cluster
Created api token in rancher cluster for this user in UI and paste it to secret
Generated a secret:
```

apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: test
  server: https://kubernetes.tdp.corp/k8s/clusters/c-5tl4w
  config: |
    {
      "bearerToken": "token-vnkzp:glnw724zdg8s9r6h7mk6jtxpwbwq4cxkaefasefasefaeh54sb",
      "tlsClientConfig": {
        "insecure": false,
        "caData": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM0VENDQWNtZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFTTVJBd0RnWURWUVFERXdkcmR<data_ommited>gQ0VSVElGSUNBVEUtLS0tLQo="
      }
    }

```

But I get an error:
Unable to create application: error while validating and normalizing app: error validating the repo: error getting k8s server version: Get "https://kubernetes.tdp.corp/k8s/clusters/c-5tl4w/version?timeout=32s": x509: certificate signed by unknown authority

Found out: argoproj/argo-cd#3945 this case, but I really do not understand. I just copy paste base encoded cert from ~/.kube/config which I loaded in cluster where rancher is for local user I created.

When I decode it I see:

-----BEGIN CERTIFICATE-----
MIIC4TCCAcmgAwIBAgIBADANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdrdWJl
<....>
js5Q9L4Lato1WfwcovXbv7o0IuoKpZXQRDevfWY3dHiZzhc+KNMNzxLg39oZ/Kjh
+6T7C54MoGzjvgLsJug0gQEvcE/D
-----END CERTIFICATE-----
If I do Insecure - true and do not paste any caData everything is ok
What am i doing wrong?
