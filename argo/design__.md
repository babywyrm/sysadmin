
#  Designing Git Repository Hierarchy

Git repository can be designed in any hierarchy. 
Usually creating three folders for Argo CD installation, Argo CD Applications and Argo CD Application Projects is pretty enough. 
I have prepared this repository with given folder structure below.

Repository folder tree:

```
argocd/
├── argocd-appprojects      # stores ArgoCD App Project's yaml files
├── argocd-apps             # stores ArgoCD Application's yaml files
├── argocd-install          # stores Argo CD installation files
│ ├── argo-cd               # argo/argo-cd helm chart
│ └── values-override.yaml  # custom values.yaml for argo-cd chart
```

3. Create App Of Everything Pattern
If we checkout values-override.yaml file, it can be seen that there is three application definition and one app project definition exist. In addition, source git repository is added in “server.config.repositories” section.

Application “argocd” is for management for Argo CD itself. It consists of argo-cd helm chart and custom values files. Application “argocd-apps”
is an example of app of apps pattern. It looks “argocd-apps” folder that contains Argo CD application definition files. Whenever a new application yaml created in that folder, 
argocd-apps application automatically apply this yaml to cluster and so that Argo CD application automatically created. Application “argocd-appprojects” is similar to “argocd-apps”.
It is responsible for creating Argo CD Application Projects.
Additional project “argocd” is used in argocd additional applications to provide proper access control.

```
server:
  configEnabled: true
  config:
    repositories: |
      - type: git
        url: https://github.com/gokul0815/argocd.git
      - name: argo-helm
        type: helm
        url: https://argoproj.github.io/argo-helm
  additionalApplications: 
    - name: argocd
      namespace: argocd
      destination:
        namespace: argocd
        server: https://kubernetes.default.svc
      project: argocd
      source:
        helm:
          version: v3
          valueFiles:
          - values.yaml
          - ../values-override.yaml
        path: argocd-install/argo-cd
        repoURL: https://github.com/gokul0815/argocd.git
        targetRevision: HEAD
      syncPolicy:
        syncOptions:
        - CreateNamespace=true
    - name: argocd-apps
      namespace: argocd
      destination:
        namespace: argocd
        server: https://kubernetes.default.svc
      project: argocd
      source:
        path: argocd-apps
        repoURL: https://github.com/gokul0815/argocd.git
        targetRevision: HEAD
        directory:
          recurse: true
          jsonnet: {}
      syncPolicy:
        automated:
          selfHeal: true
          prune: true
    - name: argocd-appprojects
      namespace: argocd
      destination:
        namespace: argocd
        server: https://kubernetes.default.svc
      project: argocd
      source:
        path: argocd-appprojects
        repoURL: https://github.com/gokul0815/argocd.git
        targetRevision: HEAD
        directory:
          recurse: true
          jsonnet: {}
      syncPolicy:
        automated:
          selfHeal: true
          prune: true
  additionalProjects: 
  - name: argocd
    namespace: argocd
    additionalLabels: {}
    additionalAnnotations: {}
    description: Argocd Project
    sourceRepos:
    - '*'
    destinations:
    - namespace: argocd
      server: https://kubernetes.default.svc
    clusterResourceWhitelist:
    - group: '*'
      kind: '*'
    orphanedResources:
      warn: false
```

With that configuration we have configured our Argo CD installation for both self management and app of apps pattern.

4. Install… Ready !
We are ready to install. Pull the repo and run helm install command.
```
$ git clone https://github.com/gokul0815/argocd.git
$ cd argocd/argocd-install/
$ helm install argocd ./argo-cd \
    --namespace=argocd \
    --create-namespace \
    -f values-override.yaml
```


Wait until all pods are running.

```
$ kubectl -n argocd get podsNAME                                            READY   STATUS    RESTARTS
argocd-application-controller-bcc4f7584-vsbc7   1/1     Running   0       
argocd-dex-server-77f6fc6cfb-v844k              1/1     Running   0       
argocd-redis-7966999975-68hm7                   1/1     Running   0       
argocd-repo-server-6b76b7ff6b-2fgqr             1/1     Running   0       
argocd-server-848dbc6cb4-r48qp                  1/1     Running   0
```

Get initial admin password.

$ kubectl -n argocd get secrets argocd-initial-admin-secret \
    -o jsonpath='{.data.password}' | base64 -d
Forward argocd-server service port 80 to localhost:8080 using kubectl.

$ kubectl -n argocd port-forward service/argocd-server 8080:80
Browse http://localhost:8080 and login with initial admin password. 
As you can see three applications we described in our values-override.yaml file is ready. 
Application “argocd” looks out of sync but don’t worry. It’s a result of using different templating parameter of my local helm binary and Argo CD ‘s hem binary. 
Simply click “Sync” button and wait until it’s green.


Finally we have self managed Argo CD with app of apps pattern. All configuration and definitions are located at our git repository. It’s enough to push changes to our git repo to configure Argo CD or to create/update an application. If you want you can also enable auto-sync for “argocd” application. But I recommend to keep it manual to have more secure and stable management.

5. Sample Application Demo
In this demo we will create an application project called “sample-project” that can access only to “sample-app” namespace and create an application called “sample-app” in that project.

Let’s start with “sample-project”.

Create a yaml file with below content and place it in application project folder in your git repo. In my case it is “argocd-appprojects” folder.

```
$ cat << EOF > argocd-appprojects/sample-project.yaml
> apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: sample-project
  namespace: argocd
spec:
  clusterResourceWhitelist:
  - group: '*'
    kind: '*'
  destinations:
  - namespace: sample-app
    server: https://kubernetes.default.svc
  orphanedResources:
    warn: false
  sourceRepos:
  - '*'
EOF
```


Push changes to your repository.

```

$ git add argocd-appprojects/sample-project.yaml
$ git commit -m "Create sample-project"
$ git push
```

Argo CD checks git repo every three minutes. You can wait a couple of minutes or click “Refresh” button of “argocd-appproject” application. After synchronization you can see “sample-project” is created. It is also possible to check it under Project menu of Setting pane.


Next, “sample-app”.
Create a yaml file with below content and place it in application folder in your git repo. In my case it is “argocd-apps” folder. You can check Argo CD official documentation for all available fields and parameters.

```
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sample-app
  namespace: argocd
spec:
  destination:
    namespace: sample-app
    server: https://kubernetes.default.svc
  project: sample-project
  source:
    path: sample-app/
    repoURL: https://github.com/kurtburak/argocd.git
    targetRevision: HEAD
  syncPolicy:
    syncOptions:
    - CreateNamespace=true
    automated:
      selfHeal: true
      prune: true
```

Push changes to your repository.

$ git add argocd-apps/sample-app.yaml
$ git commit -m "Create application"
$ git push
In several minutes or by clicking the refresh button of “argocd-apps”, you can observe creation of “sample-app” on GUI.



You can also verify with kubectl commands.

```
$ kubectl -n sample-app get all
NAME                                  READY   STATUS    AGE
pod/details-v1-79f774bdb9-7sw9q       1/1     Running   112m
pod/productpage-v1-6b746f74dc-vwkdq   1/1     Running   112m
pod/ratings-v1-b6994bb9-rf7lk         1/1     Running   112m
pod/reviews-v1-545db77b95-pzcj9       1/1     Running   112m
pod/reviews-v2-7bf8c9648f-q8b6m       1/1     Running   112m
pod/reviews-v3-84779c7bbc-9nfp4       1/1     Running   112mNAME                  TYPE        CLUSTER-IP      PORT(S)    AGE
service/details       ClusterIP   10.96.27.232    9080/TCP   112m
service/productpage   ClusterIP   10.96.72.223    9080/TCP   112m
service/ratings       ClusterIP   10.96.0.174     9080/TCP   112m
service/reviews       ClusterIP   10.96.115.169   9080/TCP   112mNAME                             READY   UP-TO-DATE   AVAILABLE
deployment.apps/details-v1       1/1     1            1        
deployment.apps/productpage-v1   1/1     1            1        
deployment.apps/ratings-v1       1/1     1            1        
deployment.apps/reviews-v1       1/1     1            1        
deployment.apps/reviews-v2       1/1     1            1        
deployment.apps/reviews-v3       1/1     1            1NAME                                        DESIRED   CURRENT   READY
replicaset.apps/details-v1-79f774bdb9       1         1         1    
replicaset.apps/productpage-v1-6b746f74dc   1         1         1    
replicaset.apps/ratings-v1-b6994bb9         1         1         1    
replicaset.apps/reviews-v1-545db77b95       1         1         1    
replicaset.apps/reviews-v2-7bf8c9648f       1         1         1    
replicaset.apps/reviews-v3-84779c7bbc       1         1         1
Everything is running and ready!
```


6. Cleanup
Remove application and application project definition files in git repo.

```
$ rm -f argocd-apps/sample-app.yaml
$ rm -f argocd-appprojects/sample-project.yaml
$ git rm argocd-apps/sample-app.yaml
$ git rm argocd-appprojects/sample-project.yaml
$ git commit -m "Remove app and project."
$ git push
Delete application “sample-app”.


```



# ArgoCD Installation Part 2 - Quick Start
Argo CD is a declarative continuous delivery tool for Kubernetes applications. It uses the GitOps style to create and manage Kubernetes clusters. When any changes are made to the application configuration in Git, Argo CD will compare it with the configurations of the running application and notify users to bring the desired and live state into sync.

Argo CD has been developed under the Cloud Native Computing Foundation’s (CNCF) Argo Project- a project, especially for Kubernetes application lifecycle management. The project also includes Argo Workflow, Argo Rollouts, and Argo Events.. Each solves a particular set of problems in the agile development process and make the Kubernetes application delivery scalable and secure.
### Upgrade Packages & Install Prerequisites

### Install ArgoCD
```sh
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```
### Change Service to NodePort
Edit the service can change the service type from `ClusterIP` to `NodePort`
```sh
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "NodePort"}}' 
```
### Fetch Password
```sh
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```
# Deploy Demo Application
You can use the below repository to deploy a demo nginx application
```sh
https://github.com/dmancloud/argocd-tutorial
```
### Scale Replicaset 
```sh
kubectl scale --replicas=3 deployment nginx -n default
```
### Clean Up
```sh
kubectl delete -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl delete namespace argocd
```
