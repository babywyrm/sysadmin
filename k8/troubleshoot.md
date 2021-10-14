Kubernetes kubectl cheat sheet
Dijeesh Padinharethil on Apr 17
 Jun 8 1 min
Few kubectl commands that will be helpful in troubleshooting K8S environments

Cheat Sheet
Sort events by timestamp

kubectl get events --sort-by='.metadata.creationTimestamp'
Get list of resources stuck in a namespace

kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get --show-kind --ignore-not-found -n <namespace>
Delete namespace stuck in Terminating Status

kubectl get namespace NAMESPACE -o json > NAMESPACE.json
Remove kubernetes from finalizers array which is under spec
kubectl replace --raw "/api/v1/namespaces/NAMESPACE/finalize" -f ./NAMESPACE.json
Get list of pods sorted by node name

kubectl get pods --all-namespaces -o wide --sort-by="{.spec.nodeName}"
Get list of images running on your cluster

kubectl get pods --all-namespaces -o jsonpath="{..image}" | tr -s '[[:space:]]' '\n' | sort | uniq -c
Get list of PODs in not running state

kubectl get pods --field-selector=status.phase!=Running --all-namespaces

 ###################################
 ###################################

 To start with anything on command line: 
To understand the meaning of yaml files use 
          
          Kubectl explain <objecttype>
          Kubectl explain pods
          Kubectl explain pods.spec

To see the logs of a container 

    docker logs <container id>
    kubectl logs <podname> 
    kubectl logs <podname> -c <containername>

Container logs are automatically rotated daily and every time the log file reaches 10MB in size. 
The kubectl logs command only shows the log entries from the last rotation.

### Know more about your kubectl and cluster
    kubectl version
    kubectl cluster-info
    kubectl config current-context
    kubectl get componentstatus
 
 ### generic commands
 
    kubectl describe <objecttype> <objectname>
    kubectl edit <objecttype> <objectname>
    kubectl delete <objecttype> <objectname>
 
 
### Creating any object in kubernetes

    kubectl create -f <object.yaml>
 
### modifying an object 
    kubectl apply -f <object.yaml>

### Get the service acccounts
    kubectl get serviceaccounts

### K8s api server details
    kubectl get pod/kube-apiserver-kubemaster-01 -n kube-system -o json

 ### get deployment reated info 
    kubectl get deploy/<deplyment-name> -o json
 
 ## Rollback 
 ### First look at the revision names of the deployments:
    kubectl rollback history deploy/<deployment-name>
 
 ### Pick a version from the past and rollback
    kubectl rollback 
 
 ## Get info about other objects 
### secrets
    kubectl get secrets
    kubectl describe secret/default-token-3dj6w
    kubectl get secret/default-token-3dj6w -o json
  
 ### Role
    kubectl get role/<role-name> -o json
    kubectl get rolebinding/<rolebinding-name> -o json
 
 ### Pods 
    kubectl get pods --all-namespaces
    kubectl get pods
    kubectl describe pod/<podname>
    kubectl describe pod/<podname> -o json|wide 
 
### Entering into a container running inside a pod :
 
    kubectl exec <podname> -c <containername>  -i -t -- bash
    kubectl exec -it <containername> -- /bin/bash

 ## labels
    kubectl get pods --show--labels
    kubectl get pods --selector <key-label>=<value-label>
    kubectl get pods -l <key-label>=<value-label>
    kubectl get pods -l '<label-name> in (label-value1, label-value2)'
    e.g. : kubectl get pods -l 'env in (dev, prod)'
 
 
 ## Investigating the logs:
 
Controller Deployment logs
          kubectl get deploy/<deplyment-name> -o json

pod logs
          kubectl logs pod/<pod-name>
 
To get more columns in the result use -L

    kubectl get po -L creation_method,env
    NAME            READY   STATUS    RESTARTS   AGE   CREATION_METHOD   ENV
    kubia-manual    1/1     Running   0          16m   <none>            <none>
    kubia-manual-v2 1/1     Running   0          2m    manual            prod
    kubia-zxzij     1/1     Running   0          1d    <none>            <none>

To get more all the pods that have label creation_method:manual
   
    kubectl get po -l creation_method=manual

 To list all pods that include the env label, whatever its value is:

    kubectl get po -l env
    NAME              READY     STATUS    RESTARTS   AGE
    kubia-manual-v2   1/1       Running   0          37m

namespaces

    kubectl config set-context current-context --name-space name-space-name


When you want to figure out why the previous container terminated, you’ll want to see those logs instead of the current container’s logs. This can be done by using the --previous option:

    kubectl logs mypod --previous


Instead of using the kubectl scale command, you’re going to scale it in a declarative way by editing the ReplicationController’s definition:

    kubectl edit rc kubia

When deploying a pod, you don’t need to constantly poll the list of pods by repeatedly executing kubectl get pods. 
Instead, you can use the --watch flag and be notified of each creation, modification, or deletion of a pod,

    kubectl get pods --watch

Both the Control Plane components and the Kubelet emit events to the API server as they perform these actions. 
They do this by creating Event resources, which are like any other Kubernetes resource.

          kubectl get events --watch

Remove the taints on the master so that you can schedule pods on master as well.

          kubectl taint nodes --all node-role.kubernetes.io/master-

Run Kubectl with better logging to see what kubectl is doing.

          kubectl get pods -v=8

### Never do this 
    kubectl delete all --all
