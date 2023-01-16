A Kubernetes Deployment tells Kubernetes how to create or modify instances of the pods that hold a containerized application. 
Deployments can help to efficiently scale the number of replica pods, enable the rollout of updated code in a controlled manner, or roll back to an earlier deployment version if necessary.

A Kubernetes deployment is a resource object in Kubernetes that provides declarative updates to applications. 
A deployment allows you to describe an application’s life cycle, such as which images to use for the app, the number of pods there should be, and the way in which they should be updated. 

What Makes Up a Kubernetes Deployment?
Before creating a deployment, you should know the parts that make up the deployment, and how they work together to make a deployment functional.

A deployment is made up of the following components:

YAML file: A YAML file describes the desired state for the Kubernetes cluster.

Pods: Pods consist of containers, configurations, and environments to run the applications.

ReplicaSet: This is a group of identical pod instances, configured so that the number of running pods always matches the number of pods specified by the YAML file. It ensures that a new pod is created when one fails.

kube-scheduler: The kube-scheduler is a component of the control plane, and declares how the pods and ReplicaSets are deployed in the worker nodes.

kube-controller-manager: This is another component of the control plane. It watches and modifies the present cluster state to match the desired state defined in the YAML file. It creates, updates, and removes pods and ReplicaSets.

##
##


Kubernetes - Deployment
Step-01: Introduction to Deployments
What is a Deployment?
What all we can do using Deployment?
Create a Deployment
Scale the Deployment
Expose the Deployment as a Service
Step-02: Create Deployment
Create Deployment to rollout a ReplicaSet
Verify Deployment, ReplicaSet & Pods
Docker Image Location: https://hub.docker.com/repository/docker/stacksimplify/kubenginx
# Create Deployment
```
kubectl create deployment <Deplyment-Name> --image=<Container-Image>
kubectl create deployment my-first-deployment --image=stacksimplify/kubenginx:1.0.0 

# Verify Deployment
kubectl get deployments
kubectl get deploy 

# Describe Deployment
kubectl describe deployment <deployment-name>
kubectl describe deployment my-first-deployment

# Verify ReplicaSet
kubectl get rs

# Verify Pod
kubectl get po
Step-03: Scaling a Deployment
Scale the deployment to increase the number of replicas (pods)
# Scale Up the Deployment
kubectl scale --replicas=20 deployment/<Deployment-Name>
kubectl scale --replicas=20 deployment/my-first-deployment 
 
  
# Verify Deployment
kubectl get deploy

# Verify ReplicaSet
kubectl get rs

# Verify Pods
kubectl get po

```
# Scale Down the Deployment
kubectl scale --replicas=10 deployment/my-first-deployment 
kubectl get deploy
Step-04: Expose Deployment as a Service
Expose Deployment with a service (NodePort Service) to access the application externally (from internet)
# Expose Deployment as a Service
kubectl expose deployment <Deployment-Name>  --type=NodePort --port=80 --target-port=80 --name=<Service-Name-To-Be-Created>
kubectl expose deployment my-first-deployment --type=NodePort --port=80 --target-port=80 --name=my-first-deployment-service

# Get Service Info
kubectl get svc
Observation: Make a note of port which starts with 3 (Example: 80:3xxxx/TCP). Capture the port 3xxxx and use it in application URL below. 

# Get Public IP of Worker Nodes
kubectl get nodes -o wide
Observation: Make a note of "EXTERNAL-IP" if your Kubernetes cluster is setup on AWS EKS.
Access the Application using Public IP
http://<worker-node-public-ip>:<Node-Port>
