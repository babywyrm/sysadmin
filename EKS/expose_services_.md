++++++++++++++++++++++++
+++++++++++++++++++++++++++

https://aws.amazon.com/premiumsupport/knowledge-center/eks-kubernetes-services-cluster/

+++++++++++++++++++++++++++
++++++++++++++++++++++++


How do I expose the Kubernetes services running on my Amazon EKS cluster?
Last updated: 2021-04-21

I want to expose the Kubernetes services running on my Amazon Elastic Kubernetes Service (Amazon EKS) cluster.

Short description
To expose the Kubernetes services running on your cluster, create a sample application. Then, apply the ClusterIP, NodePort, and LoadBalancer Kubernetes ServiceTypes to your sample application.

Keep in mind the following:

ClusterIP exposes the service on a cluster's internal IP address.
NodePort exposes the service on each node’s IP address at a static port.
LoadBalancer exposes the service externally using a load balancer.
Note: Amazon EKS supports the Network Load Balancer and the Classic Load Balancer for pods running on Amazon Elastic Compute Cloud (Amazon EC2) instance worker nodes. Amazon EKS provides this support by using the LoadBalancer. You can load balance network traffic to a Network Load Balancer (instance or IP targets) or a Classic Load Balancer (instance target only).

Resolution
Create a sample application
1.    Define and apply a deployment file. The following example creates a ReplicaSet that spins up two nginx pods, and then creates filed called nginx-deployment.yaml.

cat <<EOF > nginx-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
EOF
2.    Create the deployment:

kubectl apply -f nginx-deployment.yaml
3.    Verify that your pods are running and have their own internal IP addresses:

kubectl get pods -l 'app=nginx' -o wide | awk {'print $1" " $3 " " $6'} | column -t
Output:

NAME                               STATUS   IP
nginx-deployment-574b87c764-hcxdg  Running  192.168.20.8
nginx-deployment-574b87c764-xsn9s  Running  192.168.53.240
Create a ClusterIP service
1.    Create a file called clusterip.yaml, and then set type to ClusterIP. For example:

cat <<EOF > clusterip.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-cluster-ip
spec:
  type: ClusterIP
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
EOF
2.    Create the ClusterIP object in Kubernetes using either a declarative or imperative command.

To create the object and apply the clusterip.yaml file, run the following declarative command:

kubectl create -f clusterip.yaml
Output:

service/nginx-service-cluster-ip created
-or-

To expose a deployment of ClusterIP type, run the following imperative command:

kubectl expose deployment nginx-deployment  --type=ClusterIP  --name=nginx-service-cluster-ip
Output:

service "nginx-service-cluster-ip" exposed
Note: The expose command creates a service without creating a YAML file. However, kubectl translates your imperative command into a declarative Kubernetes Deployment object.

3.    Access the application and get the ClusterIP number:

kubectl get service nginx-service-cluster-ip
Output:

NAME                       TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
nginx-service-cluster-ip   ClusterIP   10.100.12.153   <none>        80/TCP    23s
4.    Delete the ClusterIP service:

kubectl delete service nginx-service-cluster-ip
Output:

service "nginx-service-cluster-ip" deleted
Create a NodePort service
1.    To create a NodePort service, create a file called nodeport.yaml, and then set type to NodePort. For example:

cat <<EOF > nodeport.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-nodeport
spec:
  type: NodePort
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
EOF
2.    Create the NodePort object in Kubernetes using either a declarative or imperative command.

To create the object and apply the nodeport.yaml file, run the following declarative command:

kubectl create -f nodeport.yaml
-or-

To expose a deployment of NodePort type, run the following imperative command:

kubectl expose deployment nginx-deployment  --type=NodePort  --name=nginx-service-nodeport
Output:

service/nginx-service-nodeport exposed
3.    Get information about nginx-service:

kubectl get service/nginx-service-nodeport
Output:

NAME                     TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
nginx-service-nodeport   NodePort   10.100.106.151   <none>        80:30994/TCP   27s
Important: The ServiceType is a NodePort and ClusterIP that are created automatically for the service. The output from the preceding command shows that the NodePort service is exposed externally on the port (30994) of the available worker node's EC2 instance. Before you access NodeIP:NodePort from outside the cluster, you must set the security group of the nodes to allow incoming traffic. You can allow incoming traffic through the port (30994) that's listed in the output of the preceding kubectl get service command.

4.    If the node is in a public subnet and is reachable from the internet, check the node’s public IP address:

kubectl get nodes -o wide |  awk {'print $1" " $2 " " $7'} | column -t
Output:

NAME                                      STATUS  EXTERNAL-IP
ip-10-0-3-226.eu-west-1.compute.internal  Ready   1.1.1.1
ip-10-1-3-107.eu-west-1.compute.internal  Ready   2.2.2.2
-or-

If the node is in a private subnet and is reachable only inside or through a VPC, then check the node’s private IP address:

kubectl get nodes -o wide |  awk {'print $1" " $2 " " $6'} | column -t
Output:

NAME                                      STATUS  INTERNAL-IP
ip-10-0-3-226.eu-west-1.compute.internal  Ready   10.0.3.226
ip-10-1-3-107.eu-west-1.compute.internal  Ready   10.1.3.107
5.     Delete the NodePort service:

kubectl delete service nginx-service-nodeport
Output:

service "nginx-service-nodeport" deleted
Create a LoadBalancer service
1.    To create a LoadBalancer service, create a file called loadbalancer.yaml, and then set type to LoadBalancer. For example:

cat <<EOF > loadbalancer.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-loadbalancer
spec:
  type: LoadBalancer
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
EOF
2.    Apply the loadbalancer.yaml file:

kubectl create -f loadbalancer.yaml
Output:

service/nginx-service-loadbalancer created
-or-

Expose a deployment of LoadBalancer type:

kubectl expose deployment nginx-deployment  --type=LoadBalancer  --name=nginx-service-loadbalancer
Output:

service "nginx-service-loadbalancer" exposed
3.    Get information about nginx-service:

kubectl get service/nginx-service-loadbalancer |  awk {'print $1" " $2 " " $4 " " $5'} | column -t
Output:

NAME                        TYPE          EXTERNAL-IP                        PORT(S)
nginx-service-loadbalancer  LoadBalancer  *****.eu-west-1.elb.amazonaws.com  80:30039/TCP
4.    Verify that you can access the load balancer externally:

curl -silent *****.eu-west-1.elb.amazonaws.com:80 | grep title
You should receive the following output between HTML title tags: "Welcome to nginx!"

5.    Delete the LoadBalancer service:

kubectl delete service nginx-service-loadbalancer
Output:

service "nginx-service-loadbalancer" deleted
Note: By default, the preceding LoadBalancer service creates a Classic Load Balancer.

6.    To create a Network Load Balancer with an instance type target, add the following annotation to the service manifest:

service.beta.kubernetes.io/aws-load-balancer-type: nlb
-or-

To create a Network Load Balancer with IP targets, deploy the AWS Load Balancer Controller, and then create a load balancer that uses IP targets.

