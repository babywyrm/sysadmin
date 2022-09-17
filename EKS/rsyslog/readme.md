Run Rsyslog server in Kubernetes

#
##
##
https://itnext.io/run-rsyslog-server-in-kubernetes-bb51a7a6e227
#
https://github.com/jumanjihouse/docker-rsyslog
#
https://github.com/puzzle/kubernetes-rsyslog-logging
##
##
#

In my previous article, I explained how to dockerize Rsyslog server and run it as a container. Now, in this article let’s see how to use container orchestration tools like Kubernetes to manage and scale the Rsyslog server dynamically without any manual intervention.

Build and Push your image Docker Registry
Buil and push your Docker image to a Docker registry like DockerHub or ECR. In this article, I will push my image to DockerHub. Below is a copy of my Dockerfile from my previous article.


Dockerfile
Build the image.

docker build -t sudheerc1190/rsyslog .
Push to Dockerhub

docker push sudheerc1190/rsyslog:latest
Note that I have already logged in to my Docker registry.

Create Separate Namespace
Create a separate Namespace if you want to isolate the Syslog server, else you can run this in a Namespace of your choice. Deploy the following file to create rsyslog Namespace


namespace.yaml
kubectl apply -f namespace.yaml
Create Persistent storage
As our rsyslog server collects logs from different kinds of applications and devices, it is very much important to persist this data. In this example, I will be using AWS EFS to persist data.

If efs-provisioner is not configured already in your cluster, you can configure it by following the steps here. I have my EFS provisioner configured already.

Deploy the following YAML file to create a Persistent Volume and Persistent claim.


efs.yaml
Note: Change fs-xxxx with a valid EFS ID .

kubectl apply -f namespace.yaml
Also, I do hear that people have few concerns over EFS performance, but EFS has improved a lot with the recent feature additions. If you have any questions regarding the EFS performance you can refer to this AWS documentation Amazon EFS Performance

Create Rsyslog Deployment
Deploy the following YAML to create rsyslog deployment with three replicas with persistent EFS volume.


deployment.yaml
kubectl apply -f deployment.yaml
Verify if the deployment status. You can see here all my 3 replicas are running

kubectl get deployment -n rsyslog
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
rsyslog-deployment   3/3     3            3           3m19s
Expose deployment to service
Expose service so that any other pod inside this cluster can access and publish logs.


service.yaml
kubectl apply -f service.yaml
Expose service to NLB
Let's expose the service to NLB so that we can start accepting logs from applications running across the environment. Exposing to NLB also helps us to create VPC endpoints and securely allows us to accept connections across any VPC in the same region.

Deploy the following and wait for few minutes till the NLB is provisioned successfully.


nlb-ingress.yaml
kubectl apply -f nlb-ingress.yaml
After a few minutes, describe the service and copy the NLB endpoint.

kubectl get svc -n rsyslog
Now that we have our Rsyslog server is ready to accept logs from applications. Let's test this.

Testing
Run the following Docker container which will stream logs to Syslog server(Replace NLB endpoint with your NLB endpoint ).

docker run --log-driver syslog --log-opt syslog-address=tcp://<NLBENDPOINT>:514 alpine echo hello world
Now exec into rsyslog pod and navigate to /var/log/remote/ and you can see the log file.

kubectl get pods -n rsyslog
Copy any of pod Name and exec into it(replace podname).

kubectl -n rsyslog exec -it <podname> -- ls /var/log/remote/2019/12/21/
Yay! I can see my log.

Scaling
Now that we have our rsyslog working perfectly as Kubernetes deployment. We can use HPA to scale to pods easily.

Additional Resources
########################
##
##
##
##
  
  #
  
  All YAML files are available here: https://github.com/sudheerchamarthi/rsyslogd.git

  #

