
<br>
<br>
http://coding-bootcamps.com/blog/build-containerized-applications-with-golang-on-kubernetes.html#p1
<br>
<br>

Build and Deploy Containerized Applications with Golang on Kubernetes
decorative line
Learn about Golang, Docker and Kubernetes

Containerized Applications with Golang on Kubernetes
Tutorial outline
Requirements
Tutorial source codes
Background
Step 1- Build a basic web application in Go
Step 2- Apply Docker containers to a Go application
Step 3- Integrate the Docker image to Docker hub
Step 4- Creating a Kubernetes deployment
Step 5- Create Kubernetes cluster using Minikube for deploying the app
Step 6- Create a Kubernetes Service
Step 7- Scale a Kubernetes deployment
Step 8- Delete Kubernetes resources
Step 9- Stop and Delete the Minikube cluster
Summary
Resources

Requirements
If you are new to Kubernetes, Docker and/or Golang, taking the following courses is highly recommended.

Live training class for mastering Docker, containers and cloud deployment
Live training class for mastering Kubernetes, containers and Cloud Native
Complete live training for mastering DevOps and all of its tools
Introduction to Go Programming
Go programming language- Private tutoring sessions
Tutorial source codes
Click here to download the source codes for this tutorial.

Background
Originally started as a Google project and now maintained by The Linux Foundation under The Cloud Native as an open-source container orchestrator, Kubernetes is used to run, manage, and scale containerized applications on the cloud.
Following the principals of microservices, Kubernetes has everything to automate the deployment, scaling, and management of modern applications. Some of prominent features of Kubernetes are:

Horizontal auto-scaling
Service discovery and Load balancing
Rolling updates with zero downtime
Self-healing mechanisms (using health-checks)
Secret and configuration management
On top of that, all the major cloud providers (Google Cloud, IBM, Oracle AWS, Azure, etc) support Kubernetes in their platforms. For example, blockchain applications with Hyperledger Fabric on Azure use Kubernetes instead of Docker to manage its decentralized network.
With the support of Kubernetes by all major cloud providers, migrating to a different cloud provider or building an application on multiple cloud platforms become easy. Such flexibility allows system architects to build resilient and scalable applications. In this tutorial, we show you how to deploy, manage, and scale a simple Go web app on Kubernetes.
We will deploy the app on a local kubernetes cluster created using minikube. Minikube is a tool that lets you set up a single-node Kubernetes cluster inside a VM on your local machine. It’s great for learning and playing with Kubernetes.

Step 1- Build a sample web application in Go (Move to Top)
Let’s build a simple Go web app to deploy on Kubernetes. Fire up your terminal and create a new folder for the project:

$ mkdir go-kubernetes
Next, Initialize Go modules by running the following command

$ cd go-kubernetes
$ go mod init github.com/xyz # Change the module path as per your Github username
Now, Create a file named main.go and copy the following code -

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	name := query.Get("name")
	if name == "" {
		name = "Guest"
	}
	log.Printf("Received request for %s\n", name)
	w.Write([]byte(fmt.Sprintf("Hello, %s\n", name)))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	// Create Server and Route Handlers
	r := mux.NewRouter()

	r.HandleFunc("/", handler)
	r.HandleFunc("/health", healthHandler)
	r.HandleFunc("/readiness", readinessHandler)

	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start Server
	go func() {
		log.Println("Starting Server")
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Graceful Shutdown
	waitForShutdown(srv)
}

func waitForShutdown(srv *http.Server) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive our signal.
	<-interruptChan

	// create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	srv.Shutdown(ctx)

	log.Println("Shutting down")
	os.Exit(0)
}
    
The app uses gorilla mux library for routing. It also has /health and /readiness endpoints apart from the / endpoint. You’ll find out what is the use of these endpoints in the later section.
Let’s now build and run the app locally:

  $ go build
$ ./go-kubernetes
2020/05/17 7:11:58 Starting Server
$ curl localhost:8080?name=Tom
Hello, Tom
Step 2- Apply Docker containers to a Go application (Move to Top)
To deploy our app on Kubernetes, we need to first containerize it. Create a file named Dockerfile inside the project’s folder and add the following configurations in the Dockerfile.


# Dockerfile References: https://docs.docker.com/engine/reference/builder/

# Start from the latest golang base image
FROM golang:latest as builder

# Add Maintainer Info
LABEL maintainer="Tom"

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .


######## Start a new stage from scratch #######
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"] 

We shall not discuss the details of the Dockerfile here. Please check out our Introduction to Docker course to learn more.

Step 3- Integrate the Docker image to Docker hub (Move to Top)
Let’s build and push the docker image of our Go app on docker hub so that we can later use this image while deploying the app on Kubernetes -


# Build the docker image
$ docker build -t go-kubernetes .

# Tag the image
$ docker tag go-kubernetes callicoder/go-hello-world:1.0.0

# Login to docker with your docker Id
$ docker login
Login with your Docker ID to push and pull images from Docker Hub. If you do not have a Docker ID, head over to https://hub.docker.com to create one.
Username (callicoder): callicoder
Password:
Login Succeeded

# Push the image to docker hub
$ docker push callicoder/go-hello-world:1.0.0
Step 4- Creating a Kubernetes deployment (Move to Top)
Now we can move on moving a Kubernetes deployment for our app. Deployments are a declarative way to instruct Kubernetes how to create and update instances of your application. A deployment consists of a set of identical, indistinguishable Pods.

A Pod represents a unit of deployment, i.e. a single instance of your application in Kubernetes, which might consist of either a single container or a small number of containers that are tightly coupled and that share resources.
When it comes to managing Pods, deployments abstract away the low-level details like what node is the Pod running on. Pods are tied to the lifetime of the node. So when the node dies, so does the Pod. It’s the job of the deployment to ensure that the current number of Pods equals the desired number of Pods.

We specify the details of the number of Pods, what containers to run inside the Pod, how to check if the Pod is healthy or not, in a so-called manifest file. It’s a simple yaml file with a bunch of configurations containing the desired state of our application.

k8s-deployment.yml


---
apiVersion: apps/v1
kind: Deployment                 # Type of Kubernetes resource
metadata:
  name: go-hello-world           # Name of the Kubernetes resource
spec:
  replicas: 3                    # Number of pods to run at any given time
  selector:
    matchLabels:
      app: go-hello-world        # This deployment applies to any Pods matching the specified label
  template:                      # This deployment will create a set of pods using the configurations in this template
    metadata:
      labels:                    # The labels that will be applied to all of the pods in this deployment
        app: go-hello-world 
    spec:                        # Spec for the container which will run in the Pod
      containers:
      - name: go-hello-world
        image: callicoder/go-hello-world:1.0.0 
        imagePullPolicy: IfNotPresent
        ports:
          - containerPort: 8080  # Should match the port number that the Go application listens on
        livenessProbe:           # To check the health of the Pod
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 5
          periodSeconds: 15
          timeoutSeconds: 5
        readinessProbe:          # To check if the Pod is ready to serve traffic or not
          httpGet:
            path: /readiness
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 5
          timeoutSeconds: 1    

We have added comments alongside each configuration in the above deployment manifest file. But we want to talk more about some of them.
Notice the configuration replicas: 3 in the above file. It instructs Kubernetes to run 3 instances of our application at any given time. If an instance dies, Kubernetes automatically spins up another instance.
Let’s also talk about the livenessProbe and readinessProbe. Sometimes a container on a pod can be running but the application inside of the container might be malfunctioning as if your code was deadlocked.
Kubernetes has built-in support to make sure that your application is running correctly with user implemented application health and readiness checks.
Readiness probes indicate when an application is ready to serve traffic. If a readiness check fails then the container will be marked as not ready and will be removed from any load balancers.
Liveness probes indicate a container is alive. If a liveness probe fails multiple times, then the container will be restarted.

Step 5- Create Kubernetes cluster using Minikube for deploying the app (Move to Top)
For this step, you need to install and set up kubectl (Kubernetes command-line tool) and Minikube to proceed further. Please follow the instructions on the official Kubernetes website to install kubectl and minikube.
Once the installation is complete, type the following command to start a Kubernetes cluster:

$ minikube start
Let’s now deploy our app to the minikube cluster by applying the deployment manifest using kubectl.

$ kubectl apply -f k8s-deployment.yml
  deployment.apps/go-hello-world created
Done! The deployment is created. You can get the deployments like this:

$ kubectl get deployments
  NAME             READY   UP-TO-DATE   AVAILABLE   AGE
  go-hello-world   3/3     3            3           25s
You can type the following command to get the pods in the cluster:

$ kubectl get pods
 NAME                              READY   STATUS    RESTARTS   AGE
  go-hello-world-69b45499fb-7fh87   1/1     Running   0          37s
  go-hello-world-69b45499fb-rt2xj   1/1     Running   0          37s
  go-hello-world-69b45499fb-xjmlq   1/1     Running   0          37s
  
Pods are allocated a private IP address by default and cannot be reached outside of the cluster. You can use the kubectl port-forward command to map a local port to a port inside the pod like this:

$ kubectl port-forward go-hello-world-69b45499fb-7fh87 8080:8080
  Forwarding from 127.0.0.1:8080 -> 8080 
  Forwarding from [::1]:8080 -> 8080 
You can now interact with the Pod on the forwarded port:

$ curl localhost:8080
  Hello, Guest
  
 $ curl localhost:8080?name=Tom
 Hello, Tom
You can also stream the Pod logs by typing the following command:

$ kubectl logs -f go-hello-world-69b45499fb-7fh87
2020/07/27 06:12:09 Starting Server
2020/07/27 06:15:42 Received request for Guest
2020/07/27 06:16:02 Received request for Tom

Step 6- Create a Kubernetes Service (Move to Top)
The port-forward command is good for testing the pods directly. But in production, you would want to expose the pod using services.
Pods can be restarted for all kinds of reasons like failed liveliness checks, readiness checks or they can be killed if the node they are running on dies.
Instead of relying on the Pods IP addresses which change, Kubernetes provides services as stable endpoint for pods. The pods that the service exposes are based on a set of labels. If Pods have the correct labels, they are automatically picked up and exposed by our services.
The level of access the service provides to the set of pods depends on the service type which can be:

ClusterIP: Internal only.
NodePort: Gives each node an external IP that’s accessible from outside the cluster and also opens a Port. A kube-proxy component that runs on each node of the Kubernetes cluster listens for incoming traffic on the port and forwards them to the selected pods in a round-robin fashion.
LoadBalancer: Adds a load balancer from the cloud provider which forwards traffic from the service to the nodes within it.
Let’s expose our Pods by creating a service. Add the following configurations in the k8s-deployment.yml file:


---
apiVersion: v1
kind: Service                    # Type of kubernetes resource
metadata:
  name: go-hello-world-service   # Name of the resource
spec:
  type: NodePort                 # A port is opened on each node in your cluster via Kube proxy.
  ports:                         # Take incoming HTTP requests on port 9090 and forward them to the targetPort of 8080
  - name: http
    port: 9090
    targetPort: 8080
  selector:
    app: go-hello-world         # Map any pod with label `app=go-hello-world` to this service
    
Let’s now apply the above configurations by typing the following command:

$ kubectl apply -f k8s-deployment.yml
deployment.apps/go-hello-world unchanged
service/go-hello-world-service created
A service is created for exposing the Pods. You can get the list of services in the Kubernetes cluster like this:

$ kubectl get services
NAME                     TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
go-hello-world-service   NodePort    10.111.51.170           9090:32550/TCP   35s
kubernetes               ClusterIP   10.96.0.1               443/TCP          13h
Type the following command to get the URL for the service in the minikube cluster:

$ minikube service go-hello-world-service --url
http://192.168.99.100:32550
Done! You can now interact with the service on the above URL:

$ curl http://192.168.99.100:32550
Hello, Guest

$ curl http://192.168.99.100:32550?name=Tom
Hello, Rajeev


Step 7- Scale a Kubernetes deployment (Move to Top)
You can scale the number of Pods by increasing the number of replicas in the Kubernetes deployment manifest and applying the changes using kubectl.
You can also use kubectl scale command to increase the number of pods:

  $ kubectl scale --replicas=4 deployment/go-hello-world
deployment.extensions/go-hello-world scaled
$ kubectl get pods
NAME                              READY   STATUS    RESTARTS   AGE
go-hello-world-69b45499fb-7fh87   1/1     Running   0          112m
go-hello-world-69b45499fb-hzb6v   1/1     Running   0          10s
go-hello-world-69b45499fb-rt2xj   1/1     Running   0          112m
go-hello-world-69b45499fb-xjmlq   1/1     Running   0          112m
  
  

Step 8- Delete Kubernetes resources (Move to Top)
Deleting a Pod

$ kubectl delete pod go-hello-world-69b45499fb-7fh87
   pod "go-hello-world-69b45499fb-7fh87" deleted
Deleting a Service

$ kubectl delete service go-hello-world-service
    service "go-hello-world-service" deleted
Deleting a Deployment

$ kubectl delete deployment go-hello-world
    deployment.extensions "go-hello-world" deleted

Step 9- Stop and Delete the Minikube cluster (Move to Top)
Stopping the minikube Kubernetes cluster

$ minikube stop
Deleting the minikube Kubernetes cluster

$ minikube delete

Summary (Move to Top)
In this tutorial, we learn how to deploy and manage Go applications on Kubernetes via Docker images.  Along the way, you learn how to build and manage Docker images on your local machine using Minikube. At a very high level, we started with a Go application, then containerize it with Docker, and use its Docker image in deploying our Kubernetes pods. We moved on exploring our Kubernetes cluster on Minikube. In doing so, we learned how to create a Kubernetes Service, Scale a Kubernetes deployment, Delete Kubernetes resources, and Stop and Delete the Minikube cluster.
Read our tutorials on the below resources section to learn more on Kubernetes.


Resources- Free Webinars
Here is the list of our free webinars that are highly recommended:

Intro to Amazon Web Services certifications and AWS careers
Into cloud and Docker and cloud careers
intro to DevOps enterprise software development, DevOps tools and careers
Intro to Cloud Native and Kubernetes and cloud careers

Resources- Free Courses
Here is the list of our 10 free self-paced courses that are highly recommended:

IT Career Roadmap Explained
Web Design with Bootstrap
User Experience Best Practices
Intro to Search Engine Optimization
Web Design with WordPress
Introduction to Drupal CMS
Intro to Joomla CMS
Intro to Cybersecurity
Introduction to Cloud Technology
Recorded Live Webinars and Classes

Resources- Live Cloud Courses
If you like to learn more about Kubernetes, AWS, Docker and DevOps, taking the following live classes is highly recommended:

Live training class for mastering Docker, containers and cloud deployment
Live training class for mastering Kubernetes, containers and Cloud Native
Complete live training for mastering DevOps and all of its tools
Live training class for obtaining AWS Cloud Practitioner certification
Live training class for obtaining AWS Solutions Architect Associate certification
Live training class for obtaining AWS Developer Associate certification
Live training class for obtaining AWS SysOps Administrator certification
Live training class for obtaining AWS Security Specialist certification
Red Hat Certified System Administrator Live Training Class
Live training class for obtaining Red Hat Certified Engineer certification

Resources- Tutorials on Cloud Technology
If you like to learn more about the cloud technology, reading the following articles and tutorials is highly recommended:

17 Best Practices for Managing Kubernetes Containers
Advance System Admin Guide- 9 Best Practices for Managing Kubernetes
System Admin Guide- What is Kubernetes and how it works
Comprehensive Guide for Migration From Monolithic To Microservices Architecture
Review of Pod-to-Pod Communications in Kubernetes
