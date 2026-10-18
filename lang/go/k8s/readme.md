#####
##### https://sysadmins.co.za/develop-build-and-deploy-a-golang-app-to-k3s/
#####
##
##

Develop Build and Deploy a Golang App to K3S
Kubernetes RaspberryPi K3S Golang
Develop Build and Deploy a Golang App to K3S
From my previous post, we flashed a RaspberryPi 4 with RaspbianOS and Installed K3S Distribution of Kubernetes.

In this post we will develop, build and deploy a Basic Golang Web Application and Deploy it to K3S and access our application via Traefik's Reverse Proxy capabilities.

Docker
We will require a container runtime as we will be building a image from our application application code, so in this case we will be installing Docker.

Docker gave some issues installing from the raspbian repositories, so I will be using the get.docker.com source:

$ curl -fsSL get.docker.com -o get-docker.sh && sh get-docker.sh
To verify that docker has been installed:

$ docker version
Client: Docker Engine - Community
 Version:           19.03.1
 API version:       1.40
 Go version:        go1.12.5
 Git commit:        74b1e89
 Built:             Thu Jul 25 21:33:17 2019
 OS/Arch:           linux/arm
 Experimental:      false

Server: Docker Engine - Community
 Engine:
  Version:          19.03.1
  API version:      1.40 (minimum version 1.12)
  Go version:       go1.12.5
  Git commit:       74b1e89
  Built:            Thu Jul 25 21:27:09 2019
  OS/Arch:          linux/arm
  Experimental:     false
 containerd:
  Version:          1.2.6
  GitCommit:        894b81a4b802e4eb2a91d1ce216b8817763c29fb
 runc:
  Version:          1.0.0-rc8
  GitCommit:        425e105d5a03fabd737a126ad93d62a9eeede87f
 docker-init:
  Version:          0.18.0
  GitCommit:        fec3683
Our Golang Application
We will develop a basic web application that returns the hostname from the container where its running from when making a http request.

Our code, app.go :

package main

import (
    "fmt"
    "os"
    "net/http"
)

func hostnameHandler(w http.ResponseWriter, r *http.Request) {
    myhostname, _ := os.Hostname()
    fmt.Fprintln(w, "Hostname:", myhostname)
}

func main() {
    const port string = "8000"
    fmt.Println("Server listening on port", port)
    http.HandleFunc("/", hostnameHandler)
    http.ListenAndServe(":" + port, nil)
}
For our Dockerfile, we will be using a golang alpine image from arm32v7 for our build to compile our binary.

Note that I am compiling it for ARM architecture, if you want to run this on anything else than a RaspberryPi or ARM, then specify the arch of your choice.

Once the binary is built, we will then copy the compiled golang binary to a scratch image.

Our Dockerfile:

FROM arm32v7/golang:alpine AS builder
ADD app.go /go/src/hello/app.go
WORKDIR /go/src/hello
RUN apk add --no-cache gcc libc-dev
RUN GOOS=linux GOARCH=arm GOARM=5 go build app.go

FROM hypriot/rpi-alpine-scratch
COPY --from=builder /go/src/hello/app /app
CMD ["/app"]
Build the image by using the image name and tag of your own account:

$ docker build -t ruanbekker/rpi-hostname:latest .
Now the image has been built, let's test this locally:

$ docker run -it -p 80:8000 ruanbekker/rpi-hostname:latest
Server listening on port 8000
Make a HTTP Request:

$ curl -i http://192.168.0.100/
HTTP/1.1 200 OK
Date: Sat, 10 Aug 2019 13:14:20 GMT
Content-Length: 23
Content-Type: text/plain; charset=utf-8

Hostname: 7c5f0d0bc212
And we can see it works as expected. Push the image to your image repository of choice, I will be using docker hub (make sure to use your own account):

$ docker push ruanbekker/rpi-hostname
Deploying to Kubernetes
Since we have a working application packaged up into a image, its time to deploy our application to Kubernetes.

You can use my image if you did not push to your own repository. Our deployment spec, k3s-demo.yml:

apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: k3s-demo
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: k3s-demo
  template:
    metadata:
      labels:
        app: k3s-demo
    spec:
      containers:
      - name: k3s-demo
        image: ruanbekker/rpi-hostname:latest
---
apiVersion: v1
kind: Service
metadata:
  name: k3s-demo
  namespace: default
spec:
  ports:
  - name: http
    targetPort: 8000
    port: 80
  selector:
    app: k3s-demo
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: k3s-demo
  annotations:
    kubernetes.io/ingress.class: "traefik"

spec:
  rules:
  - host: k3s-demo.example.org
    http:
      paths:
      - path: /
        backend:
          serviceName: k3s-demo
          servicePort: http
From the configuration above we are using Traefik for our ingress and mapping port 80 to the k3s-demo service via the dns name k3s-demo.example.org

As I do not own example.org, I will be setting that in my /etc/hosts file:

$ cat /etc/hosts | grep k3s
192.168.0.100 k3s-demo.example.org
Deploy our application:

$ kubectl apply -f k3s-demo.yml
deployment.extensions/k3s-demo created
service/k3s-demo created
ingress.extensions/k3s-demo created
After a minute or so, have a look at the services:

$ kubectl get service
NAMESPACE     NAME         TYPE           CLUSTER-IP     EXTERNAL-IP     PORT(S)                      AGE
default       k3s-demo     ClusterIP      10.43.89.51    <none>          80/TCP                       31s
The deployments:

$ kubectl get deployments
NAMESPACE     NAME       READY   UP-TO-DATE   AVAILABLE   AGE
default       k3s-demo   1/1     1            1           42s
And our pods:

$ kubectl get pods
NAME                        READY   STATUS    RESTARTS   AGE
k3s-demo-777b9b7799-68kxg   1/1     Running   0          49s
From the above output we can see that our application is deployed and running in Kubernetes.

Testing our Application
Now that our application is deployed and our hosts file is set, let's test the application:

$ curl k3s-demo.example.org
Hostname: k3s-demo-777b9b7799-68kxg
And as you can see the Traefik accepted the connection and routed to the correct container.

Scaling our Application
As the application returns the hostname, it will return the hostname of the container where the application is running.

So if we scale our application to more replicas, every time a request comes in, it will return the hostname of that container and we should see the served hostname from every request that has been made.

Let's scale our application to 3 replicas:

$ kubectl scale --replicas=3 deployments/k3s-demo
deployment.extensions/k3s-demo scaled
Ensure that the deployment has been scaled and the desired number of pods has been checked in:

$ kubectl get deployments
NAMESPACE     NAME       READY   UP-TO-DATE   AVAILABLE   AGE
default       k3s-demo   3/3     3            3           4m3s
Which is true, then we can look a bit further at the pods, where we should see 3 pods:

$ kubectl get pods
NAMESPACE     NAME                         READY   STATUS      RESTARTS   AGE
default       k3s-demo-777b9b7799-68kxg    1/1     Running     0          4m8s
default       k3s-demo-777b9b7799-hm7hm    1/1     Running     0          39s
default       k3s-demo-777b9b7799-j6p7m    1/1     Running     0          39s
Making 3 HTTP Requests, should show the hostnames that we are seeing from the above output:

$ curl k3s-demo.example.org
Hostname: k3s-demo-777b9b7799-68kxg

$ curl k3s-demo.example.org
Hostname: k3s-demo-777b9b7799-hm7hm

$ curl k3s-demo.example.org
Hostname: k3s-demo-777b9b7799-j6p7m
If you are interested in having more nodes in your cluster you can have a look at this gist: https://gist.github.com/ruanbekker/d999161cde3e440194b3f7cd60d57fc2

That's it for now
