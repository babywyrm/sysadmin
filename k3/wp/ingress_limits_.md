##
#
https://www.civo.com/learn/rate-limiting-applications-with-nginx-ingress
#
##

Here's how you can set it up and some suggestions for developing an ingress-based firewall with NGINX in your k3s cluster.

Steps for Implementing Rate Limiting in NGINX Ingress
Install NGINX Ingress Controller If you haven't already, you need to install the NGINX Ingress Controller in your k3s cluster:

bash
Copy code
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml
This command deploys the NGINX Ingress Controller with a default configuration.

Create Ingress for Your WordPress Pods Make sure your WordPress pods are accessible through an ingress resource. Here's an example of a basic ingress for your WordPress service:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wordpress-ingress
  namespace: wordpress
spec:
  rules:
  - host: wordpress.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: wordpress-service
            port:
              number: 80

```
Enable Rate Limiting Annotations To enable rate limiting, you can use specific annotations supported by the NGINX Ingress Controller. These annotations allow you to set request rate limits per IP, reducing the risk of abuse.

Here’s an example ingress resource with rate limiting enabled:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wordpress-ingress
  namespace: wordpress
  annotations:
    nginx.ingress.kubernetes.io/limit-rps: "10"  # Requests per second limit
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "3"  # Burst capacity (allows bursts 3x the limit)
    nginx.ingress.kubernetes.io/limit-rate-after: "5"  # After 5 requests, start rate limiting
spec:
  rules:
  - host: wordpress.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: wordpress-service
            port:
              number: 80
```

Key Annotations for Rate Limiting:

nginx.ingress.kubernetes.io/limit-rps: Limits the number of requests per second from a single IP.
nginx.ingress.kubernetes.io/limit-burst-multiplier: Allows a burst of requests before rate limiting starts.
nginx.ingress.kubernetes.io/limit-rate-after: Number of requests allowed before applying the rate limit.
Enforce Connection Limits (Optional) To further protect your WordPress pods, you can also limit the number of concurrent connections:

```
metadata:
  annotations:
    nginx.ingress.kubernetes.io/limit-connections: "20"  # Max concurrent connections per IP

```
Enable Global Rate Limiting (Optional) You can use NGINX Global Rate Limiting if you want to limit requests across the entire cluster or specific endpoints:

This can be done via Lua scripts and Redis to store the request counts globally.
Monitor and Tune Limits It’s important to monitor the traffic coming to your WordPress pods and adjust the limits as needed. Use tools like kubectl logs to inspect the logs of the NGINX Ingress Controller, and consider setting up metrics collection for better visibility.

Other Considerations
Fail2Ban: Consider integrating a solution like Fail2Ban for blocking IPs that repeatedly exceed the rate limit.

ModSecurity (WAF): Add a Web Application Firewall (WAF) for even more protection. You can integrate ModSecurity with NGINX for application-layer protection against SQL injections, XSS, etc.

API Gateway: If your WordPress has APIs, consider using an API gateway to enforce further rate limits or OAuth protections for those endpoints.

Example Configuration for Helm Chart (NGINX Ingress with Rate Limiting)
If you're using Helm to deploy the NGINX Ingress Controller, you can configure rate limiting in the Helm values file as follows:

```
controller:
  config:
    limit-rate: "10"
    limit-rate-after: "5"
    limit-burst: "30"

```

Then deploy the ingress controller with the new values:
```
helm install nginx-ingress ingress-nginx/ingress-nginx --values values.yaml
```



Rate-limiting is a method of reducing the rate at which requests are made to a server or resource on a network, rate-limiting plays a crucial role in preventing abuse of network resources and traffic control.

In this tutorial, we are going to demonstrate how we can achieve this using the NGINX Ingress controller. One of the advantages of using NGINX Ingress for rate limiting is that you don't need to introduce any additional logic or modifications to your application code.

Your Ingress sits between the external traffic and your application, allowing you to enforce rate-limiting rules without making changes to the application itself. This decoupling of rate-limiting logic from your application simplifies the deployment process and enables you to manage rate limits centrally, regardless of the underlying application architecture.

Benefits of rate-limiting
Before we jump into the demo, let’s take a closer look at why you’d want to consider rate-limiting:

Abuse prevention: By limiting the rate at which clients can make requests within a given time frame, you can effectively deter malicious users from performing brute-force attacks.
Denial-of-service (DoS) prevention: Unlike brute-force attacks, denial-of-service attacks are aimed at rendering applications unresponsive or taking them offline entirely. By implementing rate-limits, you can mitigate a potential denial of service attack.
Cost optimization: Rate-limiting is an effective strategy for optimizing costs, especially when you rely on third-party APIs that charge based on the number of API calls. By implementing rate limits, you can control the number of requests made to these APIs, ensuring that you stay within your allocated usage limits and avoid unnecessary charges.
Prerequisites
This tutorial assumes some familiarity with Kubernetes, in addition you would need the following:

Kubectl installed
A Civo account
The Civo CLI installed
Creating a cluster
We’ll begin by creating a Kubernetes cluster with the Nginx Ingress controller installed. For simplicity, we will be doing it from the CLI:

civo k3s create --create-firewall --nodes 2 -m --save --switch --wait nginx-rate-test -r=Traefik -a=Nginx
This would launch a two-node cluster with Nginx ingress installed. This would also point your kube-context to the cluster we just launched.

Deploying a sample application
Next, let’s deploy a sample application. This would enable us to send traffic from the ingress and eventually rate-limit the amount of traffic we can send. For this demonstration, we will be deploying the whoami service from Traefik.

In your editor of choice, add the following code:
```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: whoami
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: whoami
  template:
    metadata:
      labels:
        app: whoami
    spec:
      containers:
        - name: whoami
          image: traefik/whoami
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: whoami
  namespace: default
spec:
  selector:
    app: whoami
  ports:
    - protocol: TCP
    port: 80
    targetPort: 80
    ```
    
Next, apply the manifest to your cluster:

kubectl apply -f manifest.yaml 
Exposing the Service
Create a file called ingress.yaml, using your editor of choice, add the following code, making sure to change the host field to match the DNS entry created for your cluster:
```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whoami
spec:
  rules:
  - host: "<your-civo-dns-name>"
    http:
    paths:
    - path: /
        pathType: Prefix
        backend:
        service:
            name: whoami
            port:
            number: 80
  ingressClassName: nginx

```

Apply the manifest:

kubectl apply -f ingress.yaml 
Now you should be able to access the service using curl:

curl http://<civo-dns-address>
# output 
Hostname: whoami-848ddc4d99-mxvrk
IP: 127.0.0.1
IP: ::1
IP: 10.42.0.8
IP: fe80::c483:3cff:fe08:a7b3
RemoteAddr: 10.42.1.3:56572
GET / HTTP/1.1
Host: 
User-Agent: curl/7.87.0
Implementing Rate-Limiting on the Service
Now we have a service and Ingress in place, let's implement rate-limiting. To do this open up ingress.yaml and follow along with the code below:
```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whoami
  annotations:
    nginx.ingress.kubernetes.io/limit-rps: "10"
spec:
  rules:
  - host: <civo-dns-name>
    http:
    paths:
    - path: /
        pathType: Prefix
        backend:
        service:
            name: whoami
            port:
            number: 80
  ingressClassName: nginx

```


In this version of the Ingress manifest, we introduce the `limit-rps` annotation, this allows us to control the number of requests accepted from a given IP each second.
Apply the updated manifest to the cluster:

kubectl apply -f ingress.yaml 
In order for us to test these changes, we’ll need to install a load-testing tool. For this demonstration, we will be using Fortio.

Fortio started out as Istio’s load testing tool and eventually graduated into its own tool.

To install Fortio on MacOS you can use the brew package manager:

brew install fortio 
Alternatively, if you are not on a Mac, and have Golang (1.18 and above), you can use the go install command:

go install fortio.org/fortio@latest 
With Fortio installed, you should be able to run the following command:

fortio load  --qps 15 -t 30s   http://< civo dns name>
This command initiates a load test against the specified target URL.

The options provided in the command determine the parameters of the load test. -qps 15 sets the desired query per second rate, indicating the number of requests to send to the target per second. In this example, 15 requests per second will be generated - keep in mind in our ingress annotation, we had the rps set to 10. If our setup is correct, we should get a HTTP 503 error once we exceed this threshold.

-t 30s sets the test duration to 30 seconds, specifying how long the load test will run.

Once this command is executed, you should start getting the following response after a few seconds:

{"ts":1688428309.538757,"level":"warn","file":"http_client.go","line":1079,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"2","run":"0"}
{"ts":1688428310.015853,"level":"warn","file":"http_client.go","line":1079,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"2","run":"0"}
{"ts":1688428310.016098,"level":"warn","file":"http_client.go","line":1079,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"3","run":"0"}
{"ts":1688428311.244832,"level":"warn","file":"http_client.go","line":1079,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"0","run":"0"}
{"ts":1688428311.245496,"level":"warn","file":"http_client.go","line":1079,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"2","run":"0"}
We’ve been rate-limited!

While rate-limiting by requests can be useful it’s sometimes better to rate-limit by the number of connections.

Rate-Limiting by Connections
Limiting connections can be useful in scenarios where you want to control the overall connection load on your infrastructure rather than focusing on the request rate specifically. By setting a connection limit, you can prevent excessive concurrent connections from overwhelming or slowing down your entire system.

To do this, head back to ingress.yaml and update the manifest as follows:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whoami
  annotations:
    nginx.ingress.kubernetes.io/limit-connections: "5"
spec:
  rules:
  - host: eb116325-cec1-4026-b2b4-52c9e98696fc.lb.civo.com
    http:
    paths:
    - path: /
        pathType: Prefix
        backend:
        service:
            name: whoami
            port:
            number: 80
  ingressClassName: nginx

```
In the updated manifest, we replaced the previous annotation with the limit-connections annotation, which should limit the number of concurrent connections allowed from a single IP address.

Apply the changes:

kubectl apply -f ingress.yaml
To test the changes we just made, we’d need to modify the fortio command slightly, to add the number of concurrent connections (in this case, 8):

 fortio load  --qps 30 -t 30s  -c 8 <civo dns url > 
Execute the command, and you should see 503s being logged to the terminal, indicating we are hitting the rate limit.

Summary
Rate-Limiting can be extremely useful in mitigating DoS attacks and preventing abuse. However, assessing your specific environment and requirements is crucial before implementing rate limits. Analyzing factors such as expected traffic patterns, application sensitivity, and potential security risks will help you determine if rate limiting is necessary.

In this tutorial, we covered some of the ways in which you can rate-limit your applications using the Nginx Ingress. However, Nginx provides a few more annotations for rate-limiting, some of which might be even more useful to your use-case. Click here to learn more.

Finally, if you’d like to learn more about rate-limiting implementations, solo.io has a great post about rate-limiting algorithms.

Additional Resources:
To further enhance your understanding of related topics, we recommend the following resources:

Introduction to Nginx Ingress Controller: This article provides a comprehensive introduction to the Nginx Ingress Controller, which plays a crucial role in the rate-limiting process.

Securing the Kubernetes API with Intel SGX: Learn about securing the Kubernetes API, a key component of your Kubernetes cluster, with Intel SGX.

Kubernetes Security: All Civo’s tutorials dedicated to Kubernetes security, providing a range of articles that can help you understand and implement security measures, including rate-limiting.

Nginx Resources: Explore a collection of resources dedicated to Nginx, the open-source software that powers the Ingress controller used in the rate-limiting process.

