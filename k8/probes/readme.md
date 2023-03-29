When a Kubernetes pod is created, it is assigned one or more probes to ensure that it is running and healthy. There are two types of probes that can be assigned to a pod: readiness and liveness probes.

A readiness probe is used to determine when a pod is ready to start receiving traffic. A liveness probe is used to determine whether a pod is still alive and responding to requests.

If you are experiencing issues with a readiness or liveness probe for a Kubernetes pod, here are some steps you can take to troubleshoot and fix the problem:

Check the pod logs: Check the pod logs to see if there are any error messages that might indicate the problem. Use the following command to view the logs for the pod:

```
kubectl logs <pod-name>
```

Check the probe configuration: Make sure that the probe configuration is correct and matches the application’s health check endpoint. If the probe configuration is incorrect, update it using the following command:

```
kubectl edit pod <pod-name>
```

Check the application code: Check the application code to ensure that it is running correctly and responding to requests.

Check the network configuration: Check the network configuration to ensure that the pod can communicate with other pods and services.

Restart the pod: If none of the above steps resolve the issue, you may need to restart the pod using the following command:

```
kubectl delete pod <pod-name>
```

Kubernetes will automatically create a new pod to replace the one you just deleted.

By following these steps, you should be able to resolve most readiness and liveness probe problems for your Kubernetes pod.

#
#



In Kubernetes, readiness and liveness probes are used to determine if a pod is healthy and ready to serve traffic. Here are some examples of readiness and liveness configurations:

HTTP readiness probe:

```
readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
This configuration specifies an HTTP GET request to the path "/healthz" on port 8080. The probe will start 5 seconds after the container starts, and will be repeated every 10 seconds.
```



TCP liveness probe:


```
livenessProbe:
  tcpSocket:
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 20
```  
  
This configuration specifies a TCP socket check on port 8080. The probe will start 15 seconds after the container starts, and will be repeated every 20 seconds.

Exec liveness probe:


```
livenessProbe:
  exec:
    command:
    - /bin/sh
    - -c
    - ps aux | grep myprocess
  initialDelaySeconds: 10
  periodSeconds: 30
```
  
  
This configuration specifies an executable command to check if a process with the name "myprocess" is running. The probe will start 10 seconds after the container starts, and will be repeated every 30 seconds.

These are just a few examples of readiness and liveness probe configurations in Kubernetes. There are many other types of probes and configurations available.



#
#

What is a Readiness Probe

Distributed systems are complex. They have many moving parts, and when one part experiences a problem, other parts need to detect this, know not to access or send requests to it, and hopefully heal or replace the failed component. Automated health checks are a useful way to help one component in a distributed system understand when another component is down, and try to remediate the problem.

In Kubernetes, by default, a pod receives traffic when all containers inside it are running. Kubernetes can detect when containers crash and restart them. This is good enough for some deployments, but if you need more reliability, you can use several types of readiness probes to check the status of applications running inside your pods. In essence, probes are a way to perform customized health checks within your Kubernetes environments.

A readiness probe indicates whether applications running in a container are ready to receive traffic. If so, Services in Kubernetes can send traffic to the pod, and if not, the endpoint controller removes the pod from all services.

Learn more about Kubernetes node management and errors in our guide to Kubernetes nodes, or check out the video below:
What are the Three Types of Kubernetes Probes?

Kubernetes provides the following types of probes. For all these types, if the container does not implement the probe handler, their result is always Success.

    Liveness Probe—indicates if the container is operating. If so, no action is taken. If not, the kubelet kills and restarts the container. Learn more in our guide to Kubernetes liveness probes.
    Readiness Probe—indicates whether the application running in the container is ready to accept requests. If so, Services matching the pod are allowed to send traffic to it. If not, the endpoints controller removes the pod from all matching Kubernetes Services.
    Startup Probe—indicates whether the application running in the container has started. If so, other probes start functioning. If not, the kubelet kills and restarts the container.

When to Use Readiness Probes

Readiness probes are most useful when an application is temporarily malfunctioning and unable to serve traffic. If the application is running but not fully available, Kubernetes may not be able to scale it up and new deployments could fail. A readiness probe allows Kubernetes to wait until the service is active before sending it traffic.

When you use a readiness probe, keep in mind that Kubernetes will only send traffic to the pod if the probe succeeds.

There is no need to use a readiness probe on deletion of a pod. When a pod is deleted, it automatically puts itself into an unready state, regardless of whether readiness probes are used. It remains in this status until all containers in the pod have stopped.
How Readiness Probes Work in Kubernetes

A readiness probe can be deployed as part of several Kubernetes objects. For example, here is how to define a readiness probe in a Deployment:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  template:
    metadata:
      labels:
        app: my-test-app
    spec:
      containers:
     —name: my-test-app
        image: nginx:1.14.2
        readinessProbe:
          httpGet:
            path: /ready
            port: 80
          successThreshold: 3
```
Once the above Deployment object is applied to the cluster, the readiness probe runs continuously throughout the lifecycle of the application.

A readiness probe has the following configuration options:
Parameter 	Description 	Default Value
initialDelaySeconds 	Number of seconds between container start and probe start to allow for services to initialize. 	0
periodSeconds 	Frequency of readiness test. 	10
timeoutSeconds 	Timeout for probe responses. 	1
successThreshold 	The number of consecutive success results needed to switch probe status to “Success”. 	1
failureThreshold 	The number of consecutive failed results needed to switch probe status to “Failure”. 	3
Why Do Readiness Probes Fail? Common Error Scenarios

Readiness probes are used to verify tasks during a container lifecycle. This means that if the probe’s response is interrupted or delayed, service may be interrupted. Keep in mind that if a readiness probe returns Failure status, Kubernetes will remove the pod from all matching service endpoints. Here are two examples of conditions that can cause an application to incorrectly fail the readiness probe.
Delayed Response

In some circumstances, readiness probes may be late to respond—for example, if the application needs to read large amounts of data with low latency or perform heavy computations. Consider this behavior when configuring readiness probes, and always test your application thoroughly before running it in production with a readiness probe.
Cascading Failures

A readiness probe response can be conditional on components that are outside the direct control of the application. For example, you could configure a readiness probe using HTTPGet, in such a way that the application first checks the availability of a cache service or database before responding to the probe. This means that if the database is down or late to respond, the entire application will become unavailable.

This may or may not make sense, depending on your application setup. If the application cannot function at all without the third-party component, maybe this behavior is warranted. If it can continue functioning, for example, by falling back to a local cache, the database or external cache should not be connected to probe responses.

In general, if the pod is technically ready, even if it cannot function perfectly, it should not fail the readiness probe. A good compromise is to implement a “degraded mode,” for example, if there is no access to the database, answer read requests that can be addressed by local cache and return 503 (service unavailable) on write requests. Ensure that downstream services are resilient to a failure in the upstream service.


##
##


