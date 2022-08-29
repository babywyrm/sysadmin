Health Checks
https://kubebyexample.com/concept/health-checks
#
#
##
##
##
#


How to Perform Health checks in Kubernetes (K8s)
Kubernetes provides a health checking mechanism to verify if a container in a pod is working or not working.


Health Checks source Thanks to (https://wideops.com/)
Kubernetes gives you two types of health checks performed by the kubelet.

They are:

Startup Probe
Liveness Probe
Readiness Probe
Startup Probe

Whenever we are dealing with physical/Legacy apps those may require extra startup time at first initialization. In this case, we have a tendency to established a startup probe with the constant command, protocol, or TCP check, with a failure threshold period seconds long enough to hide the more severe case startup time.

ports:
- name: liveness-port
  containerPort: 8080
  hostPort: 8080
livenessProbe:
  httpGet:
    path: /healthz
    port: liveness-port
  failureThreshold: 1
  periodSeconds: 10
startupProbe:
  httpGet:
    path: /healthz
    port: liveness-port
  failureThreshold: 30
  periodSeconds: 10
Liveness Probe

Liveness probe checks the status of the container (whether it is running or not).

If the liveness probe fails, then automatically container move on with its restart policy


Liveness Probe source Thanks to (https://wideops.com/)
Readiness Probe

Readiness probe checks whether your application is ready to serve the requests.

When the readiness probe fails, the pod’s IP is removed from the endpoint list of the service.


Readiness Healthcheck source Thanks to (https://wideops.com/)
There are three types of actions kubelet performs on a pod, which are:

Executes a command inside the container
Checks for a state of a particular port on the container
Performs a GET request on container’s IP
Define a liveness command

livenessProbe:
  exec:
    command:
    - sh
    - /tmp/status_check.sh
  initialDelaySeconds: 10
  periodSeconds: 5
Define a liveness HTTP request

livenessProbe:
  httpGet:
    path: /health
    port: 8080
 initialDelaySeconds: 5
 periodSeconds: 3
Define a TCP liveness probe

--- 
initialDelaySeconds: 15
livenessProbe: ~
periodSeconds: 20
port: 8080
tcpSocket: ~
Readiness probes are configured similarly to liveness probes.

The only difference is that you use the readiness probe field instead of the liveness probe field.

Define readiness probe

--- 
command: 
  - sh
  - /tmp/status_check.sh
exec: ~
initialDelaySeconds: 5
periodSeconds: 5
readinessProbe: ~
Configure Probes

Probes have several fields that you can use to more precisely control the behavior of liveness and readiness checks:

initialDelaySeconds: Number of seconds after the container has started before liveness or readiness probes are initiated.
Defaults to 0 seconds. The minimum value is 0.
periodSeconds: How often (in seconds) to perform the probe.
Default to 10 seconds. The minimum value is 1.
timeout seconds: Number of seconds after which the probe times out.
Defaults to 1 second. The minimum value is 1.
success threshold: Minimum consecutive successes for the probe to be considered successful after having failed.
Defaults to 1. Must be 1 for liveness. The minimum value is 1.
failure threshold: Minimum consecutive fails for the probe to be considered restarting the container. In the case of readiness probe, the Pod will be marked Unready.
Defaults to 3. The minimum value is 1.
Nginx deployment

apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-webserver
  labels:
    app: webserver
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: webserver
    spec:
      containers:
        - name: webserver
          image: nginx
          imagePullPolicy: Always
          ports:
            - containerPort: 80
          livenessProbe:
            httpGet:
              path: /
              port: 80
            initialDelaySeconds: 5
            periodSeconds: 3
          readinessProbe:
            httpGet:
              path: /
              port: 80
            initialDelaySeconds: 5
            periodSeconds: 3
HTTP get has additional fields that can be set:

path: Path to access on the HTTP server.
port: Name or number of the port to access the container. The number must be in the range of 1 to 65535.
host: Hostname to connect to, defaults to the pod IP. You probably want to set “Host” in HTTP headers instead.
HTTP headers: Custom headers to set in the request. HTTP allows repeated headers.
scheme: Scheme to use for connecting to the host (HTTP or HTTPS). Defaults to HTTP.


##
##
##


#
In order to verify if a container in a pod is healthy and ready to serve traffic, Kubernetes provides for a range of health checking mechanisms. Health checks, or probes as they are called in Kubernetes, are carried out by the kubelet to determine when to restart a container (liveness probes) and used by services and deployments to determine if a pod should receive traffic (readiness probes). We will focus on HTTP health checks in the following. Note that it is the responsibility of the application developer to expose a URL that the kubelet can use to determine if the container is healthy (and potentially ready).

Let's create a pod that exposes an endpoint /health, responding with a HTTP 200 status code:

kubectl apply -f https://raw.githubusercontent.com/openshift-evangelists/kbe/main/specs/healthz/pod.yaml
In the pod specification we've defined the following:

livenessProbe:
initialDelaySeconds: 2
periodSeconds: 5
httpGet:
path: /health
port: 9876
The configuration above tells Kubernetes to start checking the /health endpoint, after initially waiting 2 seconds, every 5 seconds.  

If we now look at the pod we can see that it is considered healthy:
kubectl describe pod hc
The following (truncated) output shows the relevant sections:

Name:         hc
Namespace:    default
Priority:     0
Node:         minikube/192.168.39.51
...
Containers:
  sise:
    Container ID:   docker://2cfe4187808a89ae4731abfe242ac42611e1f658505691f540ac31ca8f6ce86f
    Image:          quay.io/openshiftlabs/simpleservice:0.5.0
    ...
    Ready:          True
    Restart Count:  0
    Liveness:       http-get http://:9876/health delay=2s timeout=1s period=5s #success=1 #failure=3
    Environment:    <none>
Conditions:
  Type              Status
  Initialized       True 
  Ready             True 
  ContainersReady   True 
  PodScheduled      True 
...
Now launch a bad pod which will randomly (in the time range 1 to 4 sec) not return a 200 code:
kubectl apply -f https://raw.githubusercontent.com/openshift-evangelists/kbe/main/specs/healthz/badpod.yaml
Looking at the events of the bad pod, we can see that the health check failed:

kubectl describe pod badpod
In particular, look at the events section at the bottom:
Events:
  Type     Reason     Age               From               Message
  ----     ------     ----              ----               -------
  Normal   Scheduled  24s               default-scheduler  Successfully assigned default/badpod to minikube
  Normal   Pulled     22s               kubelet            Container image "quay.io/openshiftlabs/simpleservice:0.5.0" already present on machine
  Normal   Created    22s               kubelet            Created container sise
  Normal   Started    22s               kubelet            Started container sise
  Warning  Unhealthy  9s (x3 over 19s)  kubelet            Liveness probe failed: Get "http://172.17.0.4:9876/health": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
  Normal   Killing    9s                kubelet            Container sise failed liveness probe, will be restarted
This can also be verified with the get subcommand:

kubectl get pods
Notice that badpod has been restarted multiple times because of the failing health checks.

NAME     READY   STATUS    RESTARTS   AGE
badpod   1/1     Running   2          109s
hc       1/1     Running   0          11m
In addition to a liveness probe, you can also specify a readiness probe. Readiness probes are configured in the same way, but have different use cases and semantics. The readiness probe indicates when the application itself is running and able to receive traffic.

Let's create a pod with a readiness probe that reports success after 10 seconds:
kubectl apply -f https://raw.githubusercontent.com/openshift-evangelists/kbe/main/specs/healthz/ready.yaml
Looking at the events of the pod, we can see that, eventually, the pod is ready to serve traffic:

kubectl describe pod ready
Depending on how quickly you ran the describe command, you may have noticed the pod reflected that it was not ready to receive traffic:

Conditions:
  Type              Status
  Initialized       True 
  Ready             False 
  ContainersReady   False 
  PodScheduled      True 
You can remove all of the created pods with:
kubectl delete pod/hc pod/ready pod/badpod
