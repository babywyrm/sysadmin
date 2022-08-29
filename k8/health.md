Health Checks
https://kubebyexample.com/concept/health-checks
#
#
##
##
##
#
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
