Inject an Executable Script into a Container in Kubernetes

##
#
https://etoews.github.io/blog/2017/07/29/inject-an-executable-script-into-a-container-in-kubernetes/
#
##

29 Jul 2017

Often times you need to inject a configuration file into a container in Kubernetes. This is really easy to do using the ConfigMap resource. But once in a while you might need to inject an executable script into a container.

There are any number of reasons why you might need to do so. In my case, I needed to alter the default behaviour of a Docker image. Normally you might create a new git repo with a Dockerfile and the script, and then build a whole new Docker image just to include the script. Instead you can inject an executable script into the container at runtime using a ConfigMap and the defaultMode of a volume.

The versions used in this post at the time of writing are:

    Minikube: 0.21.0
    VirtualBox: 5.1.22
    Kubernetes and kubectl: 1.7.0

Run it

Create a Kubernetes cluster with Minikube, clone the gist with example code, and run it. Note how the source of the ConfigMap is the wrapper.sh file.
$ minikube start
Starting local Kubernetes v1.7.0 cluster...
Starting VM...
Getting VM IP address...
Moving files into cluster...
Setting up certs...
Starting cluster components...
Connecting to cluster...
Setting up kubeconfig...
Kubectl is now configured to use the cluster.

$ git clone https://gist.github.com/82c039843663de7e7f1e18bf4debe5fa.git inject-exec-script

$ cd inject-exec-script

$ kubectl create configmap wrapper --from-file=wrapper.sh
configmap "wrapper" created

$ kubectl apply -f deployment.yaml
deployment "ghost" created

$ kubectl get pods
NAME                     READY     STATUS    RESTARTS   AGE
ghost-3057289974-zvqm8   1/1       Running   0          30s

$ kubectl logs ghost-3057289974-zvqm8
Do my special initialization here then run the regular entrypoint
...
Ghost is running in development...
Listening on 0.0.0.0:2368
Url configured as: http://localhost:2368
Ctrl+C to shut down
view raw
terminal.sh hosted with ❤ by GitHub
The Executable Script

In this case, the script is just a wrapper around the regular entrypoint for the ghost image that allows you to do some special initialization beforehand.
```
#!/bin/sh

set -euo pipefail

echo "Do my special initialization here then run the regular entrypoint"

exec docker-entrypoint.sh npm start
view raw
wrapper.sh hosted with ❤ by GitHub
The Deployment

A volume is created from the ConfigMap with defaultMode: 0744, that’s what makes it executable. It’s then mounted to a /scripts dir but it could be mounted anywhere. The command: ["/scripts/wrapper.sh"] overrides the Docker image’s entrypoint and runs wrapper.sh instead.
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: ghost
  labels:
    role: blog
spec:
  replicas: 1
  template:
    metadata:
      labels:
        role: blog
    spec:
      containers:
      - name: ghost
        image: ghost:0.11-alpine
        command: ["/scripts/wrapper.sh"]
        ports:
        - name: ghost
          containerPort: 2368
          protocol: TCP
        volumeMounts:
        - name: wrapper
          mountPath: /scripts
      volumes:
      - name: wrapper
        configMap:
          name: wrapper
          defaultMode: 0744

```
view raw
deployment.yaml hosted with ❤ by GitHub
First Crack

Before I found out about defaultMode, my first crack at solving this problem was to use an Init Container like this.
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: ghost
  labels:
    role: blog
spec:
  replicas: 1
  template:
    metadata:
      labels:
        role: blog
      annotations:
        pod.beta.kubernetes.io/init-containers: '[
            {
                "name": "init-ghost",
                "image": "alpine:3.6",
                "command": ["sh", "-c", "chmod u+x /scripts/..data/wrapper.sh"],
                "volumeMounts": [{"name": "wrapper", "mountPath": "/scripts"}]
            }
        ]'
    spec:
      containers:
      - name: ghost
        image: ghost:0.11-alpine
        command: ["/scripts/wrapper.sh"]
        ports:
        - name: ghost
          containerPort: 2368
          protocol: TCP
        volumeMounts:
        - name: wrapper
          mountPath: /scripts
      volumes:
      - name: wrapper
        configMap:
          name: wrapper
view raw
deployment-first-crack.yaml hosted with ❤ by GitHub

It gets the job done but defaultMode is a much more elegant and succinct way to do it.
Coda

You can inject any kind of text based file into a container in Kubernetes. Making it an executable script is just one special case of that. I like this approach a lot because you don’t have to create and maintain yet another Docker image just to inject one particular file.

P.S. I discovered that this is also extremely useful for extending the official Postgres image and creating scripts in the /docker-entrypoint-initdb.d/ dir of the Postgres container.



# Does ConfigMap data propagate to pods where it is used?

## Experiment

Let's see. We first create a config map called `testcm`:

```
kubectl create configmap testcm --from-literal=somekey=INITIAL_VALUE
```

Now a pod that uses the `testcm` config map in an environment variable and via a volume mount:

```
kubectl apply -f podusecm.yaml
```

Let's have a look at the value of the environment variable created from the config map:

```
$ kubectl exec -it cmtest -- env | grep SOME_KEY
SOME_KEY=INITIAL_VALUE
```

And now at the volume mount created from the config map:

```
$ kubectl exec -it cmtest -- cat /tmp/somekey
INITIAL_VALUE
```

Now we change the value of the config map data, that is, we assign the `somekey` key in the `testcm` config map a new value:

```
kubectl patch configmap testcm --type merge  -p '{"data":{"somekey":"UPDATED_VALUE"}}'
```

And check again, first the environment variable:

```
$ kubectl exec -it cmtest -- env | grep SOME_KEY
SOME_KEY=INITIAL_VALUE
```

The value of the environment variable `SOME_KEY` in the pod, which we created from the config map HAS NOT changed.

Finally, we check the volume mount:

```
$ kubectl exec -it cmtest -- cat /tmp/somekey
UPDATED_VALUE
```

The value of the file `/tmp/somekey` in the pod, which we created from the config map HAS changed.

## Conclusion

The config map data changes do propagate automatically if used via a volume mount, however not via environmment variables. See also [Issue 22368](https://github.com/kubernetes/kubernetes/issues/22368) for details.


```
apiVersion: v1
kind: Pod
metadata:
  name: cmtest
spec:
  containers:
    - name: main
      image: quay.io/mhausenblas/jump:0.2
      command: [ "sh", "-c", "sleep 10000" ]
      env:
        - name: SOME_KEY
          valueFrom:
            configMapKeyRef:
              name: testcm
              key: somekey
      volumeMounts:
        - name: config-volume
          mountPath: /tmp
  volumes:
    - name: config-volume
      configMap:
        name: testcm
```
