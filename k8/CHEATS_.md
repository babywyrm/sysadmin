# Kubernetes cheatsheet

- [Kubernetes cheatsheet](#kubernetes-cheatsheet)
  - [Getting Started](#getting-started)
  - [Sample yaml](#sample-yaml)
  - [Workflow](#workflow)
  - [Physical components](#physical-components)
    - [Master](#master)
    - [Node](#node)
  - [Everything is an object - persistent entities](#everything-is-an-object---persistent-entities)
    - [Namespaces](#namespaces)
    - [Labels](#labels)
      - [ClusterIP](#clusterip)
    - [Controller manager](#controller-manager)
    - [Kube-scheduler](#kube-scheduler)
    - [Pod](#pod)
      - [Status](#status)
      - [Probe](#probe)
      - [Pod priorities](#pod-priorities)
      - [Multi-Container Pods](#multi-container-pods)
      - [Init containers](#init-containers)
      - [Lifecycle hooks](#lifecycle-hooks)
      - [Quality of Service (QoS)](#quality-of-service-qos)
      - [PodPreset](#podpreset)
    - [ReplicaSet](#replicaset)
    - [Deployments](#deployments)
    - [ReplicationController](#replicationcontroller)
    - [DaemonSet](#daemonset)
    - [StatefulSet](#statefulset)
    - [Job (batch/v1)](#job-batchv1)
    - [Cronjob](#cronjob)
    - [Horizontal pod autoscaler](#horizontal-pod-autoscaler)
    - [Services](#services)
    - [Volumes](#volumes)
      - [Persistent volumes](#persistent-volumes)
    - [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
    - [Custom Resource Definitions](#custom-resource-definitions)
  - [Notes](#notes)
    - [Basic commands](#basic-commands)
    - [jsonpath](#jsonpath)
    - [Resource limit](#resource-limit)
      - [CPU](#cpu)
      - [Memory](#memory)
    - [Chapter 13. Integrating storage solutions and Kubernetes](#chapter-13-integrating-storage-solutions-and-kubernetes)
      - [Downward API](#downward-api)
  - [Labs](#labs)
    - [Guaranteed Scheduling For Critical Add-On Pods](#guaranteed-scheduling-for-critical-add-on-pods)
    - [Set command or arguments via env](#set-command-or-arguments-via-env)

## Getting Started

- Fault tolerance
- Rollback
- Auto-healing
- Auto-scaling
- Load-balancing
- Isolation (sandbox)

## Sample yaml

```yaml
apiVersion: <>
kind: <>
metadata:
  name: <>
  labels:
    ...
  annotations:
    ...
spec:
  containers:
    ...
  initContainers:
    ...
  priorityClassName: <>
```

## Workflow

Credit: https://www.reddit.com/user/__brennerm/

![](https://i.redd.it/cqud3rjkss361.png)

- (kube-scheduler, controller-manager, etcd) --443--> API Server

- API Server --10055--> kubelet
  - non-verified certificate
  - MITM
  - Solution:
    - set kubelet-certificate-authority
    - ssh tunneling

- API server --> (nodes, pods, services)
  - Plain HTTP (unsafe)

## Physical components

### Master

- API Server (443)
- kube-scheduler
- controller-manager
  - cloud-controller-manager
  - kube-controller-manager
- etcd

Other components talk to API server, no direct communication

### Node

- Kubelet
- Container Engine
  - CRI
    - The protocol which used to connect between Kubelet & container engine

- Kube-proxy

## Everything is an object - persistent entities

- maintained in etcd, identified using
  - names: client-given
  - UIDs: system-generated
- Both need to be unique

- three management methods
  - Imperative commands (kubectl)
  - Imperative object configuration (kubectl + yaml)
    - repeatable
    - observable
    - auditable
  - Declarative object configuration (yaml + config files)
    - Live object configuration
    - Current object configuration file
    - Last-applied object configuration file

```text
      Node Capacity
---------------------------
| kube-reserved             |
|---------------------------|
| system-reserved           |
| ------------------------- |
| eviction-threshold        |
| ------------------------- |
|                           |
| allocatable               |
| (available for pods)      |
|                           |
|                           |
---------------------------
```

### Namespaces

- Three pre-defined
  - default
  - kube-system
  - kube-public: auto-readable by all users

- Objects without namespaces
  - Nodes
  - PersistentVolumes
  - Namespaces

### Labels

- key / value
- loose coupling via selectors
- need not be unique

#### ClusterIP

- Independent of lifespan of any backend pod
- Service object has a static port assigned to it

### Controller manager

- ReplicaSet, deployment, daemonset, statefulSet
- Actual state <-> desired state
- reconciliation loop

### Kube-scheduler

- nodeSelector
- Affinity & Anti-Affinity
  - Node
    - Steer pod to node
  - Pod
    - Steer pod towards or away from pods
- Taints & tolerations (anti-affinity between node and pod!)
  - Base on predefined configuration (env=dev:NoSchedule)
    ```yaml
    ...
    tolerations:
    - key: "dev"
      operator: "equal"
      value: "env"
      effect: NoSchedule
    ...
    ```
  - Base on node condition (alpha in v1.8)
    - taints added by node controller

### Pod

```bash
kubectl run name --image=<image>
```

What's available inside the container?

- File system
  - Image
  - Associated Volumes
    - ordinary
    - persistent
  - Container
    - Hostname
  - Pod
    - Pod name
    - User-defined envs
  - Services
    - List of all services

Access with:

- Symlink (important):

  - /etc/podinfo/labels
  - /etc/podinfo/annotations

- Or:

```yaml
volumes:
  - name: podinfo
    downwardAPI:
      items:
        - path: "labels"
          fieldRef:
            fieldPath: metadata.labels
        - path: "annotations"
          fieldRef:
            fieldPath: metadata.annotations
```

#### Status

- Pending
- Running
- Succeeded
- Failed
- Unknown

#### Probe

- Liveness
  - Failed? Restart policy applied
- Readiness
  - Failed? Removed from service

#### Pod priorities

- available since 1.8
- PriorityClass object
- Affect scheduling order
  - High priority pods could jump the queue
- Preemption
  - Low priority pods could be pre-empted to make way for higher one (if no node is available for high priority)
  - These preempted pods would have a graceful termination period

#### Multi-Container Pods

- Share access to memory space
- Connect to each other using localhost
- Share access to the same volume
- entire pod is host on the same node
- all in or nothing
- no auto healing or scaling

#### Init containers

- run before app containers
- always run to completion
- run serially

#### Lifecycle hooks

- PostStart
- PreStop (blocking)

Handlers:

- Exec
- HTTP

```yaml
...
spec:
  containers:
    lifecycle:
      postStart:
        exec:
          command: <>
      preStop:
        http:
...
```

Could invoke multiple times

#### Quality of Service (QoS)

When Kubernetes creates a Pod it assigns one of these QoS classes to the Pod:

- Guaranteed (all containers have limits == requests)

>If a Container specifies its own memory limit, but does not specify a memory request, Kubernetes automatically assigns a memory request that matches the limit. Similarly, if a Container specifies its own cpu limit, but does not specify a cpu request, Kubernetes automatically assigns a cpu request that matches the limit.

- Burstable (at least 1 has limits or requests)
- BestEffort (no limits or requests)

#### PodPreset

You can use a podpreset object to inject information like secrets, volume mounts, and environment variables etc into pods at creation time. This task shows some examples on using the PodPreset resource

```yaml
apiVersion: settings.k8s.io/v1alpha1
kind: PodPreset
metadata:
  name: allow-database
spec:
  selector:
    matchLabels:
      role: frontend
  env:
    - name: DB_PORT
      value: "6379"
  volumeMounts:
    - mountPath: /cache
      name: cache-volume
  volumes:
    - name: cache-volume
      emptyDir: {}
```

### ReplicaSet

Features:

- Scaling and healing
- Pod template
- number of replicas

Components:

- Pod template
- Pod selector (could use matchExpressions)
- Label of replicaSet
- Number of replica

- Could delete replicaSet without its pods using `--cascade =false`
- Isolating pods from replicaSet by changing its labels

### Deployments

- versioning and rollback
- Contains spec of replicaSet within it
- advanced deployment
- blue-green
- canary

- Update containers --> new replicaSet & new pods created --> old RS still exists --> reduced to zero
- Every change is tracked

- Append `--record` in kubectl to keep history
- Update strategy
  - Recreate
    - Old pods would be killed before new pods come up
  - RollingUpdate
    - progressDeadlineSeconds
    - minReadySeconds
    - rollbackTo
    - revisionHistoryLimit
    - paused
      - spec.Paused

- `kubectl rollout undo deployment/<> --to-revision=<>`
- `kubectl rollout statua deployment/<>`
- `kubectl set image deployment/<> <>=<>:<>`
- `kubectl rollout resume/pause <>`

### ReplicationController

- RC = ( RS + deployment ) before
- Obsolete

### DaemonSet

- Ensure all nodes run a copy of pod
- Cluster storage, log collection, node monitor ...

### StatefulSet

- Maintains a sticky identity
- Not interchangeable
- Identifier maintains across any rescheduling

Limitation

- volumes must be pre-provisioned
- Deleting / Scaling will not delete associated volumes

Flow

- Deployed 0 --> (n-1)
- Deleted (n-1) --> 0 (successor must be completely shutdown before proceed)
- Must be all ready and running before scaling happens

### Job (batch/v1)

- Non-parallel jobs
- Parallel jobs
  - Fixed completion count
    - job completes when number of completions reaches target
  - With work queue
    - requires coordination
- Use spec.activeDeadlineSeconds to prevent infinite loop

### Cronjob

- Job should be idempotent

### Horizontal pod autoscaler

- Targets: replicaControllers, deployments, replicaSets
- CPU or custom metrics
- Won't work with non-scaling objects: daemonSets
- Prevent thrashing (upscale/downscale-delay)

### Services

Credit: https://www.reddit.com/user/__brennerm/

![](https://i.redd.it/brjcbq9xk7261.png)

- Logical set of backend pods + frontend
- Frontend: static IP + port + dns name
- Backend: set of backend pods (via selector)

- Static IP and networking.
- Kube-proxy route traffic to VIP.
- Automatically create endpoint based on selector.

- CluterIP
- NodePort
  - external --> NodeIP + NodePort --> kube-proxy --> ClusterIP
- LoadBalancer
  - Need to have cloud-controller-manager
    - Node controller
    - Route controller
    - Service controller
    - Volume controller
  - external --> LB --> NodeIP + NodePort --> kube-proxy --> ClusterIP
- ExternalName
  - Can only resolve with kube-dns
  - No selector

`Service discovery`

- SRV record for named port
  - port-name.port-protocol.service-name.namespace.svc.cluster.local
- Pod domain
  - pod-ip-address.namespace.pod.cluster.local
  - hostname is `metadata.name`

`spec.dnsPolicy`

- default
  - inherit node's name resolution
- ClusterFirst
  - Any DNS query that does not match the configured cluster domain suffix, such as “www.kubernetes.io”, is forwarded to the upstream nameserver inherited from the node
- ClusterFirstWithHostNet
  - if host network = true
- None (since k8s 1.9)
  - Allow custom dns server usage

Headless service

- with selector? --> associate with pods in cluster
- without selector? --> forward to externalName

Could specify externalIP to service

### Volumes

Credit: https://www.reddit.com/user/__brennerm/

![](https://i.redd.it/iaflueca8m261.png)

Lifetime longer than any containers inside a pod.

4 types:

- configMap

- emptyDir
  - share space / state across containers in same pod
  - containers can mount at different times
  - pod crash --> data lost
  - container crash --> ok
- gitRepo

- secret
  - store on RAM

- hostPath

#### Persistent volumes

### Role-Based Access Control (RBAC)

Credit: https://www.reddit.com/user/__brennerm/

![](https://i.redd.it/868lf3pp70361.png)

- Role
  - Apply on namespace resources
- ClusterRole
  - cluster-scoped resources (nodes,...)
  - non-resources endpoint (/healthz)
  - namespace resources across all namespaces

### Custom Resource Definitions

CustomResourceDefinitions themselves are non-namespaced and are available to all namespaces.

```yaml
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  # name must match the spec fields below, and be in the form: <plural>.<group>
  name: crontabs.stable.example.com
spec:
  # group name to use for REST API: /apis/<group>/<version>
  group: stable.example.com
  # version name to use for REST API: /apis/<group>/<version>
  version: v1
  # either Namespaced or Cluster
  scope: Namespaced
  names:
    # plural name to be used in the URL: /apis/<group>/<version>/<plural>
    plural: crontabs
    # singular name to be used as an alias on the CLI and for display
    singular: crontab
    # kind is normally the CamelCased singular type. Your resource manifests use this.
    kind: CronTab
    # shortNames allow shorter string to match your resource on the CLI
    shortNames:
    - ct
    # categories is a list of grouped resources the custom resource belongs to.
    categories:
    - all
  validation:
   # openAPIV3Schema is the schema for validating custom objects.
    openAPIV3Schema:
      properties:
        spec:
          properties:
            cronSpec:
              type: string
              pattern: '^(\d+|\*)(/\d+)?(\s+(\d+|\*)(/\d+)?){4}$'
            replicas:
              type: integer
              minimum: 1
              maximum: 10
  # subresources describes the subresources for custom resources.
  subresources:
    # status enables the status subresource.
    status: {}
    # scale enables the scale subresource.
    scale:
      # specReplicasPath defines the JSONPath inside of a custom resource that corresponds to Scale.Spec.Replicas.
      specReplicasPath: .spec.replicas
      # statusReplicasPath defines the JSONPath inside of a custom resource that corresponds to Scale.Status.Replicas.
      statusReplicasPath: .status.replicas
      # labelSelectorPath defines the JSONPath inside of a custom resource that corresponds to Scale.Status.Selector.
      labelSelectorPath: .status.labelSelector
```

## Notes

### Basic commands

```bash
# show current context
kubectl config current-context

# get specific resource
kubectl get (pod|svc|deployment|ingress) <resource-name>

# Get pod logs
kubectl logs -f <pod-name>

# Get nodes list
kubectl get no -o custom-columns=NAME:.metadata.name,AWS-INSTANCE:.spec.externalID,AGE:.metadata.creationTimestamp

# Run specific command | Drop to shell
kubectl exec -it <pod-name> <command>

# Describe specific resource
kubectl describe (pod|svc|deployment|ingress) <resource-name>

# Set context
kubectl config set-context $(kubectl config current-context) --namespace=<namespace-name>

# Run a test pod
kubectl run -it --rm --generator=run-pod/v1 --image=alpine:3.6 tuan-shell -- sh
```

- from @so0k [link](https://gist.github.com/so0k/42313dbb3b547a0f51a547bb968696ba#gistcomment-2040702)

- access dashboard

```bash
# bash
kubectl -n kube-system port-forward $(kubectl get pods -n kube-system -o wide | grep dashboard | awk '{print $1}') 9090

# fish
kubectl -n kube-system port-forward (kubectl get pods -n kube-system -o wide | grep dashboard | awk '{print $1}') 9090
```

### jsonpath

From [link](https://github.com/kubernetes/website/blob/master/content/en/docs/reference/kubectl/jsonpath.md)

```json
{
  "kind": "List",
  "items":[
    {
      "kind":"None",
      "metadata":{"name":"127.0.0.1"},
      "status":{
        "capacity":{"cpu":"4"},
        "addresses":[{"type": "LegacyHostIP", "address":"127.0.0.1"}]
      }
    },
    {
      "kind":"None",
      "metadata":{"name":"127.0.0.2"},
      "status":{
        "capacity":{"cpu":"8"},
        "addresses":[
          {"type": "LegacyHostIP", "address":"127.0.0.2"},
          {"type": "another", "address":"127.0.0.3"}
        ]
      }
    }
  ],
  "users":[
    {
      "name": "myself",
      "user": {}
    },
    {
      "name": "e2e",
      "user": {"username": "admin", "password": "secret"}
    }
  ]
}
```

| Function          | Description               | Example                                                       | Result                                          |
|-------------------|---------------------------|---------------------------------------------------------------|-------------------------------------------------|
| text              | the plain text            | kind is {.kind}                                               | kind is List                                    |
| @                 | the current object        | {@}                                                           | the same as input                               |
| . or []           | child operator            | {.kind} or {['kind']}                                         | List                                            |
| ..                | recursive descent         | {..name}                                                      | 127.0.0.1 127.0.0.2 myself e2e                  |
| \*                | wildcard. Get all objects | {.items[*].metadata.name}                                     | [127.0.0.1 127.0.0.2]                           |
| [start:end :step] | subscript operator        | {.users[0].name}                                              | myself                                          |
| [,]               | union operator            | {.items[*]['metadata.name', 'status.capacity']}               | 127.0.0.1 127.0.0.2 map[cpu:4] map[cpu:8]       |
| ?()               | filter                    | {.users[?(@.name=="e2e")].user.password}                      | secret                                          |
| range, end        | iterate list              | {range .items[*]}[{.metadata.name}, {.status.capacity}] {end} | [127.0.0.1, map[cpu:4]] [127.0.0.2, map[cpu:8]] |
| ''                | quote interpreted string  | {range .items[*]}{.metadata.name}{'\t'}{end}                  | 127.0.0.1    127.0.0.2                          |

Below are some examples using jsonpath:

```shell
$ kubectl get pods -o json
$ kubectl get pods -o=jsonpath='{@}'
$ kubectl get pods -o=jsonpath='{.items[0]}'
$ kubectl get pods -o=jsonpath='{.items[0].metadata.name}'
$ kubectl get pods -o=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.startTime}{"\n"}{end}'
```

### Resource limit

#### CPU

The CPU resource is measured in cpu units. One cpu, in Kubernetes, is equivalent to:

- 1 AWS vCPU
- 1 GCP Core
- 1 Azure vCore
- 1 Hyperthread on a bare-metal Intel processor with Hyperthreading

#### Memory

The memory resource is measured in bytes. You can express memory as a plain integer or a fixed-point integer with one of these suffixes: E, P, T, G, M, K, Ei, Pi, Ti, Gi, Mi, Ki. For example, the following represent approximately the same value:

128974848, 129e6, 129M , 123Mi

### Chapter 13. Integrating storage solutions and Kubernetes

- External service without selector (access with `external-database.svc.default.cluster` endpoint)

```yaml
kind: Service
apiVersion: v1
metadata:
  name: external-database
spec:
  type: ExternalName
  externalName: "database.company.com
```

- external service with IP only

```yaml
kind: Service
apiVersion: v1
metadata:
  name: external-ip-database
---
kind: Endpoints
apiVersion: v1
metadata:
  name: external-ip-database
subsets:
  - addresses:
    - ip: 192.168.0.1
    ports:
    - port: 3306
```

#### Downward API

The following information is available to containers through environment variables and downwardAPI volumes:

Information available via fieldRef:

- spec.nodeName - the node’s name
- status.hostIP - the node’s IP
- metadata.name - the pod’s name
- metadata.namespace - the pod’s namespace
- status.podIP - the pod’s IP address
- spec.serviceAccountName - the pod’s service account name
- metadata.uid - the pod’s UID
- metadata.labels['<KEY>'] - the value of the pod’s label <KEY> (for example, metadata.labels['mylabel']); available in Kubernetes 1.9+
- metadata.annotations['<KEY>'] - the value of the pod’s annotation <KEY> (for example, metadata.annotations['myannotation']); available in Kubernetes 1.9+
- Information available via resourceFieldRef:
- A Container’s CPU limit
- A Container’s CPU request
- A Container’s memory limit
- A Container’s memory request

In addition, the following information is available through downwardAPI volume fieldRef:

- metadata.labels - all of the pod’s labels, formatted as label-key="escaped-label-value" with one label per line
- metadata.annotations - all of the pod’s annotations, formatted as annotation-key="escaped-annotation-value" with one annotation per line

## Labs

### Guaranteed Scheduling For Critical Add-On Pods

See [link](https://kubernetes.io/docs/tasks/administer-cluster/guaranteed-scheduling-critical-addon-pods/)

- Marking pod as critical when using Rescheduler. To be considered critical, the pod has to:
  - Run in the `kube-system` namespace (configurable via flag)
  - Have the `scheduler.alpha.kubernetes.io/critical-pod` annotation set to empty string
  - Have the PodSpec’s tolerations field set to `[{"key":"CriticalAddonsOnly", "operator":"Exists"}]`.

> The first one marks a pod a critical. The second one is required by Rescheduler algorithm.

- Marking pod as critical when priorites are enabled. To be considered critical, the pod has to:
  - Run in the `kube-system` namespace (configurable via flag)
  - Have the priorityClass set as `system-cluster-critical` or `system-node-critical`, the latter being the highest for entire cluster
  - `scheduler.alpha.kubernetes.io/critical-pod` annotation set to empty string(This will be deprecated too).

### Set command or arguments via env

```yaml
env:
- name: MESSAGE
  value: "hello world"
command: ["/bin/echo"]
args: ["$(MESSAGE)"]
```
