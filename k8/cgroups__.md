| Isolation Axis      | cgroup v2 Controller            | Namespace Type    | What It Controls                                                                                   | Kubernetes (k3s/k8s) Usage                                                             |
| ------------------- | ------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **CPU**             | `cpu`                           | —                 | CPU shares, quotas, throttling                                                                     | Pod/container CPU requests & limits are enforced via cgroup CPU quotas.                |
| **Memory**          | `memory`                        | —                 | Maximum RAM usage, OOM behavior                                                                    | Enforces pod/container memory limits and guarantees.                                   |
| **Block I/O**       | `io`                            | —                 | Disk I/O bandwidth, IOPS throttling                                                                | Limits disk throughput for pods (e.g., heavy storage workloads).                       |
| **Process Count**   | `pids`                          | PID namespace     | Maximum number of PIDs; PID visibility                                                             | Kubernetes `pod.pidsLimit` and each container sees only its own PIDs.                  |
| **Network**         | `net_cls` / `net_prio` *(opt.)* | Network namespace | *cgroup*: class-based packet tagging<br>*ns*: isolated network stack (interfaces, routes, sockets) | Each pod gets its own veth pair and IP namespace; CNI plugins manage network policies. |
| **Filesystem View** | —                               | Mount namespace   | Isolated mount points and root filesystem tree                                                     | Containers see only their image filesystem and any declared volumes.                   |
| **IPC Objects**     | —                               | IPC namespace     | SysV IPC (shared memory, semaphores, message queues)                                               | Prevents containers from sharing IPC resources across pods.                            |
| **Hostname/Domain** | —                               | UTS namespace     | Hostname and NIS domain name                                                                       | Each pod/container can have its own hostname (e.g. `pod-xyz`).                         |
| **User IDs**        | —                               | User namespace    | Mappings of UID/GID between host and container                                                     | Allows “root” inside a container to map to an unprivileged host user.                  |

# Container Creation
When the kubelet launches a container, it creates a new set of namespaces (PID, network, mount, UTS, IPC, optionally user) so the container has its own isolated view of processes, networking, filesystem, etc.

# cgroup v2 Hierarchy
The kubelet also places that container’s process tree into a dedicated cgroup slice under the node’s unified cgroup v2 hierarchy. Each controller (CPU, memory, io, pids, …) in that slice then enforces the resource limits the user specified in the Pod manifest.

# CNI Networking
The Container Network Interface (CNI) plugin hooks into the network namespace setup, attaching a veth pair to the Pod’s net-ns and programming the host’s bridge/router so the Pod can send and receive traffic.

# Storage and Volumes
Kubernetes mounts volumes into the container’s mount namespace; from inside, the container only sees what the kubelet gave it—no host-fs leaks.

# Enforcement at Runtime
If a container tries to spawn too many processes, exceed its memory limit, or hammer the disk, the respective cgroup controller throttles or kills it. Meanwhile, namespaces ensure it can’t peek at other containers’ processes, files, or network sockets.
