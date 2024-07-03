# Podman as a Docker Desktop alternative

## Prerequisites

1. Install Homebrew from https://brew.sh

## Install Podman

```shell
$ brew install podman
$ podman machine init # optionally configure memory / CPU / disk sizes
```

If you want to share your host filesystem with the guest VM, provide the `-v` option to set the host path and the location where it should be mapped to. For convenience, I use the same path in both cases to avoid needing to remember that mapping on every `podman run` command:

```bash
$ podman machine init -v $(realpath ~/Projects):$(realpath ~/Projects)
```

## Using Podman

When you want to run containers, start the VM which Podman will use to run them:

```shell
$ podman machine start
```

The `podman` CLI is mostly compatible with the `docker` CLI. You can either retrain your memory or add an alias to your shell configuration:

```shell
$ alias docker podman
```

### Docker Compose

As of 3.x, podman works with Compose. See e.g. https://www.redhat.com/sysadmin/podman-docker-compose for a tutorial.

If you run into problems with compose builds failing with this error it's because of [compatibility issues with BuildKit](https://github.com/containers/podman/issues/13889) which are in the process of being resolved. You can avoid those by setting `DOCKER_BUILDKIT=0` in your environment:

```bash
$ docker-compose create
[+] Building 0.0s (0/0)                                                                                                                
listing workers for Build: failed to list workers: Unavailable: connection error: desc = "transport: Error while dialing unable to upgrade to h2c, received 404"
$ DOCKER_BUILDKIT=0 docker-compose up
Sending build context to Docker daemon  2.723GB
STEP 1/16: FROM amazonlinux:2
…
```

### Legacy networking

Podman does not support the legacy Docker network linking feature (`docker run --link`) which has been deprecated by Docker as well. You can replace this with the new [network](https://podman.io/getting-started/network.html) calls ([`podman network create`](https://docs.podman.io/en/latest/markdown/podman-network-create.1.html), etc.) and replacing `--link` with `--network` in your invocations, which is a good move for the future when the deprecated functionality is removed from `dockerd`.

### Apple Silicon and AMD-64 x86 container images

Thanks to [a recently-landed QEMU patch](https://github.com/Homebrew/homebrew-core/pull/85173), ARM64 containers work seamlessly. If you want to run x86 containers, the multiarch [qemu-user-static](https://github.com/multiarch/qemu-user-static) package will need a one-time install:

```shell
$ podman machine ssh podman-machine-default sudo rpm-ostree install qemu-user-static
$ podman machine ssh podman-machine-default sudo systemctl reboot
```

##
##

## Secrets

Podman now (well, for a while now) has support for secrets. RedHat has a [blog](https://www.redhat.com/sysadmin/new-podman-secrets-command) about it. This is particularly useful to 1) maintain better compatibility with Kubernetes manifests and 2) keep your secrets out of your git commits!

So, what is not well documented (that I could find) is that you can use these secrets in a Kubernetes manifest to inject secrets into environment variables. To do this, you have to first base64 encode them as you would for an actual Kubernetes secret.

Here, I'm taking a YAML snippet, using `yq` to make it to JSON, then using `jq` to create a base64 encoded JSON. Finally, pass that to podman and tell it to create a secret called `ec-creds`.

```shell
cat <<EOF | yq e -o=json | jq '{ "cloud_id": (.cloud_id | @base64 ), "cloud_auth": (.cloud_auth | @base64)}' | sudo podman secret create ec-creds -
---
cloud_id: "<CLOUD ID NAME>:<ENCODED CLOUD ID}"
cloud_auth: "<CLOUD USER>:<CLOUD PASSWORD>"
EOF
```

You can now use that in a Kubernetes manifest as normal.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: filebeat
spec:
  containers:
  - name: filebeat
    image: docker.elastic.co/beats/filebeat:7.15.0
    env:
      - name: ELASTIC_CLOUD_ID
        valueFrom:
          secretKeyRef:
            name: ec-creds
            key: cloud_id
      - name: ELASTIC_CLOUD_AUTH
        valueFrom:
          secretKeyRef:
            name: ec-creds
            key: cloud_auth
  restartPolicy: Never
```



# Podman is a daemon-less container engine for developing, managing, and running OCI Containers on your Linux System. 

# Containers can either be run as root or in rootless mode.


Podman
Docker VS Podman
Daemonless — Docker is built on top of runC runtime container runtime, which runs a docker daemon to execute tasks. Podman is light-weight and doesn’t require an always running instance for running containers, It is directly using the runC runtime container.
Rootless — Podman can be run as either root or non-root. We can run podman containers as non-root user and still be working with running containers, but docker daemon need to run sudo.
Pods — The term Pods originated from Kubernetes. Pods are a collections of containers which are run as close as possible. Podman provides this feature out of the box for running multiple containers together.
Image & Containers Location:
- Docker: /var/lib/docker
- Podman ( root ): /var/lib/containers
- Podman ( normal_user ): ~/.local/share/containers
Note: You can also use docker alongside podman, So you don’t need to remove docker from your machine to install podman
Install Podman as Rootless
To run podman as rootless:
Prerequisites
Enable cgroups v2
To allow rootless operation of Podman containers, first determine which user(s) and group(s) you want to use for the containers, and then add their corresponding entries to /etc/subuid and /etc/subgid respectively.
1.0 Enable cgroups-v2
====================================================================
Enable cgroups v2
====================================================================
# Enable This Kernel Paramater
$ echo 'kernel.unprivileged_userns_clone=1' > /etc/sysctl.d/userns.conf
```
# Edit grub

# Use one of them:
- systemd.unified_cgroup_hierarchy=1 - Systemd will mount /sys/fs/cgroup as cgroup v2
- cgroup_no_v1="all" - The kernel will disable all v1 cgroup controllers

---
$ sudo vim /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT=".... systemd.unified_cgroup_hierarchy=1 --or-- cgroup_no_v1="all""
---

# Manual Method
$ mount -t cgroup2 none /sys/fs/cgroup

# To Check
# For V2
$ ls /sys/fs/cgroup

cgroup.controllers      cgroup.subtree_control  init.scope/      system.slice/
cgroup.max.depth        cgroup.threads          io.cost.model    user.slice/
cgroup.max.descendants  cpu.pressure            io.cost.qos
cgroup.procs            cpuset.cpus.effective   io.pressure
cgroup.stat             cpuset.mems.effective   memory.pressure

# V1 ( if you see these file then your cgroup is on v1 )
$ ls /sys/fs/cgroup

blkio/    cpu,cpuacct/  freezer/  net_cls@           perf_event/  systemd/
cpu@      cpuset/       hugetlb/  net_cls,net_prio/  pids/        unified/
cpuacct@  devices/      memory/   net_prio@          rdma/

# Update
$ sudo grub-mkconfig -o /boot/grub/grub.cfg
$ reboot
2.0 Enable Uid’ss and Gid’s for User
====================================================================
User Specification
====================================================================

# The following below commands enables the podman user and group to run Podman containers (or other types of containers in that case).
# It allocates the UIDs and GIDs from 100000to 165535 to the podman user and group respectively.

$ sudo touch /etc/{subgid,subuid}
$ sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {USER}
$ grep {USER} /etc/subuid /etc/subgid
/etc/subuid:{USER}:100000:65536
/etc/subgid:{USER}:100000:65536
Install Podman
====================================================================
Install Podman
====================================================================

$ sudo pacman -S podman crun cockpit-podman
# cockpit-podman : supports podman containers in cockpit

$ podman system migrate

$ podman --version
podman version 2.1.1

====================================================================
Add Registries
====================================================================

$ sudo vim /etc/containers/registries.conf
[registries.search]
registries = ['docker.io', 'registry.fedoraproject.org', 'quay.io', 'registry.access.redhat.com', 'registry.centos.org']
Basic Podman Commands
# Podman commands are same as docker commands: ( It some of new commands like podman system )
  attach      Attach to a running container
  auto-update Auto update containers according to their auto-update policy
  build       Build an image using instructions from Containerfiles
  commit      Create new image based on the changed container
  container   Manage containers
  cp          Copy files/folders between a container and the local filesystem
  create      Create but do not start a container
  diff        Display the changes to the object's file system
  events      Show podman events
  exec        Run a process in a running container
  export      Export container's filesystem contents as a tar archive
  generate    Generate structured data based on containers and pods.
  healthcheck Manage health checks on containers
  help        Help about any command
  history     Show history of a specified image
  image       Manage images
  images      List images in local storage
  import      Import a tarball to create a filesystem image
  info        Display podman system information
  init        Initialize one or more containers
  inspect     Display the configuration of object denoted by ID
  kill        Kill one or more running containers with a specific signal
  load        Load an image from container archive
  login       Login to a container registry
  logout      Logout of a container registry
  logs        Fetch the logs of one or more containers
  manifest    Manipulate manifest lists and image indexes
  mount       Mount a working container's root filesystem
  network     Manage networks
  pause       Pause all the processes in one or more containers
  play        Play a pod and its containers from a structured file.
  pod         Manage pods
  port        List port mappings or a specific mapping for the container
  ps          List containers
  pull        Pull an image from a registry
  push        Push an image to a specified destination
  restart     Restart one or more containers
  rm          Remove one or more containers
  rmi         Removes one or more images from local storage
  run         Run a command in a new container
  save        Save image(s) to an archive
  search      Search registry for image
  start       Start one or more containers
  stats       Display a live stream of container resource usage statistics
  stop        Stop one or more containers
  system      Manage podman
  tag         Add an additional name to a local image
  top         Display the running processes of a container
  unmount     Unmounts working container's root filesystem
  unpause     Unpause the processes in one or more containers
  unshare     Run a command in a modified user namespace
  untag       Remove a name from a local image
  version     Display the Podman Version Information
  volume      Manage volumes
  wait        Block on one or more containers

---

# Podman System Commands
  connection  Manage remote ssh destinations
  df          Show podman disk usage
  info        Display podman system information
  migrate     Migrate containers
  prune       Remove unused data
  renumber    Migrate lock numbers
  reset       Reset podman storage
  service     Run API service

# Ex:
# You can add another podman server like this:
$ podman system connection add server2 ssh://user@ip

# Show podman space usage
$ podman systemd df
TYPE           TOTAL   ACTIVE  SIZE     RECLAIMABLE
Images         4       4       1.024GB  0B (0%)
Containers     4       0       495.4kB  495.4kB (100%)
Local Volumes  3       0       246.6kB  66.34kB (0%)
Add a Container
====================================================================
Add a container
====================================================================

# For Example: I Install a Linkding ( which is a bookmark manager built with Python and JS )
# Demo here : https://demo.linkding.link/
# Github : https://github.com/sissbruecker/linkding
$ podman volume create linkding_data
$ podman run --name linkding -p 9050:9090 -v linkding_data:/etc/linkding/data -d sissbruecker/linkding

# Create a user on linkding
$ podman exec -it linkding python manage.py createsuperuser --username=admin --email=hi@example.com

# List Containers
$ podman ls

# Stop Container
$ podman stop {container_name--or--id}

# Remove Container
$ podman rm {container_name--or--id}

# Note: As we know podman is daemonless, so this container is stopped on next boot.
# To make it persistent

# Enable linger
$ sudo loginctl enable-linger {USER}
$ sudo loginctl user-status {USER}

# Create user systemd service for a container
$ cd .config
$ mkdir -p systemd/user
$ cd systemd/user
$ podman generate systemd --name linkding --files
$ systemctl --user daemon-reload
$ systemctl --user enable --now container-linkding.service
$ systemctl --user status container-linkding.service

Linkding
Enable Docker Like API
====================================================================
REST-API
====================================================================

$ podman system service --time=0 unix://temp/podman.sock &
[1] 9860

# To gather info
$ curl -s --unix-socket /tmp/podman.sock http://d/v1.0.0/libpod/info | jq
Podman-Compose
====================================================================
podmon-compose
====================================================================
# Github : https://github.com/containers/podman-compose

# Installation
$ pip3 install podman-compose

# For example: I use mongodb and mongodb-express
---docker-compose.yml
version: '3.1'

services:
  mongo:
    image: mongo
    container_name: 'mongo_db'
    restart: always
    ports:
      - 27017:27017
    environment:
      MONGO_INITDB_ROOT_USERNAME: root
      MONGO_INITDB_ROOT_PASSWORD: password
    volumes:
      - $HOME/containers/mongodb/data:/data/db

  mongo-express:
    image: mongo-express
    restart: always
    ports:
      - 8081:8081
    environment:
      ME_CONFIG_MONGODB_ADMINUSERNAME: root
      ME_CONFIG_MONGODB_ADMINPASSWORD: password
---

$ podman-compose up -d

# Note: This will create a pod with containers
# If you dont know what pod is: Pods are a group of one or more containers sharing the same network, pid and ipc namespaces.

# Show Containers
$ podman pod ps
POD ID        NAME     STATUS   CREATED        # OF CONTAINERS  INFRA ID
25508df4be69  mongodb  Running  7 seconds ago  3                3da85cb0b359

# To show containers details
$ podman pod inspect mongodb

# Available Commands for podman pod:
  create      Create a new empty pod
  exists      Check if a pod exists in local storage
  inspect     Displays a pod configuration
  kill        Send the specified signal or SIGKILL to containers in pod
  pause       Pause one or more pods
  prune       Remove all stopped pods and their containers
  ps          List pods
  restart     Restart one or more pods
  rm          Remove one or more pods
  start       Start one or more pods
  stats       Display a live stream of resource usage statistics for the containers in one or more pods
  stop        Stop one or more pods
  top         Display the running processes of containers in a pod
  unpause     Unpause one or more pods
