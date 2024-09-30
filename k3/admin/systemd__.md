# README - Setup K3s cluster (multiple nodes)

##
#
https://gist.github.com/drmalex07/72fe55b32e341f8392a45eb6ca5c7317
#
##

Download `k3s` binary on all machines at `/usr/local/bin` (see instructions at https://k3s.io/) 

## 1. Setup server (controlplane)

Prepare env file for the service unit (`/etc/default/k3s`). For example:

```
INTERNAL_IP=10.0.5.19
```

Prepare service unit for K3s server (`/etc/systemd/system/k3s.service`):

```ini
[Unit]
Description=Lightweight Kubernetes
Documentation=https://k3s.io
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=-/etc/default/%N
ExecStart=/usr/local/bin/k3s server --bind-address ${INTERNAL_IP} --node-external-ip ${INTERNAL_IP} --disable=traefik
KillMode=process
Delegate=yes

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start service:

    sudo systemctl enable k3s.service
    sudo systemctl start k3s.service

Ensure that service status is UP. 

Copy the kubeconfig file to our normal user. For example:

    sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config

In order to connect to K8s api server (as a normal user):

    export KUBECONFIG=~/.kube/config
    k3s kubectl get no -o wide


## 2. Setup agent(s) (workers)


Copy `/var/lib/rancher/k3s/server/node-token` from server node into `/etc/default/k3s-token` into the agent node.

Prepare the env file (at `/etc/default/k3s`). For example:

```
K3S_URL=https://k3s-server:6443
K3S_TOKEN_FILE=/etc/default/k3s-token
```

Prepare the service unit for the K3s agent (at `/etc/systemd/system/k3s.service`):

```ini
[Unit]
Description=Lightweight Kubernetes
Documentation=https://k3s.io
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=-/etc/default/%N
ExecStart=/usr/local/bin/k3s agent
KillMode=process
Delegate=yes

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start the service. 

On the server node, ensure that agent has joined the K8s cluster
