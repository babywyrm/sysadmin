# Podman Installation on Ubuntu 20.04 WSL2

Execute the following command to install Podman:
```
sudo apt update
sudo apt install ca-certificates
. /etc/os-release
echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/Release.key | sudo apt-key add -
sudo apt update
sudo apt -y upgrade
sudo apt -y install podman
```

Execute `podman info` to initialize rootless Podman:
```
podman info
```

Execute the following command to create `/etc/containers/containers.conf` based on sample config:
```
sudo cp -v /usr/share/containers/containers.conf /etc/containers/
```

In `/etc/containers/containers.conf` file, change the following values (make sure these lines are not commented):
1) Change `cgroup_manager = "systemd"` to `cgroup_manager = "cgroupfs"`
2) Change `events_logger = "journald"` to `events_logger = "file"`
3) Increase `ulimits` to `65535` and make `memlock` unlimited:
```
[containers]
default_ulimits = [ 
  "nofile=65535:65535",
  "memlock=-1:-1"
]
```

Since `ulimit` config above only works for rootful Podman, it will cause a permission error when running on rootless Podman. To prevent this error, create an empty `default_ulimits` in `~/.config/containers/containers.conf` file:
```
[containers]

default_ulimits = []
```

Allow IPv4 forwarding and ping in `/etc/containers/containers.conf`:
```
[containers]
default_sysctls = [
 "net.ipv4.ping_group_range=0 0",
 "net.ipv4.ip_forward=1"
]
```

In `/etc/sysctl.conf`, make sure `vm.max_map_count` is set to at least `262144`:
```
vm.max_map_count=300000
```

To apply `vm.max_map_count` without reboot, execute the following command:
```
sudo sysctl -w vm.max_map_count=300000
```
