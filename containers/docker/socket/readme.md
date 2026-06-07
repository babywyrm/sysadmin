# Docker Socket Protection Strategies 

# Brainstorming Session (Beta)


## 1. Socket Isolation with Socket Proxy

Instead of directly exposing the Docker socket, implement a proxy layer:

```bash
# Install Docker Socket Proxy
docker run -d --restart=always \
  --name socket-proxy \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -p 127.0.0.1:2375:2375 \
  tecnativa/docker-socket-proxy:latest \
  CONTAINERS=1 \
  IMAGES=1 \
  NETWORKS=0 \
  VOLUMES=0 \
  POST=0
```

This creates a configurable access control layer in front of your socket.

## 2. Enhanced Socket Protection with AuthZ Plugin

```bash
# Install Docker AuthZ Plugin
docker plugin install --alias authz opcycle/docker-authz-plugin \
  --grant-all-permissions \
  settings.rules="deny all except specified containers and operations"

# Configure in daemon.json
cat > /etc/docker/daemon.json <<EOF
{
  "authorization-plugins": ["authz"],
  "live-restore": true
}
EOF

systemctl restart docker
```

## 3. Socket Mount Interception

Create a protection layer using bind mounts with a read-only overlay:

```bash
# Create interceptor directory
mkdir -p /var/docker/intercept
chmod 700 /var/docker/intercept

# Run socket interceptor
docker run -d --name socket-guard \
  --privileged \
  -v /var/run:/var/run:ro \
  -v /var/docker/intercept:/intercept \
  alpine:latest \
  sh -c "apk add socat && socat UNIX-LISTEN:/intercept/docker.sock,mode=600,fork UNIX-CONNECT:/var/run/docker.sock"

# Now containers can only use /intercept/docker.sock
```

## 4. Mandatory Access Control

Implement AppArmor/SELinux profiles to restrict access to the socket:

```bash
# AppArmor profile for Docker socket
cat > /etc/apparmor.d/docker-socket <<EOF
profile docker-socket {
  /var/run/docker.sock rw,
  deny /var/run/docker.sock w, # Deny write for non-specific services
  /var/run/docker.sock r, # Allow read
  
  # Only allow specific binaries to access with write
  /usr/bin/docker-proxy rwix,
  /usr/bin/dockerd rwix,
  /usr/bin/containerd rwix,
}
EOF

apparmor_parser -r /etc/apparmor.d/docker-socket
```

## 5. Linux Security Module (LSM) with BPF

For more advanced protection, use eBPF to monitor and restrict socket access:

```bash
# Using BCC tools (first install bcc-tools)
cat > docker_socket_monitor.py <<EOF
from bcc import BPF
import time

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

BPF_HASH(socket_access, u32, u64);

int trace_open(struct pt_regs *ctx, const char __user *filename) {
    char fname[256] = {0};
    bpf_probe_read_user(fname, sizeof(fname), filename);
    
    if (strncmp(fname, "/var/run/docker.sock", 20) == 0) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 ts = bpf_ktime_get_ns();
        socket_access.update(&pid, &ts);
        
        // Log the event
        bpf_trace_printk("Docker socket access by PID %d\\n", pid);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="do_sys_open", fn_name="trace_open")

print("Monitoring docker.sock access... Ctrl+C to exit")
b.trace_print()
EOF

python docker_socket_monitor.py
```

## 6. File Permission Hardening

Apply strict permissions and implement socket rotation:

```bash
# Restrict permissions
chmod 600 /var/run/docker.sock
chown root:docker /var/run/docker.sock

# Create socket rotation service
cat > /etc/systemd/system/docker-socket-rotate.service <<EOF
[Unit]
Description=Docker Socket Permission Reset
After=docker.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod 600 /var/run/docker.sock && chown root:docker /var/run/docker.sock"

[Install]
WantedBy=multi-user.target
EOF

systemctl enable docker-socket-rotate.service
```

## 7. Namespace Isolation for Containers That Need Docker Access

```bash
# Create Docker-in-Docker container with socket access
docker run -d --name docker-proxy \
  --privileged \
  --network none \
  --security-opt apparmor=docker-socket \
  --security-opt no-new-privileges=true \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /tmp/secure-docker.sock:/tmp/docker.sock \
  alpine:latest \
  sh -c "apk add socat && socat UNIX-LISTEN:/tmp/docker.sock,mode=600,fork,su=nobody UNIX-CONNECT:/var/run/docker.sock"

# Set very restricted permissions
chmod 600 /tmp/secure-docker.sock
```

## 8. Audit and Monitoring

Monitor all socket access in real-time:

```bash
# Set up auditd rules
auditctl -w /var/run/docker.sock -p rwa -k docker_socket_access

# Monitor in real-time
ausearch -k docker_socket_access -ts recent -i | grep -i docker.sock
```

## Complete Implementation Example

For a robust setup combining multiple methods:

```bash
#!/bin/bash
# Docker Socket Protection Suite

# 1. Create dedicated group
groupadd docker-socket-users

# 2. Set strict permissions
chmod 600 /var/run/docker.sock
chown root:docker-socket-users /var/run/docker.sock

# 3. Create socket proxy with access controls
docker run -d --restart=always \
  --name docker-socket-proxy \
  --network none \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/run/secure-docker.sock:/var/run/secure-docker.sock \
  alpine:latest \
  sh -c "apk add socat && socat UNIX-LISTEN:/var/run/secure-docker.sock,mode=600,fork UNIX-CONNECT:/var/run/docker.sock"

# 4. Set up audit monitoring
cat > /etc/audit/rules.d/docker-socket.rules <<EOF
-w /var/run/docker.sock -p rwa -k docker_socket_access
-w /var/run/secure-docker.sock -p rwa -k docker_socket_access
EOF
auditd -R

# 5. Create AppArmor profile
cat > /etc/apparmor.d/docker-socket <<EOF
profile docker-socket flags=(attach_disconnected) {
  /var/run/docker.sock rw,
  /var/run/secure-docker.sock rw,
  
  # Only specific processes can write
  /usr/bin/docker-proxy rwix,
  /usr/bin/dockerd rwix,
  /usr/bin/containerd rwix,
  /usr/bin/socat rwix,
  
  # Block all other writes
  deny /var/run/docker.sock w,
  deny /var/run/secure-docker.sock w,
}
EOF
apparmor_parser -r /etc/apparmor.d/docker-socket

echo "Docker socket protection enabled."
```

