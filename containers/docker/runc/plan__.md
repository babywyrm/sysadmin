

# 1. Adopt a Defense-in-Depth Strategy
Multi-layer Isolation:
Rely on container isolation plus additional layers. Containers (via runc) reduce the attack surface but aren’t foolproof. Consider running containers inside lightweight VMs (e.g., using Firecracker or gVisor) to provide an extra barrier between the host and potentially malicious code.

Minimize the Trust Boundary:
Assume that the container runtime or even the kernel might be exploited. Design your architecture so that even if one layer is compromised, damage is limited.


# 2. Harden runc Containers
User Namespaces:
Always run containers with unprivileged user namespaces so that processes inside the container run as non-root relative to the host. This prevents a container breakout from immediately yielding host-level root.

1. Use Unprivileged User Namespaces
Running your container processes as non‑root on the host is one of the most important steps. In your OCI spec’s linux section, add a new user namespace along with UID/GID mappings.

Example snippet in config.json:

```
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": {
      "uid": 0,
      "gid": 0
    },
    "args": [
      "/path/to/your/executable"
    ],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "cwd": "/"
  },
  "root": {
    "path": "rootfs",
    "readonly": true
  },
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" },
    { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] }
    // Add other necessary mounts here
  ],
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "network" },
      { "type": "ipc" },
      { "type": "uts" },
      { "type": "mount" },
      { "type": "user" }
    ],
    "uidMappings": [
      {
        "containerID": 0,
        "hostID": 1001,
        "size": 1
      }
    ],
    "gidMappings": [
      {
        "containerID": 0,
        "hostID": 1001,
        "size": 1
      }
    ],
    "noNewPrivileges": true
    // Other sections follow…
  }
}
```



Notes:

Replace 1001 with a non‑privileged UID/GID on your Ubuntu host.
The process still “sees” itself as root (uid 0 inside the container) but on the host it’s mapped to a non‑privileged user.
2. Configure Seccomp to Block Dangerous Syscalls
Using a seccomp profile restricts the syscalls available to the container. Ubuntu Jammy uses a modern kernel that supports seccomp filtering. You can embed a seccomp policy directly in your OCI spec or reference an external file.

Example inline seccomp section:

```
"seccomp": {
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": [
        "execveat",
        "kexec_file_load",
        "swapon",
        "swapoff"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": [
        "clone",
        "unshare"
      ],
      "action": "SCMP_ACT_ALLOW",
      "args": [
        {
          "index": 0,
          "value": 2080505856,
          "op": "SCMP_CMP_MASKED_EQ"
        }
      ]
    }
    // Add more syscall rules as needed based on your workload.
  ]
}
```


Tips:

Start with a “deny‑by‑default” policy (defaultAction: "SCMP_ACT_ERRNO") and only allow syscalls that you know are needed.
You might want to use an existing profile (for example, Docker’s default seccomp profile) as a baseline and then remove any calls you deem risky.
3. Drop Unnecessary Capabilities
By default, Linux capabilities can allow processes to perform privileged operations. In your OCI spec, explicitly drop all capabilities, then add back only those absolutely necessary.

Example snippet:

```
"capabilities": {
  "bounding": [],
  "effective": [],
  "inheritable": [],
  "permitted": [],
  "ambient": []
}
```

Recommendations:

Evaluate your application’s needs carefully. For many workloads, you won’t need to grant any extra capabilities.
If you need a minimal set (for instance, if ChromeDriver needs network-related capabilities), add only those specific capabilities in the appropriate lists.
4. Enforce a Read-Only Root Filesystem
A read-only root filesystem helps prevent modifications from within the container. In the root section of config.json, set "readonly": true as shown in the example above.

Additional mounts:
If your application needs write access in certain directories, mount them as separate volumes with specific permissions rather than allowing writes everywhere.

5. Utilize AppArmor for Additional Mandatory Access Control
Ubuntu Jammy uses AppArmor by default. You can assign an AppArmor profile to your container in the OCI spec’s linux section. First, create a custom profile (or adapt an existing one), then reference it.

Example:

```
"apparmorProfile": "my-custom-apparmor-profile"
```

Steps to use AppArmor:

Create/Modify a Profile:
Create a profile (e.g., /etc/apparmor.d/my-custom-apparmor-profile) that defines the allowed file accesses, network access, etc. You can start with a restrictive template and adjust as needed.

Load the Profile:
Use sudo apparmor_parser -r -W /etc/apparmor.d/my-custom-apparmor-profile to load or update the profile.

Assign in OCI Spec:
Include the apparmorProfile field in your config as shown above.

Verify on Host:
Check that AppArmor is active using sudo aa-status.

6. Set Resource Limits with Cgroups
Limiting CPU, memory, and process counts can help prevent denial-of-service attacks from runaway containers.

Example snippet (in the resources section):

```
"resources": {
  "memory": {
    "limit": 536870912  // 512 MB in bytes
  },
  "cpu": {
    "shares": 512
  },
  "pids": {
    "limit": 100
  }
}
```


Note:
Ubuntu Jammy generally uses cgroups v2 by default. Confirm your host’s configuration with:

```
stat -fc %T /sys/fs/cgroup/
```

If it returns cgroup2fs, then you’re on cgroups v2.

7. Additional Hardening Options
No New Privileges:
In the linux section, ensure that "noNewPrivileges": true is set. This tells the kernel to prevent the container from gaining additional privileges (even if an executable tries to execute a setuid binary).

Masked and Read-only Paths:
You can further reduce risk by masking sensitive host paths and making some paths read-only. For example:

```
"linux": {
  "maskedPaths": [
    "/proc/kcore",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/sched_debug"
  ],
  "readonlyPaths": [
    "/proc/asound",
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger"
  ]
  // Other settings…
}
```

Mount Options:
Use restrictive mount options (like nosuid, nodev, noexec) on your container mounts where applicable.

Final Integrated Example
Below is a simplified, combined example of a hardened config.json:

```
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": {
      "uid": 0,
      "gid": 0
    },
    "args": ["/usr/bin/chromedriver"],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "cwd": "/"
  },
  "root": {
    "path": "rootfs",
    "readonly": true
  },
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
    }
    // Add any additional necessary mounts.
  ],
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "network" },
      { "type": "ipc" },
      { "type": "uts" },
      { "type": "mount" },
      { "type": "user" }
    ],
    "uidMappings": [
      {
        "containerID": 0,
        "hostID": 1001,
        "size": 1
      }
    ],
    "gidMappings": [
      {
        "containerID": 0,
        "hostID": 1001,
        "size": 1
      }
    ],
    "noNewPrivileges": true,
    "seccomp": {
      "defaultAction": "SCMP_ACT_ERRNO",
      "syscalls": [
        {
          "names": ["execveat", "kexec_file_load", "swapon", "swapoff"],
          "action": "SCMP_ACT_ALLOW"
        }
        // Further syscall allowances as needed…
      ]
    },
    "capabilities": {
      "bounding": [],
      "effective": [],
      "inheritable": [],
      "permitted": [],
      "ambient": []
    },
    "resources": {
      "memory": { "limit": 536870912 },
      "cpu": { "shares": 512 },
      "pids": { "limit": 100 }
    },
    "maskedPaths": [
      "/proc/kcore",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/sched_debug"
    ],
    "readonlyPaths": [
      "/proc/asound",
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger"
    ],
    "apparmorProfile": "my-custom-apparmor-profile"
  }
}
```

Reminder:
Adjust the UID/GID mappings, resource limits, allowed syscalls, and AppArmor profile to match the actual requirements of your application (in your case, transaction tests via ChromeDriver) while keeping the profile as restrictive as possible.

Final Steps and Testing
Bundle Creation:
Every time you create a container bundle, ensure that the above security parameters are enforced. Consider automating bundle generation with a templating tool to reduce human error.

Testing:

Penetration Testing: Run tests to simulate breakout attempts.
Audit Logs: Enable kernel audit logs to monitor for any unusual syscall activity.
Keep Everything Up-to-Date:
Regularly update your host (Ubuntu Jammy), kernel, runc, and AppArmor profiles. Monitor for CVEs or security advisories that affect any of these components.




Seccomp Profiles:
Use a restrictive seccomp profile to filter out dangerous syscalls. Customize the profile to your workload (e.g., the needs of ChromeDriver) and ensure that syscalls known to be exploited are blocked.

Capabilities:
Drop all capabilities by default and only add back the ones absolutely necessary for your containerized workloads. For example, in many cases, the container won’t need capabilities like CAP_SYS_ADMIN or CAP_NET_ADMIN.

Mandatory Access Control:
Use SELinux or AppArmor profiles to further confine what processes inside the container can do. This adds another kernel-enforced policy layer.

Read-Only Filesystems:
Run containers with a read-only filesystem where possible. If write access is needed in specific directories, use bind mounts with explicit permissions rather than giving blanket write access.

Resource Limits:
Set strict limits using cgroups for CPU, memory, disk I/O, etc., to mitigate denial-of-service (DoS) risks and prevent runaway processes.

3. Network and Runtime Considerations
Network Isolation:
Apply network namespace isolation and firewall rules (or use a service mesh) to restrict network access from the containers. For instance, limit outbound connections to only what’s necessary for your tests.

Ephemeral and Disposable Containers:
Use short-lived containers that are regularly torn down and replaced. This minimizes the window of opportunity for an attacker to persist after a breakout.

Monitoring and Logging:
Continuously monitor container activity and log syscalls, network traffic, and resource usage. Anomaly detection can alert you to potential escape attempts or misbehaviors.

Patching and Updates:
Keep the host kernel, container runtime (runc), and all security profiles up-to-date. Many exploits come from known vulnerabilities that have been patched.

4. Consider the Limitations of runc Alone
Low-Level Tool:
Runc is a low-level container runtime, so it won’t provide the additional safety features of a full container engine (like Podman or Docker) by default. Make sure your orchestration system (or your wrapper scripts) enforce the above policies consistently.

Sandboxing JavaScript Code:
If customers are bringing in their own JavaScript, consider running that code inside a further sandboxed environment (for example, using a dedicated JS sandbox or even a separate runtime environment) before passing it to ChromeDriver. This adds an extra layer of defense if the JS itself is malicious.

5. Test and Audit Your Security Posture
Penetration Testing:
Before going live, conduct rigorous penetration tests and security audits of your entire stack. Invite third parties to test for breakout scenarios.

Automated Security Tools:
Integrate container security scanners (such as Clair or Anchore Engine) into your CI/CD pipeline to catch vulnerabilities in container images.

Incident Response:
Prepare an incident response plan in case a breakout is detected. Know how to quickly isolate or shut down compromised hosts.

