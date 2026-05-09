# Dirty Frag vs CopyFail: Linux Page-Cache Write LPE Deep Dive ..beta..

> Status: research note for defenders, security engineers, and platform teams.  
> Scope: defensive analysis, exploit-class taxonomy, mitigation, detection, and operational triage.  
> Last updated: 2026-05-08.

## TL;DR

Dirty Frag and CopyFail are best understood as members of the same broad Linux local privilege escalation family: controlled or semi-controlled writes into the Linux page cache through kernel logic bugs. They are not the same vulnerability, but they rhyme technically and operationally.

CopyFail is CVE-2026-31431 and is associated with the Linux kernel Crypto API / AF_ALG / `algif_aead` path. Public summaries describe the primitive as a controlled small write into page-cache-backed file data, often discussed as a Dirty Pipe-like successor.

Dirty Frag is a chain currently associated with CVE-2026-43284 and CVE-2026-43500. Public reporting maps the two halves to xfrm/ESP/IPsec and RxRPC page-cache write behavior. The important operational point is that disabling only CopyFail's `algif_aead` exposure does not cover Dirty Frag, because Dirty Frag enters through different kernel subsystems.

```text
Same class?       Yes, broadly: page-cache write / Dirty Pipe-like LPE family.
Same bug?         No.
Same mitigation?  No.
Same risk model?  Very close: local foothold -> root.
Same priority?    Treat both as urgent on shared, multi-user, CI, dev, bastion, and Kubernetes nodes.
```

## Side-by-side summary

| Item | CopyFail | Dirty Frag |
|---|---|---|
| Primary CVE(s) | CVE-2026-31431 | CVE-2026-43284, CVE-2026-43500 |
| Broad class | Linux page-cache write local privilege escalation | Linux page-cache write local privilege escalation chain |
| Primary subsystem discussed publicly | Crypto API / AF_ALG / `algif_aead` | xfrm/ESP/IPsec and RxRPC |
| Attack precondition | Local code execution or local user context | Local code execution or local user context |
| Outcome | Local privilege escalation to root | Local privilege escalation to root |
| Why defenders care | Post-compromise accelerator; useful after any low-priv shell | Post-compromise accelerator; may bypass CopyFail-specific module mitigation |
| Best immediate response | Patch kernel; mitigate `algif_aead` exposure where appropriate | Patch kernel when available; disable/unload ESP/RxRPC-related modules where safe |
| Kubernetes relevance | Node compromise risk after pod/container foothold depending on isolation | Node compromise risk after pod/container foothold depending on isolation |

## Why this family matters

These issues are not remote entry points by themselves. They matter because they compress the attacker journey after initial access.

```text
Before this class:

  low-priv shell/container foothold
        |
        v
  noisy enumeration + environment-specific privesc
        |
        v
  possible root, maybe after many failures

With reliable page-cache write LPE:

  low-priv shell/container foothold
        |
        v
  deterministic local exploit path
        |
        v
  root on host or higher-value runtime context
```

The operational blast radius is largest where untrusted or semi-trusted code runs near valuable hosts:

- CI/CD runners
- developer workstations
- bastions and jump boxes
- shared Linux servers
- Kubernetes worker nodes
- container hosts
- multi-tenant build systems
- lab and CTF infrastructure where users run arbitrary binaries
- EDR or security tooling hosts that ingest untrusted samples

## Exploit-class taxonomy

```text
Linux local privilege escalation families

  Race / timing bugs
  |-- Dirty COW-style copy-on-write races
  `-- use-after-free races

  Object lifetime / refcount bugs
  |-- slab reuse
  |-- UAF primitives
  `-- type confusion

  Page-cache write primitive bugs
  |-- Dirty Pipe
  |-- CopyFail
  `-- Dirty Frag

  Policy bypass / namespace boundary bugs
  |-- mount namespace escapes
  |-- user namespace edge cases
  `-- capability confusion
```

The page-cache write family is scary because the attacker may not need to write to the file on disk directly. Instead, they influence memory-backed file contents seen by the kernel or privileged processes.

## Conceptual page-cache model

```text
                 +----------------------+
                 |        Disk          |
                 |  /usr/bin/su, etc.   |
                 +----------+-----------+
                            |
                            | file read / mmap / exec path
                            v
                 +----------------------+
                 |    Linux page cache  |
                 | cached file pages    |
                 +----------+-----------+
                            |
                            | privileged process consumes cached bytes
                            v
                 +----------------------+
                 | privileged execution |
                 | setuid/helper/etc.   |
                 +----------------------+
```

The vulnerable class appears when a kernel path that should not permit a write into protected cached file data accidentally allows one.

```text
Expected behavior:

  unprivileged process
        |
        v
  asks kernel to transform/copy/splice data
        |
        v
  kernel preserves file/page-cache integrity
        |
        v
  no privileged state change

Vulnerable behavior:

  unprivileged process
        |
        v
  reaches flawed kernel path
        |
        v
  page-cache-backed bytes are changed or influenced
        |
        v
  privileged consumer observes attacker-influenced bytes
        |
        v
  privilege escalation
```

## CopyFail process chart

This is deliberately conceptual and omits exploit implementation details.

```text
CopyFail / CVE-2026-31431

  user process
      |
      | uses reachable kernel crypto interface
      v
  AF_ALG / algif_aead path
      |
      | logic flaw around copy/splice/page-cache behavior
      v
  controlled small write primitive
      |
      | target is page-cache-backed file content
      v
  privileged executable/helper observes altered cached bytes
      |
      v
  root / elevated execution context
```

Defensive interpretation:

```text
Observable themes:

  unusual AF_ALG socket creation
  suspicious use of crypto API interfaces by ordinary user processes
  local execution near setuid/helper binaries
  short-lived processes attempting LPE-like behavior
  kernel upgrade lag on shared hosts
```

## Dirty Frag process chart

Dirty Frag is a chain, not just a single entry point.

```text
Dirty Frag / CVE-2026-43284 + CVE-2026-43500

  user process
      |
      +-----------------------------+
      |                             |
      v                             v
  xfrm / ESP / IPsec path       RxRPC path
  CVE-2026-43284               CVE-2026-43500
      |                             |
      +-------------+---------------+
                    |
                    v
        page-cache write influence
                    |
                    v
      privileged consumer sees changed cached bytes
                    |
                    v
             local root escalation
```

Defensive interpretation:

```text
Observable themes:

  esp4 / esp6 module presence or autoloading
  rxrpc module presence or autoloading
  unusual local use of IPsec ESP-related paths on systems that do not use IPsec
  unusual RxRPC activity on hosts that do not use AFS/RxRPC-like workflows
  sudden root transition after low-priv process activity
```

## Shared exploit-class lifecycle

```text
               +-------------------------+
               | local attacker context  |
               | user, service, pod, CI  |
               +------------+------------+
                            |
                            v
               +-------------------------+
               | reachable kernel API    |
               | crypto / xfrm / rxrpc   |
               +------------+------------+
                            |
                            v
               +-------------------------+
               | flawed data movement    |
               | copy/splice/frags/etc.  |
               +------------+------------+
                            |
                            v
               +-------------------------+
               | page-cache corruption   |
               | or attacker influence   |
               +------------+------------+
                            |
                            v
               +-------------------------+
               | privileged consumer     |
               | setuid/helper/root proc |
               +------------+------------+
                            |
                            v
               +-------------------------+
               | root / host compromise  |
               +-------------------------+
```

## Why module-only mitigation is incomplete

CopyFail-focused mitigations often discuss `algif_aead`. Dirty Frag does not depend on that same entry point.

```text
Mitigation dependency map

  algif_aead disabled
        |
        +--> helps reduce CopyFail exposure
        |
        +--> does not remove Dirty Frag exposure

  esp4 / esp6 / rxrpc disabled where unused
        |
        +--> helps reduce Dirty Frag exposure
        |
        +--> does not replace kernel patching
```

The safest durable fix is still vendor-provided kernel patching and reboot/livepatch validation.

## Exposure triage checklist

### 1. Identify kernel and distro state

```bash
uname -a
cat /etc/os-release
```

### 2. Inventory loaded modules

```bash
lsmod | egrep 'algif_aead|esp4|esp6|rxrpc|ipcomp4|ipcomp6' || true
```

### 3. Check whether modules can autoload

```bash
modprobe -n -v algif_aead 2>/dev/null || true
modprobe -n -v esp4 2>/dev/null || true
modprobe -n -v esp6 2>/dev/null || true
modprobe -n -v rxrpc 2>/dev/null || true
```

### 4. Prioritize hosts

```text
Priority 0:
  internet-facing hosts with local user workloads
  bastions / jump boxes
  Kubernetes worker nodes
  CI/CD runners
  multi-tenant compute

Priority 1:
  developer workstations
  build hosts
  shared admin hosts
  container hosts

Priority 2:
  single-purpose servers with no untrusted local execution
  lab hosts
```

### 5. Validate patch state

Use distro-specific package status tooling:

```bash
# Debian/Ubuntu style
apt-cache policy linux-image-generic linux-image-$(uname -r) 2>/dev/null || true

# RHEL/Fedora style
rpm -q kernel 2>/dev/null || true
```

Then compare against vendor advisories for the exact distribution and kernel stream.

## Temporary mitigation examples

These examples are intentionally conservative. Test on systems that use IPsec, AFS, RxRPC, or kernel crypto interfaces before broad deployment.

### CopyFail-oriented hardening

```bash
sudo install -m 0644 /dev/null /etc/modprobe.d/copyfail-mitigation.conf
printf 'install algif_aead /bin/false\n' | sudo tee /etc/modprobe.d/copyfail-mitigation.conf
sudo rmmod algif_aead 2>/dev/null || true
```

### Dirty Frag-oriented hardening

```bash
sudo install -m 0644 /dev/null /etc/modprobe.d/dirtyfrag-mitigation.conf
cat <<'MITIGATION_EOF' | sudo tee /etc/modprobe.d/dirtyfrag-mitigation.conf
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
install ipcomp4 /bin/false
install ipcomp6 /bin/false
MITIGATION_EOF

sudo rmmod esp4 esp6 rxrpc ipcomp4 ipcomp6 2>/dev/null || true
```

### Validate mitigation state

```bash
lsmod | egrep 'algif_aead|esp4|esp6|rxrpc|ipcomp4|ipcomp6' || true
modprobe -n -v algif_aead esp4 esp6 rxrpc ipcomp4 ipcomp6 2>/dev/null || true
```

Expected behavior for blocked modules is usually an `install /bin/false`-style response from `modprobe -n -v`.

## Kubernetes and container risk model

These are kernel LPEs. Containers share the host kernel, so containerization alone should not be treated as a complete boundary against kernel vulnerabilities.

```text
Kubernetes path of concern

  workload RCE / shell in pod
        |
        v
  local code execution inside container
        |
        v
  reachable host kernel attack surface
        |
        v
  kernel LPE succeeds
        |
        v
  node-level root
        |
        v
  credential theft / kubelet abuse / pod secrets / lateral movement
```

Risk is higher when pods have any of the following:

- privileged mode
- hostPID, hostIPC, or hostNetwork
- broad capabilities
- writable hostPath mounts
- weak seccomp/AppArmor/SELinux profiles
- access to sensitive service account tokens
- CI runner workloads that execute untrusted code

## Kubernetes mitigation pattern

If you must deploy a temporary module block across nodes, use your normal node management system first. A privileged DaemonSet can work as an emergency control, but it is itself a privileged workload and should be short-lived, reviewed, and removed after patching.

```text
Emergency DaemonSet lifecycle

  create privileged mitigation DaemonSet
        |
        v
  write /etc/modprobe.d/*.conf on host
        |
        v
  unload unused vulnerable modules
        |
        v
  verify across nodes
        |
        v
  patch/reboot nodes
        |
        v
  remove emergency DaemonSet
```

Prefer:

```text
golden image update
node pool replacement
managed node upgrade
livepatch if supported
configuration management enforcement
```

## Detection engineering ideas

Detection is hard because successful exploitation may be short-lived and kernel-level. Still, defenders can build useful signals.

### Host telemetry

Look for:

```text
- unexpected root shell/process shortly after low-priv process execution
- unusual AF_ALG socket usage by non-crypto applications
- unexpected module loads: algif_aead, esp4, esp6, rxrpc, ipcomp4, ipcomp6
- short-lived processes touching setuid-heavy paths
- suspicious process lineage: web worker -> local binary -> root shell
- package/kernel update drift on nodes running untrusted workloads
```

### Auditd examples

Module load watch:

```bash
-w /sbin/insmod -p x -k kernel-module-load
-w /sbin/modprobe -p x -k kernel-module-load
-w /sbin/rmmod -p x -k kernel-module-load
-w /usr/sbin/insmod -p x -k kernel-module-load
-w /usr/sbin/modprobe -p x -k kernel-module-load
-w /usr/sbin/rmmod -p x -k kernel-module-load
```

Setuid-heavy path monitoring, tune for noise:

```bash
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root-exec-from-user
```

### eBPF/Falco-style logic

Conceptual rules:

```yaml
- rule: Unexpected Kernel Module Load Related To Dirty Class
  condition: process.name in (modprobe, insmod) and command contains one of (algif_aead, esp4, esp6, rxrpc, ipcomp4, ipcomp6)
  output: Suspicious kernel module action related to page-cache LPE mitigation surface
  priority: warning

- rule: User Process Spawned Root Shell
  condition: parent user is non-root and child process euid is root and child process is shell
  output: Possible local privilege escalation
  priority: critical
```

### SIEM query themes

```text
module_load AND (algif_aead OR esp4 OR esp6 OR rxrpc OR ipcomp4 OR ipcomp6)

process_start AND euid=0 AND parent_euid!=0 AND process IN (sh,bash,zsh,dash,python,perl,ruby)

host.kernel_version vulnerable AND host.role IN (k8s-node,ci-runner,bastion,developer-workstation)
```

## Response playbook

```text
1. Scope exposure
   - Which hosts run affected kernels?
   - Which hosts allow untrusted local code execution?
   - Which hosts have vulnerable modules loaded or autoloadable?

2. Reduce attack surface
   - Disable unused vulnerable modules where safe.
   - Restrict untrusted local execution.
   - Tighten container profiles and node access.

3. Patch
   - Apply vendor kernel updates.
   - Reboot or validate livepatch state.
   - Confirm runtime kernel is fixed, not just package installed.

4. Hunt
   - Review privilege transitions.
   - Review module load events.
   - Review suspicious root shells.
   - Review CI runner and Kubernetes node activity.

5. Recover hard
   - Treat confirmed exploitation as root compromise.
   - Rotate secrets exposed to affected hosts.
   - Rebuild nodes where warranted.
   - Review lateral movement paths.
```

## Side-by-side operational chart

```text
+--------------------------+--------------------------+--------------------------+
| Phase                    | CopyFail                 | Dirty Frag               |
+--------------------------+--------------------------+--------------------------+
| Initial attacker state   | local user/code exec     | local user/code exec     |
| Kernel entry area        | AF_ALG / algif_aead      | xfrm/ESP + RxRPC         |
| Vulnerability class      | page-cache write LPE     | page-cache write chain   |
| Race required?           | publicly described as no | publicly described as no |
| Direct remote exploit?   | no                       | no                       |
| Container relevance      | host kernel shared       | host kernel shared       |
| Module mitigation        | algif_aead               | esp4/esp6/rxrpc/etc.     |
| Durable fix              | vendor kernel patch      | vendor kernel patch      |
| Incident severity        | root compromise          | root compromise          |
+--------------------------+--------------------------+--------------------------+
```

## Practical guidance for security teams

### For security leadership

```text
Message:
  These are local privilege escalation vulnerabilities. They do not provide initial remote access by themselves, but they significantly raise the impact of any initial foothold.

Decision:
  Prioritize patching where local code execution is normal or likely: CI, Kubernetes, shared servers, developer endpoints, bastions.
```

### For platform engineering

```text
Action:
  Treat kernel patching and node rotation as the primary fix. Use module blocking only as temporary exposure reduction.

Validate:
  Make sure the running kernel changed after patching. Installed packages alone are not enough.
```

### For detection engineering

```text
Action:
  Add detections for suspicious module use, root transitions, unexpected root shells, and vulnerable-kernel inventory.

Reality:
  Do not expect perfect exploit detection. Focus on exposure reduction plus post-exploitation signals.
```

### For Kubernetes teams

```text
Action:
  Patch or rotate nodes. Review privileged workloads and CI runner pods first.

Priority:
  Nodes running untrusted builds, browser automation, customer workloads, or security labs should go first.
```

## Suggested GitHub repo structure

```text
linux-page-cache-lpe-research/
|-- README.md
|-- docs/
|   |-- dirtyfrag-vs-copyfail.md
|   |-- mitigation.md
|   |-- detection-engineering.md
|   `-- kubernetes-risk.md
|-- diagrams/
|   |-- exploit-class-flow.txt
|   |-- copyfail-flow.txt
|   `-- dirtyfrag-flow.txt
|-- queries/
|   |-- splunk.md
|   |-- falco.md
|   `-- auditd.md
`-- scripts/
    `-- inventory-modules.sh
```

## README blurb

```markdown
# Linux Page-Cache LPE Research: Dirty Frag vs CopyFail

This repository tracks defensive research for recent Linux local privilege escalation vulnerabilities in the Dirty Pipe-like page-cache write family, including CopyFail and Dirty Frag. It focuses on exploit-class understanding, mitigation, detection engineering, Kubernetes risk, and operational response.

This repo does not publish exploit code. It is intended for defenders and platform teams.
```

## References

- The Hacker News, “Linux Kernel Dirty Frag LPE Exploit Enables Root Access Across Major Distributions,” 2026-05-08.
- Microsoft Security Blog, “Active attack: Dirty Frag Linux vulnerability expands post-compromise risk,” 2026-05-08.
- Wiz, “Dirty Frag: Linux Kernel Local Privilege Escalation via ESP and RxRPC,” 2026-05-08.
- Tenable, “Dirty Frag (CVE-2026-43284, CVE-2026-43500) FAQ,” 2026-05-08.
- AlmaLinux, “Dirty Frag (CVE-2026-43284, CVE-2026-43500) Patches Released,” 2026-05-07.
- Red Hat, “RHSB-2026-003 Networking subsystem Privilege Escalation,” 2026-05-08.
- Cloudflare, “How Cloudflare responded to the Copy Fail Linux vulnerability,” 2026-05.
- Unit 42, “Copy Fail: What You Need to Know About the Most Severe Linux Threat in Years,” 2026-05-05.
