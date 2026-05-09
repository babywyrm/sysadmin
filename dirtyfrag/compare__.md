> Defensive research note for security engineering, platform engineering, incident response, and vulnerability management teams.
>
> Scope: compare CopyFail (`CVE-2026-31431`) with Dirty Frag (`CVE-2026-43284`, `CVE-2026-43500`) at the vulnerability-class, subsystem, exposure, detection, and mitigation levels.
>
> This document intentionally does **not** include exploit code, weaponized trigger sequences, or step-by-step privilege escalation instructions.

---

## Executive summary

CopyFail and Dirty Frag belong in the same broad risk bucket: **Linux local privilege escalation through page-cache write behavior**. They are close enough operationally that defenders should triage them together, but they are not the same vulnerability and they are not mitigated by the same module controls.

CopyFail is a single CVE, `CVE-2026-31431`, associated with the Linux kernel `AF_ALG` userspace crypto interface, specifically the `algif_aead` path. Public reporting describes it as a local privilege escalation in the kernel crypto subsystem where an unprivileged local user can corrupt the cache of a readable file and escalate to root.

Dirty Frag is a two-CVE chain, currently mapped to `CVE-2026-43284` and `CVE-2026-43500`. Public reporting describes the first as an `xfrm`/ESP page-cache write issue and the second as an RxRPC page-cache write issue. The chain expands the same general page-cache-write bug class into different kernel networking and memory-fragment handling paths.

The most important operational point:

```text
CopyFail mitigation != Dirty Frag mitigation.

Blocking or mitigating algif_aead may reduce CopyFail exposure,
but Dirty Frag can remain reachable through esp4/esp6 and rxrpc paths.
```

---

## At-a-glance comparison

| Area | CopyFail | Dirty Frag |
|---|---|---|
| Nickname | CopyFail / Copy Fail | Dirty Frag |
| CVE mapping | `CVE-2026-31431` | `CVE-2026-43284`, `CVE-2026-43500` |
| Vulnerability count | One CVE | Two-CVE chain |
| Main subsystem | Linux Crypto API / `AF_ALG` | Kernel networking / ESP-XFRM and RxRPC |
| Main module names defenders discuss | `algif_aead`, often also `af_alg` | `esp4`, `esp6`, `rxrpc` |
| High-level primitive | Page-cache write/corruption behavior | Page-cache write/corruption behavior through different paths |
| Access required | Local unprivileged execution | Local unprivileged execution |
| Result | Local privilege escalation to root | Local privilege escalation to root |
| Risk context | Cloud VMs, CI, shared hosts, Kubernetes nodes, developer workstations | Same, plus systems using IPsec/VPN/ESP or RxRPC/AFS-like environments |
| Relationship | Earlier member of the same bug-class discussion | Sibling/extension that overlaps at the sink/impact but differs in trigger path |
| Mitigation focus | Patch kernel; restrict/disable vulnerable crypto module path where advised | Patch kernel; restrict/disable ESP/RxRPC modules where safe and vendor-advised |
| Detection focus | local suspicious execution, module exposure, kernel version/package posture, unexpected root transition | same, plus `esp4`/`esp6`/`rxrpc` module posture and namespace/network-related context |

---

## CVE taxonomy

```text
Linux kernel local privilege escalation family
|
+-- CopyFail
|   |
|   +-- CVE-2026-31431
|       |
|       +-- Linux Crypto API / AF_ALG / algif_aead
|       +-- Local unprivileged user -> root
|       +-- Page-cache corruption/write behavior
|
+-- Dirty Frag
    |
    +-- CVE-2026-43284
    |   |
    |   +-- xfrm / ESP page-cache write issue
    |   +-- commonly discussed modules: esp4, esp6
    |
    +-- CVE-2026-43500
        |
        +-- RxRPC page-cache write issue
        +-- commonly discussed module: rxrpc
```

The overlap is the **class and consequence**. The difference is the **path into the vulnerable behavior**.

---

## The shared mental model: page-cache write LPE

Linux uses the page cache to hold recently accessed file data in memory. The security boundary is supposed to remain simple:

```text
Readable file       Writable file
     |                   |
     v                   v
read path only      authorized write path
     |                   |
     v                   v
page cache view     page cache modification
```

The bug-class concern appears when an unprivileged operation that should only read, transform, or receive data causes modification to page-cache-backed memory for a file the user is not allowed to write.

Conceptually:

```text
Expected behavior
-----------------
Unprivileged process
  -> opens/uses allowed interface
  -> receives or transforms data
  -> cannot modify protected file cache
  -> no privilege boundary crossed

Bug-class behavior
------------------
Unprivileged process
  -> reaches vulnerable kernel path
  -> causes unexpected page-cache write/corruption
  -> modifies bytes associated with a protected readable file
  -> turns file/cache behavior into privilege escalation
```

This is why CopyFail and Dirty Frag are compared to older “Dirty” vulnerabilities such as Dirty COW and Dirty Pipe. The exact mechanics differ, but the defensive story is similar: a local user influences kernel-backed memory/file state in a way that should not be possible.

---

## Where they overlap

### 1. Same broad bug class

Both sit in the “page-cache write/corruption leading to local privilege escalation” family.

```text
Shared class:
  local user
    -> kernel interface reachable without root
    -> unexpected page-cache modification
    -> privileged file/cache effect
    -> root escalation
```

### 2. Same attacker prerequisite

Both are post-compromise accelerants. They do not usually replace initial access. They matter after an attacker already has some local execution foothold:

```text
Initial access examples
-----------------------
compromised SSH account
web shell
CI runner job execution
container foothold
low-privileged service account
malicious local user on shared system
```

### 3. Same impact category

Both should be triaged as **high-impact local privilege escalation** because root access can enable:

```text
root shell
security tooling tampering
credential theft
host persistence
log modification
container-host boundary abuse
lateral movement
Kubernetes node compromise
```

### 4. Same asset-priority classes

Prioritize both on systems where untrusted or semi-trusted code can execute:

```text
Highest priority
----------------
Kubernetes worker nodes
CI/CD runners
shared build hosts
multi-user Linux servers
bastions and jump hosts
internet-facing app servers
developer workstations
cloud VMs running tenant or plugin workloads
```

### 5. Same patch philosophy

Module mitigations are temporary. The durable remediation is a patched kernel plus reboot or verified livepatch state.

```text
Permanent fix:
  vendor kernel update
  reboot into fixed kernel or verify livepatch
  validate running kernel, not just installed package

Temporary reduction:
  disable vulnerable module paths where operationally safe
  monitor for module load attempts
  restrict local code execution paths
```

---

## Where they differ

### 1. Different CVE shape

CopyFail is tracked as one CVE.

```text
CopyFail
  CVE-2026-31431
```

Dirty Frag is tracked as two CVEs that are discussed as a chain.

```text
Dirty Frag
  CVE-2026-43284  -> xfrm/ESP page-cache write issue
  CVE-2026-43500  -> RxRPC page-cache write issue
```

This matters because vulnerability management systems may show them differently. You may see one host reported for CopyFail and two findings for Dirty Frag, or partial coverage if scanners only picked up one Dirty Frag CVE.

### 2. Different kernel subsystems

CopyFail lives in the crypto/userspace crypto interface conversation.

```text
CopyFail subsystem path
-----------------------
user process
  -> AF_ALG userspace crypto interface
  -> algif_aead behavior
  -> page-cache corruption/write condition
  -> local privilege escalation
```

Dirty Frag lives in networking and memory-fragment handling paths.

```text
Dirty Frag subsystem path
-------------------------
user process
  -> networking-related kernel paths
  -> ESP/XFRM and RxRPC components
  -> page-cache corruption/write condition
  -> local privilege escalation
```

### 3. Different module posture

CopyFail conversations often focus on `algif_aead` and related AF_ALG crypto functionality.

Dirty Frag conversations focus on `esp4`, `esp6`, and `rxrpc`.

```text
Module comparison
-----------------
CopyFail:   algif_aead, af_alg
Dirty Frag: esp4, esp6, rxrpc
```

This is the primary reason mitigation does not fully overlap.

### 4. Different operational blast radius

CopyFail risk is broad because AF_ALG crypto functionality may exist across many general-purpose Linux systems.

Dirty Frag risk is broad because the affected networking modules may be present on many kernels, but operational impact from disabling modules varies depending on whether the environment uses IPsec, ESP tunnels, RxRPC, AFS, or adjacent functionality.

```text
CopyFail mitigation risk:
  may affect consumers of AF_ALG / kernel crypto interface

Dirty Frag mitigation risk:
  may affect IPsec / ESP / VPN-like workloads
  may affect RxRPC / AFS-like environments
```

### 5. Different scanner logic

A defensive scanner should not just look for “one patched kernel version.” Vendor backports make version-only logic unreliable.

Instead, treat them as separate checks:

```text
CopyFail scanner checks
-----------------------
- running kernel release
- vendor advisory status
- installed vs running kernel mismatch
- algif_aead / af_alg loaded
- algif_aead / af_alg available on disk
- modprobe blacklist or install false controls

Dirty Frag scanner checks
-------------------------
- running kernel release
- vendor advisory status for both CVEs
- esp4 / esp6 / rxrpc loaded
- esp4 / esp6 / rxrpc available on disk
- modprobe blacklist or install false controls
- IPsec / RxRPC dependency review
```

---

## Side-by-side conceptual flow

```text
+------------------------------------------------+   +------------------------------------------------+
| CopyFail                                       |   | Dirty Frag                                     |
| CVE-2026-31431                                 |   | CVE-2026-43284 + CVE-2026-43500                |
+------------------------------------------------+   +------------------------------------------------+
| Local unprivileged execution                   |   | Local unprivileged execution                   |
+------------------------------------------------+   +------------------------------------------------+
| Reachable crypto/userspace crypto interface    |   | Reachable networking / fragment handling path  |
| AF_ALG / algif_aead                            |   | ESP/XFRM + RxRPC                               |
+------------------------------------------------+   +------------------------------------------------+
| Unexpected page-cache write/corruption behavior|   | Unexpected page-cache write/corruption behavior|
+------------------------------------------------+   +------------------------------------------------+
| Protected readable file/cache state influenced |   | Protected readable file/cache state influenced |
+------------------------------------------------+   +------------------------------------------------+
| Privilege boundary crossed                     |   | Privilege boundary crossed                     |
+------------------------------------------------+   +------------------------------------------------+
| Root-level impact                              |   | Root-level impact                              |
+------------------------------------------------+   +------------------------------------------------+
```

---

## Shared sink, different trigger paths

A useful way to explain this to leadership and platform teams:

```text
                            Shared consequence
                                  |
                                  v
                  +-------------------------------+
                  | Page-cache write/corruption   |
                  | against protected file state  |
                  +-------------------------------+
                       ^                         ^
                       |                         |
          CopyFail trigger path       Dirty Frag trigger paths
                       |                         |
                       v                         v
             +------------------+     +---------------------------+
             | AF_ALG crypto    |     | ESP/XFRM + RxRPC          |
             | algif_aead       |     | esp4/esp6 + rxrpc         |
             +------------------+     +---------------------------+
```

This model explains why the bugs are related but not interchangeable.

---

## Mitigation comparison

### CopyFail temporary mitigations

Common defensive controls discussed publicly include disabling or restricting the vulnerable crypto module path where vendor guidance supports doing so.

Conceptually:

```text
CopyFail temporary reduction
----------------------------
check loaded modules:
  algif_aead
  af_alg

check module availability:
  /lib/modules/$(uname -r)/.../algif_aead.ko*
  /lib/modules/$(uname -r)/.../af_alg.ko*

check controls:
  /etc/modprobe.d/*.conf
  install algif_aead /bin/false
  blacklist algif_aead
```

### Dirty Frag temporary mitigations

Dirty Frag mitigation discussions focus on `esp4`, `esp6`, and `rxrpc`.

Conceptually:

```text
Dirty Frag temporary reduction
------------------------------
check loaded modules:
  esp4
  esp6
  rxrpc

check module availability:
  /lib/modules/$(uname -r)/.../esp4.ko*
  /lib/modules/$(uname -r)/.../esp6.ko*
  /lib/modules/$(uname -r)/.../rxrpc.ko*

check controls:
  /etc/modprobe.d/*.conf
  install esp4 /bin/false
  install esp6 /bin/false
  install rxrpc /bin/false
```

### Why one mitigation does not cover both

```text
If you only mitigate CopyFail:
  algif_aead blocked
  AF_ALG path reduced
  ESP/XFRM and RxRPC may still be reachable
  Dirty Frag exposure may remain

If you only mitigate Dirty Frag:
  esp4/esp6/rxrpc blocked
  networking path reduced
  algif_aead may still be reachable
  CopyFail exposure may remain
```

---

## Detection and hunting comparison

### Runtime indicators both may share

Neither vulnerability should be expected to produce a single perfect log event. Hunt for surrounding behavior:

```text
Potential surrounding signals
-----------------------------
low-privileged shell starts unusual binary
unknown ELF appears in /tmp, /dev/shm, /var/tmp, workspace, CI directory
process quickly transitions to root context
unexpected su/sudo/pkexec execution patterns
new root-owned file appears shortly after unprivileged execution
security tooling disabled after local execution
kernel module load/unload activity near suspicious execution
container workload interacts unusually with host namespaces or mounts
```

### CopyFail-specific posture checks

```text
CopyFail posture
----------------
lsmod | grep -E '^(algif_aead|af_alg)\b'
modinfo algif_aead
modinfo af_alg
grep -R 'algif_aead\|af_alg' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
```

### Dirty Frag-specific posture checks

```text
Dirty Frag posture
------------------
lsmod | grep -E '^(esp4|esp6|rxrpc)\b'
modinfo esp4
modinfo esp6
modinfo rxrpc
grep -R 'esp4\|esp6\|rxrpc' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
```

### Falco-style detection ideas

These are not exploit signatures. They are behavioral guardrails around suspicious post-exploitation patterns.

```yaml
# Conceptual only. Tune for your environment.
- rule: Suspicious Temp Binary Privilege Escalation Pattern
  desc: Untrusted temp path binary executed shortly before privileged transition
  condition: >
    spawned_process and
    proc.exepath startswith /tmp or
    proc.exepath startswith /var/tmp or
    proc.exepath startswith /dev/shm
  output: >
    Suspicious temp binary execution user=%user.name proc=%proc.cmdline exe=%proc.exepath
  priority: WARNING

- rule: Kernel Module Tool Used From Unusual Context
  desc: modprobe/rmmod/insmod used outside approved maintenance context
  condition: >
    spawned_process and
    proc.name in (modprobe, insmod, rmmod) and
    not proc.pname in (systemd, kubelet, approved-maintenance-wrapper)
  output: >
    Kernel module tool used unexpectedly user=%user.name proc=%proc.cmdline parent=%proc.pname
  priority: WARNING
```

---

## Kubernetes and containerized environments

Both vulnerabilities matter in Kubernetes because they change the value of a low-privileged foothold.

```text
Kubernetes risk flow
--------------------
initial pod compromise
  -> local code execution in container
  -> host kernel is shared by containers
  -> kernel LPE may become node-level root
  -> node credentials / kubelet material exposed
  -> cluster lateral movement risk
```

Important nuance:

```text
Container image patched?        Useful, but not enough.
Host kernel patched?            Required.
Node reboot/livepatch verified? Required.
Module posture validated?       Strongly recommended.
```

For managed Kubernetes, the key question is not only “did the vendor publish a patched kernel?” It is:

```text
Are my nodes actually running the fixed kernel right now?
```

Recommended Kubernetes triage:

```bash
kubectl get nodes -o wide
kubectl describe node <node-name> | grep -i 'Kernel Version'

# From privileged node diagnostic tooling or EDR inventory:
uname -r
lsmod | egrep '^(algif_aead|af_alg|esp4|esp6|rxrpc)\b'
grep -R 'algif_aead\|af_alg\|esp4\|esp6\|rxrpc' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
```

---

## Vulnerability-management decision tree

```text
Start
 |
 v
Do we have local/untrusted code execution on this asset class?
 |-- No  -> Still patch, but prioritize below shared execution surfaces.
 |
 |-- Yes
      |
      v
Is the asset a shared host, CI runner, K8s node, bastion, or internet-facing app server?
      |-- No  -> Patch through normal emergency kernel process.
      |
      |-- Yes
           |
           v
Check CopyFail and Dirty Frag separately.
           |
           +-- CopyFail: CVE-2026-31431 / algif_aead / AF_ALG
           |
           +-- Dirty Frag: CVE-2026-43284 + CVE-2026-43500 / esp4 esp6 rxrpc
           |
           v
Patch kernel and reboot/livepatch-verify.
           |
           v
If patch unavailable, apply vendor-approved module mitigations after impact review.
           |
           v
Monitor for local suspicious execution and root transitions.
```

---

## IR triage checklist

### Fast host check

```bash
hostnamectl 2>/dev/null || hostname
uname -a
cat /etc/os-release 2>/dev/null

printf '\nLoaded watched modules:\n'
lsmod | egrep '^(algif_aead|af_alg|esp4|esp6|rxrpc)\b' || true

printf '\nModprobe controls:\n'
grep -R 'algif_aead\|af_alg\|esp4\|esp6\|rxrpc' \
  /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d \
  2>/dev/null || true

printf '\nRecent suspicious temp execution:\n'
find /tmp /var/tmp /dev/shm -xdev -type f -perm -111 -mtime -7 -ls 2>/dev/null || true
```

### Package state

Debian/Ubuntu:

```bash
uname -r
dpkg -l 'linux-image*' 'linux-modules*' 2>/dev/null | awk '/^ii/ {print $2, $3}'
apt list --upgradable 2>/dev/null | grep -Ei 'linux-image|linux-modules|linux-generic' || true
```

RHEL/Fedora-like:

```bash
uname -r
rpm -qa 'kernel*' | sort
sudo dnf check-update --security kernel kernel-core kernel-modules 2>/dev/null || true
```

### Kubernetes node state

```bash
kubectl get nodes -o custom-columns=NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion,OS:.status.nodeInfo.osImage,CONTAINER_RUNTIME:.status.nodeInfo.containerRuntimeVersion
```

---

## Communication-ready explanation

Use this when briefing leadership or CAB:

```text
CopyFail and Dirty Frag are related Linux kernel local privilege escalation issues.
They overlap because both abuse page-cache write behavior to turn local unprivileged execution into root access.
They differ because they enter the kernel through different subsystems: CopyFail through the AF_ALG crypto path, Dirty Frag through ESP/XFRM and RxRPC networking paths.
As a result, mitigation must be tracked separately. Blocking algif_aead for CopyFail does not automatically mitigate Dirty Frag, and blocking esp4/esp6/rxrpc for Dirty Frag does not automatically mitigate CopyFail.
The durable fix is patched kernels plus reboot or verified livepatch across high-risk hosts, especially Kubernetes nodes, CI runners, shared servers, bastions, and internet-facing application hosts.
```

---

## ASCII overlap map

```text
                               +-----------------------------+
                               | Linux kernel LPE via        |
                               | page-cache write behavior   |
                               +--------------+--------------+
                                              |
                 +----------------------------+----------------------------+
                 |                                                         |
                 v                                                         v
+-----------------------------------+                 +-----------------------------------+
| CopyFail                          |                 | Dirty Frag                        |
| CVE-2026-31431                    |                 | CVE-2026-43284 + CVE-2026-43500   |
+-----------------------------------+                 +-----------------------------------+
| Entry path: AF_ALG / algif_aead   |                 | Entry path: ESP/XFRM + RxRPC      |
| Module focus: algif_aead, af_alg  |                 | Module focus: esp4, esp6, rxrpc   |
| Shape: single CVE                 |                 | Shape: chained CVEs               |
+-----------------------------------+                 +-----------------------------------+
                 |                                                         |
                 +----------------------------+----------------------------+
                                              |
                                              v
                               +-----------------------------+
                               | Local root impact           |
                               | post-compromise accelerator |
                               +-----------------------------+
```

---

## CAB review table

| Question | CopyFail | Dirty Frag | Action |
|---|---|---|---|
| Is local code execution required? | Yes | Yes | Prioritize systems where local execution is plausible. |
| Is kernel patching required? | Yes | Yes | Patch and reboot or verify livepatch. |
| Can module mitigation reduce risk? | Yes, if vendor-approved | Yes, if vendor-approved | Test workload impact before broad rollout. |
| Does CopyFail mitigation cover Dirty Frag? | No | No | Track separately. |
| Does Dirty Frag mitigation cover CopyFail? | No | No | Track separately. |
| Are Kubernetes nodes high priority? | Yes | Yes | Node kernel, not container image, is the key patch target. |
| Is exploitation network-remote by itself? | No | No | Treat as post-initial-access escalation. |
| Should EDR hunt focus only on CVE signatures? | No | No | Hunt surrounding execution, root transitions, module posture. |

---

## Practical repo layout

```text
docs/
  dirtyfrag-copyfail-compare-deep-dive.md
  dirtyfrag-copyfail-executive-summary.md
  dirtyfrag-copyfail-triage.md

tools/
  dirtyfrag-copyfail-check.py
  dirtyfrag-copyfail-check.pl

mitigations/
  modprobe-copyfail.conf.example
  modprobe-dirtyfrag.conf.example
  k8s-node-validation.sh
```

---

## Defensive guardrails for this repo

Recommended README language:

```text
This repository is defensive. It does not publish exploit code, weaponized proof-of-concept code, or instructions to reproduce privilege escalation. The purpose is to help defenders understand exposure, prioritize patching, validate mitigations, and hunt for post-compromise activity related to CopyFail and Dirty Frag.
```

---

## Source notes

These sources were used to build the comparison. Validate against vendor advisories for your specific distro/kernel before taking production action.

- Microsoft Security Blog: CVE-2026-31431 CopyFail overview and Defender guidance.
- Microsoft Security Blog: Dirty Frag overview, affected components, exploitation scenarios, and mitigation guidance.
- Tenable FAQ: Dirty Frag CVE mapping, relationship to CopyFail, and mitigation discussion.
- Nebius advisory: Dirty Frag module-focused mitigation notes for compute and managed Kubernetes.
- NVD CVE-2026-31431: KEV status, CWE, and references.
- Sysdig writeup: Dirty Frag disclosure details, root cause overview, affected versions, and detection framing.

---

## Appendix A: Minimal validation commands

```bash
# Running kernel
uname -r

# CopyFail-related module posture
lsmod | egrep '^(algif_aead|af_alg)\b' || true
modinfo algif_aead 2>/dev/null | head || true
modinfo af_alg 2>/dev/null | head || true

# Dirty Frag-related module posture
lsmod | egrep '^(esp4|esp6|rxrpc)\b' || true
modinfo esp4 2>/dev/null | head || true
modinfo esp6 2>/dev/null | head || true
modinfo rxrpc 2>/dev/null | head || true

# Modprobe controls
grep -R 'algif_aead\|af_alg\|esp4\|esp6\|rxrpc' \
  /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d \
  2>/dev/null || true
```

---

## Appendix B: Summary for issue tracker

```text
Title: Track CopyFail and Dirty Frag Linux kernel LPE exposure separately

Summary:
CopyFail and Dirty Frag are related Linux kernel local privilege escalation issues in the broader page-cache write/corruption family. CopyFail maps to CVE-2026-31431 and the AF_ALG/algif_aead crypto path. Dirty Frag maps to CVE-2026-43284 and CVE-2026-43500 and involves ESP/XFRM plus RxRPC paths. They overlap in impact and bug class but differ in CVE shape, kernel subsystem, module exposure, and temporary mitigations.

Action:
- Inventory running kernels, not just installed packages.
- Prioritize K8s nodes, CI runners, shared Linux hosts, bastions, and internet-facing app servers.
- Patch kernel and reboot or verify livepatch.
- Validate CopyFail module posture: algif_aead / af_alg.
- Validate Dirty Frag module posture: esp4 / esp6 / rxrpc.
- Apply vendor-approved module mitigations only after workload impact review.
- Hunt for suspicious local execution, root transitions, temp-path ELF execution, and unusual module activity.
```
