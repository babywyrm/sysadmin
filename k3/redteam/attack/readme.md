
# Kubernetes Privilege Escalation EZ Lab ..(beta)..
### Red Team vs Secure Configuration Demonstration

---

## Overview

This repository demonstrates a full Kubernetes attack chain resulting in node-level compromise, followed by secure configuration countermeasures.

The objective is to teach:

- How Kubernetes misconfigurations lead to privilege escalation
- Why exposed kubelet is dangerous
- Why pod creation permissions are highly sensitive
- How `hostPath`, privileged containers, and namespace sharing break isolation
- How to harden Kubernetes workloads properly

This lab is intended for **security training and controlled environments only**.

---

## Repository Structure

```
attack/
├── death.yaml        # Malicious pod demonstrating node compromise
├── safe.yaml         # Secure hardened pod configuration
├── kubelet__.md      # Kubelet exploitation notes
└── README.md         # This file
```

---

# Attack Walkthrough Summary

## Phase 1 — Exposed Kubelet

An externally accessible kubelet (port 10250) allows:

- Pod enumeration
- Remote command execution
- Container access without authentication

Example:

```bash
curl -k https://<NODE_IP>:10250/pods
```

Impact:
- Direct container command execution
- Initial foothold inside cluster

---

## Phase 2 — Service Account Token Extraction

Inside the compromised container:

```
/var/run/secrets/kubernetes.io/serviceaccount/
```

Contains:

- JWT token
- CA certificate

These credentials allow interaction with the Kubernetes API server.

---

## Phase 3 — RBAC Enumeration

Using the service account token:

```bash
kubectl auth can-i --list
```

If permissions include:

```
pods [get create list]
```

This enables privilege escalation.

---

## Phase 4 — Malicious Pod Creation

If pod creation is allowed, an attacker can deploy a pod that:

- Mounts the host filesystem
- Runs as privileged
- Shares host namespaces
- Mounts docker.sock
- Reads Kubernetes admin configuration

See:

```
death.yaml
```

This configuration demonstrates:

- `hostPath: /`
- `privileged: true`
- `hostPID: true`
- `hostNetwork: true`
- Docker socket mounting

Result:
Full node compromise.

---

## Phase 5 — Host-Level Validation

Once host root is mounted, the following confirms full node access:

```bash
cat /mnt/etc/shadow
cat /mnt/etc/passwd
ls /mnt/root
cat /mnt/etc/kubernetes/admin.conf
```

Impact:

- Password hash extraction
- SSH key exposure
- Cluster-admin credential theft
- Persistent access

---

# Secure Configuration Companion

See:

```
safe.yaml
```

This configuration demonstrates:

- No host namespace sharing
- No hostPath volumes
- No privileged mode
- No service account token
- Non-root container execution
- Dropped Linux capabilities
- Read-only root filesystem

This represents a hardened workload aligned with:

- Least privilege
- Strong isolation
- Minimal attack surface

---

# Attack Chain Visualization

```
[External Access]
        |
        v
[Exposed Kubelet]
        |
        v
[Container RCE]
        |
        v
[Extract Service Account Token]
        |
        v
[Access Kubernetes API]
        |
        v
[RBAC: Can Create Pods]
        |
        v
[Deploy Malicious Pod]
        |
        v
[Mount Host Filesystem]
        |
        v
[Read /etc/shadow]
        |
        v
[Full Node Compromise]
```

---

# Security Lessons

## 1. Never Expose Kubelet Publicly
Port 10250 must be restricted.

---

## 2. Restrict Service Account Permissions
Default service accounts should not be able to create pods.

---

## 3. Block Dangerous Pod Capabilities
Disallow:

- `hostPath`
- `privileged: true`
- `hostPID`
- `hostNetwork`
- Docker socket mounts

---

## 4. Enforce Policy Controls

Recommended mechanisms:

- Pod Security Admission (restricted profile)
- OPA / Gatekeeper
- Kyverno
- Network segmentation
- RBAC hardening

---

# Red Team vs Blue Team Takeaway

| Red Team Exploit | Blue Team Defense |
|------------------|------------------|
| Exposed kubelet | Firewall + disable anonymous auth |
| Service account token abuse | Restrictive RBAC |
| Pod creation escalation | Admission policies |
| hostPath mounting | Disallow via policy |
| Privileged containers | Restricted Pod Security level |

---

# Educational Objectives

After completing this lab, students should understand:

- Kubernetes attack surface fundamentals
- Container isolation limitations
- Why pod creation permission is highly sensitive
- How minor misconfigurations stack into total compromise
- How to design secure workloads

---

# Disclaimer

This repository is for:

- Security research
- Defensive training
- Controlled lab environments

Do not deploy these configurations in production systems.

---

# Final Principle

In Kubernetes:

```
Pod Creation Permission
        +
hostPath or Privileged Mode
        =
Node Root Access
```

Security must be layered.
One misconfiguration can collapse isolation.

---
##
##
