
# 🛠️ Post-Mortem & Recovery Guide

## Surviving a Failed EL7 → EL8 Upgrade with cPanel, Apache, MariaDB, and Docker

> **Audience:** Linux sysadmins, SREs, security engineers
> **Scope:** Enterprise Linux 7 → 8 upgrades (Alma/Rocky/RHEL), cPanel, Docker
> **Goal:** Document common failure modes and proven recovery patterns
> **Outcome:** Fully bootable system, patched OS, functional control plane, restored container runtime

---

## 1. Executive Summary

A major Enterprise Linux upgrade (EL7 → EL8) was initiated using supported tooling.
During the process, the system experienced **boot failure, initramfs corruption, kernel/runtime mismatches, service startup failures, and container runtime conflicts**.

Despite these failures, the system was **fully recovered without data loss** using:

* Recovery mode boot
* Manual initramfs reconstruction
* Service-by-service remediation
* Controlled cleanup of stale state (not blind reinstalls)

This document captures **what failed, why it failed, and how it was fixed**.

---

## 2. High-Risk Areas in EL7 → EL8 Upgrades (Observed)

### 2.1 Kernel & initramfs Mismatch

**Symptoms**

* System boot loops or drops to emergency shell
* `dracut` errors during initramfs regeneration
* Missing storage/network drivers at boot

**Root Causes**

* Kernel upgraded but initramfs incomplete
* Required drivers (e.g., virtio, overlay) not embedded
* Interrupted upgrade left a zero-byte or partial initramfs

**Recovery Pattern**

* Boot into recovery / rescue environment
* Verify installed kernel version vs `/lib/modules`
* Rebuild initramfs *explicitly* for the target kernel
* Validate `/boot` contents before rebooting

---

### 2.2 Service Stack Failures After Boot

After achieving a successful boot, **multiple services failed independently** — each for different reasons.

This is expected in major upgrades.

---

## 3. cPanel Elevation & Package Conflicts

### 3.1 Elevation Stalling During Stage Execution

**Symptoms**

* Elevation script loops waiting for completion
* Metadata download failures
* Repository resolution errors

**Key Insight**
Elevation tooling assumes:

* Working DNS
* Clean repo metadata
* No unresolved EL7 packages

A single failure can stall the entire process.

**Recovery Pattern**

* Fix base OS networking first
* Validate `dnf repolist`
* Resolve conflicts manually
* Resume elevation using continuation mode

---

### 3.2 Cross-Version Database Packages (MariaDB/MySQL)

**Symptoms**

* Database service won’t start
* Socket missing
* Client/server version conflicts
* Modular filtering errors in DNF

**Root Causes**

* EL7 database packages left installed
* EL8 module streams blocked or filtered
* Service unit files missing or mismatched

**Recovery Pattern**

* Identify and remove incompatible EL7 DB packages
* Install EL8-native database server
* Re-establish systemd units
* Initialize or reattach to existing data directory
* Start service and validate socket

---

## 4. Apache / ModSecurity / Vendor Rule Failures

### 4.1 Apache Fails Due to WAF Rule Syntax

**Symptoms**

* Apache fails to start
* Errors referencing ModSecurity vendor configs
* PCRE compilation failures
* Missing rule files

**Root Causes**

* Third-party WAF rules not EL8-compatible
* Old regex syntax rejected by newer PCRE
* Vendor config paths changed or removed

**Recovery Pattern**

* Start Apache in config-test mode
* Identify failing rule file and line
* Disable or remove broken vendor rule sets
* Prefer service availability over legacy WAF correctness
* Restart Apache cleanly

> **Key lesson:** Vendor security rules are *not* upgrade-safe by default.

---

## 5. Package Management Validation (DNF/YUM)

After recovery:

**Validation Checklist**

```bash
dnf repolist
dnf updateinfo summary
dnf update --security --assumeno
```

**Outcome**

* BaseOS + AppStream reachable
* Security advisories functional
* No silent downgrade to local-only repos

This confirms the system can receive **ongoing security updates**.

---

## 6. Docker & Container Runtime Recovery

### 6.1 Docker Daemon Fails to Start (Post-Upgrade)

**Symptoms**

* `docker ps` cannot connect
* Docker service exits immediately
* containerd runs fine
* Debug logs show network conflicts

**Root Cause (Critical Insight)**

```
error creating default "bridge" network:
conflicts with network ... (docker0)
networks have same bridge name
```

This happens when:

* Docker partially initializes networking
* Service restarts mid-initialization
* Old libnetwork state survives the upgrade

---

### 6.2 Correct Docker Recovery (Safe Method)

**Do NOT reinstall blindly.**

**Correct Fix**

```bash
systemctl stop docker
systemctl stop containerd

rm -rf /var/lib/docker/network

restorecon -Rv /var/lib/docker
restorecon -Rv /var/lib/containerd

systemctl start containerd
systemctl start docker
```

**Why this works**

* Removes only stale network metadata
* Preserves images, volumes, containers
* Allows Docker to recreate `docker0` cleanly

---

## 7. Lessons Learned (Hard-Won)

### ✅ What Worked

* Incremental recovery
* Reading *actual* logs instead of guessing
* Fixing root causes, not symptoms
* Respecting service boundaries

### ❌ What Fails Reliably

* Blind reinstalls
* Skipping kernel/initramfs validation
* Trusting third-party vendor configs during upgrades
* Assuming Docker state is stateless

---

## 8. Recommended Upgrade Playbook (Future-Safe)

**Before Upgrade**

* Snapshot / backup
* Inventory kernel modules
* Disable nonessential vendor repos
* Audit Docker networks & volumes

**During Upgrade**

* Expect breakage
* Fix one layer at a time
* Never reboot blindly

**After Upgrade**

* Validate boot
* Validate package security feeds
* Validate core services
* Validate container runtime

---

## 9. Final Outcome

✔ System booted cleanly
✔ OS upgraded successfully
✔ cPanel functional
✔ Apache operational
✔ Database running
✔ Docker restored correctly
✔ Security updates enabled

**No data loss. No rebuild required.**

---

## 10. Closing Note

This incident demonstrates that **complex Linux upgrades fail in predictable ways** — and that with discipline, logs, and patience, they are **fully recoverable**.

If this document prevents even one unnecessary rebuild, it has done its job.

---

##
##
