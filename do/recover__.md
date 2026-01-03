
# 🛠️ Deep-Dive Post-Mortem & Recovery Runbook ..beta..

## EL7 → EL8 Upgrade Failure Recovery (cPanel, Apache, MariaDB, Docker)

> **Document type:** Technical incident post-mortem + recovery reference
> **Audience:** Senior Linux admins, SREs, platform security engineers
> **OS class:** Enterprise Linux–compatible (EL7 → EL8)
> **Control plane:** cPanel / EasyApache
> **Container runtime:** Docker + containerd
> **Security tooling:** ModSecurity, vendor WAF rules
> **Data sensitivity:** Scrubbed / anonymized

---

## 1. System Context (Anonymized)

| Component       | Representative State            |
| --------------- | ------------------------------- |
| Original OS     | EL7-compatible (kernel 3.10.x)  |
| Target OS       | EL8-compatible (kernel 4.18.x)  |
| Boot Mode       | BIOS / legacy GRUB              |
| Filesystem      | ext4 (root, /boot)              |
| Control Panel   | cPanel (EasyApache 4)           |
| Web Server      | Apache 2.4.x                    |
| Database        | MariaDB 10.x                    |
| Containers      | Docker Engine + containerd      |
| Security        | ModSecurity + vendor rule packs |
| Upgrade Tooling | Leapp / Elevate                 |

---

## 2. Failure Timeline (High-Level)

1. **OS elevation initiated** (EL7 → EL8)
2. **Reboot into upgraded kernel**
3. System **fails to boot normally**
4. Recovery mode used to regain access
5. **initramfs rebuild attempts partially fail**
6. System boots, but **core services broken**
7. cPanel elevation **stalls mid-stage**
8. Apache fails due to **WAF rule syntax**
9. Database fails due to **cross-version conflicts**
10. Docker fails due to **stale network state**
11. All subsystems repaired incrementally
12. System returns to stable, patched state

---

## 3. Boot Failure: Kernel & initramfs Mismatch

### 3.1 Observed Symptoms

* Boot drops to emergency shell or hangs
* GRUB loads kernel but fails to mount root FS
* Missing drivers during early boot
* `initramfs-<kernel>.img` is:

  * zero bytes
  * partially written
  * missing required modules

### 3.2 Root Causes

* Upgrade replaced kernel **without a valid initramfs**
* `dracut` execution interrupted mid-run
* Required drivers (e.g., virtio, storage, network) not embedded
* Kernel version mismatch between:

  * `/boot/vmlinuz-*`
  * `/lib/modules/<kver>`

### 3.3 Recovery Method (Safe Pattern)

1. Boot into **rescue / recovery environment**
2. Mount system root filesystem
3. Verify kernel artifacts:

   ```bash
   ls /boot
   ls /lib/modules/
   uname -r   # rescue kernel, not target
   ```
4. Rebuild initramfs **explicitly for target kernel**:

   ```bash
   dracut --force \
     /boot/initramfs-<target-kernel>.img \
     <target-kernel>
   ```
5. Validate initramfs size (should be tens of MB, not zero)
6. Regenerate GRUB config
7. Reboot cautiously

**Key Insight:**

> A successful `dracut` *exit code* does **not** guarantee a usable initramfs. Always verify file size and contents.

---

## 4. Package Manager State Validation (DNF/YUM)

After first successful boot:

### 4.1 Repository Sanity Check

```bash
dnf repolist
```

Expected:

* BaseOS
* AppStream
* Extras
* Optional third-party repos (epel, control panel, etc.)

### 4.2 Security Advisory Validation

```bash
dnf updateinfo summary
dnf update --security --assumeno
```

**Why this matters:**
A system that boots but cannot resolve security metadata is **effectively unpatchable**.

---

## 5. cPanel Elevation Stalling (Stage Failure)

### 5.1 Symptoms

* Elevation script loops indefinitely
* Logs indicate waiting on upgrade completion
* Repository metadata fetch failures
* Repeated DNF failures during stage execution

### 5.2 Root Causes

* DNS resolution unavailable or inconsistent
* Repo metadata unreachable
* Pre-existing EL7 packages conflicting with EL8 dependency resolution
* Elevation assumes *clean dependency graph*

### 5.3 Recovery Strategy

* Fix **base OS networking and DNS first**
* Validate `dnf repolist` works reliably
* Manually resolve blocking packages
* Resume elevation using continuation mode

```bash
/usr/local/cpanel/scripts/elevate-cpanel --continue
```

---

## 6. Database Stack Failure (MariaDB / MySQL)

### 6.1 Observed Failures

* Database service fails to start
* Missing socket file
* Client/server version mismatch
* DNF modular filtering blocks installation
* Service units missing or incorrect

### 6.2 Root Causes

* EL7 database packages still installed post-upgrade
* EL8 module streams disabled or filtered
* Systemd service names changed between versions
* Data directory exists but service binary incompatible

### 6.3 Safe Recovery Pattern

1. Identify legacy packages:

   ```bash
   rpm -qa | grep -i maria
   ```
2. Remove incompatible EL7 packages
3. Enable correct EL8 module stream if required
4. Install EL8-native database server
5. Recreate or relink systemd service units
6. Validate permissions on data directory
7. Start service and confirm socket availability

**Critical Rule:**

> Do **not** delete `/var/lib/mysql` unless you intend to destroy data.

---

## 7. Apache / ModSecurity Failure

### 7.1 Symptoms

* Apache fails to start
* Config test reports syntax errors
* Errors reference ModSecurity vendor rules
* PCRE compilation failures

### 7.2 Root Causes

* Vendor WAF rules written for older PCRE versions
* Regex character classes invalid under newer libraries
* Missing or renamed rule include files
* Control panel upgrade does not validate third-party rule sets

### 7.3 Resolution Strategy

1. Run Apache config test:

   ```bash
   apachectl configtest
   ```
2. Identify failing rule file and line
3. Disable or remove problematic vendor rule set
4. Restart Apache
5. Reintroduce security controls later, selectively

**Security Tradeoff Decision:**

> Availability > legacy WAF correctness during recovery.

---

## 8. Docker Runtime Failure (Post-Upgrade)

### 8.1 Symptoms

* `docker ps` cannot connect
* Docker service fails immediately
* `containerd` runs successfully
* Docker debug logs show network conflicts

### 8.2 Root Cause (Non-Obvious)

```
error creating default "bridge" network:
networks have same bridge name (docker0)
```

This indicates:

* Stale libnetwork state
* Partial Docker startup left network objects behind
* Upgrade/reboot sequence interrupted Docker cleanup

### 8.3 Correct Recovery (Non-Destructive)

```bash
systemctl stop docker
systemctl stop containerd

rm -rf /var/lib/docker/network

restorecon -Rv /var/lib/docker
restorecon -Rv /var/lib/containerd

systemctl start containerd
systemctl start docker
```

**Why this works:**

* Removes only network metadata
* Preserves images, volumes, containers
* Allows Docker to recreate `docker0` cleanly

---

## 9. Validation Checklist (Post-Recovery)

### OS

* `uname -a` shows target kernel
* `dnf updateinfo summary` works

### Services

* Apache running
* Database socket present
* Control panel accessible

### Containers

* `docker info`
* `docker ps`
* Default bridge network recreated

---

## 10. Lessons Learned (Technical)

### What Predictably Breaks

* initramfs generation
* Vendor security rules
* Database module streams
* Docker network state

### What Saves You

* Recovery boot access
* Logs over assumptions
* Incremental fixes
* Understanding *why* services fail

---

## 11. Recommended Upgrade Hardening (Future)

* Snapshot before elevation
* Disable third-party WAF rules pre-upgrade
* Stop Docker cleanly before reboot
* Record kernel/module inventory
* Expect manual intervention

---

## 12. Final Outcome

✔ Bootable EL8 system
✔ Fully patched OS
✔ Functional control panel
✔ Stable Apache & DB
✔ Docker restored without data loss

---

## 13. Closing Thought

> Major OS upgrades don’t fail randomly —
> they fail **systematically**, and therefore can be fixed **systematically**.

This document exists so the next time this happens, recovery takes **minutes**, not **hours**.

---

##
##
