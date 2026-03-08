#!/usr/bin/env python3
"""
forensic_collect.py — Remote Forensic Collection Framework
===========================================================
Connects to target hosts over SSH, executes a comprehensive suite of
forensic commands, and archives all evidence locally with integrity
metadata.

Features
--------
- Parallel multi-host collection via ThreadPoolExecutor
- Per-file SHA-256 integrity manifests
- Automatic gzip archiving of completed host evidence trees
- ANSI-coloured, timestamped console output
- Configurable retry logic with exponential back-off
- Output directory/file permissions hardened to 0o700/0o600
- Optional real-time streaming and sudo elevation
- Machine-readable JSON execution summary

Usage
-----
    ./forensic_collect.py [--show] [--sudo] [--workers N] [--no-archive]

Examples
--------
    # Quiet collection across all hosts, two parallel workers:
    ./forensic_collect.py --workers 2

    # Stream output and elevate with sudo on a single host:
    ./forensic_collect.py --show --sudo

    # Collect without archiving (keep raw tree for live triage):
    ./forensic_collect.py --no-archive

Dependencies
------------
    pip install fabric invoke

Python
------
    >= 3.10
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shutil
import stat
import tarfile
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional

from fabric import Connection
from invoke import UnexpectedExit

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("forensic_collect")

# ── ANSI Colour Helpers ───────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"


def _c(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI escape codes.

    Parameters
    ----------
    text:
        The string to colourise.
    *codes:
        One or more ANSI escape strings (e.g. ``_RED``, ``_BOLD``).

    Returns
    -------
    str
        ANSI-wrapped string, reset at the end.

    Examples
    --------
    >>> print(_c("critical", _RED, _BOLD))   # bold red text
    >>> print(_c("ok", _GREEN))
    """
    return "".join(codes) + text + _RESET


# ── Target Configuration ──────────────────────────────────────────────────────

HOSTS: list[str] = [
    "things.edu",
    "host2.example.com",
    # Add additional hosts here...
]

DEFAULT_USER      = "HUMAN"
LOCAL_LOGS_DEST   = "./___invest"
SHOW_DELAY        = 2       # seconds between streamed commands when --show
CONNECT_TIMEOUT   = 15      # SSH connect timeout in seconds
COMMAND_TIMEOUT   = 120     # per-command execution timeout in seconds
MAX_RETRIES       = 3       # attempts before marking a task as failed
RETRY_BACKOFF     = 2.0     # exponential back-off base (seconds)
DEFAULT_WORKERS   = 4       # parallel host workers

# Files pulled verbatim from each host into <host_dir>/configs/
CONFIG_FILES: list[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/common-auth",
    "/etc/nsswitch.conf",
    "/etc/os-release",
    "/proc/version",
]

# ── Forensic Task Definitions ─────────────────────────────────────────────────
# Keys   → output filename saved under <host_dir>/
# Values → shell command executed on the remote host
#
# Each command prefixes its section with a clearly delimited header so that
# multiple commands concatenated into a single log remain grep-friendly.

TASKS: dict[str, str] = {

    # ── Identity & Session ────────────────────────────────────────────────────
    "id_whoami.log": (
        "echo '==== EFFECTIVE IDENTITY ===='; id; echo; whoami"
    ),
    "last.log": (
        "echo '==== SESSION HISTORY (last -Faiw) ===='; last -Faiw"
    ),
    "lastb.log": (
        "echo '==== FAILED LOGIN ATTEMPTS (lastb) ===='; lastb -Faiw 2>/dev/null || echo 'lastb unavailable'"
    ),
    "lastlog.log": (
        "echo '==== LAST LOGIN PER USER (lastlog) ===='; lastlog"
    ),
    "who.log": (
        "echo '==== CURRENTLY LOGGED-IN USERS (who -aH) ===='; who -aH"
    ),
    "w.log": (
        "echo '==== USER ACTIVITY (w) ===='; w"
    ),
    "utmp_wtmp_sizes.log": (
        "echo '==== WTMP/BTMP FILE METADATA ===='; "
        "stat /var/log/wtmp /var/log/btmp 2>/dev/null"
    ),

    # ── Process Enumeration ───────────────────────────────────────────────────
    "ps_aux.log": (
        "echo '==== ALL PROCESSES (ps auxwwf) ===='; ps auxwwf"
    ),
    "ps_env.log": (
        "echo '==== PROCESS ENVIRONMENT VARIABLES ===='; "
        "for pid in $(ls /proc | grep -E '^[0-9]+$'); do "
        "  cmdline=$(tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null | head -c 120); "
        "  env=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null); "
        "  [ -n \"$env\" ] && printf '\\n---- PID %s: %s\\n%s\\n' \"$pid\" \"$cmdline\" \"$env\"; "
        "done"
    ),
    "suspicious_processes.log": (
        "echo '==== PROCESSES MATCHING INTERPRETER/SCRIPT SIGNATURES ===='; "
        "ps auxww | grep -Ei 'python|\\.py\\b|ruby|\\.rb\\b|perl|\\.pl\\b|go(lang)?|node|bash|sh ' || true"
    ),
    "proc_maps.log": (
        "echo '==== MEMORY MAPS FOR RUNNING PROCESSES ===='; "
        "for pid in $(ls /proc | grep -E '^[0-9]+$'); do "
        "  maps=/proc/$pid/maps; "
        "  [ -r \"$maps\" ] && echo \"---- PID $pid ----\" && cat \"$maps\"; "
        "done 2>/dev/null"
    ),
    "deleted_exe.log": (
        "echo '==== PROCESSES RUNNING FROM DELETED EXECUTABLES ===='; "
        "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' || echo 'None found'"
    ),
    "fd_sockets.log": (
        "echo '==== PROCESS FILE DESCRIPTORS POINTING TO SOCKETS ===='; "
        "for pid in $(ls /proc | grep -E '^[0-9]+$'); do "
        "  ls -la /proc/$pid/fd 2>/dev/null | grep socket && "
        "  echo \"    ^ PID $pid: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' ')\"; "
        "done || true"
    ),

    # ── Network State ─────────────────────────────────────────────────────────
    "ss_all.log": (
        "echo '==== ALL SOCKETS (ss -atunpoe) ===='; ss -atunpoe"
    ),
    "ss_summary.log": (
        "echo '==== SOCKET SUMMARY (ss -s) ===='; ss -s"
    ),
    "lsof_network.log": (
        "echo '==== OPEN NETWORK FILES (lsof -i -P -n) ===='; lsof -i -P -n 2>/dev/null"
    ),
    "arp_cache.log": (
        "echo '==== ARP CACHE ===='; arp -an 2>/dev/null || ip neigh show"
    ),
    "routing_table.log": (
        "echo '==== ROUTING TABLE ===='; ip route show table all"
    ),
    "ip_addresses.log": (
        "echo '==== NETWORK INTERFACES & ADDRESSES ===='; ip -s addr show"
    ),
    "iptables.log": (
        "echo '==== IPTABLES RULES ===='; "
        "for tbl in filter nat mangle raw; do "
        "  echo \"---- table: $tbl ----\"; "
        "  iptables -t \"$tbl\" -nvL --line-numbers 2>/dev/null || echo 'n/a'; "
        "done; "
        "echo '==== IP6TABLES RULES ===='; "
        "for tbl in filter nat mangle raw; do "
        "  echo \"---- table: $tbl ----\"; "
        "  ip6tables -t \"$tbl\" -nvL --line-numbers 2>/dev/null || echo 'n/a'; "
        "done"
    ),
    "nftables.log": (
        "echo '==== NFTABLES RULESET ===='; nft list ruleset 2>/dev/null || echo 'nft not available'"
    ),
    "dns_cache.log": (
        "echo '==== SYSTEMD-RESOLVE STATS ===='; "
        "resolvectl statistics 2>/dev/null || systemd-resolve --statistics 2>/dev/null || echo 'resolvectl unavailable'"
    ),

    # ── Filesystem Indicators ─────────────────────────────────────────────────
    "tmp_listing.log": (
        "echo '==== FILES IN /tmp ===='; find /tmp -type f -exec ls -la {} \\;"
    ),
    "shm_listing.log": (
        "echo '==== FILES IN /dev/shm ===='; find /dev/shm -type f -exec ls -la {} \\;"
    ),
    "var_tmp_listing.log": (
        "echo '==== FILES IN /var/tmp ===='; find /var/tmp -type f -exec ls -la {} \\;"
    ),
    "run_listing.log": (
        "echo '==== FILES IN /run (depth 3) ===='; find /run -maxdepth 3 -type f -exec ls -la {} \\;"
    ),
    "suid_sgid.log": (
        "echo '==== SUID BINARIES ===='; find / -xdev -perm -4000 -type f -exec ls -la {} \\; 2>/dev/null; "
        "echo '==== SGID BINARIES ===='; find / -xdev -perm -2000 -type f -exec ls -la {} \\; 2>/dev/null"
    ),
    "world_writable.log": (
        "echo '==== WORLD-WRITABLE FILES (excl. /proc /sys /dev) ===='; "
        "find / -xdev -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' "
        "-perm -o+w -type f -exec ls -la {} \\; 2>/dev/null"
    ),
    "recently_modified.log": (
        "echo '==== FILES MODIFIED IN THE LAST 24h (excl. /proc /sys /dev /run) ===='; "
        "find / -xdev "
        "-not -path '/proc/*' -not -path '/sys/*' "
        "-not -path '/dev/*'  -not -path '/run/*' "
        "-mtime -1 -type f -exec ls -la {} \\; 2>/dev/null"
    ),
    "immutable_files.log": (
        "echo '==== IMMUTABLE FILES (lsattr) ===='; "
        "lsattr -R /etc /usr /bin /sbin /lib 2>/dev/null | grep -- '----i' || echo 'None found'"
    ),
    "mounts.log": (
        "echo '==== MOUNTED FILESYSTEMS (findmnt) ===='; findmnt -A; "
        "echo '==== /proc/mounts ===='; cat /proc/mounts"
    ),
    "open_files.log": (
        "echo '==== ALL OPEN FILES (lsof +L1) ===='; lsof +L1 2>/dev/null"
    ),

    # ── Persistence Mechanisms ────────────────────────────────────────────────
    "systemd_units_list.log": (
        "echo '==== SYSTEMD SERVICE UNIT FILES ===='; "
        "find /etc/systemd /usr/lib/systemd /run/systemd -type f -name '*.service' 2>/dev/null"
    ),
    "systemd_units_contents.log": (
        "echo '==== SYSTEMD SERVICE UNIT CONTENTS ===='; "
        "find /etc/systemd /usr/lib/systemd /run/systemd "
        "-type f -name '*.service' -exec echo '---- {} ----' \\; -exec cat {} \\; 2>/dev/null"
    ),
    "systemd_timers.log": (
        "echo '==== SYSTEMD TIMERS ===='; systemctl list-timers --all --no-pager"
    ),
    "systemd_dropins.log": (
        "echo '==== SYSTEMD DROP-IN FILES ===='; "
        "find /etc/systemd /usr/lib/systemd /run/systemd "
        "-path '*.d/*.conf' -exec echo '---- {} ----' \\; -exec cat {} \\; 2>/dev/null"
    ),
    "cronjobs.log": (
        "echo '==== /etc/crontab ===='; cat /etc/crontab 2>/dev/null; "
        "echo '==== /etc/cron.* ===='; "
        "for d in /etc/cron.*; do "
        "  [ -d \"$d\" ] && echo \"---- $d ----\" && ls -la \"$d\"; "
        "done; "
        "echo '==== /var/spool/cron ===='; ls -laR /var/spool/cron 2>/dev/null; "
        "echo '==== PER-USER CRONTABS ===='; "
        "for u in $(cut -f1 -d: /etc/passwd); do "
        "  ct=$(crontab -u \"$u\" -l 2>/dev/null); "
        "  [ -n \"$ct\" ] && echo \"---- $u ----\" && echo \"$ct\"; "
        "done"
    ),
    "at_jobs.log": (
        "echo '==== AT / BATCH JOBS ===='; atq 2>/dev/null || echo 'at not available'"
    ),
    "startup_scripts.log": (
        "echo '==== /etc/rc.local ===='; "
        "[ -f /etc/rc.local ] && cat /etc/rc.local || echo 'not found'; "
        "echo '==== /etc/init.d ===='; ls -la /etc/init.d 2>/dev/null; "
        "echo '==== /etc/profile.d ===='; ls -la /etc/profile.d 2>/dev/null; "
        "echo '==== /etc/profile ===='; cat /etc/profile 2>/dev/null"
    ),
    "xdg_autostart.log": (
        "echo '==== XDG AUTOSTART ENTRIES ===='; "
        "find /etc/xdg/autostart /home -path '*autostart*.desktop' "
        "-exec echo '---- {} ----' \\; -exec cat {} \\; 2>/dev/null"
    ),
    "ld_preload.log": (
        "echo '==== LD_PRELOAD / LD_SO_PRELOAD ===='; "
        "cat /etc/ld.so.preload 2>/dev/null || echo '/etc/ld.so.preload not present'; "
        "echo; grep -r LD_PRELOAD /etc/environment /etc/profile.d/ /etc/profile 2>/dev/null || true"
    ),

    # ── Kernel & Hardware ─────────────────────────────────────────────────────
    "kernel_modules.log": (
        "echo '==== LOADED KERNEL MODULES (lsmod) ===='; lsmod; "
        "echo '==== MODULE PARAMETERS ===='; "
        "for m in $(lsmod | tail -n +2 | awk '{print $1}'); do "
        "  echo \"---- $m ----\"; "
        "  ls /sys/module/$m/parameters/ 2>/dev/null | while read p; do "
        "    printf '  %s = %s\\n' \"$p\" \"$(cat /sys/module/$m/parameters/$p 2>/dev/null)\"; "
        "  done; "
        "done"
    ),
    "dmesg.log": (
        "echo '==== KERNEL RING BUFFER (dmesg -T) ===='; dmesg -T 2>/dev/null || dmesg | tail -n 300"
    ),
    "cpuinfo.log": (
        "echo '==== CPU INFORMATION ===='; cat /proc/cpuinfo"
    ),
    "meminfo.log": (
        "echo '==== MEMORY INFORMATION ===='; cat /proc/meminfo; "
        "echo '==== VMSTAT ===='; vmstat -s"
    ),
    "sysctl.log": (
        "echo '==== KERNEL PARAMETERS (sysctl -a) ===='; sysctl -a 2>/dev/null"
    ),

    # ── System & Service Logs ─────────────────────────────────────────────────
    "journalctl_recent.log": (
        "echo '==== JOURNALCTL — LAST 1000 LINES ===='; journalctl -n 1000 --no-pager"
    ),
    "journalctl_boot.log": (
        "echo '==== JOURNALCTL — CURRENT BOOT ===='; journalctl -b --no-pager"
    ),
    "auth_log.log": (
        "echo '==== AUTH LOG (tail -n 500) ===='; "
        "tail -n 500 /var/log/auth.log 2>/dev/null || "
        "tail -n 500 /var/log/secure 2>/dev/null || echo 'Auth log not found'"
    ),
    "syslog.log": (
        "echo '==== SYSLOG (tail -n 500) ===='; "
        "tail -n 500 /var/log/syslog 2>/dev/null || "
        "tail -n 500 /var/log/messages 2>/dev/null || echo 'Syslog not found'"
    ),
    "audit_log.log": (
        "echo '==== AUDIT LOG (tail -n 500) ===='; "
        "tail -n 500 /var/log/audit/audit.log 2>/dev/null || echo 'Audit log not found'"
    ),

    # ── Package & Software Inventory ──────────────────────────────────────────
    "installed_packages.log": (
        "echo '==== INSTALLED PACKAGES ===='; "
        "if command -v dpkg-query &>/dev/null; then "
        "  dpkg-query -l; "
        "elif command -v rpm &>/dev/null; then "
        "  rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'; "
        "else echo 'No known package manager found'; fi"
    ),
    "recently_installed.log": (
        "echo '==== RECENTLY INSTALLED PACKAGES (last 30 days) ===='; "
        "if [ -f /var/log/dpkg.log ]; then "
        "  grep ' install ' /var/log/dpkg.log | tail -n 200; "
        "elif command -v rpm &>/dev/null; then "
        "  rpm -qa --queryformat '%{INSTALLTIME:date} %{NAME}\\n' | sort | tail -n 200; "
        "else echo 'Unable to determine recently installed packages'; fi"
    ),

    # ── Containers & Virtualisation ───────────────────────────────────────────
    "docker_state.log": (
        "echo '==== DOCKER CONTAINERS ===='; docker ps -a 2>/dev/null || echo 'Docker not available'; "
        "echo '==== DOCKER IMAGES ===='; docker images 2>/dev/null || true; "
        "echo '==== DOCKER NETWORKS ===='; docker network ls 2>/dev/null || true; "
        "echo '==== DOCKER VOLUMES ===='; docker volume ls 2>/dev/null || true"
    ),
    "container_runtime.log": (
        "echo '==== PODMAN CONTAINERS ===='; podman ps -a 2>/dev/null || echo 'Podman not available'; "
        "echo '==== CONTAINERD NAMESPACES ===='; ctr namespaces list 2>/dev/null || echo 'containerd not available'"
    ),
    "virt_indicators.log": (
        "echo '==== VIRTUALISATION DETECTION ===='; "
        "systemd-detect-virt 2>/dev/null || "
        "hostnamectl status 2>/dev/null | grep -i virt || "
        "cat /proc/cpuinfo | grep -i hypervisor || echo 'Unable to detect'; "
        "echo '==== DMI INFO ===='; dmidecode -t system 2>/dev/null | head -40 || echo 'dmidecode not available'"
    ),

    # ── User & Credential Artefacts ───────────────────────────────────────────
    "bash_history.log": (
        "echo '==== BASH HISTORY FILES ===='; "
        "for f in /root/.bash_history /home/*/.bash_history; do "
        "  [ -f \"$f\" ] && echo \"---- $f ----\" && cat \"$f\"; "
        "done"
    ),
    "shell_rc_files.log": (
        "echo '==== SHELL RC / PROFILE FILES ===='; "
        "for f in /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc "
        "         /home/*/.profile /home/*/.bash_profile /home/*/.zshrc; do "
        "  [ -f \"$f\" ] && echo \"---- $f ----\" && cat \"$f\"; "
        "done"
    ),
    "ssh_keys.log": (
        "echo '==== SSH KEYS & AUTHORIZED_KEYS ===='; "
        "find /etc/ssh/ /home /root -type f "
        "\\( -name 'id_rsa*' -o -name 'id_ed25519*' -o -name 'id_ecdsa*' "
        "-o -name 'authorized_keys' -o -name 'authorized_keys2' \\) "
        "-exec echo '---- {} ----' \\; -exec ls -la {} \\; -exec cat {} \\;"
    ),
    "ssh_known_hosts.log": (
        "echo '==== KNOWN HOSTS FILES ===='; "
        "for f in /etc/ssh/ssh_known_hosts /root/.ssh/known_hosts /home/*/.ssh/known_hosts; do "
        "  [ -f \"$f\" ] && echo \"---- $f ----\" && cat \"$f\"; "
        "done"
    ),
    "hidden_files.log": (
        "echo '==== HIDDEN FILES IN HOME DIRECTORIES (maxdepth 3) ===='; "
        "find /home /root -maxdepth 3 -name '.*' -type f -exec ls -la {} \\;"
    ),
    "sudo_config.log": (
        "echo '==== SUDOERS ===='; cat /etc/sudoers 2>/dev/null; "
        "echo '==== /etc/sudoers.d ===='; "
        "find /etc/sudoers.d -type f -exec echo '---- {} ----' \\; -exec cat {} \\; 2>/dev/null"
    ),
    "passwd_shadow_diff.log": (
        "echo '==== USERS WITH UID 0 (potential root equivalents) ===='; "
        "awk -F: '($3==0){print}' /etc/passwd; "
        "echo '==== USERS WITH EMPTY PASSWORDS ===='; "
        "awk -F: '($2==\"\" || $2==\"!\"){print $1}' /etc/shadow 2>/dev/null || echo 'Cannot read /etc/shadow'"
    ),
    "pam_config.log": (
        "echo '==== PAM CONFIGURATION FILES ===='; "
        "find /etc/pam.d -type f -exec echo '---- {} ----' \\; -exec cat {} \\;"
    ),

    # ── Integrity & Backdoor Indicators ──────────────────────────────────────
    "integrity_checksums.log": (
        "echo '==== MD5 CHECKSUMS: /etc AND /usr/bin ===='; "
        "for dir in /etc /usr/bin /usr/sbin /bin /sbin; do "
        "  echo \"---- $dir ----\"; "
        "  find \"$dir\" -type f -exec md5sum {} \\; 2>/dev/null; "
        "done"
    ),
    "rootkit_indicators.log": (
        "echo '==== ROOTKIT INDICATORS — COMMON HIDING PATHS ===='; "
        "for p in /dev/.udev /dev/shm /tmp/.* /var/tmp/.* /usr/share/.* /etc/.*; do "
        "  [ -e \"$p\" ] && ls -la \"$p\" 2>/dev/null; "
        "done; "
        "echo '==== RKHUNTER (if available) ===='; "
        "rkhunter --check --sk --nocolors 2>/dev/null || echo 'rkhunter not installed'; "
        "echo '==== CHKROOTKIT (if available) ===='; "
        "chkrootkit 2>/dev/null || echo 'chkrootkit not installed'"
    ),
    "capabilities.log": (
        "echo '==== FILES WITH LINUX CAPABILITIES ===='; "
        "getcap -r / 2>/dev/null || echo 'getcap not available'"
    ),
    "library_preload.log": (
        "echo '==== SHARED LIBRARY CACHE (ldconfig -p) ===='; ldconfig -p"
    ),

    # ── Disk & Resource Usage ─────────────────────────────────────────────────
    "disk_usage.log": (
        "echo '==== DISK USAGE (df -h) ===='; df -h; "
        "echo '==== INODE USAGE (df -i) ===='; df -i"
    ),
    "large_files.log": (
        "echo '==== FILES > 100MB (excl. /proc /sys) ===='; "
        "find / -xdev -not -path '/proc/*' -not -path '/sys/*' "
        "-type f -size +100M -exec ls -lh {} \\; 2>/dev/null"
    ),
    "uptime_load.log": (
        "echo '==== UPTIME & LOAD ===='; uptime; "
        "echo '==== WHO -b (last boot) ===='; who -b"
    ),
}

# ── Decorators ────────────────────────────────────────────────────────────────


def retry(
    max_attempts: int = MAX_RETRIES,
    backoff: float = RETRY_BACKOFF,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable:
    """Decorator: retry a function up to *max_attempts* times with exponential back-off.

    Parameters
    ----------
    max_attempts:
        Maximum number of total attempts (default: ``MAX_RETRIES``).
    backoff:
        Base sleep time in seconds; sleep doubles each attempt (default: ``RETRY_BACKOFF``).
    exceptions:
        Tuple of exception types that trigger a retry.

    Returns
    -------
    Callable
        Decorated function.

    Examples
    --------
    >>> @retry(max_attempts=3, backoff=1.5, exceptions=(IOError,))
    ... def flaky_io():
    ...     ...
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    delay = backoff ** (attempt - 1)
                    logger.warning(
                        "Attempt %d/%d failed for %s: %s — retrying in %.1fs",
                        attempt, max_attempts, fn.__name__, exc, delay,
                    )
                    time.sleep(delay)
            raise RuntimeError(
                f"{fn.__name__} failed after {max_attempts} attempts"
            ) from last_exc
        return wrapper
    return decorator


def timed(fn: Callable) -> Callable:
    """Decorator: log the elapsed wall-clock time of a function call.

    Examples
    --------
    >>> @timed
    ... def slow_task():
    ...     time.sleep(5)
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        t0 = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed = time.perf_counter() - t0
        logger.debug("%s completed in %.2fs", fn.__name__, elapsed)
        return result
    return wrapper

# ── Security Helpers ──────────────────────────────────────────────────────────


def secure_mkdir(path: str, mode: int = 0o700) -> None:
    """Create *path* (including parents) and enforce *mode* permissions.

    Creates the directory only if it does not already exist.  Sets strict
    permissions so that only the owning user can read, write, or traverse
    the directory — protecting potentially sensitive forensic evidence.

    Parameters
    ----------
    path:
        Filesystem path to create.
    mode:
        Unix permission bits (default: ``0o700`` — owner rwx only).

    Examples
    --------
    >>> secure_mkdir("/tmp/case_001")         # creates with 0o700
    >>> secure_mkdir("/tmp/case_001/configs", mode=0o700)
    """
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)


def secure_write(path: str, content: str, mode: int = 0o600) -> None:
    """Write *content* to *path* and restrict permissions to *mode*.

    Ensures collected evidence files are not readable by other system
    users on the analyst's workstation.

    Parameters
    ----------
    path:
        Destination file path.
    content:
        Text content to write (UTF-8).
    mode:
        Unix permission bits (default: ``0o600`` — owner rw only).

    Examples
    --------
    >>> secure_write("/tmp/case_001/passwd.log", file_contents)
    """
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(content)
    os.chmod(path, mode)


def sha256_file(path: str) -> str:
    """Return the hex-encoded SHA-256 digest of the file at *path*.

    Reads the file in 64 KiB chunks to avoid loading large evidence
    files entirely into memory.

    Parameters
    ----------
    path:
        Path to the file to hash.

    Returns
    -------
    str
        Lowercase hex digest string (64 characters).

    Examples
    --------
    >>> digest = sha256_file("/tmp/case_001/ps_aux.log")
    >>> print(digest)  # e.g. 'a3f1...'
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(host_dir: str) -> str:
    """Walk *host_dir* and write a SHA-256 manifest to ``MANIFEST.sha256``.

    The manifest format mirrors ``sha256sum``-compatible output so it can
    be verified offline with ``sha256sum -c MANIFEST.sha256``.

    Parameters
    ----------
    host_dir:
        Root directory of a single host's evidence tree.

    Returns
    -------
    str
        Absolute path to the written manifest file.

    Examples
    --------
    >>> manifest_path = write_manifest("./___invest/things_edu")
    >>> # Later verification:
    >>> # cd ./___invest/things_edu && sha256sum -c MANIFEST.sha256
    """
    manifest_path = os.path.join(host_dir, "MANIFEST.sha256")
    lines: list[str] = []
    for root, _, files in os.walk(host_dir):
        for name in sorted(files):
            if name == "MANIFEST.sha256":
                continue
            abs_path = os.path.join(root, name)
            rel_path = os.path.relpath(abs_path, host_dir)
            lines.append(f"{sha256_file(abs_path)}  {rel_path}")
    secure_write(manifest_path, "\n".join(lines) + "\n")
    return manifest_path


def archive_host_dir(host_dir: str) -> str:
    """Compress *host_dir* into a gzipped tar archive beside the directory.

    The archive is named ``<host_dir>.tar.gz``.  After successful archiving
    the source directory is removed to reduce footprint on the analyst's disk.

    Parameters
    ----------
    host_dir:
        Path to the evidence directory to compress.

    Returns
    -------
    str
        Path to the resulting ``.tar.gz`` archive.

    Examples
    --------
    >>> archive = archive_host_dir("./___invest/things_edu")
    >>> print(archive)  # ./___invest/things_edu.tar.gz
    """
    archive_path = host_dir.rstrip("/") + ".tar.gz"
    with tarfile.open(archive_path, "w:gz", compresslevel=9) as tar:
        tar.add(host_dir, arcname=os.path.basename(host_dir))
    os.chmod(archive_path, 0o600)
    shutil.rmtree(host_dir)
    return archive_path

# ── SSH / Command Helpers ─────────────────────────────────────────────────────


def make_connection(host: str) -> Connection:
    """Build a Fabric :class:`~fabric.connection.Connection` for *host*.

    Uses SSH agent forwarding and respects ``~/.ssh/known_hosts`` for host
    key verification.  The ``connect_timeout`` is capped at
    :data:`CONNECT_TIMEOUT` to prevent indefinite blocking on unreachable
    targets.

    Parameters
    ----------
    host:
        Hostname or IP address of the target.

    Returns
    -------
    Connection
        Configured but not yet open Fabric connection.

    Examples
    --------
    >>> conn = make_connection("10.0.0.42")
    >>> with conn:
    ...     result = conn.run("id", hide=True)
    """
    return Connection(
        host=host,
        user=DEFAULT_USER,
        forward_agent=True,
        connect_timeout=CONNECT_TIMEOUT,
        connect_kwargs={
            "allow_agent": True,
            "look_for_keys": True,
        },
    )


def run_cmd(
    conn: Connection,
    command: str,
    use_sudo: bool,
    hide: bool = True,
) -> str:
    """Execute *command* on *conn*, optionally via sudo, and return stdout.

    On :class:`~invoke.exceptions.UnexpectedExit` the error string is
    returned rather than raising so callers can persist the failure details
    alongside normal output.

    Parameters
    ----------
    conn:
        Active Fabric SSH connection.
    command:
        Shell command string to execute on the remote host.
    use_sudo:
        If ``True`` the command is run via ``sudo`` on the remote host.
    hide:
        If ``True`` suppress stdout/stderr from the local terminal
        (passed directly to Fabric's ``hide`` argument).

    Returns
    -------
    str
        Stripped stdout of the command, or an error message string.

    Examples
    --------
    >>> output = run_cmd(conn, "id", use_sudo=False)
    >>> output = run_cmd(conn, "cat /etc/shadow", use_sudo=True)
    """
    try:
        fn = conn.sudo if use_sudo else conn.run
        result = fn(command, hide=hide, warn=True, timeout=COMMAND_TIMEOUT)
        return result.stdout.strip()
    except UnexpectedExit as exc:
        return f"[ERROR] UnexpectedExit: {exc}"
    except Exception as exc:
        return f"[ERROR] {type(exc).__name__}: {exc}"

# ── Core Collection Functions ─────────────────────────────────────────────────


@timed
def collect_forensics(
    conn: Connection,
    host_dir: str,
    show: bool,
    use_sudo: bool,
    results: dict,
) -> None:
    """Execute every entry in :data:`TASKS` and persist output locally.

    Iterates over all defined forensic tasks, runs each command on *conn*,
    writes output to a dedicated log file, and records pass/fail state into
    the shared *results* dict for later summary reporting.

    Parameters
    ----------
    conn:
        Active Fabric SSH connection to the target host.
    host_dir:
        Local directory path where log files will be written.
    show:
        Stream output to the terminal in real time with a
        :data:`SHOW_DELAY`-second pause between tasks.
    use_sudo:
        Elevate all commands via ``sudo``.
    results:
        Mutable dict updated in place:
        ``results["tasks"][filename] = "ok" | "error"``.

    Examples
    --------
    >>> results = {"tasks": {}}
    >>> collect_forensics(conn, "/evidence/host1", show=False,
    ...                   use_sudo=True, results=results)
    >>> failed = [k for k, v in results["tasks"].items() if v == "error"]
    """
    total = len(TASKS)
    for idx, (filename, command) in enumerate(TASKS.items(), start=1):
        label = _c(f"[{conn.host}]", _CYAN, _BOLD)
        progress = _c(f"({idx}/{total})", _DIM)
        print(f"{label} {progress} {command[:100]}")

        output = run_cmd(conn, command, use_sudo, hide=not show)
        is_error = output.startswith("[ERROR]")
        results["tasks"][filename] = "error" if is_error else "ok"

        header = (
            f"# Command:   {command}\n"
            f"# Host:      {conn.host}\n"
            f"# Collected: {datetime.now(timezone.utc).isoformat()}\n"
            f"# Status:    {'ERROR' if is_error else 'OK'}\n\n"
        )
        local_file = os.path.join(host_dir, filename)
        secure_write(local_file, header + output)

        status_tag = (
            _c("ERROR", _RED, _BOLD) if is_error else _c("saved", _GREEN)
        )
        print(f"{label} {status_tag} → {local_file}")

        if show:
            print(f"\n{output}\n")
            time.sleep(SHOW_DELAY)


@timed
def fetch_configs(
    conn: Connection,
    config_dest: str,
    use_sudo: bool,
    show: bool,
    results: dict,
) -> None:
    """Retrieve each path in :data:`CONFIG_FILES` from *conn* to *config_dest*.

    Prefers ``sudo cat`` when *use_sudo* is ``True`` (e.g. to reach
    ``/etc/shadow``), otherwise falls back to Fabric's native
    :meth:`~fabric.connection.Connection.get`.

    Parameters
    ----------
    conn:
        Active Fabric SSH connection.
    config_dest:
        Local directory for pulled configuration files.
    use_sudo:
        Use ``sudo cat`` instead of SFTP ``get`` to access privileged files.
    show:
        Insert a :data:`SHOW_DELAY`-second pause after each file transfer.
    results:
        Mutable dict updated in place:
        ``results["configs"][basename] = "ok" | "error"``.

    Examples
    --------
    >>> results = {"configs": {}}
    >>> fetch_configs(conn, "/evidence/host1/configs",
    ...              use_sudo=True, show=False, results=results)
    """
    label = _c(f"[{conn.host}]", _CYAN, _BOLD)
    for remote_path in CONFIG_FILES:
        basename = os.path.basename(remote_path)
        local_path = os.path.join(config_dest, basename)
        try:
            if use_sudo:
                output = run_cmd(conn, f"cat {remote_path}", use_sudo=True)
                secure_write(local_path, output)
            else:
                conn.get(remote_path, local=local_path)
                os.chmod(local_path, 0o600)

            results["configs"][basename] = "ok"
            print(f"{label} {_c('fetched', _GREEN)} {remote_path} → {local_path}")
        except Exception as exc:
            results["configs"][basename] = "error"
            print(f"{label} {_c('FAILED', _RED, _BOLD)} {remote_path}: {exc}")

        if show:
            time.sleep(SHOW_DELAY)

# ── Per-Host Orchestration ────────────────────────────────────────────────────


def collect_host(host: str, show: bool, use_sudo: bool, archive: bool) -> dict:
    """Run the full forensic collection pipeline for a single *host*.

    Orchestrates connection, command execution, config fetching, manifest
    generation, optional archiving, and summary construction.  Designed to
    be called concurrently by :func:`main` via a thread pool.

    Parameters
    ----------
    host:
        Hostname or IP address of the target.
    show:
        Stream live command output to the terminal.
    use_sudo:
        Elevate commands and file reads via ``sudo``.
    archive:
        Compress and remove the host evidence directory after collection.

    Returns
    -------
    dict
        Execution summary for this host::

            {
                "host":     str,
                "status":   "ok" | "error",
                "started":  ISO-8601 timestamp,
                "finished": ISO-8601 timestamp,
                "elapsed":  float (seconds),
                "tasks":    {filename: "ok" | "error", ...},
                "configs":  {basename: "ok" | "error", ...},
                "manifest": str | None,
                "archive":  str | None,
                "error":    str | None,
            }

    Examples
    --------
    >>> summary = collect_host("10.0.0.42", show=False, use_sudo=True, archive=True)
    >>> print(summary["status"], summary["elapsed"])
    """
    started = datetime.now(timezone.utc)
    results: dict = {
        "host":     host,
        "status":   "ok",
        "started":  started.isoformat(),
        "finished": None,
        "elapsed":  None,
        "tasks":    {},
        "configs":  {},
        "manifest": None,
        "archive":  None,
        "error":    None,
    }

    safe_host = host.replace(".", "_").replace(":", "_")
    host_dir = os.path.join(LOCAL_LOGS_DEST, safe_host)
    config_dest = os.path.join(host_dir, "configs")

    divider = "=" * 64
    print(f"\n{_c(divider, _YELLOW)}")
    print(_c(f"  TARGET : {host}", _YELLOW, _BOLD))
    print(_c(f"  STARTED: {started.strftime('%Y-%m-%dT%H:%M:%S%z')}", _YELLOW))
    print(f"{_c(divider, _YELLOW)}\n")

    try:
        secure_mkdir(host_dir)
        secure_mkdir(config_dest)

        with make_connection(host) as conn:
            collect_forensics(conn, host_dir, show, use_sudo, results)
            fetch_configs(conn, config_dest, use_sudo, show, results)

        manifest = write_manifest(host_dir)
        results["manifest"] = manifest
        print(f"{_c(f'[{host}]', _CYAN, _BOLD)} Manifest → {manifest}")

        if archive:
            arc = archive_host_dir(host_dir)
            results["archive"] = arc
            print(f"{_c(f'[{host}]', _CYAN, _BOLD)} Archive  → {arc}")

    except Exception as exc:
        results["status"] = "error"
        results["error"] = str(exc)
        logger.error("Collection failed for %s: %s", host, exc, exc_info=True)

    finished = datetime.now(timezone.utc)
    elapsed = (finished - started).total_seconds()
    results["finished"] = finished.isoformat()
    results["elapsed"] = round(elapsed, 2)

    status_tag = (
        _c("COMPLETED", _GREEN, _BOLD)
        if results["status"] == "ok"
        else _c("FAILED", _RED, _BOLD)
    )
    print(f"\n{_c(f'[{host}]', _CYAN, _BOLD)} {status_tag} in {elapsed:.1f}s\n")
    return results

# ── Summary Reporting ─────────────────────────────────────────────────────────


def print_summary(all_results: list[dict]) -> None:
    """Print a human-readable collection summary table to stdout.

    Counts successes and failures across both command tasks and config
    fetches for every host, then writes the full machine-readable result
    set to ``<LOCAL_LOGS_DEST>/summary.json``.

    Parameters
    ----------
    all_results:
        List of result dicts returned by :func:`collect_host`.

    Examples
    --------
    >>> print_summary(summaries)
    # Writes ./___invest/summary.json
    """
    divider = "=" * 64
    print(f"\n{_c(divider, _YELLOW)}")
    print(_c("  COLLECTION SUMMARY", _YELLOW, _BOLD))
    print(f"{_c(divider, _YELLOW)}")

    for r in all_results:
        task_ok  = sum(1 for v in r["tasks"].values()   if v == "ok")
        task_err = sum(1 for v in r["tasks"].values()   if v == "error")
        cfg_ok   = sum(1 for v in r["configs"].values() if v == "ok")
        cfg_err  = sum(1 for v in r["configs"].values() if v == "error")

        host_tag = _c(r["host"], _BOLD)
        status = (
            _c("OK",     _GREEN, _BOLD)
            if r["status"] == "ok"
            else _c("FAILED", _RED,   _BOLD)
        )
        print(
            f"  {host_tag:<40} {status}  "
            f"tasks {_c(str(task_ok), _GREEN)}/{_c(str(task_err), _RED)}  "
            f"configs {_c(str(cfg_ok), _GREEN)}/{_c(str(cfg_err), _RED)}  "
            f"{r['elapsed']}s"
        )
        if r["error"]:
            print(f"    {_c('Error:', _RED)} {r['error']}")
        if r["archive"]:
            print(f"    {_c('Archive:', _DIM)} {r['archive']}")

    print(f"{_c(divider, _YELLOW)}\n")

    summary_path = os.path.join(LOCAL_LOGS_DEST, "summary.json")
    secure_write(summary_path, json.dumps(all_results, indent=2))
    print(f"Full JSON summary → {summary_path}\n")

# ── Entry Point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Parse CLI arguments and dispatch collection across all target hosts.

    Uses a :class:`~concurrent.futures.ThreadPoolExecutor` to collect from
    multiple hosts in parallel.  The number of workers is capped by
    ``--workers`` (default: :data:`DEFAULT_WORKERS`).

    Exit Codes
    ----------
    0   All hosts completed without top-level errors.
    1   One or more hosts failed.

    Examples
    --------
    Quiet parallel collection::

        ./forensic_collect.py --workers 4

    Live streaming with sudo on a single host (set HOSTS = [...] first)::

        ./forensic_collect.py --show --sudo --workers 1

    Collect but keep the raw directory tree (skip compression)::

        ./forensic_collect.py --no-archive
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Stream command output to the terminal (adds a 2s pause per step).",
    )
    parser.add_argument(
        "--sudo",
        action="store_true",
        help="Elevate all remote commands and file reads via sudo.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=f"Parallel host workers (default: {DEFAULT_WORKERS}).",
    )
    parser.add_argument(
        "--no-archive",
        dest="archive",
        action="store_false",
        help="Skip gzip archiving; leave the raw evidence tree on disk.",
    )
    args = parser.parse_args()

    secure_mkdir(LOCAL_LOGS_DEST)

    workers = min(args.workers, len(HOSTS))
    all_results: list[dict] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(collect_host, host, args.show, args.sudo, args.archive): host
            for host in HOSTS
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                all_results.append(future.result())
            except Exception as exc:
                logger.error("Unhandled error for %s: %s", host, exc, exc_info=True)
                all_results.append({
                    "host": host, "status": "error", "error": str(exc),
                    "tasks": {}, "configs": {}, "elapsed": None,
                    "started": None, "finished": None,
                    "manifest": None, "archive": None,
                })

    print_summary(all_results)

    any_failed = any(r["status"] == "error" for r in all_results)
    raise SystemExit(1 if any_failed else 0)


if __name__ == "__main__":
    main()
