#!/usr/bin/env python3
"""
Forensic Collection Script using Fabric ..beta edition..

Connects to specified hosts via SSH, runs forensic commands, collects outputs,
and saves them locally. Also fetches critical configuration files from each host.

Usage:
    ./forensic_collect.py [--show] [--sudo]

Arguments:
    --show   Show command results in real time with a 2-second pause between commands.
    --sudo   Run commands and fetch files using sudo.
"""

import os
import time
import argparse
from datetime import datetime
from fabric import Connection
from invoke import UnexpectedExit
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────

HOSTS = [
    "things.edu",
    "host2.example.com",
    # Add additional hosts as needed...
]

DEFAULT_USER = "HUMAN"
LOCAL_LOGS_DEST = "./___invest"
SHOW_DELAY_SECONDS = 2

CONFIG_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
]

# ── Forensic Tasks ─────────────────────────────────────────────────────────────

TASKS: dict[str, str] = {
    # ── Session & Basic Info ──────────────────────────────────────────────────
    "last.log": (
        "echo '==== SESSION LOGS ===='; last -a"
    ),
    "who.log": (
        "echo '==== CURRENT USERS ===='; who"
    ),
    "ps_aux.log": (
        "echo '==== RUNNING PROCESSES ===='; ps auxww"
    ),
    "netstat.log": (
        "echo '==== SOCKET/NETWORK BINDINGS (ss) ===='; ss -tulnp"
    ),
    "lsof_sockets.log": (
        "echo '==== OPEN SOCKETS (lsof) ===='; lsof -i -P -n"
    ),

    # ── Suspicious Processes ──────────────────────────────────────────────────
    "suspicious_processes.log": (
        "echo '==== SCANNING FOR PYTHON/GO/RUBY PROCESSES ===='; "
        'ps auxww | grep -Ei "python|\\.py|go(lang)?|ruby" || true'
    ),

    # ── Systemd Persistence ───────────────────────────────────────────────────
    "systemd_units_list.log": (
        "echo '==== SYSTEMD SERVICE UNITS ===='; "
        "find /etc/systemd/system -type f -name '*.service'"
    ),
    "systemd_units_contents.log": (
        "echo '==== SYSTEMD SERVICE CONTENTS ===='; "
        "find /etc/systemd/system -type f -name '*.service' -exec cat {} \\;"
    ),
    "systemd_dropins.log": (
        "echo '==== SYSTEMD DROP-IN FILES ===='; "
        "find /etc/systemd/system -path '*.d/*' -type f -exec cat {} \\;"
    ),

    # ── System & Kernel Logs ──────────────────────────────────────────────────
    "journalctl.log": (
        "echo '==== JOURNALCTL OUTPUT (last 500 lines) ===='; "
        "journalctl -n 500 --no-pager"
    ),
    "dmesg.log": (
        "echo '==== KERNEL MESSAGES (dmesg) ===='; dmesg | tail -n 200"
    ),

    # ── Cron & Startup ────────────────────────────────────────────────────────
    "cronjobs.log": (
        "echo '==== SYSTEM CRON & USER CRON JOBS ===='; "
        "echo '---- /etc/crontab ----'; cat /etc/crontab 2>/dev/null; "
        "echo '---- /etc/cron.* directories ----'; "
        "for d in /etc/cron.*; do "
        '  [ -d "$d" ] && echo "Directory: $d" && ls -la "$d"; '
        "done; "
        "echo '---- User cron jobs ----'; "
        "for u in $(cut -f1 -d: /etc/passwd); do "
        '  echo "Crontab for $u:"; crontab -u "$u" -l 2>/dev/null; '
        "done"
    ),
    "startup_scripts.log": (
        "echo '==== STARTUP SCRIPTS & INIT FILES ===='; "
        "echo '---- /etc/rc.local ----'; "
        "[ -f /etc/rc.local ] && cat /etc/rc.local || echo '/etc/rc.local not found'; "
        "echo '==== DROP-IN STARTUP FILES IN /etc/systemd/system ===='; "
        "find /etc/systemd/system -type f \\( -iname '*rc*' -o -iname '*init*' \\) -exec ls -la {} \\;"
    ),

    # ── Kernel, Memory & Sockets ──────────────────────────────────────────────
    "kernel_modules.log": (
        "echo '==== LOADED KERNEL MODULES ===='; lsmod"
    ),
    "meminfo.log": (
        "echo '==== MEMORY INFORMATION (/proc/meminfo) ===='; cat /proc/meminfo"
    ),
    "ss_summary.log": (
        "echo '==== SOCKET SUMMARY (ss -s) ===='; ss -s"
    ),

    # ── Filesystem & Temp Directories ─────────────────────────────────────────
    "tmp_listing.log": (
        "echo '==== FILES IN /tmp ===='; find /tmp -type f -exec ls -la {} \\;"
    ),
    "shm_listing.log": (
        "echo '==== FILES IN /dev/shm ===='; find /dev/shm -type f -exec ls -la {} \\;"
    ),

    # ── User & Configuration ──────────────────────────────────────────────────
    "bash_history.log": (
        "echo '==== BASH HISTORY FILES ===='; "
        "for f in /home/*/.bash_history /root/.bash_history; do "
        '  [ -f "$f" ] && echo "==== $f ====" && cat "$f"; '
        "done"
    ),
    "integrity_checksums.log": (
        "echo '==== CHECKSUMS FOR /etc AND /usr/bin ===='; "
        "for dir in /etc /usr/bin; do "
        '  echo "==== $dir ===="; find "$dir" -type f -exec md5sum {} \\;; '
        "done"
    ),
    "ssh_keys.log": (
        "echo '==== SEARCHING FOR SSH KEYS ===='; "
        "find /etc/ssh/ /home -type f \\( -name 'id_rsa*' -o -name 'authorized_keys*' \\) -ls"
    ),
    "hidden_files.log": (
        "echo '==== HIDDEN FILES IN USER HOMES ===='; "
        "find /home -maxdepth 2 -type f -name '.*' -ls"
    ),
}

# ── Helpers ───────────────────────────────────────────────────────────────────


def log(host: str, msg: str) -> None:
    print(f"[{host}] {msg}")


def run_cmd(
    conn: Connection,
    command: str,
    use_sudo: bool,
    hide: bool = True,
) -> Optional[str]:
    """Run a command (with or without sudo) and return stdout, or None on error."""
    try:
        fn = conn.sudo if use_sudo else conn.run
        result = fn(command, hide=hide, warn=True)
        return result.stdout.strip()
    except UnexpectedExit as exc:
        return f"Error running command: {exc}"


# ── Core Collection Functions ─────────────────────────────────────────────────


def collect_forensics(
    conn: Connection, host_dir: str, show: bool, use_sudo: bool
) -> None:
    """Run all forensic TASKS on the remote host and save outputs locally."""
    for filename, command in TASKS.items():
        log(conn.host, f"Running: {command}")

        output = run_cmd(conn, command, use_sudo, hide=not show)

        local_file = os.path.join(host_dir, filename)
        with open(local_file, "w") as f:
            f.write(
                f"# Command:   {command}\n"
                f"# Host:      {conn.host}\n"
                f"# Collected: {datetime.now()}\n\n"
            )
            f.write(output or "")

        if show:
            print(f"\n{output}\n")
            time.sleep(SHOW_DELAY_SECONDS)

        log(conn.host, f"Saved → {local_file}")


def fetch_file(
    conn: Connection,
    remote_path: str,
    local_path: str,
    use_sudo: bool,
    show: bool,
) -> None:
    """Fetch a remote file and store it locally."""
    try:
        if use_sudo:
            output = run_cmd(conn, f"cat {remote_path}", use_sudo=True, hide=not show)
            with open(local_path, "w") as f:
                f.write(output or "")
        else:
            conn.get(remote_path, local=local_path)

        log(conn.host, f"Fetched {remote_path} → {local_path}")

        if show:
            time.sleep(SHOW_DELAY_SECONDS)

    except Exception as exc:
        log(conn.host, f"Failed to fetch {remote_path}: {exc}")


# ── Entry Point ───────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Forensic collection via Fabric: live output, optional sudo, "
            "and extended memory/kernel/socket inspection."
        )
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Print command output in real time with a 2-second pause between steps.",
    )
    parser.add_argument(
        "--sudo",
        action="store_true",
        help="Run commands and fetch files via sudo.",
    )
    args = parser.parse_args()

    os.makedirs(LOCAL_LOGS_DEST, exist_ok=True)

    for host in HOSTS:
        print(f"\n{'='*60}")
        print(f"Starting forensic collection on: {host}")
        print(f"{'='*60}")

        safe_host = re.sub(r"[.:]", "_", host) if False else host.replace(".", "_").replace(":", "_")
        host_dir = os.path.join(LOCAL_LOGS_DEST, safe_host)
        os.makedirs(host_dir, exist_ok=True)

        with Connection(
            host=host,
            user=DEFAULT_USER,
            forward_agent=True,
            connect_kwargs={"allow_agent": True, "look_for_keys": True},
        ) as conn:
            collect_forensics(conn, host_dir, args.show, args.sudo)

            config_dest = os.path.join(host_dir, "configs")
            os.makedirs(config_dest, exist_ok=True)
            for file_path in CONFIG_FILES:
                local_file = os.path.join(config_dest, os.path.basename(file_path))
                fetch_file(conn, file_path, local_file, args.sudo, args.show)

        print(f"Completed forensic collection for {host}")


if __name__ == "__main__":
    main()
