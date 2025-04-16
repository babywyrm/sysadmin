#!/usr/bin/env python3
"""
Forensic Collection Script using Fabric - Probably Needs TLC

This script connects to specified hosts via SSH, runs forensic commands,
collects outputs, and saves them locally. It also fetches critical configuration
files from each host. Options include displaying outputs in real time and using sudo.

Usage:
    ./forensic_collect.py [--show] [--sudo]

Arguments:
    --show   Show command results in real time with a 2-second pause between commands.
    --sudo   Run commands and fetch files using sudo.
"""

import os,sys,re
import time
import argparse
from datetime import datetime
from fabric import Connection
from invoke import UnexpectedExit
from typing import Dict

# List your target hosts (hostnames or IP addresses)
HOSTS = [
    "things.edu",
    "host2.example.com",
    # Add additional hosts as needed...
]

# Default SSH user
DEFAULT_USER = "HUMAN"

# Local directory to store forensic collection results
LOCAL_LOGS_DEST = "./___invest"
os.makedirs(LOCAL_LOGS_DEST, exist_ok=True)

# Forensic tasks: dictionary mapping output filenames to the commands to run.
# Commands include headers to clearly delineate the sections in the output.
TASKS: Dict[str, str] = {
    # =========== SESSION & BASIC INFO ===========
    "last.log": "echo '==== SESSION LOGS ===='; last -a",
    "who.log": "echo '==== CURRENT USERS ===='; who",
    "ps_aux.log": "echo '==== RUNNING PROCESSES ===='; ps auxww",
    "netstat.log": "echo '==== SOCKET/NETWORK BINDINGS (ss) ===='; ss -tulnp",
    "lsof_sockets.log": "echo '==== OPEN SOCKETS (lsof) ===='; lsof -i -P -n",

    # =========== SUSPICIOUS PROCESSES ===========
    "suspicious_processes.log": (
        'echo "==== SCANNING FOR PYTHON/GO/RUBY PROCESSES ===="; '
        'ps auxww | egrep -i "python|\\.py|go(|lang)|ruby" || true'
    ),

    # =========== SYSTEMD PERSISTENCE ===========
    "systemd_units_list.log": "echo '==== SYSTEMD SERVICE UNITS ===='; find /etc/systemd/system -type f -name '*.service'",
    "systemd_units_contents.log": (
        "echo '==== SYSTEMD SERVICE CONTENTS ===='; "
        "find /etc/systemd/system -type f -name '*.service' -exec cat {} \\;"
    ),
    "systemd_dropins.log": (
        "echo '==== SYSTEMD DROP-IN FILES ===='; "
        "find /etc/systemd/system -type d -name '*.d' -exec find {} -type f -exec cat {} \\; -print"
    ),

    # =========== SYSTEM & KERNEL LOGS ===========
    "journalctl.log": "echo '==== JOURNALCTL OUTPUT (last 500 lines) ===='; journalctl -n 500 --no-pager",
    "dmesg.log": "echo '==== KERNEL MESSAGES (dmesg) ===='; dmesg | tail -n 200",

    # =========== CRON & STARTUP ===========
    "cronjobs.log": (
        "echo '==== SYSTEM CRON & USER CRON JOBS ===='; "
        "echo 'Contents of /etc/crontab:'; cat /etc/crontab 2>/dev/null; "
        "echo '---- Listing /etc/cron.* directories ----'; "
        "for d in /etc/cron.*; do [ -d \"$d\" ] && { echo 'Directory:' $d; ls -la \"$d\"; }; done; "
        "echo '---- Listing user cron jobs ----'; "
        "for u in $(cut -f1 -d: /etc/passwd); do echo 'Crontab for' $u ':'; crontab -u $u -l 2>/dev/null; done"
    ),
    "startup_scripts.log": (
        "echo '==== STARTUP SCRIPTS & INIT FILES ===='; "
        "echo '/etc/rc.local:'; [ -f /etc/rc.local ] && cat /etc/rc.local || echo '/etc/rc.local not found'; "
        "echo '==== DROP-IN STARTUP FILES IN /etc/systemd/system ===='; "
        "find /etc/systemd/system -type f \\( -iname '*rc*' -o -iname '*init*' \\) -exec ls -la {} \\;"
    ),

    # =========== KERNEL, MEMORY & SOCKETS ===========
    "kernel_modules.log": "echo '==== LOADED KERNEL MODULES ===='; lsmod",
    "meminfo.log": "echo '==== MEMORY INFORMATION (/proc/meminfo) ===='; cat /proc/meminfo",
    "ss_summary.log": "echo '==== SOCKET SUMMARY (ss -s) ===='; ss -s",
    
    # =========== FILESYSTEM & TEMP DIRECTORIES ===========
    "tmp_listing.log": "echo '==== FILES IN /tmp ===='; find /tmp -type f -exec ls -la {} \\;",
    "shm_listing.log": "echo '==== FILES IN /dev/shm ===='; find /dev/shm -type f -exec ls -la {} \\;",

    # =========== USER & CONFIGURATION ===========
    "bash_history.log": (
        'bash -c "echo \'==== BASH HISTORY FILES ====\'; '
        'for f in /home/*/.bash_history /root/.bash_history; do '
        'if [ -f \\"$f\\" ]; then echo \'==== Contents of \\"$f\\" ====\'; cat \\"$f\\"; echo \\"\n\\"; fi; '
        'done"'
    ),
    "integrity_checksums.log": (
        'bash -c "echo \'==== CHECKSUMS FOR IMPORTANT DIRECTORIES (/etc and /usr/bin) ====\'; '
        'for dir in /etc /usr/bin; do echo \'Checksums for $dir:\'; find $dir -type f -exec md5sum {} \\;; done"'
    ),
    "ssh_keys.log": (
        'bash -c "echo \'==== SEARCHING FOR SSH KEYS ====\'; '
        'find /etc/ssh/ /home -type f \\( -name \'id_rsa*\' -o -name \'authorized_keys*\' \\) -ls"'
    ),
    "hidden_files.log": (
        'bash -c "echo \'==== HIDDEN FILES IN USER HOMES ====\'; '
        'find /home -maxdepth 2 -type f -name \".*\" -ls"'
    ),
}


def collect_forensics(conn: Connection, host_dir: str, show: bool, use_sudo: bool) -> None:
    """
    Run forensic commands on the remote host and save outputs locally.

    Args:
        conn (Connection): Active Fabric SSH connection.
        host_dir (str): Local directory path for storing the host's logs.
        show (bool): If True, print output in real time with delays.
        use_sudo (bool): If True, execute commands with sudo privileges.
    """
    for filename, command in TASKS.items():
        print(f"[{conn.host}] Running command: {command}")
        try:
            # Execute the command with or without sudo based on the flag.
            result = conn.sudo(command, hide=not show, warn=True) if use_sudo else conn.run(command, hide=not show, warn=True)
            output = result.stdout.strip()
        except UnexpectedExit as exc:
            output = f"Error running command: {exc}"

        # Compose local file path and save the output.
        local_file = os.path.join(host_dir, filename)
        with open(local_file, "w") as f:
            header = (
                f"# Output of: '{command}'\n"
                f"# Collected from {conn.host} on {datetime.now()}\n\n"
            )
            f.write(header)
            f.write(output)
        if show:
            print(f"[{conn.host}] Output:\n{output}\n")
            time.sleep(2)
        print(f"[{conn.host}] Saved output to {local_file}")


def fetch_file(conn: Connection, remote_path: str, local_path: str, use_sudo: bool, show: bool) -> None:
    """
    Fetch a remote file and store it locally.

    Args:
        conn (Connection): Active Fabric SSH connection.
        remote_path (str): Full path to the remote file.
        local_path (str): Full local path where the file will be stored.
        use_sudo (bool): If True, use 'sudo cat' to fetch file contents.
        show (bool): If True, display output delays.
    """
    try:
        if use_sudo:
            # Fetch file using sudo (reading the file content)
            result = conn.sudo(f"cat {remote_path}", hide=not show, warn=True)
            output = result.stdout
            with open(local_path, "w") as f:
                f.write(output)
            msg = f"Fetched file {remote_path} using sudo to {local_path}"
            print(f"[{conn.host}] {msg}")
        else:
            # Get file directly (Fabric's get method handles file download)
            conn.get(remote_path, local=local_path)
            msg = f"Fetched file {remote_path} to {local_path}"
            print(f"[{conn.host}] {msg}")
        if show:
            time.sleep(2)
    except Exception as e:
        print(f"[{conn.host}] Failed to fetch {remote_path}: {e}")


def main() -> None:
    """Parse command-line arguments and run forensic collection on each host."""
    parser = argparse.ArgumentParser(
        description=("Forensic collection using Fabric with live output, optional sudo, "
                     "and extended memory/kernel/socket inspection.")
    )
    parser.add_argument("--show", action="store_true",
                        help="Show command results in real time with a 2-second pause between steps.")
    parser.add_argument("--sudo", action="store_true",
                        help="Run commands and fetch files via sudo.")
    args = parser.parse_args()

    # Process each host in the HOSTS list.
    for host in HOSTS:
        print(f"Starting forensic collection on: {host}")
        # Create a sanitized local directory name for the host
        safe_host = host.replace(".", "_").replace(":", "_")
        host_dir = os.path.join(LOCAL_LOGS_DEST, safe_host)
        os.makedirs(host_dir, exist_ok=True)

        # Establish SSH connection using the default user and agent forwarding.
        conn = Connection(
            host=host,
            user=DEFAULT_USER,
            forward_agent=True,
            connect_kwargs={
                "allow_agent": True,
                "look_for_keys": True,
            },
        )

        # Collect forensic command outputs
        collect_forensics(conn, host_dir, args.show, args.sudo)

        # Fetch critical configuration files into a dedicated subdirectory.
        config_files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
        config_dest = os.path.join(host_dir, "configs")
        os.makedirs(config_dest, exist_ok=True)
        for file_path in config_files:
            local_file = os.path.join(config_dest, os.path.basename(file_path))
            fetch_file(conn, file_path, local_file, args.sudo, args.show)

        print(f"Completed forensic collection for {host}\n")


if __name__ == "__main__":
    main()

