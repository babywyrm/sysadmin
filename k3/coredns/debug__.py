#!/usr/bin/env python3
"""
coredns_debugger.py - CoreDNS Troubleshooting Helper

Wraps kubectl + stern to make it easier to enable/disable query logging,
stream logs, and analyze common noisy patterns (NXDOMAIN, PTR lookups).
"""

import subprocess
import sys
import argparse
from datetime import datetime


NAMESPACE = "kube-system"
DEPLOYMENT = "coredns"


def run_cmd(cmd: list[str]):
    """Run a shell command and stream output."""
    print(f"[{datetime.now().isoformat()}] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {e}")


def enable_logging():
    """
    Enable the `log` directive in CoreDNS ConfigMap.
    """
    print(">>> Enabling CoreDNS query logging...")
    cmd = ["kubectl", "-n", NAMESPACE, "edit", "configmap", "coredns"]
    print("Opening editor… Add `log` under the .:53 stanza, then save and exit.")
    run_cmd(cmd)
    print("Restarting CoreDNS...")
    run_cmd(["kubectl", "-n", NAMESPACE, "rollout", "restart", f"deployment/{DEPLOYMENT}"])


def disable_logging():
    """
    Disable the `log` directive in CoreDNS ConfigMap.
    """
    print(">>> Disabling CoreDNS query logging...")
    cmd = ["kubectl", "-n", NAMESPACE, "edit", "configmap", "coredns"]
    print("Remove the `log` line, then save and exit.")
    run_cmd(cmd)
    print("Restarting CoreDNS...")
    run_cmd(["kubectl", "-n", NAMESPACE, "rollout", "restart", f"deployment/{DEPLOYMENT}"])


def stern_logs(filter_str=None, since="1s", tail="0"):
    """
    Stream CoreDNS logs using stern.
    """
    cmd = [
        "stern",
        "-n", NAMESPACE,
        "coredns-.*",
        "--timestamps",
        f"--since={since}",
        f"--tail={tail}",
    ]
    if filter_str:
        cmd.extend(["-i", filter_str])

    run_cmd(cmd)


def analyze_logs(filter_str="NXDOMAIN", lines=200):
    """
    Grab last N lines of CoreDNS logs and grep for a pattern (e.g., NXDOMAIN).
    """
    print(f">>> Analyzing last {lines} lines for '{filter_str}'...")
    cmd = [
        "kubectl", "-n", NAMESPACE,
        "logs", f"deploy/{DEPLOYMENT}",
        "--tail", str(lines)
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    grep = subprocess.Popen(["grep", "-i", filter_str], stdin=proc.stdout)
    grep.communicate()


def main():
    parser = argparse.ArgumentParser(description="CoreDNS Debugging Helper")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("enable", help="Enable CoreDNS query logging")
    sub.add_parser("disable", help="Disable CoreDNS query logging")

    stern_parser = sub.add_parser("stern", help="Stream CoreDNS logs with stern")
    stern_parser.add_argument("-f", "--filter", help="Regex filter (e.g., NXDOMAIN)")
    stern_parser.add_argument("--since", default="1s", help="Start logs from this duration ago")
    stern_parser.add_argument("--tail", default="0", help="Tail this many lines at start")

    analyze_parser = sub.add_parser("analyze", help="Analyze CoreDNS logs for patterns")
    analyze_parser.add_argument("-f", "--filter", default="NXDOMAIN", help="Pattern to search for")
    analyze_parser.add_argument("-n", "--lines", type=int, default=200, help="How many lines to fetch")

    args = parser.parse_args()

    if args.command == "enable":
        enable_logging()
    elif args.command == "disable":
        disable_logging()
    elif args.command == "stern":
        stern_logs(args.filter, args.since, args.tail)
    elif args.command == "analyze":
        analyze_logs(args.filter, args.lines)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()


##
##


# Enable CoreDNS query logging
./coredns_debugger.py enable

# Disable query logging
./coredns_debugger.py disable

# Stream live CoreDNS logs (all queries)
./coredns_debugger.py stern

# Stream only NXDOMAINs in real-time
./coredns_debugger.py stern -f NXDOMAIN

# Analyze last 500 lines for PTR lookups
./coredns_debugger.py analyze -f in-addr.arpa -n 500
