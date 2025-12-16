#!/usr/bin/env python3
"""
net_configurator.py

Modernized network automation script using Paramiko.
Designed for IOS / IOS-XE style devices.

Features:
- Python 3 only
- Argparse-driven CLI
- Structured logging
- Safe SSH handling
- Extensible command framework
"""

import argparse
import logging
import time
from typing import Iterable, List

import paramiko


# -------------------------
# Logging
# -------------------------

def setup_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


# -------------------------
# SSH Client Wrapper
# -------------------------

class NetworkSSHClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 10,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.client = paramiko.SSHClient()
        self.shell = None

    def connect(self) -> None:
        logging.info("Connecting to %s", self.host)
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self.shell = self.client.invoke_shell()
        time.sleep(1)
        self._drain()

    def close(self) -> None:
        logging.info("Closing SSH connection")
        if self.client:
            self.client.close()

    def _drain(self) -> str:
        output = ""
        while self.shell.recv_ready():
            output += self.shell.recv(65535).decode(errors="ignore")
        return output

    def send_commands(self, commands: Iterable[str], delay: float = 0.3) -> str:
        output = ""
        for cmd in commands:
            logging.debug("Sending: %s", cmd)
            self.shell.send(cmd + "\n")
            time.sleep(delay)
            output += self._drain()
        return output


# -------------------------
# Configuration Builders
# -------------------------

def build_base_config(loopbacks: List[str]) -> List[str]:
    cmds = [
        "configure terminal",
    ]

    for idx, ip in enumerate(loopbacks):
        cmds.extend([
            f"interface loopback {idx}",
            f"ip address {ip} 255.255.255.255",
        ])

    cmds.extend([
        "router ospf 1",
        "network 0.0.0.0 255.255.255.255 area 0",
    ])

    return cmds


def build_vlan_config(start: int, end: int) -> List[str]:
    cmds = []
    for vlan in range(start, end + 1):
        cmds.extend([
            f"vlan {vlan}",
            f"name Python_VLAN_{vlan}",
        ])
    return cmds


# -------------------------
# Main Logic
# -------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network device configuration via SSH (Paramiko)"
    )

    parser.add_argument("--host", required=True, help="Target device IP/hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")

    parser.add_argument("--vlan-start", type=int, default=2)
    parser.add_argument("--vlan-end", type=int, default=20)

    parser.add_argument(
        "--loopbacks",
        nargs="+",
        default=["1.1.1.1", "2.2.2.2"],
        help="Loopback IP addresses",
    )

    parser.add_argument("-v", "--verbose", action="count", default=0)

    args = parser.parse_args()
    setup_logging(args.verbose)

    ssh = NetworkSSHClient(
        host=args.host,
        username=args.username,
        password=args.password,
    )

    try:
        ssh.connect()

        base_cfg = build_base_config(args.loopbacks)
        vlan_cfg = build_vlan_config(args.vlan_start, args.vlan_end)

        logging.info("Applying base configuration")
        output = ssh.send_commands(base_cfg)

        logging.info(
            "Creating VLANs %d-%d", args.vlan_start, args.vlan_end
        )
        output += ssh.send_commands(vlan_cfg)

        output += ssh.send_commands(["end", "write memory"])

        print("\n====== DEVICE OUTPUT ======\n")
        print(output)

    except Exception as exc:
        logging.error("Configuration failed: %s", exc)
        raise
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
