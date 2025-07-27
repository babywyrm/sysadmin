#!/usr/bin/env python3

import json
import time
from scapy.all import IP, TCP, UDP, ICMP
from netfilterqueue import NetfilterQueue
from pathlib import Path

RULES_FILE = Path("basic_firewallrules.json")

# Default values
default_config = {
    "ListOfBannedIpAddr": [],
    "ListOfBannedPorts": [],
    "ListOfBannedPrefixes": [],
    "TimeThreshold": 10,
    "PacketThreshold": 100,
    "BlockPingAttacks": True,
}

# Load firewall rules
def load_firewall_config(path: Path) -> dict:
    if not path.exists():
        print(f"[!] Rule file '{path}' not found. Using default rules.")
        return default_config

    try:
        with path.open("r") as f:
            config = json.load(f)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse JSON in '{path}'. Using default rules.")
        return default_config

    validated = default_config.copy()
    if isinstance(config.get("ListOfBannedIpAddr"), list):
        validated["ListOfBannedIpAddr"] = config["ListOfBannedIpAddr"]

    if isinstance(config.get("ListOfBannedPorts"), list):
        validated["ListOfBannedPorts"] = config["ListOfBannedPorts"]

    if isinstance(config.get("ListOfBannedPrefixes"), list):
        validated["ListOfBannedPrefixes"] = config["ListOfBannedPrefixes"]

    if isinstance(config.get("TimeThreshold"), int):
        validated["TimeThreshold"] = config["TimeThreshold"]

    if isinstance(config.get("PacketThreshold"), int):
        validated["PacketThreshold"] = config["PacketThreshold"]

    block_ping = config.get("BlockPingAttacks")
    if isinstance(block_ping, bool):
        validated["BlockPingAttacks"] = block_ping
    elif isinstance(block_ping, str):
        if block_ping.lower() == "true":
            validated["BlockPingAttacks"] = True
        elif block_ping.lower() == "false":
            validated["BlockPingAttacks"] = False

    return validated


# Track pings by IP
DictOfPackets = {}

# Load config
config = load_firewall_config(RULES_FILE)

def firewall(pkt):
    sca = IP(pkt.get_payload())

    # IP check
    if sca.src in config["ListOfBannedIpAddr"]:
        print(f"[DROP] Banned IP: {sca.src}")
        pkt.drop()
        return

    # TCP/UDP port checks
    for proto in [TCP, UDP]:
        if sca.haslayer(proto):
            dport = sca.getlayer(proto).dport
            if dport in config["ListOfBannedPorts"]:
                print(f"[DROP] Blocked port {dport} from {sca.src}")
                pkt.drop()
                return

    # IP prefix check
    for prefix in config["ListOfBannedPrefixes"]:
        if sca.src.startswith(prefix):
            print(f"[DROP] Banned prefix {prefix} matched for {sca.src}")
            pkt.drop()
            return

    # ICMP Ping flood check
    if config["BlockPingAttacks"] and sca.haslayer(ICMP):
        icmp = sca.getlayer(ICMP)
        if icmp.code == 0:
            now = time.time()
            pkt_times = DictOfPackets.get(sca.src, [])
            pkt_times = [t for t in pkt_times if now - t <= config["TimeThreshold"]]

            if len(pkt_times) >= config["PacketThreshold"]:
                print(f"[DROP] Ping flood detected from {sca.src}")
                pkt.drop()
                return
            pkt_times.append(now)
            DictOfPackets[sca.src] = pkt_times

    # Accept everything else
    pkt.accept()


def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, firewall)

    try:
        print("[*] Starting firewall...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[!] Caught interrupt. Exiting cleanly.")
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
