#!/usr/bin/env python3
"""
NetfilterQueue-based firewall with live rule reloading
"""

import json
import time
import argparse
import threading
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP
from netfilterqueue import NetfilterQueue

RULE_RELOAD_INTERVAL = 10  # seconds

# Embedded demo config
EMBEDDED_RULE_DEMO = {
    "ListOfBannedIpAddr": ["192.168.1.10", "10.0.0.1"],
    "ListOfBannedPorts": [22, 23, 3389],
    "ListOfBannedPrefixes": ["192.168.0.", "172.16."],
    "TimeThreshold": 5,
    "PacketThreshold": 10,
    "BlockPingAttacks": True
}

DictOfPackets = {}
config_lock = threading.Lock()
config = EMBEDDED_RULE_DEMO.copy()


def print_demo_rules():
    print(json.dumps(EMBEDDED_RULE_DEMO, indent=2))


def load_firewall_config(path: Path) -> dict:
    if not path.exists():
        print(f"[!] Rule file '{path}' not found. Using demo/defaults.")
        return EMBEDDED_RULE_DEMO.copy()
    try:
        with path.open("r") as f:
            raw = json.load(f)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse JSON in '{path}'. Using demo/defaults.")
        return EMBEDDED_RULE_DEMO.copy()

    validated = EMBEDDED_RULE_DEMO.copy()
    if isinstance(raw.get("ListOfBannedIpAddr"), list):
        validated["ListOfBannedIpAddr"] = raw["ListOfBannedIpAddr"]
    if isinstance(raw.get("ListOfBannedPorts"), list):
        validated["ListOfBannedPorts"] = raw["ListOfBannedPorts"]
    if isinstance(raw.get("ListOfBannedPrefixes"), list):
        validated["ListOfBannedPrefixes"] = raw["ListOfBannedPrefixes"]
    if isinstance(raw.get("TimeThreshold"), int):
        validated["TimeThreshold"] = raw["TimeThreshold"]
    if isinstance(raw.get("PacketThreshold"), int):
        validated["PacketThreshold"] = raw["PacketThreshold"]
    if isinstance(raw.get("BlockPingAttacks"), bool):
        validated["BlockPingAttacks"] = raw["BlockPingAttacks"]
    elif isinstance(raw.get("BlockPingAttacks"), str):
        val = raw["BlockPingAttacks"].lower()
        validated["BlockPingAttacks"] = val == "true"
    return validated


def reload_config_loop(rules_path: Path):
    global config
    while True:
        new_config = load_firewall_config(rules_path)
        with config_lock:
            config = new_config
        time.sleep(RULE_RELOAD_INTERVAL)


def firewall(pkt):
    global config
    sca = IP(pkt.get_payload())

    with config_lock:
        conf = config.copy()

    if sca.src in conf["ListOfBannedIpAddr"]:
        print(f"[DROP] Banned IP: {sca.src}")
        pkt.drop()
        return

    for proto in [TCP, UDP]:
        if sca.haslayer(proto):
            dport = sca.getlayer(proto).dport
            if dport in conf["ListOfBannedPorts"]:
                print(f"[DROP] Blocked port {dport} from {sca.src}")
                pkt.drop()
                return

    for prefix in conf["ListOfBannedPrefixes"]:
        if sca.src.startswith(prefix):
            print(f"[DROP] Banned prefix {prefix} matched for {sca.src}")
            pkt.drop()
            return

    if conf["BlockPingAttacks"] and sca.haslayer(ICMP):
        icmp = sca.getlayer(ICMP)
        if icmp.code == 0:
            now = time.time()
            pkt_times = DictOfPackets.get(sca.src, [])
            pkt_times = [t for t in pkt_times if now - t <= conf["TimeThreshold"]]

            if len(pkt_times) >= conf["PacketThreshold"]:
                print(f"[DROP] Ping flood from {sca.src}")
                pkt.drop()
                return

            pkt_times.append(now)
            DictOfPackets[sca.src] = pkt_times

    pkt.accept()


def main():
    parser = argparse.ArgumentParser(
        description="Modern NetfilterQueue Firewall with live rule reloads."
    )
    parser.add_argument(
        "--rules", default="basic_firewallrules.json", help="Path to JSON rule file"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Print an example JSON rule file and exit"
    )
    args = parser.parse_args()

    if args.demo:
        print_demo_rules()
        return

    rules_path = Path(args.rules)
    global config
    config = load_firewall_config(rules_path)

    # Launch background rule reloader
    t = threading.Thread(target=reload_config_loop, args=(rules_path,), daemon=True)
    t.start()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, firewall)

    try:
        print(f"[*] Firewall active using rules from '{rules_path}'.")
        print("[*] Live rule reload every", RULE_RELOAD_INTERVAL, "seconds.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[!] Caught interrupt. Exiting.")
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
