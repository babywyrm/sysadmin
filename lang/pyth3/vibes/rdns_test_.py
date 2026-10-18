#!/usr/bin/env python3
"""
Local Network Reverse DNS Scanner
Tests PTR resolution across your local subnet
"""

import socket
import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import time

def get_local_network():
    """Get the local network subnet"""
    try:
        # Get default gateway info
        result = subprocess.run(['route', '-n', 'get', 'default'], 
                              capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'interface:' in line:
                interface = line.split(':')[1].strip()
                break
        
        # Get IP of interface
        result = subprocess.run(['ifconfig', interface], 
                              capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and 'netmask' in line:
                parts = line.split()
                ip = parts[1]
                netmask = parts[3]
                # Convert hex netmask to CIDR
                cidr = bin(int(netmask, 16)).count('1')
                return f"{ip}/{cidr}"
    except:
        # Fallback - common private networks
        return "192.168.1.0/24"

def ping_host(ip):
    """Check if host is alive using ping"""
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '1000', str(ip)],
                              capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def reverse_dns_lookup(ip):
    """Attempt reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except:
        return None

def dns_dig_ptr(ip):
    """Use dig for PTR lookup"""
    try:
        result = subprocess.run(['dig', '-x', str(ip), '+short'],
                              capture_output=True, text=True)
        ptr = result.stdout.strip()
        return ptr if ptr else None
    except:
        return None

def scan_host(ip):
    """Comprehensive scan of single host"""
    ip_str = str(ip)
    
    # Test if host is alive
    alive = ping_host(ip)
    if not alive:
        return None
    
    # Get hostname via reverse DNS
    ptr_socket = reverse_dns_lookup(ip)
    ptr_dig = dns_dig_ptr(ip)
    
    # Try to get additional info
    try:
        # Try to connect to common ports to get more info
        ports_open = []
        for port in [22, 80, 443, 445, 139]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_str, port))
            sock.close()
            if result == 0:
                ports_open.append(port)
    except:
        ports_open = []
    
    return {
        'ip': ip_str,
        'alive': alive,
        'ptr_socket': ptr_socket,
        'ptr_dig': ptr_dig,
        'ports_open': ports_open
    }

def main():
    print("🔍 Local Network Reverse DNS Scanner")
    print("=" * 50)
    
    # Get network range
    network_str = get_local_network()
    print(f"📡 Scanning network: {network_str}")
    
    try:
        network = ipaddress.IPv4Network(network_str, strict=False)
    except:
        print("❌ Could not determine network range")
        sys.exit(1)
    
    print(f"🎯 Scanning {network.num_addresses} addresses...")
    print()
    
    # Scan all hosts in parallel
    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in network.hosts()}
        
        for i, future in enumerate(futures):
            if i % 10 == 0:
                print(f"⏳ Progress: {i}/{len(futures)}", end='\r')
            
            result = future.result()
            if result:
                results.append(result)
    
    print("\n" + "=" * 80)
    print("📊 SCAN RESULTS")
    print("=" * 80)
    
    # Print results table
    print(f"{'IP Address':<15} {'Alive':<6} {'Socket PTR':<25} {'Dig PTR':<25} {'Open Ports'}")
    print("-" * 80)
    
    for result in sorted(results, key=lambda x: ipaddress.IPv4Address(x['ip'])):
        ptr_socket = result['ptr_socket'] or 'None'
        ptr_dig = result['ptr_dig'] or 'None'
        ports = ','.join(map(str, result['ports_open'])) or 'None'
        
        print(f"{result['ip']:<15} {'✅':<6} {ptr_socket:<25} {ptr_dig:<25} {ports}")
    
    # Analysis
    print("\n" + "=" * 80)
    print("📈 ANALYSIS")
    print("=" * 80)
    
    total_hosts = len(results)
    socket_resolved = sum(1 for r in results if r['ptr_socket'])
    dig_resolved = sum(1 for r in results if r['ptr_dig'])
    
    print(f"Total active hosts: {total_hosts}")
    print(f"Resolved via socket.gethostbyaddr(): {socket_resolved} ({socket_resolved/total_hosts*100:.1f}%)")
    print(f"Resolved via dig: {dig_resolved} ({dig_resolved/total_hosts*100:.1f}%)")
    
    # Show differences
    socket_only = [r for r in results if r['ptr_socket'] and not r['ptr_dig']]
    dig_only = [r for r in results if r['ptr_dig'] and not r['ptr_socket']]
    
    if socket_only:
        print(f"\n🔍 Resolved by socket only ({len(socket_only)}):")
        for r in socket_only:
            print(f"  {r['ip']} -> {r['ptr_socket']}")
    
    if dig_only:
        print(f"\n🔍 Resolved by dig only ({len(dig_only)}):")
        for r in dig_only:
            print(f"  {r['ip']} -> {r['ptr_dig']}")

if __name__ == "__main__":
    main()
