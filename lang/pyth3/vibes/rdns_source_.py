#!/usr/bin/env python3
"""
Complete Subnet PTR Source Scanner (..beta..)
Automatically scans entire local network and identifies resolution sources
"""

import socket
import ipaddress
import subprocess
import sys
import json
from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path

class SubnetPTRSourceScanner:
    def __init__(self):
        self.results = {}
        self.lock = threading.Lock()
        self.dns_servers = {
            'local_gateway': '192.168.1.1',
            'att_dns1': '68.94.156.1',
            'att_dns2': '68.94.157.1', 
            'google_dns': '8.8.8.8',
            'cloudflare_dns': '1.1.1.1'
        }
    
    def get_local_network(self):
        """Get the local network subnet"""
        try:
            # Get default gateway info on macOS
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
                    cidr = bin(int(netmask, 16)).count('1')
                    return f"{ip}/{cidr}"
        except:
            return "192.168.1.0/24"

    def ping_host(self, ip):
        """Quick ping test"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1000', str(ip)],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def test_resolution_sources(self, ip_str):
        """Test all possible resolution sources for an IP"""
        sources = {}
        
        # 1. Test /etc/hosts
        try:
            with open('/etc/hosts', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ip_str:
                            sources['hosts_file'] = parts[1]
                            break
        except:
            pass
        
        # 2. Test socket.gethostbyaddr()
        try:
            result = socket.gethostbyaddr(ip_str)
            sources['socket'] = result[0]
        except:
            pass
        
        # 3. Test system dig
        try:
            result = subprocess.run(['dig', '-x', ip_str, '+short'],
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and result.stdout.strip():
                sources['dig_system'] = result.stdout.strip().rstrip('.')
        except:
            pass
        
        # 4. Test specific DNS servers
        for name, server in self.dns_servers.items():
            try:
                result = subprocess.run(['dig', f'@{server}', '-x', ip_str, '+short'],
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout.strip():
                    sources[f'dig_{name}'] = result.stdout.strip().rstrip('.')
            except:
                continue
        
        # 5. Test mDNS (macOS)
        try:
            result = subprocess.run(['dns-sd', '-G', 'v4', ip_str], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '.local' in line and ip_str in line:
                        hostname = line.split()[-1].rstrip('.')
                        sources['mdns'] = hostname
                        break
        except:
            pass
        
        # 6. Test DNS cache (macOS)
        try:
            result = subprocess.run(['dscacheutil', '-q', 'host', '-a', 'ip_address', ip_str],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.split('\n'):
                    if 'name:' in line:
                        sources['dns_cache'] = line.split('name:')[1].strip()
                        break
        except:
            pass
        
        return sources

    def scan_ip(self, ip):
        """Scan single IP for PTR sources"""
        ip_str = str(ip)
        
        # Quick ping test
        if not self.ping_host(ip):
            return None
        
        # Test all resolution sources
        sources = self.test_resolution_sources(ip_str)
        
        # Only return if we found something
        if sources:
            result = {
                'ip': ip_str,
                'sources': sources,
                'total_sources': len(sources)
            }
            
            with self.lock:
                self.results[ip_str] = result
            
            return result
        
        return None

    def scan_subnet(self):
        """Scan entire subnet"""
        network_str = self.get_local_network()
        print(f"🔍 Scanning PTR Sources for Network: {network_str}")
        print("=" * 80)
        
        try:
            network = ipaddress.IPv4Network(network_str, strict=False)
        except:
            print("❌ Could not determine network range")
            sys.exit(1)
        
        print(f"🎯 Testing {network.num_addresses} addresses for PTR resolution sources...")
        print()
        
        # Scan all hosts
        completed = 0
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.scan_ip, ip): ip for ip in network.hosts()}
            
            for future in futures:
                result = future.result()
                completed += 1
                
                if completed % 20 == 0:
                    print(f"⏳ Progress: {completed}/{len(futures)}", end='\r')
        
        print(f"\n✅ Scan complete! Found {len(self.results)} hosts with PTR resolution")
        return self.results

    def print_results(self):
        """Print comprehensive results table"""
        if not self.results:
            print("❌ No hosts found with PTR resolution")
            return
        
        print("\n" + "=" * 120)
        print("📊 PTR RESOLUTION SOURCE ANALYSIS")
        print("=" * 120)
        
        # Header
        sources_headers = ['hosts', 'socket', 'dig_sys', 'dig_gw', 'dig_att1', 'dig_att2', 'dig_goog', 'dig_cf', 'mdns', 'cache']
        header = f"{'IP Address':<15} {'#Src':<4} "
        for src in sources_headers:
            header += f"{src:<8} "
        header += "Hostname"
        print(header)
        print("-" * 120)
        
        # Sort results by IP
        sorted_results = sorted(self.results.values(), key=lambda x: ipaddress.IPv4Address(x['ip']))
        
        for result in sorted_results:
            ip = result['ip']
            sources = result['sources']
            total_sources = result['total_sources']
            
            # Build source indicator row
            row = f"{ip:<15} {total_sources:<4} "
            
            source_map = {
                'hosts': sources.get('hosts_file', ''),
                'socket': sources.get('socket', ''),
                'dig_sys': sources.get('dig_system', ''),
                'dig_gw': sources.get('dig_local_gateway', ''),
                'dig_att1': sources.get('dig_att_dns1', ''),
                'dig_att2': sources.get('dig_att_dns2', ''),
                'dig_goog': sources.get('dig_google_dns', ''),
                'dig_cf': sources.get('dig_cloudflare_dns', ''),
                'mdns': sources.get('mdns', ''),
                'cache': sources.get('dns_cache', '')
            }
            
            for src_name in sources_headers:
                if source_map[src_name]:
                    row += f"{'✅':<8} "
                else:
                    row += f"{'❌':<8} "
            
            # Primary hostname (prefer socket, then dig_system)
            primary_hostname = sources.get('socket') or sources.get('dig_system') or list(sources.values())[0]
            row += primary_hostname[:40]  # Truncate long hostnames
            
            print(row)
        
        # Summary analysis
        self.print_analysis()

    def print_analysis(self):
        """Print detailed analysis"""
        print("\n" + "=" * 80)
        print("📈 RESOLUTION ANALYSIS")
        print("=" * 80)
        
        total_hosts = len(self.results)
        source_counts = {}
        
        # Count each source type
        for result in self.results.values():
            for source_name in result['sources'].keys():
                source_counts[source_name] = source_counts.get(source_name, 0) + 1
        
        print(f"Total hosts with PTR: {total_hosts}")
        print("\nResolution by source:")
        for source, count in sorted(source_counts.items()):
            percentage = (count / total_hosts) * 100
            print(f"  {source:<20}: {count:>3} hosts ({percentage:>5.1f}%)")
        
        # Find unique resolution patterns
        print(f"\n🔍 Unique Resolution Patterns:")
        
        socket_only = []
        dig_only = []
        multi_source = []
        
        for result in self.results.values():
            sources = result['sources']
            has_socket = 'socket' in sources
            has_dig = any(k.startswith('dig_') for k in sources.keys())
            
            if has_socket and not has_dig:
                socket_only.append(result)
            elif has_dig and not has_socket:
                dig_only.append(result)
            elif len(sources) > 2:
                multi_source.append(result)
        
        if socket_only:
            print(f"\n🔌 Socket-only resolution ({len(socket_only)} hosts):")
            for result in socket_only[:5]:  # Show first 5
                print(f"  {result['ip']} -> {result['sources']['socket']}")
        
        if dig_only:
            print(f"\n🛠  Dig-only resolution ({len(dig_only)} hosts):")
            for result in dig_only[:5]:
                dig_source = next(k for k in result['sources'].keys() if k.startswith('dig_'))
                print(f"  {result['ip']} -> {result['sources'][dig_source]}")
        
        if multi_source:
            print(f"\n🌐 Multi-source resolution ({len(multi_source)} hosts):")
            for result in multi_source[:3]:
                source_list = ', '.join(result['sources'].keys())
                print(f"  {result['ip']} -> {source_list}")

def main():
    scanner = SubnetPTRSourceScanner()
    
    # Run the scan
    results = scanner.scan_subnet()
    
    # Print results
    scanner.print_results()
    
    # Save detailed results
    timestamp = subprocess.run(['date', '+%Y%m%d_%H%M%S'], capture_output=True, text=True).stdout.strip()
    filename = f"ptr_source_scan_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {filename}")

if __name__ == "__main__":
    main()
