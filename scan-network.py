#!/usr/bin/env python3
"""
Network Scanner - Red Team & CTF Edition - "beta"
Author: some absolute randoms, tbh
License: Apache 2.0
"""

import argparse
import json
import csv
import sys
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import shutil

# Terminal colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

class NetworkScanner:
    REQUIRED_TOOLS = ['nmap', 'ip']
    SCAN_TYPES = {
        'ping': '-sn -T4',
        'tcp': '-sS -sV -T4 --top-ports 1000',
        'stealth': '-Pn -sS -T2 -f --randomize-hosts',
        'full': '-sS -sV -O -A -T4 --script=default,discovery'
    }

    def __init__(self, args):
        self.network = args.network
        self.scan_type = args.type
        self.output_format = args.output
        self.logfile = args.file or f"scan_{datetime.now():%Y%m%d_%H%M%S}"
        self.interactive = args.interactive
        self.verbose = args.verbose
        self.results: List[Dict] = []

    def check_dependencies(self) -> bool:
        """Verify required tools are installed."""
        missing = [
            tool for tool in self.REQUIRED_TOOLS
            if not shutil.which(tool)
        ]
        
        if missing:
            print(f"{Colors.RED}[!] Missing tools: {', '.join(missing)}{Colors.NC}")
            print(f"{Colors.YELLOW}[i] Install: sudo apt install {' '.join(missing)}{Colors.NC}")
            return False
        return True

    def get_local_networks(self) -> List[str]:
        """Get available local networks."""
        try:
            result = subprocess.run(
                ['ip', '-o', '-f', 'inet', 'addr', 'show'],
                capture_output=True,
                text=True,
                check=True
            )
            networks = []
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    networks.append(f"{parts[1]} {parts[3]}")
            return networks
        except subprocess.CalledProcessError:
            return []

    def choose_network(self) -> Optional[str]:
        """Interactive network selection."""
        networks = self.get_local_networks()
        
        if not networks:
            print(f"{Colors.RED}[!] No network interfaces found{Colors.NC}")
            return None

        print(f"\n{Colors.BLUE}[*] Available Networks:{Colors.NC}\n")
        for idx, net in enumerate(networks, 1):
            print(f"  {idx}. {net}")
        
        while True:
            try:
                choice = int(input(f"\n{Colors.YELLOW}Select network [1-{len(networks)}]: {Colors.NC}"))
                if 1 <= choice <= len(networks):
                    return networks[choice - 1].split()[1]
            except (ValueError, KeyboardInterrupt):
                print(f"\n{Colors.RED}[!] Invalid selection{Colors.NC}")
                return None

    def perform_scan(self) -> Optional[str]:
        """Execute nmap scan and return XML output path."""
        flags = self.SCAN_TYPES.get(self.scan_type, '')
        temp_xml = f"/tmp/nmap_scan_{datetime.now():%Y%m%d_%H%M%S}.xml"

        print(f"\n{Colors.BLUE}[*] Scan Configuration:{Colors.NC}")
        print(f"    Network:  {Colors.YELLOW}{self.network}{Colors.NC}")
        print(f"    Type:     {Colors.YELLOW}{self.scan_type}{Colors.NC}")
        print(f"    Output:   {Colors.YELLOW}{self.logfile}{Colors.NC}\n")
        print(f"{Colors.GREEN}[+] Starting scan...{Colors.NC}")

        cmd = ['sudo', 'nmap'] + flags.split() + ['-oX', temp_xml, self.network]
        
        try:
            if self.verbose:
                subprocess.run(cmd, check=True)
            else:
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True
                )
            return temp_xml
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[!] Scan failed: {e}{Colors.NC}")
            return None

    def parse_xml(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = []

            for host in root.findall('.//host[status[@state="up"]]'):
                host_data = {
                    'ip': 'N/A',
                    'mac': 'N/A',
                    'hostname': 'unknown',
                    'ports': []
                }

                # Extract addresses
                for addr in host.findall('address'):
                    addr_type = addr.get('addrtype')
                    if addr_type == 'ipv4':
                        host_data['ip'] = addr.get('addr')
                    elif addr_type == 'mac':
                        host_data['mac'] = addr.get('addr')

                # Extract hostname
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname = hostnames.find('hostname')
                    if hostname is not None:
                        host_data['hostname'] = hostname.get('name', 'unknown')

                # Extract ports
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port[@protocol="tcp"]'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            host_data['ports'].append(port.get('portid'))

                hosts.append(host_data)

            return hosts

        except ET.ParseError as e:
            print(f"{Colors.RED}[!] XML parsing error: {e}{Colors.NC}")
            return []

    def display_results(self, hosts: List[Dict]):
        """Display scan results in terminal."""
        if not hosts:
            print(f"{Colors.YELLOW}[!] No live hosts found{Colors.NC}")
            return

        print(f"\n{Colors.GREEN}[+] Live Hosts Detected:{Colors.NC}\n")
        
        # Header
        header = f"{'IP Address':<18} {'MAC Address':<20} {'Hostname':<25} Ports"
        print(header)
        print("-" * 90)

        # Results
        for host in hosts:
            ports_str = ','.join(host['ports'][:5]) if host['ports'] else 'N/A'
            print(
                f"{host['ip']:<18} {host['mac']:<20} "
                f"{host['hostname']:<25} {ports_str}"
            )

    def save_json(self, hosts: List[Dict]):
        """Save results as JSON."""
        output = {
            'scan_time': datetime.now().isoformat(),
            'network': self.network,
            'scan_type': self.scan_type,
            'hosts': hosts
        }
        
        json_file = f"{self.logfile}.json"
        with open(json_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"{Colors.GREEN}[+] JSON saved to: {json_file}{Colors.NC}")

    def save_csv(self, hosts: List[Dict]):
        """Save results as CSV."""
        csv_file = f"{self.logfile}.csv"
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=['ip', 'mac', 'hostname', 'ports']
            )
            writer.writeheader()
            
            for host in hosts:
                host['ports'] = ','.join(host['ports']) if host['ports'] else 'N/A'
                writer.writerow(host)
        
        print(f"{Colors.GREEN}[+] CSV saved to: {csv_file}{Colors.NC}")

    def save_results(self, hosts: List[Dict]):
        """Save results in requested format(s)."""
        if self.output_format in ('json', 'both'):
            self.save_json(hosts)
        if self.output_format in ('csv', 'both'):
            self.save_csv(hosts)

    def run(self):
        """Main execution flow."""
        print(f"{Colors.BLUE}")
        print("╔═══════════════════════════════════════╗")
        print("║   Network Scanner - Python Edition   ║")
        print("╚═══════════════════════════════════════╝")
        print(f"{Colors.NC}")

        if not self.check_dependencies():
            sys.exit(1)

        # Get network if not provided
        if not self.network:
            if self.interactive:
                self.network = self.choose_network()
            if not self.network:
                print(f"{Colors.RED}[!] No network specified{Colors.NC}")
                sys.exit(1)

        # Perform scan
        xml_file = self.perform_scan()
        if not xml_file:
            sys.exit(1)

        # Parse and display results
        hosts = self.parse_xml(xml_file)
        self.display_results(hosts)
        self.save_results(hosts)

        # Cleanup
        Path(xml_file).unlink(missing_ok=True)
        
        print(f"\n{Colors.GREEN}[✓] Scan complete!{Colors.NC}")


def main():
    parser = argparse.ArgumentParser(
        description='Network Scanner for Red Teams & CTFs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -n 192.168.1.0/24 -t tcp
  %(prog)s -n 10.0.0.0/24 -t stealth -o both
  %(prog)s --no-interactive -n 172.16.0.0/16 -t ping
        """
    )

    parser.add_argument(
        '-n', '--network',
        help='Network CIDR to scan (e.g., 192.168.1.0/24)'
    )
    parser.add_argument(
        '-t', '--type',
        choices=['ping', 'tcp', 'stealth', 'full'],
        default='ping',
        help='Scan type (default: ping)'
    )
    parser.add_argument(
        '-o', '--output',
        choices=['json', 'csv', 'both'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '-f', '--file',
        help='Output filename (without extension)'
    )
    parser.add_argument(
        '--no-interactive',
        dest='interactive',
        action='store_false',
        help='Disable interactive mode'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    try:
        scanner = NetworkScanner(args)
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.NC}")
        sys.exit(1)


if __name__ == '__main__':
    main()
