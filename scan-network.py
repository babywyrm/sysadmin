#!/usr/bin/env python3
"""
Network Scanner - Red Team & CTF Edition
Author: total absolute randoms lol
License: Apache 2.0
Version: 2.2 (macOS Compatible)
"""

import argparse
import json
import csv
import sys
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import shutil
import re
import platform

# Terminal colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'

# Detect OS
OS_TYPE = platform.system()
IS_MACOS = OS_TYPE == 'Darwin'
IS_LINUX = OS_TYPE == 'Linux'

# Built-in examples and presets
class ScanPresets:
    """Common scanning scenarios for CTFs and pentesting."""
    
    PRESETS = {
        'quick': {
            'name': 'Quick Discovery',
            'desc': 'Fast host discovery (no port scan)',
            'type': 'ping',
            'use_case': 'Initial network reconnaissance'
        },
        'ssh': {
            'name': 'SSH Discovery & Enumeration',
            'desc': 'Find SSH servers and grab banners (ports 22, 2222, 2022)',
            'type': 'ssh',
            'ports': '22,2022,2222',
            'scripts': 'ssh-hostkey,ssh-auth-methods,ssh2-enum-algos',
            'use_case': 'Locate SSH servers and enumerate authentication methods'
        },
        'webapp': {
            'name': 'Web Application Scan',
            'desc': 'Scan common web ports (80, 443, 8000, 8080, 8443)',
            'type': 'tcp',
            'ports': '80,443,8000,8080,8443,3000,5000,9090',
            'use_case': 'Finding web servers and applications'
        },
        'ctf': {
            'name': 'CTF Box Scan',
            'desc': 'Common CTF ports and services',
            'type': 'tcp',
            'ports': '21,22,23,25,80,110,139,143,443,445,3306,3389,8080',
            'use_case': 'HackTheBox, TryHackMe, CTF competitions'
        },
        'smb': {
            'name': 'SMB/NetBIOS Scan',
            'desc': 'Windows file sharing and NetBIOS',
            'type': 'tcp',
            'ports': '139,445,137,138',
            'scripts': 'smb-os-discovery,smb-protocols',
            'use_case': 'Windows network enumeration'
        },
        'db': {
            'name': 'Database Scan',
            'desc': 'Common database ports',
            'type': 'tcp',
            'ports': '1433,3306,5432,27017,6379,9200,5984',
            'use_case': 'Finding database servers'
        },
        'remote': {
            'name': 'Remote Access Scan',
            'desc': 'RDP, VNC, SSH, Telnet',
            'type': 'tcp',
            'ports': '22,23,3389,5900,5901,5902',
            'use_case': 'Finding remote access services'
        },
        'sneaky': {
            'name': 'Stealth Scan',
            'desc': 'Low-profile reconnaissance',
            'type': 'stealth',
            'use_case': 'Avoiding IDS/IPS detection'
        },
        'full': {
            'name': 'Full Enumeration',
            'desc': 'Comprehensive scan with OS/service detection',
            'type': 'full',
            'use_case': 'Deep reconnaissance of known targets'
        }
    }

    @classmethod
    def list_presets(cls):
        """Display all available presets."""
        print(f"\n{Colors.CYAN}{Colors.BOLD}Available Scan Presets:{Colors.NC}\n")
        
        for key, preset in cls.PRESETS.items():
            print(f"{Colors.GREEN}[{key}]{Colors.NC} {preset['name']}")
            print(f"  Description: {preset['desc']}")
            print(f"  Scan Type:   {preset['type']}")
            if 'ports' in preset:
                print(f"  Ports:       {preset['ports']}")
            if 'scripts' in preset:
                print(f"  NSE Scripts: {preset['scripts']}")
            print(f"  Use Case:    {Colors.YELLOW}{preset['use_case']}{Colors.NC}")
            print()

    @classmethod
    def get_preset(cls, name: str) -> Optional[Dict]:
        """Get preset configuration by name."""
        return cls.PRESETS.get(name.lower())


class Examples:
    """Built-in usage examples."""
    
    @classmethod
    def get_example_command(cls, base_cmd: str) -> str:
        """Adjust example command based on OS."""
        if IS_MACOS:
            return base_cmd.replace('python3 scanner.py', './scanner.py')
        return base_cmd
    
    SCENARIOS = [
        {
            'title': 'Home Network Discovery',
            'command': 'python3 scanner.py -n 192.168.1.0/24 -t ping',
            'description': 'Find all devices on your home network',
            'output': 'Quick list of active IPs and MAC addresses'
        },
        {
            'title': 'SSH Server Hunt',
            'command': 'python3 scanner.py -n 10.10.0.0/16 --preset ssh',
            'description': 'Find all SSH servers across network with banner grabbing',
            'output': 'List of SSH servers with version info and supported auth methods'
        },
        {
            'title': 'SSH Single Target Deep Dive',
            'command': 'python3 scanner.py -n 10.10.10.5/32 --preset ssh -v',
            'description': 'Detailed SSH enumeration of specific host',
            'output': 'SSH keys, algorithms, auth methods, and version details'
        },
        {
            'title': 'CTF Box Enumeration',
            'command': 'python3 scanner.py -n 10.10.10.5/32 --preset ctf -v',
            'description': 'Scan a single CTF machine for common services',
            'output': 'Detailed service information on common CTF ports'
        },
        {
            'title': 'Web Server Discovery',
            'command': 'python3 scanner.py -n 172.16.0.0/16 --preset webapp -o both',
            'description': 'Find all web servers in a large network',
            'output': 'JSON and CSV files with web service locations'
        },
        {
            'title': 'Remote Access Audit',
            'command': 'python3 scanner.py -n 192.168.0.0/24 --preset remote',
            'description': 'Find RDP, SSH, VNC, and Telnet services',
            'output': 'All remote access points in the network'
        },
        {
            'title': 'Stealth Reconnaissance',
            'command': 'python3 scanner.py -n 10.0.0.0/24 --preset sneaky',
            'description': 'Low-profile scan to avoid detection',
            'output': 'Host discovery with minimal network noise'
        },
        {
            'title': 'Database Hunt',
            'command': 'python3 scanner.py -n 192.168.0.0/16 --preset db',
            'description': 'Locate database servers across subnets',
            'output': 'List of hosts with database ports open'
        },
        {
            'title': 'Custom Port Range',
            'command': 'python3 scanner.py -n 10.10.10.0/24 -t tcp --ports 1-1000',
            'description': 'Scan first 1000 ports on a subnet',
            'output': 'Comprehensive low-port enumeration'
        },
        {
            'title': 'Quick Single Host',
            'command': 'python3 scanner.py -n 192.168.1.100/32 -t tcp',
            'description': 'Fast TCP scan of single machine',
            'output': 'Open ports and services on target host'
        }
    ]

    @classmethod
    def show_examples(cls):
        """Display usage examples."""
        print(f"\n{Colors.CYAN}{Colors.BOLD}Usage Examples:{Colors.NC}\n")
        
        for i, example in enumerate(cls.SCENARIOS, 1):
            cmd = cls.get_example_command(example['command'])
            print(f"{Colors.BOLD}{i}. {example['title']}{Colors.NC}")
            print(f"   {Colors.YELLOW}${Colors.NC} {cmd}")
            print(f"   {example['description']}")
            print(f"   → {Colors.GREEN}{example['output']}{Colors.NC}\n")

    @classmethod
    def show_cheatsheet(cls):
        """Display quick reference cheatsheet."""
        print(f"\n{Colors.CYAN}{Colors.BOLD}Quick Reference Cheatsheet:{Colors.NC}\n")
        
        cheat = [
            ("Basic Scans", [
                ("Ping sweep", "-n 192.168.1.0/24 -t ping"),
                ("TCP scan", "-n 192.168.1.0/24 -t tcp"),
                ("Stealth scan", "-n 192.168.1.0/24 -t stealth"),
            ]),
            ("Presets", [
                ("SSH discovery", "--preset ssh -n 10.0.0.0/24"),
                ("Web apps", "--preset webapp -n 192.168.1.0/24"),
                ("CTF box", "--preset ctf -n 10.10.10.5/32"),
                ("Databases", "--preset db -n 172.16.0.0/16"),
                ("Remote access", "--preset remote -n 192.168.0.0/24"),
            ]),
            ("Output Options", [
                ("JSON output", "-o json -f results"),
                ("CSV output", "-o csv -f results"),
                ("Both formats", "-o both -f results"),
            ]),
            ("Advanced", [
                ("Custom ports", "--ports 80,443,8080"),
                ("Port range", "--ports 1-1000"),
                ("Verbose mode", "-v"),
                ("Non-interactive", "--no-interactive"),
            ])
        ]
        
        for category, commands in cheat:
            print(f"{Colors.BOLD}{category}:{Colors.NC}")
            for desc, cmd in commands:
                print(f"  {desc:20s} → {Colors.YELLOW}{cmd}{Colors.NC}")
            print()


class NetworkScanner:
    REQUIRED_TOOLS = ['nmap']
    SCAN_TYPES = {
        'ping': '-sn -T4',
        'tcp': '-sS -sV -T4 --top-ports 1000',
        'ssh': '-sS -sV -p 22,2022,2222 --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos -T4',
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
        self.custom_ports = args.ports
        self.preset = args.preset
        self.results: List[Dict] = []

    def check_dependencies(self) -> bool:
        """Verify required tools are installed."""
        missing = [
            tool for tool in self.REQUIRED_TOOLS
            if not shutil.which(tool)
        ]
        
        if missing:
            print(f"{Colors.RED}[!] Missing tools: {', '.join(missing)}{Colors.NC}")
            if IS_MACOS:
                print(f"{Colors.YELLOW}[i] Install with: brew install nmap{Colors.NC}")
            else:
                print(f"{Colors.YELLOW}[i] Install: sudo apt install {' '.join(missing)}{Colors.NC}")
            return False
        
        # Check if nmap has proper permissions on macOS
        if IS_MACOS:
            try:
                # Test if we can run nmap with sudo
                subprocess.run(
                    ['sudo', '-n', 'nmap', '--version'],
                    capture_output=True,
                    timeout=2
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print(f"{Colors.YELLOW}[i] Note: You may be prompted for your password to run nmap{Colors.NC}")
        
        return True

    def get_local_networks(self) -> List[str]:
        """Get available local networks (cross-platform)."""
        networks = []
        
        try:
            if IS_MACOS:
                # Use ifconfig on macOS
                result = subprocess.run(
                    ['ifconfig'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                current_interface = None
                for line in result.stdout.split('\n'):
                    # Match interface name
                    if line and not line.startswith('\t'):
                        current_interface = line.split(':')[0]
                    
                    # Match IPv4 address with CIDR
                    if 'inet ' in line and current_interface:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            ip = parts[1]
                            netmask = parts[3]
                            
                            # Convert netmask to CIDR
                            cidr = self._netmask_to_cidr(netmask)
                            if cidr:
                                # Calculate network address
                                network = self._get_network_address(ip, cidr)
                                if network and not network.startswith('127.'):
                                    networks.append(f"{current_interface} {network}/{cidr}")
            
            elif IS_LINUX:
                # Use ip command on Linux
                result = subprocess.run(
                    ['ip', '-o', '-f', 'inet', 'addr', 'show'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 4:
                        networks.append(f"{parts[1]} {parts[3]}")
            
            else:
                print(f"{Colors.YELLOW}[!] Unsupported OS: {OS_TYPE}{Colors.NC}")
            
            return networks
            
        except subprocess.CalledProcessError as e:
            if self.verbose:
                print(f"{Colors.RED}[!] Error getting networks: {e}{Colors.NC}")
            return []

    def _netmask_to_cidr(self, netmask: str) -> Optional[int]:
        """Convert netmask to CIDR notation."""
        try:
            # Remove '0x' prefix if present
            if netmask.startswith('0x'):
                netmask_int = int(netmask, 16)
            else:
                # Convert dotted decimal to integer
                parts = netmask.split('.')
                if len(parts) == 4:
                    netmask_int = sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))
                else:
                    return None
            
            # Count the number of 1 bits
            return bin(netmask_int).count('1')
        except (ValueError, AttributeError):
            return None

    def _get_network_address(self, ip: str, cidr: int) -> Optional[str]:
        """Calculate network address from IP and CIDR."""
        try:
            parts = [int(p) for p in ip.split('.')]
            mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
            
            ip_int = sum(p << (8 * (3 - i)) for i, p in enumerate(parts))
            network_int = ip_int & mask
            
            network_parts = [
                (network_int >> 24) & 0xFF,
                (network_int >> 16) & 0xFF,
                (network_int >> 8) & 0xFF,
                network_int & 0xFF
            ]
            
            return '.'.join(map(str, network_parts))
        except (ValueError, IndexError):
            return None

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
                    # Extract CIDR from selection
                    selected = networks[choice - 1].split()[1]
                    return selected
            except (ValueError, KeyboardInterrupt):
                print(f"\n{Colors.RED}[!] Invalid selection{Colors.NC}")
                return None

    def apply_preset(self):
        """Apply preset configuration if specified."""
        if not self.preset:
            return
        
        preset_config = ScanPresets.get_preset(self.preset)
        if not preset_config:
            print(f"{Colors.RED}[!] Unknown preset: {self.preset}{Colors.NC}")
            print(f"{Colors.YELLOW}[i] Use --list-presets to see available options{Colors.NC}")
            sys.exit(1)
        
        print(f"{Colors.GREEN}[+] Applying preset: {preset_config['name']}{Colors.NC}")
        print(f"    {preset_config['desc']}\n")
        
        self.scan_type = preset_config['type']
        
        # Apply custom ports if specified in preset
        if 'ports' in preset_config and not self.custom_ports:
            self.custom_ports = preset_config['ports']
        
        # Apply NSE scripts if specified
        if 'scripts' in preset_config:
            self.nse_scripts = preset_config['scripts']

    def build_nmap_command(self) -> List[str]:
        """Build nmap command with all options."""
        # Start with base flags
        if self.scan_type in self.SCAN_TYPES:
            flags = self.SCAN_TYPES[self.scan_type].split()
        else:
            flags = ['-sS', '-T4']
        
        # Override ports if custom specified
        if self.custom_ports:
            # Remove any existing port specifications
            flags = [f for f in flags if not f.startswith('-p')]
            flags.extend(['-p', self.custom_ports])
        
        # Add NSE scripts if specified
        if hasattr(self, 'nse_scripts'):
            flags.extend(['--script', self.nse_scripts])
        
        return flags

    def perform_scan(self) -> Optional[str]:
        """Execute nmap scan and return XML output path."""
        flags = self.build_nmap_command()
        temp_xml = f"/tmp/nmap_scan_{datetime.now():%Y%m%d_%H%M%S}.xml"

        print(f"\n{Colors.BLUE}[*] Scan Configuration:{Colors.NC}")
        print(f"    OS:       {Colors.YELLOW}{OS_TYPE}{Colors.NC}")
        print(f"    Network:  {Colors.YELLOW}{self.network}{Colors.NC}")
        print(f"    Type:     {Colors.YELLOW}{self.scan_type}{Colors.NC}")
        if self.custom_ports:
            print(f"    Ports:    {Colors.YELLOW}{self.custom_ports}{Colors.NC}")
        if hasattr(self, 'nse_scripts'):
            print(f"    Scripts:  {Colors.YELLOW}{self.nse_scripts}{Colors.NC}")
        print(f"    Output:   {Colors.YELLOW}{self.logfile}{Colors.NC}\n")
        print(f"{Colors.GREEN}[+] Starting scan...{Colors.NC}")

        cmd = ['sudo', 'nmap'] + flags + ['-oX', temp_xml, self.network]
        
        if self.verbose:
            print(f"{Colors.CYAN}[DEBUG] Command: {' '.join(cmd)}{Colors.NC}\n")
        
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
            if IS_MACOS:
                print(f"{Colors.YELLOW}[i] Make sure you entered your password correctly{Colors.NC}")
            return None

    def parse_xml(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output with SSH-specific data."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = []

            for host in root.findall('.//host[status[@state="up"]]'):
                host_data = {
                    'ip': 'N/A',
                    'mac': 'N/A',
                    'hostname': 'unknown',
                    'ports': [],
                    'services': {},
                    'ssh_info': {}
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

                # Extract ports and services
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_id = port.get('portid')
                            host_data['ports'].append(port_id)
                            
                            # Extract service info
                            service = port.find('service')
                            if service is not None:
                                service_name = service.get('name', 'unknown')
                                service_product = service.get('product', '')
                                service_version = service.get('version', '')
                                
                                service_info = service_name
                                if service_product:
                                    service_info += f" ({service_product}"
                                    if service_version:
                                        service_info += f" {service_version}"
                                    service_info += ")"
                                
                                host_data['services'][port_id] = service_info
                                
                                # SSH-specific parsing
                                if service_name == 'ssh' or port_id in ['22', '2022', '2222']:
                                    host_data['ssh_info']['port'] = port_id
                                    host_data['ssh_info']['version'] = f"{service_product} {service_version}".strip()
                            
                            # Extract NSE script output (SSH specific)
                            for script in port.findall('script'):
                                script_id = script.get('id', '')
                                script_output = script.get('output', '')
                                
                                if 'ssh' in script_id.lower():
                                    if script_id == 'ssh-hostkey':
                                        host_data['ssh_info']['hostkeys'] = script_output
                                    elif script_id == 'ssh-auth-methods':
                                        # Extract auth methods
                                        auth_methods = re.findall(r'(\w+)', script_output)
                                        host_data['ssh_info']['auth_methods'] = auth_methods
                                    elif script_id == 'ssh2-enum-algos':
                                        host_data['ssh_info']['algorithms'] = script_output

                # Only add hosts with open ports or if it's a ping scan
                if host_data['ports'] or self.scan_type == 'ping':
                    hosts.append(host_data)

            return hosts

        except ET.ParseError as e:
            print(f"{Colors.RED}[!] XML parsing error: {e}{Colors.NC}")
            return []

    def display_results(self, hosts: List[Dict]):
        """Display scan results in terminal with SSH highlighting."""
        if not hosts:
            print(f"{Colors.YELLOW}[!] No live hosts found{Colors.NC}")
            return

        print(f"\n{Colors.GREEN}[+] Live Hosts Detected: {len(hosts)}{Colors.NC}\n")
        
        # Check if this is an SSH-focused scan
        is_ssh_scan = self.scan_type == 'ssh' or (
            self.preset and ScanPresets.get_preset(self.preset).get('type') == 'ssh'
        )
        
        if is_ssh_scan:
            self._display_ssh_results(hosts)
        else:
            self._display_standard_results(hosts)

    def _display_standard_results(self, hosts: List[Dict]):
        """Display standard scan results."""
        header = f"{'IP Address':<18} {'MAC Address':<20} {'Hostname':<25} Ports"
        print(header)
        print("-" * 100)

        for host in hosts:
            ports_str = ','.join(host['ports'][:5]) if host['ports'] else 'N/A'
            if len(host['ports']) > 5:
                ports_str += f" (+{len(host['ports']) - 5} more)"
            
            print(
                f"{host['ip']:<18} {host['mac']:<20} "
                f"{host['hostname']:<25} {ports_str}"
            )
            
            # Show service details if verbose
            if self.verbose and host['services']:
                for port, service in list(host['services'].items())[:3]:
                    print(f"  {'':18} └─ Port {port}: {Colors.CYAN}{service}{Colors.NC}")

    def _display_ssh_results(self, hosts: List[Dict]):
        """Display SSH-focused scan results."""
        print(f"{Colors.CYAN}{'='*80}{Colors.NC}")
        print(f"{Colors.BOLD}SSH Server Discovery Results{Colors.NC}")
        print(f"{Colors.CYAN}{'='*80}{Colors.NC}\n")
        
        ssh_hosts = [h for h in hosts if h.get('ssh_info')]
        
        if not ssh_hosts:
            print(f"{Colors.YELLOW}[!] No SSH servers found{Colors.NC}")
            return
        
        for i, host in enumerate(ssh_hosts, 1):
            ssh_info = host.get('ssh_info', {})
            
            print(f"{Colors.GREEN}[{i}] {host['ip']}{Colors.NC}")
            print(f"    Hostname:      {host['hostname']}")
            if host['mac'] != 'N/A':
                print(f"    MAC Address:   {host['mac']}")
            
            if ssh_info.get('port'):
                print(f"    SSH Port:      {Colors.YELLOW}{ssh_info['port']}{Colors.NC}")
            
            if ssh_info.get('version'):
                print(f"    SSH Version:   {Colors.CYAN}{ssh_info['version']}{Colors.NC}")
            
            if ssh_info.get('auth_methods'):
                methods = ', '.join(ssh_info['auth_methods'])
                print(f"    Auth Methods:  {methods}")
            
            if self.verbose and ssh_info.get('hostkeys'):
                print(f"\n    {Colors.BOLD}Host Keys:{Colors.NC}")
                for line in ssh_info['hostkeys'].split('\n')[:5]:
                    if line.strip():
                        print(f"      {line.strip()}")
            
            print()

    def save_json(self, hosts: List[Dict]):
        """Save results as JSON."""
        output = {
            'scan_time': datetime.now().isoformat(),
            'os': OS_TYPE,
            'network': self.network,
            'scan_type': self.scan_type,
            'preset': self.preset if self.preset else None,
            'total_hosts': len(hosts),
            'hosts': hosts
        }
        
        json_file = f"{self.logfile}.json"
        with open(json_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"{Colors.GREEN}[+] JSON saved to: {json_file}{Colors.NC}")

    def save_csv(self, hosts: List[Dict]):
        """Save results as CSV."""
        csv_file = f"{self.logfile}.csv"
        
        # Determine if SSH info should be included
        has_ssh = any(h.get('ssh_info') for h in hosts)
        
        fieldnames = ['ip', 'mac', 'hostname', 'ports']
        if has_ssh:
            fieldnames.extend(['ssh_port', 'ssh_version', 'ssh_auth_methods'])
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for host in hosts:
                row = {
                    'ip': host['ip'],
                    'mac': host['mac'],
                    'hostname': host['hostname'],
                    'ports': ','.join(host['ports']) if host['ports'] else 'N/A'
                }
                
                if has_ssh and host.get('ssh_info'):
                    ssh = host['ssh_info']
                    row['ssh_port'] = ssh.get('port', 'N/A')
                    row['ssh_version'] = ssh.get('version', 'N/A')
                    row['ssh_auth_methods'] = ','.join(ssh.get('auth_methods', []))
                
                writer.writerow(row)
        
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
        print("║   Network Scanner - Red Team Edition  ║")
        print("╚═══════════════════════════════════════╝")
        print(f"{Colors.NC}")

        if not self.check_dependencies():
            sys.exit(1)

        # Apply preset if specified
        self.apply_preset()

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
        description=f'Network Scanner for Red Teams & CTFs (Running on {OS_TYPE})',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -n 192.168.1.0/24 -t tcp
  %(prog)s -n 10.0.0.0/24 --preset ssh
  %(prog)s -n 172.16.0.0/16 --preset webapp -o both
  %(prog)s --list-presets
  %(prog)s --examples
        """
    )

    # Main arguments
    parser.add_argument(
        '-n', '--network',
        help='Network CIDR to scan (e.g., 192.168.1.0/24)'
    )
    parser.add_argument(
        '-t', '--type',
        choices=['ping', 'tcp', 'ssh', 'stealth', 'full'],
        default='ping',
        help='Scan type (default: ping)'
    )
    parser.add_argument(
        '--preset',
        choices=list(ScanPresets.PRESETS.keys()),
        help='Use predefined scan preset'
    )
    parser.add_argument(
        '--ports',
        help='Custom ports (e.g., 80,443 or 1-1000)'
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

    # Helper arguments
    parser.add_argument(
        '--list-presets',
        action='store_true',
        help='List all available scan presets'
    )
    parser.add_argument(
        '--examples',
        action='store_true',
        help='Show usage examples'
    )
    parser.add_argument(
        '--cheatsheet',
        action='store_true',
        help='Show quick reference cheatsheet'
    )

    args = parser.parse_args()

    # Handle helper commands
    if args.list_presets:
        ScanPresets.list_presets()
        sys.exit(0)
    
    if args.examples:
        Examples.show_examples()
        sys.exit(0)
    
    if args.cheatsheet:
        Examples.show_cheatsheet()
        sys.exit(0)

    # Validate that network is provided (unless in interactive mode)
    if not args.network and not args.interactive:
        parser.print_help()
        print(f"\n{Colors.RED}[!] Network required in non-interactive mode{Colors.NC}")
        print(f"{Colors.YELLOW}[i] Use --examples for usage examples{Colors.NC}")
        sys.exit(1)

    try:
        scanner = NetworkScanner(args)
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.NC}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
