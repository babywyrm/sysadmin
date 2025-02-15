#!/usr/bin/env python3

##
## you might want to pyenv, and pray
"""
AD GPO Enumerator using ldap3

This script connects to an Active Directory LDAP server using NTLM authentication,
searches for Group Policy Objects (GPOs) by querying for objects of class
"groupPolicyContainer" under a specified search base, and prints out key details.

Usage:
    python3 enum_gpo.py <target> [--baseDN <baseDN>] [--search-base <searchBase>] [--use-ssl] [--verbose]

    <target> should be in the format:
      domain/username:password@host[:port]

If --baseDN is not provided, it will be derived from the target domain.
The default search base for GPOs is: CN=Policies,CN=System,<baseDN>
"""

import sys
import argparse
import ssl
from ldap3 import Server, Connection, ALL, NTLM, Tls

def custom_parse_credentials(target):
    """
    Parse a target string in the format: domain/username:password@host[:port]
    Returns a tuple: (domain, username, password, host, port)
    If the port is not provided, returns port as None.
    """
    try:
        domain, remainder = target.split('/', 1)
        username, remainder = remainder.split(':', 1)
        password, remainder = remainder.split('@', 1)
        if ':' in remainder:
            host, port = remainder.split(':', 1)
        else:
            host = remainder
            port = None
        return domain, username, password, host, port
    except Exception as e:
        raise Exception("Error parsing target credentials: " + str(e))

def derive_base_dn(domain):
    """
    Derive a default base DN from a domain name.
    For example, darkcorp.htb becomes: DC=darkcorp,DC=htb
    """
    parts = domain.split('.')
    return ','.join(['DC=' + part for part in parts])

def main():
    parser = argparse.ArgumentParser(description="Enumerate GPOs from Active Directory via LDAP (using ldap3).")
    parser.add_argument("target", help="Target in the format domain/username:password@host[:port]")
    parser.add_argument("--baseDN", help="Base DN for the LDAP search (default: derived from target domain)", default=None)
    parser.add_argument("--search-base", help="LDAP search base for GPOs (default: CN=Policies,CN=System,<baseDN>)", default=None)
    parser.add_argument("--use-ssl", action="store_true", help="Use SSL/TLS for the LDAP connection")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Determine default port based on SSL option
    default_port = '636' if args.use_ssl else '389'

    try:
        domain, username, password, host, port = custom_parse_credentials(args.target)
    except Exception as e:
        print(f"[!] Error parsing target credentials: {e}")
        sys.exit(1)
    
    # Use default port if not provided
    if port is None:
        port = default_port

    if args.verbose:
        print(f"[+] Parsed target: domain={domain}, username={username}, host={host}, port={port}")

    # Determine Base DN
    if args.baseDN:
        base_dn = args.baseDN
    else:
        base_dn = derive_base_dn(domain)

    # Determine search base for GPOs
    if args.search_base:
        search_base = args.search_base
    else:
        search_base = f"CN=Policies,CN=System,{base_dn}"

    if args.verbose:
        print(f"[+] Using Base DN: {base_dn}")
        print(f"[+] Using Search Base: {search_base}")

    # Create the LDAP server object.
    if args.use_ssl:
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = Server(host, port=int(port), use_ssl=True, get_info=ALL, tls=tls_config)
    else:
        server = Server(host, port=int(port), use_ssl=False, get_info=ALL)

    # For NTLM authentication, the username should be in the form DOMAIN\username
    user_ntlm = f"{domain.upper()}\\{username}"
    if args.verbose:
        print(f"[+] Connecting to LDAP server at {host}:{port}")
        print(f"[+] Using NTLM user: {user_ntlm}")

    try:
        conn = Connection(server, user=user_ntlm, password=password, authentication=NTLM, auto_bind=True)
    except Exception as e:
        print(f"[!] LDAP bind error: {e}")
        sys.exit(1)

    # Search for GPOs with filter (objectClass=groupPolicyContainer)
    search_filter = "(objectClass=groupPolicyContainer)"
    attributes = ["displayName", "objectGUID", "gPCFileSysPath", "gPCFunctionalityVersion"]
    if args.verbose:
        print(f"[+] Searching for GPOs with filter: {search_filter}")

    try:
        conn.search(search_base, search_filter, attributes=attributes)
    except Exception as e:
        print(f"[!] LDAP search error: {e}")
        sys.exit(1)

    if not conn.entries:
        print("[*] No GPOs found.")
        sys.exit(0)

    # Print the results
    header = "{:<50} {:<40} {:<40} {:<10}".format("Display Name", "GUID", "FileSys Path", "Func Ver")
    print(header)
    print("-" * 140)
    for entry in conn.entries:
        # The objectGUID might be a byte string; convert it to a GUID string if needed.
        try:
            guid = entry.objectGUID.value
        except Exception:
            guid = "N/A"
        try:
            disp = entry.displayName.value
        except Exception:
            disp = "N/A"
        try:
            fs_path = entry.gPCFileSysPath.value
        except Exception:
            fs_path = "N/A"
        try:
            func_ver = entry.gPCFunctionalityVersion.value
        except Exception:
            func_ver = "N/A"
        print("{:<50} {:<40} {:<40} {:<10}".format(disp, guid, fs_path, func_ver))
    
    conn.unbind()

if __name__ == "__main__":
    main()
