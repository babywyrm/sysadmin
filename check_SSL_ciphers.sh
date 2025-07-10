#!/usr/bin/env python3

import argparse
import subprocess
import shlex
import sys

def get_openssl_version():
    try:
        output = subprocess.check_output(["openssl", "version"], text=True).strip()
        return output
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] Error getting OpenSSL version: {e}")

def get_ciphers():
    try:
        output = subprocess.check_output(["openssl", "ciphers", "ALL:eNULL"], text=True)
        return output.strip().split(':')
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] Error fetching cipher list: {e}")

def test_cipher(server, port, cipher, servername=None):
    base_cmd = f"openssl s_client -connect {server}:{port} -cipher {cipher}"
    if servername:
        base_cmd += f" -servername {servername}"
    try:
        result = subprocess.run(
            shlex.split(base_cmd),
            input="",
            capture_output=True,
            text=True,
            timeout=5
        )
        stdout = result.stdout
        if cipher in stdout:
            return "YES"
        elif ":error:" in stdout:
            return f"NO ({stdout.split(':')[-1].strip()})"
        else:
            return "UNKNOWN"
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR ({str(e)})"

def main():
    parser = argparse.ArgumentParser(
        description="Test TLS ciphers supported by a remote server."
    )
    parser.add_argument("-H", "--host", default="localhost", help="Target server IP/hostname (default: localhost)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target server port (default: 443)")
    parser.add_argument("-s", "--servername", help="Optional SNI server name")
    args = parser.parse_args()

    print(f"[+] OpenSSL Version: {get_openssl_version()}")
    print(f"[+] Testing ciphers on {args.host}:{args.port}\n")

    for cipher in get_ciphers():
        print(f"[*] Testing {cipher:<30}", end="")
        result = test_cipher(args.host, args.port, cipher, args.servername)
        print(result)

if __name__ == "__main__":
    main()
##
