import subprocess
import argparse
import shutil
import os,sys,re

##
##

def scan_tls(ip, output_file, debug=False):
    """
    Run nmap with ssl-enum-ciphers to scan TLS versions and ciphers.
    """
    try:
        if debug:
            print(f"DEBUG: Running nmap for {ip}")
        result = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", ip],
            capture_output=True, text=True, check=True
        )
        with open(output_file, "a") as f:
            f.write(f"Results for {ip}:\n")
            f.write(result.stdout)
            f.write("\n" + "="*80 + "\n")
    except subprocess.CalledProcessError as e:
        print(f"Error scanning {ip}: {e}")
        if debug:
            print(f"DEBUG: {e.stderr}")
        with open(output_file, "a") as f:
            f.write(f"Error scanning {ip}: {e}\n")
            f.write("\n" + "="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Scan TLS and ciphers for a list of IPs using nmap.")
    parser.add_argument("input_file", help="File containing a list of IPs or hostnames")
    parser.add_argument("output_file", help="File to store the scan results")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    # Ensure nmap is installed
    if not shutil.which("nmap"):
        print("Error: nmap is not installed. Please install it and try again.")
        return

    # Read IPs and scan each
    with open(args.input_file, "r") as infile:
        ips = [line.strip() for line in infile if line.strip()]
        for ip in ips:
            scan_tls(ip, args.output_file, debug=args.debug)


if __name__ == "__main__":
    main()

##
##
