#!/usr/bin/env python3

import os,sys,re
import subprocess
import datetime

###
###

# Function to check if the script is run as root
def check_root():
    return os.geteuid() == 0

# Function to create a CA key if running as root
def create_ca_key(ca_key_path):
    if not check_root():
        print("You must be root to create a CA key.")
        sys.exit(1)
    
    if os.path.exists(ca_key_path):
        print(f"CA key already exists at {ca_key_path}")
    else:
        print(f"Creating CA key at {ca_key_path}...")
        subprocess.run(["ssh-keygen", "-f", ca_key_path, "-t", "rsa", "-b", "4096", "-N", ""])
        print("CA key created successfully.")

# Function to sign a public key with the CA key
def sign_public_key(ca_key_path, pub_key_path, options, validity):
    valid_until = (datetime.datetime.now() + datetime.timedelta(hours=validity)).strftime('%Y-%m-%dT%H:%M:%S')
    
    sign_command = [
        "ssh-keygen",
        "-s", ca_key_path,
        "-I", "user-key",
        "-n", options.get("principals", "user"),
        "-V", f"+{validity}h",
        "-z", "1",
        pub_key_path
    ]
    
    if "force_command" in options:
        sign_command += ["-O", f"force-command={options['force_command']}"]
    
    if "source_address" in options:
        sign_command += ["-O", f"source-address={options['source_address']}"]
    
    print(f"Signing the key {pub_key_path} with CA key {ca_key_path}...")
    subprocess.run(sign_command)
    print("Public key signed successfully.")

# Function to get user input for signing options
def get_signing_options():
    options = {}
    
    principals = input("Enter comma-separated list of principals (usernames) or leave empty for default 'user': ")
    if principals:
        options["principals"] = principals
    
    force_command = input("Enter a forced command to run when the key is used (optional): ")
    if force_command:
        options["force_command"] = force_command
    
    source_address = input("Enter a source address (CIDR) restriction or leave empty for no restriction: ")
    if source_address:
        options["source_address"] = source_address
    
    validity = int(input("Enter the validity period for the key in hours (default 24): ") or "24")
    
    return options, validity

def main():
    ca_key_path = "/etc/ssh/ssh_ca"
    
    if check_root():
        create_ca = input("Do you want to create a new CA key? (y/n): ").strip().lower() == 'y'
        if create_ca:
            create_ca_key(ca_key_path)
    
    pub_key_path = input("Enter the path to the public key to sign: ").strip()
    
    if not os.path.exists(pub_key_path):
        print(f"Public key {pub_key_path} does not exist.")
        sys.exit(1)
    
    options, validity = get_signing_options()
    sign_public_key(ca_key_path, pub_key_path, options, validity)

if __name__ == "__main__":
    main()

###
###
