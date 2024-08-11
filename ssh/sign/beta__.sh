import subprocess
import os,sys,re
from datetime import datetime, timedelta

##
##

def sign_ssh_key(user_pub_key, ca_key, options, lease_time):
    # Convert lease_time to the correct format
    valid_from = datetime.now().strftime('%Y%m%d%H%M%S')
    valid_to = (datetime.now() + timedelta(minutes=lease_time)).strftime('%Y%m%d%H%M%S')
    
    # Construct the ssh-keygen command
    cmd = [
        'ssh-keygen', 
        '-s', ca_key,
        '-I', f"{user_pub_key}-cert",
        '-V', f"{valid_from}:{valid_to}",
        '-n', 'username'
    ]
    
    # Add custom options
    for option, value in options.items():
        cmd += ['-O', f"{option}={value}"]
    
    cmd.append(user_pub_key)
    
    # Execute the command
    try:
        subprocess.run(cmd, check=True)
        print("Key signed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error signing key: {e}", file=sys.stderr)

def main():
    # Example usage
    user_pub_key = '/path/to/user_public_key.pub'
    ca_key = '/path/to/ca_key'
    
    # Options for the signed key
    options = {
        'force-command': '/path/to/command',
        'no-port-forwarding': '',
        'permit-pty': ''
    }
    
    lease_time = 10  # Lease time in minutes
    
    sign_ssh_key(user_pub_key, ca_key, options, lease_time)

if __name__ == "__main__":
    main()
