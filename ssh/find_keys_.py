
##
##

import os,sys,re
import fnmatch
import stat

##
##

def find_ssh_keys(search_path):
    """
    Recursively search for SSH keys in the specified directory.
    
    Parameters:
    search_path (str): The directory path to start the search from.

    Returns:
    list: A list of paths to the found SSH keys.
    """
    ssh_key_patterns = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa.pub', 'id_dsa.pub', 'id_ecdsa.pub', 'id_ed25519.pub']
    ssh_keys = []

    for root, dirs, files in os.walk(search_path):
        for pattern in ssh_key_patterns:
            for filename in fnmatch.filter(files, pattern):
                ssh_keys.append(os.path.join(root, filename))

    return ssh_keys

def analyze_key(key_path):
    """
    Analyze the SSH key file for its type and permissions.
    
    Parameters:
    key_path (str): The path to the SSH key file.

    Returns:
    dict: A dictionary containing details about the SSH key.
    """
    key_info = {
        'path': key_path,
        'type': 'Private Key' if '.pub' not in key_path else 'Public Key',
        'permissions': oct(os.stat(key_path).st_mode)[-3:]
    }

    # Check if the key file has read permissions for others
    if key_info['type'] == 'Private Key' and key_info['permissions'][-1] != '0':
        key_info['sensitivity'] = 'Sensitive (Private key is world-readable!)'
    else:
        key_info['sensitivity'] = 'Normal'

    return key_info

def main():
    """
    Main function to execute the SSH key search and analysis.
    """
    search_path = input("Enter the path to search for SSH keys (default is home directory): ").strip() or os.path.expanduser('~')

    if not os.path.exists(search_path):
        print(f"The path {search_path} does not exist.")
        return

    print(f"Searching for SSH keys in {search_path}...\n")

    ssh_keys = find_ssh_keys(search_path)
    if not ssh_keys:
        print("No SSH keys found.")
        return

    for key in ssh_keys:
        key_info = analyze_key(key)
        print(f"Key Path: {key_info['path']}")
        print(f"Key Type: {key_info['type']}")
        print(f"Permissions: {key_info['permissions']}")
        print(f"Sensitivity: {key_info['sensitivity']}\n")

if __name__ == "__main__":
    main()

##
##
