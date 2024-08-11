import os
import fnmatch
import stat

##
##

def find_ssh_keys(root_dir="/", ssh_dir=".ssh"):
    """
    Search the filesystem for SSH keys, identify their types, and check their permissions.

    :param root_dir: The directory to start searching from (default is the root directory).
    :param ssh_dir: The name of the SSH directory to look for (default is .ssh).
    :return: List of dictionaries containing SSH key details.
    """
    ssh_key_patterns = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa.pub', 'id_dsa.pub', 'id_ecdsa.pub', 'id_ed25519.pub']
    found_keys = []

    for root, dirs, files in os.walk(root_dir):
        if ssh_dir in dirs:
            ssh_path = os.path.join(root, ssh_dir)
            for pattern in ssh_key_patterns:
                for key_file in fnmatch.filter(os.listdir(ssh_path), pattern):
                    key_path = os.path.join(ssh_path, key_file)
                    key_info = get_key_info(key_path)
                    found_keys.append(key_info)

    return found_keys

def get_key_info(key_path):
    """
    Get details about an SSH key including its type, permissions, and sensitivity.

    :param key_path: The full path to the SSH key file.
    :return: Dictionary containing key details.
    """
    key_info = {
        'path': key_path,
        'type': identify_key_type(key_path),
        'permissions': oct(os.stat(key_path).st_mode)[-3:],
        'sensitivity': check_key_sensitivity(key_path),
        'owner': get_file_owner(key_path),
    }
    return key_info

def identify_key_type(key_path):
    """
    Identify the type of an SSH key based on its filename.

    :param key_path: The full path to the SSH key file.
    :return: Type of SSH key.
    """
    if key_path.endswith('.pub'):
        return 'Public Key'
    elif 'rsa' in key_path:
        return 'RSA Private Key'
    elif 'dsa' in key_path:
        return 'DSA Private Key'
    elif 'ecdsa' in key_path:
        return 'ECDSA Private Key'
    elif 'ed25519' in key_path:
        return 'Ed25519 Private Key'
    else:
        return 'Unknown'

def check_key_sensitivity(key_path):
    """
    Check the sensitivity of the SSH key by evaluating its permissions.

    :param key_path: The full path to the SSH key file.
    :return: Sensitivity level of the key.
    """
    st = os.stat(key_path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        return 'High (world/group accessible)'
    else:
        return 'Low (private)'

def get_file_owner(key_path):
    """
    Get the owner of the SSH key file.

    :param key_path: The full path to the SSH key file.
    :return: Username of the owner.
    """
    try:
        import pwd
        stat_info = os.stat(key_path)
        return pwd.getpwuid(stat_info.st_uid).pw_name
    except ImportError:
        return 'Unknown'

def print_key_info(key_info):
    """
    Print the details of an SSH key.

    :param key_info: Dictionary containing SSH key details.
    """
    print(f"Path: {key_info['path']}")
    print(f"Type: {key_info['type']}")
    print(f"Permissions: {key_info['permissions']}")
    print(f"Sensitivity: {key_info['sensitivity']}")
    print(f"Owner: {key_info['owner']}")
    print("")

def main():
    keys = find_ssh_keys()
    if keys:
        print("SSH Keys Found:\n")
        for key in keys:
            print_key_info(key)
    else:
        print("No SSH keys found on the system.")

if __name__ == "__main__":
    main()

##
##
