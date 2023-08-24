#!/usr/bin/python3

##
##
##

import yaml, random, string, shutil, subprocess, signal
import os,sys,re

def get_user():
    return os.environ.get("SUDO_USER")

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def check_whitelist(volumes):
    for volume in volumes:
        parts = volume.split(":")
        if len(parts) == 3 and not is_path_inside_whitelist(parts[0]):
            return False
    return True

def check_read_only(volumes):
    for volume in volumes:
        if not volume.endswith(":ro"):
            return False
    return True

def check_no_symlinks(volumes):
    for volume in volumes:
        parts = volume.split(":")
        path = parts[0]
        if os.path.islink(path):
            return False
    return True

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True

def main(filename):

    if not os.path.exists(filename):
        print(f"File not found")
        return False

    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error: {e}")
            return False

        if "services" not in data:
            print("Invalid docker-compose.yml")
            return False

        services = data["services"]

        if not check_no_privileged(services):
            print("Privileged mode is not allowed.")
            return False

        for service, config in services.items():
            if "volumes" in config:
                volumes = config["volumes"]
                if not check_whitelist(volumes) or not check_read_only(volumes):
                    print(f"Service '{service}' is malicious.")
                    return False
                if not check_no_symlinks(volumes):
                    print(f"Service '{service}' contains a symbolic link in the volume, which is not allowed.")
                    return False
    return True

def create_random_temp_dir():
    letters_digits = string.ascii_letters + string.digits
    random_str = ''.join(random.choice(letters_digits) for i in range(6))
    temp_dir = f"/tmp/tmp-{random_str}"
    return temp_dir

def copy_docker_compose_to_temp_dir(filename, temp_dir):
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(filename, os.path.join(temp_dir, "docker-compose.yml"))

def cleanup(temp_dir):
    subprocess.run(["/usr/bin/docker-compose", "down", "--volumes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(temp_dir)

def signal_handler(sig, frame):
    print("\nSIGINT received. Cleaning up...")
    cleanup(temp_dir)
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Use: {sys.argv[0]} <docker-compose.yml>")
        sys.exit(1)

    filename = sys.argv[1]
    if main(filename):
        temp_dir = create_random_temp_dir()
        copy_docker_compose_to_temp_dir(filename, temp_dir)
        os.chdir(temp_dir)

        signal.signal(signal.SIGINT, signal_handler)

        print("Starting services...")
        result = subprocess.run(["/usr/bin/docker-compose", "up", "--build"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Finishing services")

        cleanup(temp_dir)

#######
##
##
