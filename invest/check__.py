
##
##

from fabric import Connection, Config
import socket
import os,sys,re

##
##

# Define your list of hosts in a file called "hosts"
with open("hosts", "r") as hostfile:
    hosts = hostfile.read().splitlines()

# List of known legitimate processes to exclude
legitimate_processes = ["fail2ban", "up2date", "unattended-upgrades"]

# Additional rogue processes
rogue_processes = ["admin_panel", "miner", "xmrig", "ngrok", "nginx", "ssh", "netcat", "socat", "telnet", "ncat", "proxychains", "sshpass", "tunnel"]

# Fabric configuration (optional)
config = Config()
config.run.forward_agent = True  # Enable SSH agent forwarding

def check_rogue_processes(c):
    # Check for each rogue process
    for process_name in rogue_processes:
        result = c.run(f"ps aux | grep {process_name} | grep -v grep", warn=True)
        if not result.failed:
            output = result.stdout
            for line in output.splitlines():
                if not any(legit_process in line for legit_process in legitimate_processes):
                    print(f"Host {c.host}: Rogue process {process_name} found!")
                    # You can add an alerting mechanism here, e.g., sending an email or logging.

def check_for_backdoors(c):
    # Check for suspicious SSH authorized keys
    authorized_keys = c.run("cat ~/.ssh/authorized_keys", warn=True)
    if not authorized_keys.failed:
        print(f"Host {c.host}: Suspicious authorized keys found!")

    # Check for common backdoor files or directories
    backdoor_files = ["backdoor", "evil.sh", "malicious.py"]
    for file_name in backdoor_files:
        file_result = c.run(f"find / -type f -name {file_name} 2>/dev/null", warn=True)
        if not file_result.failed:
            print(f"Host {c.host}: Suspicious file {file_name} found!")

    # Check for SSH port forwarding and tunneling
    ssh_processes = c.run("ps aux | grep ssh | grep -v grep", warn=True)
    if not ssh_processes.failed:
        for line in ssh_processes.stdout.splitlines():
            if "L" in line or "D" in line:
                print(f"Host {c.host}: SSH port forwarding detected!")

def check_rogue_tcp_bindings(c):
    # List of non-standard ports to check
    non_standard_ports = [8080, 9999, 12345]  # Add more ports as needed

    for port in non_standard_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((c.host, port))
                print(f"Host {c.host}: Rogue TCP binding found on port {port}")
                # You can add an alerting mechanism here, e.g., sending an email or logging.
        except Exception:
            pass  # No connection on the specified port, which is expected

def main():
    for host in hosts:
        try:
            c = Connection(host, config=config)
            check_rogue_processes(c)
            check_for_backdoors(c)
            check_rogue_tcp_bindings(c)
        except Exception as e:
            print(f"Failed to connect to {host}: {e}")

if __name__ == "__main__":
    main()

##
##
