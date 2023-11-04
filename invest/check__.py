!#/usr/bin/python3

import os,sys,re
from fabric import Connection, Config

##
##

# Define your list of hosts in a file called "hosts"
with open("hosts", "r") as hostfile:
    hosts = hostfile.read().splitlines()

# Fabric configuration (optional)
config = Config()
config.run.forward_agent = True  # Enable SSH agent forwarding

def check_rogue_processes(c):
    # List of rogue process names to check
    rogue_processes = ["bitcoin", "ngrok", "nginx"]

    # Check for each rogue process
    for process_name in rogue_processes:
        result = c.run(f"ps aux | grep {process_name} | grep -v grep", warn=True)
        if not result.failed:
            print(f"Host {c.host}: Rogue process {process_name} found!")
            # You can add an alerting mechanism here, e.g., sending an email or logging.

def check_for_backdoors(c):
    # Implement checks for backdoors here
    pass

def main():
    for host in hosts:
        try:
            c = Connection(host, config=config)
            check_rogue_processes(c)
            check_for_backdoors(c)
        except Exception as e:
            print(f"Failed to connect to {host}: {e}")

if __name__ == "__main__":
    main()

##
##
