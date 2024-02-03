#!/usr/bin/env python3

##
##

from fabric import Connection
from io import StringIO
from datetime import datetime
import os
import sys

def get_package_info(connection, filter_string=None):
    # Get a list of package names and versions
    package_info = connection.run('dpkg-query -W -f=\'${package} ${version}\n\'', hide=True).stdout.strip()

    # Display the results
    print("Installed Packages, Versions, and Installation Times:")
    print("----------------------------------------------------")

    for line in package_info.split('\n'):
        package, version = line.split()

        # If a filter string is provided, check if the package matches or starts with the filter string
        if not filter_string or package.startswith(filter_string):
            # Get the installation timestamp from the package status file if it exists
            status_file = f"/var/lib/dpkg/info/{package}.list"

            if connection.run(f'test -e {status_file}', warn=True).ok:
                install_time = connection.run(f'stat -c %Y {status_file}', hide=True).stdout.strip()
                install_date = datetime.utcfromtimestamp(int(install_time)).strftime("%Y-%m-%d %H:%M:%S")

                print(f"{package} {version} installed on {install_date}")
            else:
                print(f"Warning: Unable to retrieve installation time for {package} {version} (status file not found)")

def main():
    # Check if username is provided as a command-line argument
    if len(sys.argv) != 3:
        print("Usage: python3 package_info.py <username> <filter_string>")
        sys.exit(1)

    username = sys.argv[1]
    filter_string = sys.argv[2]

    # Read the list of hosts from the 'hosts' file
    with open('hosts', 'r') as hosts_file:
        hosts = [line.strip() for line in hosts_file]

    # Connect to each host and run the command
    for host in hosts:
        print(f"\nConnecting to {username}@{host}...")
        with Connection(f"{username}@{host}") as connection:
            get_package_info(connection, filter_string)

if __name__ == "__main__":
    main()

##
##
