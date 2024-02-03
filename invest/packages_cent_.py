#!/usr/bin/env python3

##
##

from fabric import Connection
from datetime import datetime
import os
import sys
import re

def get_package_info(connection, filter_string=None):
    # Display the results
    print("Installed Packages, Versions, and Installation Times:")
    print("----------------------------------------------------")

    # Run 'cat /var/log/yum.log*' to get a list of installed packages
    yum_log_output = connection.run('cat /var/log/yum.log*', hide=True).stdout.strip()

    # Dictionary to store installation times for each package
    package_installations = {}

    # Regular expression to extract relevant information from each line
    yum_log_pattern = re.compile(r'^(\w{3} \d{2} \d{2}:\d{2}:\d{2}).* (Installed|Updated): (\S+)-(\S+).*')

    for line in yum_log_output.split('\n'):
        match = yum_log_pattern.match(line)
        if match:
            install_date_str, action, package_name, package_version = match.groups()

            # Combine package name and version
            package_info = f"{package_name}-{package_version}"

            # Check if the package matches the filter string
            if not filter_string or filter_string in package_name:
                install_date = datetime.strptime(install_date_str, "%b %d %H:%M:%S")

                # Append the package installation information to the dictionary
                if package_info not in package_installations:
                    package_installations[package_info] = []

                package_installations[package_info].append(install_date)

    # Display the installation times for each package
    for package_info, install_dates in package_installations.items():
        install_dates.sort(reverse=True)
        print(f"{package_info} {action.lower()} on {install_dates[0]}")

def main():
    # Check if username is provided as a command-line argument
    if len(sys.argv) != 3:
        print("Usage: python3 yum_log.py <username> <filter_string>")
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
            # Retrieve and display package installation times
            get_package_info(connection, filter_string)

if __name__ == "__main__":
    main()

##
##
