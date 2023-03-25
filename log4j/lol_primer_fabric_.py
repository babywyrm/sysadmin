from fabric import Connection
import os
import json

##
## this is so much fun
## lol
## add google log4j repo logic
## clean it up
## put it somewhere nice
## and, peace
##

# Replace these with your own values
production_servers = ['prod-server-1.example.com', 'prod-server-2.example.com']
staging_servers = ['staging-server-1.example.com', 'staging-server-2.example.com']
local_output_path = '/path/to/local/output.json'

# Define a Fabric task to check for log4j vulnerabilities
def check_log4j_vulnerabilities(c):
    # Run a command to find all JAR files on the server
    jar_files = c.run('find / -type f -name "*.jar"', hide=True).stdout.splitlines()

    # Loop through each JAR file and check for log4j vulnerabilities
    findings = []
    for jar_file in jar_files:
        command = f'jar -tvf {jar_file} | grep "log4j"'
        result = c.run(command, hide=True)
        if result.stdout:
            findings.append({
                'server': c.host,
                'file': jar_file,
                'vulnerability': 'log4j'
            })

    return findings

# Define a Fabric task to check for log4j vulnerabilities on a list of servers
def check_log4j_vulnerabilities_on_servers(servers):
    # Create a connection to each server and check for log4j vulnerabilities
    findings = []
    for server in servers:
        with Connection(server) as c:
            findings += check_log4j_vulnerabilities(c)

    # Save the findings to a local JSON file
    with open(local_output_path, 'w') as f:
        json.dump(findings, f, indent=4)

    print(f"Log4j vulnerabilities check complete. Findings saved to {local_output_path}.")

# Call the check_log4j_vulnerabilities_on_servers function for both production and staging servers
check_log4j_vulnerabilities_on_servers(production_servers)
check_log4j_vulnerabilities_on_servers(staging_servers)


##
##

