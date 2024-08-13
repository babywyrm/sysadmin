import os,sys,re
import subprocess
import time
import signal

##
##

# Function to start Falco
def start_falco():
    falco_command = [
        "sudo", "falco", 
        "-r", "/etc/falco/falco_rules.yaml",
        "-o", "json_output=true",
        "-o", "json_include_output_property=true",
        "-o", "json_include_tags_property=true",
        "-o", "json_include_priority_property=true",
        "-o", "json_include_rule_property=true",
        "-o", "json_include_time_property=true",
        "-o", "json_include_host_info=true",
        "-o", "json_include_container_info=true",
        "-o", "json_include_k8s_info=true",
        "-o", "json_include_event_property=true"
    ]
    # Log both stdout and stderr to the same file for debugging purposes
    falco_proc = subprocess.Popen(falco_command, stdout=open('falco_log.json', 'w'), stderr=subprocess.STDOUT)
    return falco_proc

# Function to stop Falco
def stop_falco(falco_proc):
    os.kill(falco_proc.pid, signal.SIGTERM)
    falco_proc.wait()

# Function to run the container
def run_container():
    container_command = [
        "docker", "run", "-d", "--name", "vulnerable-container",
        "-p", "8080:8080", "vulnerable-app"
    ]
    subprocess.run(container_command, check=True)

# Function to stop and remove the container
def stop_container():
    subprocess.run(["docker", "stop", "vulnerable-container"], check=True)
    subprocess.run(["docker", "rm", "vulnerable-container"], check=True)

# Function to tail Falco logs
def tail_falco_logs():
    with subprocess.Popen(['tail', '-f', 'falco_log.json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as tail_proc:
        try:
            for line in tail_proc.stdout:
                print(line.decode(), end='')
        except KeyboardInterrupt:
            tail_proc.terminate()

# Start Falco in the background
falco_proc = start_falco()

# Run the vulnerable container
run_container()

# Tail the Falco logs while the container is running
try:
    tail_falco_logs()
finally:
    # Ensure that Falco and the container are stopped even if the script is interrupted
    stop_falco(falco_proc)
    stop_container()

# Output the log file message
print("\nFalco logs have been saved to falco_log.json")

##
##
