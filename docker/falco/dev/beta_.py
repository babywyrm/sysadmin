import os
import subprocess
import signal
import sys,re

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
    # Start Falco process
    falco_proc = subprocess.Popen(
        falco_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True
    )
    return falco_proc

# Function to stop Falco
def stop_falco(falco_proc):
    os.kill(falco_proc.pid, signal.SIGTERM)
    falco_proc.wait()

# Function to run the container
def run_container():
    container_command = [
        "docker", "run", "-d", "--name", "vulnerable-container",
        "-p", "8080:8080", "vulnerable-container"
    ]
    subprocess.run(container_command, check=True)

# Function to stop and remove the container
def stop_container():
    subprocess.run(["docker", "stop", "vulnerable-container"], check=True)
    subprocess.run(["docker", "rm", "vulnerable-container"], check=True)

# Function to stream Falco logs in real-time to console and file
def stream_falco_logs(falco_proc):
    with open('falco_log.json', 'w') as log_file:
        try:
            while True:
                line = falco_proc.stdout.readline()
                if not line:
                    break
                print(line, end='')  # Print to console
                log_file.write(line)  # Write to file
                log_file.flush()  # Ensure it's written to file immediately
                sys.stdout.flush()  # Flush Python's stdout buffer
        except KeyboardInterrupt:
            pass

# Start Falco in the background
falco_proc = start_falco()

# Run the vulnerable container
run_container()

# Stream Falco logs in real-time while the container is running
try:
    stream_falco_logs(falco_proc)
finally:
    # Ensure that Falco and the container are stopped even if the script is interrupted
    stop_falco(falco_proc)
    stop_container()

# Output the log file message
print("\nFalco logs have been saved to falco_log.json")

##
##
