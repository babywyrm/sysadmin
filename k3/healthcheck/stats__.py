import subprocess
import logging
import os,sys,re
import time

# Configure logging...
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("k3s_monitor.log"),  # Log to a file
        logging.StreamHandler(sys.stdout)         # Also log to console
    ]
)

def run_command(command):
    """Run a shell command and return the output, error, and exit code."""
    try:
        logging.debug(f"Running command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout.strip(), None
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}")
        logging.error(f"Error output: {e.stderr.strip()}")
        return None, e.stderr.strip()

def get_k3s_logs():
    """Get the last 7 entries from K3s logs using journalctl."""
    logging.info("Fetching the last 7 entries from K3s logs...")
    command = ["journalctl", "-u", "k3s", "-n", "7"]  # Get the last 7 entries
    output, error = run_command(command)
    if output:
        print("\n+++ Last 7 K3s Log Entries +++")
        print(output)
        print("-------------------------------")  # Footer
    if error:
        logging.error("Failed to retrieve K3s logs.")

def tail_stern_logs():
    """Tail logs from all pods using stern."""
    logging.info("Starting to tail logs from all namespaces using stern...")
    command = ["stern", "."]  # Tail logs from all pods in all namespaces
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return process

def check_memory_pressure():
    """Check memory pressure on the node."""
    logging.info("Checking memory pressure...")
    command = ["kubectl", "top", "nodes", "--no-headers"]
    output, error = run_command(command)
    if output:
        print("\n+++ Memory Usage on Nodes +++")
        print(output)
        print("-------------------------------")  # Footer
    if error:
        logging.error("Failed to get memory usage on nodes.")

def check_load_average():
    """Check the system load average."""
    logging.info("Checking system load average...")
    with open('/proc/loadavg', 'r') as f:
        load_avg = f.read().strip()
    print("\n+++ System Load Average +++")
    print(load_avg)
    print("-------------------------------")  # Footer

def display_status(sleep_time):
    """Display the current status of the K3s cluster."""
    while True:
        # Get the last 7 K3s log entries
        get_k3s_logs()

        # Check the status of pods in all namespaces
        logging.info("Checking pods in all namespaces...")
        command = ["kubectl", "get", "pods", "--all-namespaces", "-o", "wide"]
        output, error = run_command(command)
        if output:
            print("\n+++ Current Pods Status +++")
            print(output)
            print("-------------------------------")  # Footer
        if error:
            logging.error("Failed to get pods in all namespaces.")

        # Check the status of nodes
        logging.info("Checking nodes in the cluster...")
        command = ["kubectl", "get", "nodes", "-o", "wide"]
        output, error = run_command(command)
        if output:
            print("\n+++ Current Nodes Status +++")
            print(output)
            print("-------------------------------")  # Footer
        if error:
            logging.error("Failed to get nodes in the cluster.")

        # Check memory pressure
        check_memory_pressure()

        # Check load average
        check_load_average()

        # Wait before the next check
        time.sleep(sleep_time)  # Use the provided sleep time

def main():
    """Main function to run the K3s status monitor."""
    # Set default sleep time
    sleep_time = 3  # Default to 3 seconds

    # Check for command-line arguments
    if len(sys.argv) > 1:
        try:
            sleep_time = int(sys.argv[1])  # Get sleep time from command-line argument
            if sleep_time <= 0:
                raise ValueError("Sleep time must be a positive integer.")
        except ValueError as e:
            print(f"Invalid sleep time provided. Using default: {sleep_time} seconds.")
            logging.error(e)

    logging.info("Starting K3s Status Monitor...")

    # Start tailing stern logs in a separate thread
    stern_log_process = tail_stern_logs()

    # Start displaying the status
    try:
        display_status(sleep_time)
    except KeyboardInterrupt:
        logging.info("Stopping K3s Status Monitor...")
        stern_log_process.terminate()
        stern_log_process.wait()
        logging.info("K3s Status Monitor stopped.")

if __name__ == "__main__":
    main()
