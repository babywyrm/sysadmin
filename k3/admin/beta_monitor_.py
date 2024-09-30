
import os
import time
import psutil
import logging
import subprocess
from datetime import datetime

# Thresholds for load, memory, and pod CPU/memory usage
MAX_LOAD = 9.0  # System load threshold
MAX_MEMORY_USAGE = 80  # System memory usage threshold (%)
MAX_POD_CPU_USAGE = 80  # Pod CPU usage threshold (%)
MAX_POD_MEMORY_USAGE = 80  # Pod memory usage threshold (%)

# K3s specific configuration
NAMESPACE = 'default'  # Namespace to monitor (set to 'all' to monitor all namespaces)
EXCLUDE_NAMESPACES = ['kube-system', 'kube-public', 'metallb-system']  # Exclude critical system namespaces

# Log file setup
LOG_FILE = '/var/log/k3s_advanced_monitor.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(message)s')


def check_system_load():
    """Check system load."""
    load1, _, _ = os.getloadavg()
    return load1


def check_memory_usage():
    """Check system memory usage."""
    memory_info = psutil.virtual_memory()
    return memory_info.percent


def log_action(action):
    """Log an action."""
    logging.info(f'{action}')


def get_pods():
    """Get list of all pods in the target namespace, excluding system namespaces."""
    try:
        cmd = ['kubectl', 'get', 'pods', '-o', 'name']
        if NAMESPACE != 'all':
            cmd.extend(['-n', NAMESPACE])

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pods = result.stdout.decode().strip().split('\n')
        return [pod for pod in pods if not any(ns in pod for ns in EXCLUDE_NAMESPACES)]
    except Exception as e:
        logging.error(f"Failed to get pods: {str(e)}")
        return []


def get_pod_resources(pod):
    """Get CPU and memory usage for a specific pod using 'kubectl top'."""
    try:
        cmd = ['kubectl', 'top', 'pod', pod.split('/')[-1]]
        if NAMESPACE != 'all':
            cmd.extend(['-n', NAMESPACE])

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode().strip().split('\n')

        if len(output) > 1:
            # Example output: "POD_NAME CPU(%) MEMORY(%)"
            pod_name, cpu_usage, memory_usage = output[1].split()
            return int(cpu_usage[:-1]), int(memory_usage[:-2])  # Strip % and Mi units
        return None, None
    except Exception as e:
        logging.error(f"Failed to get pod resources for {pod}: {str(e)}")
        return None, None


def restart_pod(pod_name):
    """Restart a specific pod by deleting it, allowing its deployment or ReplicaSet to recreate it."""
    try:
        subprocess.run(['kubectl', 'delete', pod_name, '-n', NAMESPACE], check=True)
        log_action(f'Restarted pod {pod_name}')
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to restart pod {pod_name}: {str(e)}")


def restart_all_pods():
    """Restart all non-system pods by performing a rolling restart of deployments."""
    try:
        subprocess.run(['kubectl', 'rollout', 'restart', 'deployment', '-n', NAMESPACE], check=True)
        log_action('Rolled out restart for all deployments')
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to restart all deployments: {str(e)}")


def check_pods():
    """Check resource usage of all pods and restart those exceeding thresholds."""
    pods = get_pods()
    for pod in pods:
        cpu_usage, memory_usage = get_pod_resources(pod)
        if cpu_usage is None or memory_usage is None:
            continue  # Skip if we couldn't retrieve the resource usage

        log_action(f"{pod} CPU: {cpu_usage}%, Memory: {memory_usage}%")

        if cpu_usage > MAX_POD_CPU_USAGE or memory_usage > MAX_POD_MEMORY_USAGE:
            log_action(f"{pod} exceeds resource limits (CPU: {cpu_usage}%, Memory: {memory_usage}%). Restarting...")
            restart_pod(pod)


def manage_k3s_cluster():
    """Monitor system load, memory, and pod resource usage, and restart pods if needed."""
    while True:
        current_load = check_system_load()
        current_memory_usage = check_memory_usage()

        logging.info(f"Current Load: {current_load}, Memory Usage: {current_memory_usage}%")

        if current_load > MAX_LOAD or current_memory_usage > MAX_MEMORY_USAGE:
            log_action(f"High system load or memory pressure detected (Load: {current_load}, Memory: {current_memory_usage}%)")

            # Restart pods if system thresholds exceeded
            restart_all_pods()

        # Check individual pods for resource overuse
        check_pods()

        # Sleep for 5 minutes before the next check
        time.sleep(300)


if __name__ == '__main__':
    manage_k3s_cluster()

##
##
