#!/bin/bash

# Thresholds
MAX_LOAD=9.0  # System load threshold
MAX_MEMORY_USAGE=80  # System memory usage threshold (%)
MAX_POD_CPU_USAGE=80  # Pod CPU usage threshold (%)
MAX_POD_MEMORY_USAGE=80  # Pod memory usage threshold (%)

# K3s-specific configuration
NAMESPACE="default"  # Namespace to monitor (set to "all" to monitor all namespaces)
EXCLUDE_NAMESPACES=("kube-system" "kube-public" "metallb-system")  # Exclude critical system namespaces

# Log file setup
LOG_FILE="/var/log/k3s_advanced_monitor.log"

# Function to log messages
log_action() {
  echo "$(date): $1" >> $LOG_FILE
}

# Check system load
check_system_load() {
  load1=$(awk '{print $1}' /proc/loadavg)
  echo $load1
}

# Check system memory usage
check_memory_usage() {
  memory_usage=$(free | awk '/Mem/ {printf "%.0f", $3/$2 * 100.0}')
  echo $memory_usage
}

# Get all pods in the target namespace, excluding system namespaces
get_pods() {
  if [[ "$NAMESPACE" == "all" ]]; then
    pods=$(kubectl get pods --all-namespaces --no-headers -o custom-columns=":metadata.namespace,:metadata.name")
  else
    pods=$(kubectl get pods -n "$NAMESPACE" --no-headers -o custom-columns=":metadata.name")
  fi

  # Filter out system namespaces
  for ns in "${EXCLUDE_NAMESPACES[@]}"; do
    pods=$(echo "$pods" | grep -v "$ns")
  done

  echo "$pods"
}

# Get pod CPU and memory usage using 'kubectl top'
get_pod_resources() {
  pod_name=$1
  pod_resources=$(kubectl top pod "$pod_name" -n "$NAMESPACE" --no-headers 2>/dev/null)

  if [[ -z "$pod_resources" ]]; then
    echo "N/A N/A"
  else
    cpu_usage=$(echo "$pod_resources" | awk '{print $2}' | tr -d 'm')
    memory_usage=$(echo "$pod_resources" | awk '{print $3}' | tr -d 'Mi')
    echo "$cpu_usage $memory_usage"
  fi
}

# Restart a specific pod by deleting it, allowing its deployment to recreate it
restart_pod() {
  pod_name=$1
  kubectl delete pod "$pod_name" -n "$NAMESPACE" --grace-period=30 --wait=true
  log_action "Restarted pod $pod_name"
}

# Restart all non-system pods by performing a rolling restart of deployments
restart_all_pods() {
  kubectl rollout restart deployment -n "$NAMESPACE"
  log_action "Rolled out restart for all deployments in $NAMESPACE"
}

# Check resource usage of all pods and restart those exceeding thresholds
check_pods() {
  pods=$(get_pods)

  for pod in $pods; do
    pod_resources=$(get_pod_resources "$pod")
    cpu_usage=$(echo $pod_resources | awk '{print $1}')
    memory_usage=$(echo $pod_resources | awk '{print $2}')

    log_action "$pod CPU: ${cpu_usage:-N/A}, Memory: ${memory_usage:-N/A}"

    if [[ "$cpu_usage" -gt $MAX_POD_CPU_USAGE || "$memory_usage" -gt $MAX_POD_MEMORY_USAGE ]]; then
      log_action "$pod exceeds resource limits (CPU: $cpu_usage%, Memory: $memory_usage%). Restarting..."
      restart_pod "$pod"
    fi
  done
}

# Main function to monitor K3s system and restart pods as needed
manage_k3s_cluster() {
  while true; do
    current_load=$(check_system_load)
    current_memory_usage=$(check_memory_usage)

    log_action "Current Load: $current_load, Memory Usage: $current_memory_usage%"

    if (( $(echo "$current_load > $MAX_LOAD" | bc -l) )) || [[ "$current_memory_usage" -gt $MAX_MEMORY_USAGE ]]; then
      log_action "High system load or memory pressure detected (Load: $current_load, Memory: $current_memory_usage%)"
      restart_all_pods
    fi

    # Check individual pods for resource overuse
    check_pods

    # Sleep for 5 minutes before the next check
    sleep 300
  done
}

manage_k3s_cluster

##
##
