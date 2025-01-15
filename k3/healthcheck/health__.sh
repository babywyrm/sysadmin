#!/bin/bash

# Configuration
LOAD_THRESHOLD=5.0  # Set your load average threshold
KUBECTL_CMD="/usr/local/bin/kubectl"  # Path to kubectl
LOG_OUTPUT="/var/log/k3s_monitor.log"  # Log file for monitoring script
CHECK_INTERVAL=60  # Check interval in seconds
NAMESPACE_LIST=("keys" "things" "kube-system")  # Namespaces to monitor
SCALE_DEPLOYMENT_THRESHOLD=10  # Scale deployment replicas if load exceeds this threshold
MIN_REPLICAS=1  # Minimum replicas for scaling down
MAX_REPLICAS=10  # Maximum replicas for scaling up

##
##

# Helper Functions
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_OUTPUT"
}

check_load_average() {
  local load_avg=$(awk '{print $1}' /proc/loadavg)
  log "Current Load Average: $load_avg"
  
  if (( $(echo "$load_avg > $LOAD_THRESHOLD" | bc -l) )); then
    log "Load average exceeds threshold. Scaling up workloads..."
    scale_deployment "keycloak" "keycloak" "$MAX_REPLICAS"  # Scale up Keycloak deployment
  elif (( $(echo "$load_avg < $LOAD_THRESHOLD" | bc -l) )); then
    log "Load average is below threshold. Scaling down workloads..."
    scale_deployment "keycloak" "keycloak" "$MIN_REPLICAS"  # Scale down Keycloak deployment
  fi
}

check_cluster_health() {
  log "Checking cluster health..."
  unhealthy_pods=$($KUBECTL_CMD get pods -A --field-selector=status.phase!=Running -o name)

  if [ -n "$unhealthy_pods" ]; then
    log "Unhealthy Pods Detected:"
    echo "$unhealthy_pods" | tee -a "$LOG_OUTPUT"

    for pod in $unhealthy_pods; do
      log "Deleting unhealthy pod: $pod"
      $KUBECTL_CMD delete "$pod"
    done
  else
    log "All pods are healthy."
  fi
}

scale_deployment() {
  local namespace=$1
  local deployment=$2
  local replicas=$3

  current_replicas=$($KUBECTL_CMD get deployment "$deployment" -n "$namespace" -o jsonpath='{.spec.replicas}')
  
  if [ "$current_replicas" -ne "$replicas" ]; then
    log "Scaling deployment '$deployment' in namespace '$namespace' from $current_replicas to $replicas replicas..."
    $KUBECTL_CMD scale deployment "$deployment" -n "$namespace" --replicas="$replicas"
  else
    log "No scaling needed for deployment '$deployment' (current replicas: $current_replicas)."
  fi
}

tail_logs() {
  log "Tailing logs for key namespaces..."
  for ns in "${NAMESPACE_LIST[@]}"; do
    log "Tailing logs for namespace: $ns"
    pods=$($KUBECTL_CMD get pods -n "$ns" -o name)
    for pod in $pods; do
      log "Logs for $pod:"
      $KUBECTL_CMD logs "$pod" -n "$ns" --tail=10 | tee -a "$LOG_OUTPUT"
    done
  done
}

# Main Loop
log "Starting K3s Monitoring Script..."
while true; do
  check_load_average
  check_cluster_health
  tail_logs
  log "Sleeping for $CHECK_INTERVAL seconds..."
  sleep "$CHECK_INTERVAL"
done
