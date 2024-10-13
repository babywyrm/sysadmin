#!/bin/bash

###
###
###
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

namespace="$1"

cluster_objects() {
    echo -e "\n${BLUE}Collecting Cluster Information:${PLAIN}"
    deployments=$(kubectl get deployments --all-namespaces | wc -l)
    pods=$(kubectl get pods --all-namespaces | wc -l)
    services=$(kubectl get svc --all-namespaces | wc -l)
    ingresses=$(kubectl get ingresses --all-namespaces | wc -l)
    statefulsets=$(kubectl get statefulsets --all-namespaces | wc -l)
    daemonsets=$(kubectl get daemonsets --all-namespaces | wc -l)
    replicasets=$(kubectl get replicasets --all-namespaces | wc -l)
    storageclass=$(kubectl get sc --all-namespaces | wc -l)
    hpa=$(kubectl get hpa --all-namespaces | wc -l)
    pvcs=$(kubectl get pvc --all-namespaces | wc -l)

    echo -e "${BOLD}${GREEN}Cluster Resource Summary:${PLAIN}"
    echo -e "${BLUE}Deployments: ${GREEN}${deployments}"
    echo -e "${BLUE}Pods: ${GREEN}${pods}"
    echo -e "${BLUE}Services: ${GREEN}${services}"
    echo -e "${BLUE}Ingresses: ${GREEN}${ingresses}"
    echo -e "${BLUE}StatefulSets: ${GREEN}${statefulsets}"
    echo -e "${BLUE}DaemonSets: ${GREEN}${daemonsets}"
    echo -e "${BLUE}ReplicaSets: ${GREEN}${replicasets}"
    echo -e "${BLUE}Storage Classes: ${GREEN}${storageclass}"
    echo -e "${BLUE}Horizontal Pod Autoscalers: ${GREEN}${hpa}"
    echo -e "${BLUE}Persistent Volume Claims: ${GREEN}${pvcs}"
}

cluster_nodes() {
    echo -e "\n${BOLD}${GREEN}Cluster Node Information:${PLAIN}"
    nodes=$(kubectl get nodes --no-headers | wc -l)
    worker=$(kubectl get nodes --no-headers | grep -v master | wc -l)
    master=$(kubectl get nodes --no-headers | grep master | wc -l)
    
    echo -e "${BLUE}Total Nodes: ${GREEN}${nodes}"
    echo -e "${BLUE}Worker Nodes: ${GREEN}${worker}"
    echo -e "${BLUE}Master Nodes: ${GREEN}${master}"

    echo -e "\n${BOLD}${YELLOW}Node Health Status:${PLAIN}"
    kubectl get nodes --no-headers -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type

    echo -e "\n${BOLD}${YELLOW}CPU and Memory Usage per Node:${PLAIN}"
    kubectl top nodes

    echo -e "\n${BOLD}${YELLOW}Pods Per Node:${PLAIN}"
    for node in $(kubectl get nodes --no-headers | awk '{print $1}'); do
        pod_count=$(kubectl get pods --all-namespaces --field-selector spec.nodeName=$node --no-headers | wc -l)
        echo -e "${BLUE}$node: ${GREEN}$pod_count Pods"
    done
}

analyze_pods() {
    echo -e "\n${BOLD}${RED}Pods with Issues:${PLAIN}"
    kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded
    echo -e "\n${BOLD}${YELLOW}OOMKilled Pods:${PLAIN}"
    kubectl get pods --all-namespaces -o json | jq '.items[] | select(.status.containerStatuses[]?.state.terminated.reason == "OOMKilled") | {name: .metadata.name, namespace: .metadata.namespace}'
}

system_services_health() {
    echo -e "\n${BOLD}${GREEN}CoreDNS Status:${PLAIN}"
    kubectl get deployment -n kube-system coredns
    
    echo -e "\n${BOLD}${GREEN}Local Path Provisioner Status:${PLAIN}"
    kubectl get deployment -n kube-system local-path-provisioner
}

resource_usage() {
    echo -e "\n${BOLD}${YELLOW}Top Memory Consuming Pods:${PLAIN}"
    kubectl top pods --sort-by=memory --all-namespaces | head -10

    echo -e "\n${BOLD}${YELLOW}Top CPU Consuming Pods:${PLAIN}"
    kubectl top pods --sort-by=cpu --all-namespaces | head -10
}

persistent_storage() {
    echo -e "\n${BOLD}${GREEN}Persistent Volume Claims:${PLAIN}"
    kubectl get pvc --all-namespaces
    echo -e "\n${BOLD}${GREEN}Persistent Volumes:${PLAIN}"
    kubectl get pv --all-namespaces
}

cluster_disk_usage() {
    echo -e "\n${BOLD}${YELLOW}Cluster Disk Usage:${PLAIN}"
    df -h
}

# Main Script Execution
clear
cluster_objects
cluster_nodes
analyze_pods
system_services_health
resource_usage
persistent_storage
cluster_disk_usage

###
###
###
