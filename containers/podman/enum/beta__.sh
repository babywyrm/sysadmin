#!/bin/bash

# Podman socket to monitor
PODMAN_SOCKET="unix:///var/run/secret.sock"

##
##

# Log file to store the output
LOG_FILE="podman_monitor.log"

# Function to get the OS version from a container
get_os_version() {
    local container_id=$1
    os_version=$(podman --remote --url=$PODMAN_SOCKET exec $container_id cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d= -f2- | tr -d '"')
    if [ -n "$os_version" ]; then
        echo "OS Version: $os_version" | tee -a $LOG_FILE
    else
        echo "OS Version information not available." | tee -a $LOG_FILE
    fi
}

# Function to get the kernel version from a container
get_kernel_version() {
    local container_id=$1
    kernel_version=$(podman --remote --url=$PODMAN_SOCKET exec $container_id uname -r 2>/dev/null)
    if [ -n "$kernel_version" ]; then
        echo "Kernel Version: $kernel_version" | tee -a $LOG_FILE
    else
        echo "Kernel Version information not available." | tee -a $LOG_FILE
    fi
}

# Function to get the container's environment variables
get_env_variables() {
    local container_id=$1
    env_vars=$(podman --remote --url=$PODMAN_SOCKET exec $container_id printenv 2>/dev/null)
    echo "Environment Variables:" | tee -a $LOG_FILE
    echo "$env_vars" | tee -a $LOG_FILE
}

# Function to get the container's network settings
get_network_info() {
    local container_id=$1
    network_info=$(podman --remote --url=$PODMAN_SOCKET inspect $container_id --format='{{json .NetworkSettings}}' | jq '.')
    echo "Network Information:" | tee -a $LOG_FILE
    echo "$network_info" | tee -a $LOG_FILE
}

# Function to get the container's resource usage
get_resource_usage() {
    local container_id=$1
    stats=$(podman --remote --url=$PODMAN_SOCKET stats $container_id --no-stream --format=json | jq '.[]')
    cpu_usage=$(echo $stats | jq '.cpu_percent')
    mem_usage=$(echo $stats | jq '.mem_usage')
    mem_limit=$(echo $stats | jq '.mem_limit')
    echo "Resource Usage:" | tee -a $LOG_FILE
    echo "CPU Usage: $cpu_usage%" | tee -a $LOG_FILE
    echo "Memory Usage: $mem_usage of $mem_limit" | tee -a $LOG_FILE
}

# Function to check and print container mounts
check_container_mounts() {
    local container_id=$1

    echo "Checking mounts for container: $container_id" | tee -a $LOG_FILE
    get_os_version $container_id
    get_kernel_version $container_id
    get_env_variables $container_id
    get_network_info $container_id
    get_resource_usage $container_id

    # Get container mounts information
    mounts=$(podman --remote --url=$PODMAN_SOCKET inspect $container_id --format='{{json .Mounts}}' | jq -c '.[] | {Source, Destination, Type, RW, Exec}')

    for mount in $mounts; do
        source=$(echo $mount | jq -r '.Source')
        destination=$(echo $mount | jq -r '.Destination')
        writable=$(echo $mount | jq -r '.RW')
        exec=$(echo $mount | jq -r '.Exec')

        echo "Source: $source" | tee -a $LOG_FILE
        echo "Destination: $destination" | tee -a $LOG_FILE
        echo "Writable: $writable" | tee -a $LOG_FILE
        echo "Executable: $exec" | tee -a $LOG_FILE

        if [ "$writable" = "true" ]; then
            echo "Writable: Yes" | tee -a $LOG_FILE
        else
            echo "Writable: No" | tee -a $LOG_FILE
        fi

        if [ "$exec" = "true" ]; then
            echo "Executable: Yes" | tee -a $LOG_FILE
        else
            echo "Executable: No" | tee -a $LOG_FILE
        fi

        # Print detailed information about the destination mount point
        echo "Detailed information for destination mount point:" | tee -a $LOG_FILE
        podman --remote --url=$PODMAN_SOCKET exec $container_id sh -c "ls -la $destination" 2>/dev/null | tee -a $LOG_FILE
        echo "------------------------------------" | tee -a $LOG_FILE
    done
}

# Monitor containers in a perpetual loop
while true; do
    # Get a list of all running container IDs
    container_ids=$(podman --remote --url=$PODMAN_SOCKET ps -q)

    if [ -z "$container_ids" ]; then
        echo "No running containers found." | tee -a $LOG_FILE
    else
        for container_id in $container_ids; do
            check_container_mounts $container_id
        done
    fi

    # Wait for a while before checking again
    sleep 2
done

