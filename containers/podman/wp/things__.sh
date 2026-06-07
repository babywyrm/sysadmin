#!/bin/bash

##
##

# Define container and pod names
CONTAINERS=("wordpress_db" "wordpress_app")
PODS=("pod_podpress")

# Function to stop and remove containers
cleanup_containers() {
    for CONTAINER in "${CONTAINERS[@]}"; do
        # Check if container exists
        if podman ps -a --format '{{.Names}}' | grep -q "^$CONTAINER$"; then
            echo "Stopping and removing container: $CONTAINER"
            podman stop "$CONTAINER" >/dev/null 2>&1
            podman rm "$CONTAINER" >/dev/null 2>&1
        else
            echo "Container $CONTAINER does not exist."
        fi
    done
}

# Function to stop and remove pods
cleanup_pods() {
    for POD in "${PODS[@]}"; do
        # Check if pod exists
        if podman pod ls --format '{{.Name}}' | grep -q "^$POD$"; then
            echo "Stopping and removing pod: $POD"
            podman pod stop "$POD" >/dev/null 2>&1
            podman pod rm "$POD" >/dev/null 2>&1
        else
            echo "Pod $POD does not exist."
        fi
    done
}

# Function to restart podman-compose
restart_podman_compose() {
    echo "Starting podman-compose..."
    podman-compose up -d
}

# Execute cleanup and restart
cleanup_containers
cleanup_pods
restart_podman_compose

echo "Cleanup and restart completed."

##
##
