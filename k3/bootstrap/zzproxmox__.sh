#!/bin/bash

# actually, from here
# https://gist.github.com/ilude/457f2ef2e59d2bff8bb88b976464bb91
# Modern K3s Cluster Bootstrapper
# Version: 1.0.0
# Description: Creates a K3s cluster on Proxmox with modern security defaults

set -euo pipefail
IFS=$'\n\t'

# Configuration and Constants
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME=$(basename "${0}")
readonly UBUNTU_IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
readonly K3S_VERSION="v1.27.5+k3s1" # Update as needed

# Default Configuration (override with .env file)
declare -A CONFIG=(
    [CLUSTER_STORAGE]="local-lvm"
    [CLUSTER_USERNAME]=""
    [CLUSTER_PASSWORD]=""
    [DOMAIN_NAME]=""
    [ACME_EMAIL]=""
    [ACME_ENDPOINT]="https://acme-staging-v02.api.letsencrypt.org/directory"
    [CLUSTER_GW_IP]="192.168.1.1"
    [CLUSTER_LB_IP]="192.168.1.10"
    [METALLB_RANGE]="192.168.1.20-192.168.1.30"
)

# Node Configuration
declare -A MASTER_NODES=(
    [k3m-01]="192.168.1.11"
    [k3m-02]="192.168.1.12"
    [k3m-03]="192.168.1.13"
)

declare -A WORKER_NODES=(
    [k3w-01]="192.168.1.14"
    [k3w-02]="192.168.1.15"
    [k3w-03]="192.168.1.16"
)

# Logging
setup_logging() {
    readonly LOG_FILE="/var/log/k3s-bootstrap-$(date +%Y%m%d-%H%M%S).log"
    exec 1> >(tee -a "${LOG_FILE}")
    exec 2>&1
    echo "Starting K3s bootstrap at $(date)"
}

# Load Environment
load_env() {
    if [[ -f ".env" ]]; then
        echo "Loading configuration from .env file..."
        set -a
        source .env
        set +a
        
        # Validate required fields
        local required_fields=("CLUSTER_USERNAME" "CLUSTER_PASSWORD" "DOMAIN_NAME")
        for field in "${required_fields[@]}"; do
            if [[ -z "${!field}" ]]; then
                echo "ERROR: Required field ${field} is not set in .env file"
                exit 1
            fi
        done
    else
        echo "No .env file found. Using default configuration."
    fi
}

# Template Management
create_template() {
    local template_id=9000
    
    if qm status ${template_id} &>/dev/null; then
        echo "Template ${template_id} already exists. Removing..."
        qm stop ${template_id} &>/dev/null || true
        qm destroy ${template_id} --purge
    fi

    echo "Creating new template..."
    wget -nc "${UBUNTU_IMAGE_URL}" -O /tmp/ubuntu-cloud.img

    qm create ${template_id} \
        --memory 2048 \
        --cores 2 \
        --name "ubuntu-cloud-template" \
        --net0 virtio,bridge=vmbr0 \
        --agent enabled=1 \
        --cpu host \
        --bios ovmf \
        --machine q35

    qm importdisk ${template_id} /tmp/ubuntu-cloud.img ${CONFIG[CLUSTER_STORAGE]}
    qm set ${template_id} --scsihw virtio-scsi-pci --scsi0 ${CONFIG[CLUSTER_STORAGE]}:vm-${template_id}-disk-0
    qm set ${template_id} --boot c --bootdisk scsi0
    qm set ${template_id} --ide2 ${CONFIG[CLUSTER_STORAGE]}:cloudinit
    qm set ${template_id} --serial0 socket --vga serial0
    qm set ${template_id} --ipconfig0 ip=dhcp
    
    # Create cloud-init config
    create_cloud_init_config ${template_id}
    
    qm template ${template_id}
}

# Node Creation
create_nodes() {
    local template_id=9000
    
    # Create master nodes
    for node in "${!MASTER_NODES[@]}"; do
        create_node "${node}" "${MASTER_NODES[$node]}" "master" 2 4096
    done
    
    # Create worker nodes
    for node in "${!WORKER_NODES[@]}"; do
        create_node "${node}" "${WORKER_NODES[$node]}" "worker" 4 8192
    done
}

create_node() {
    local name=$1
    local ip=$2
    local type=$3
    local cores=$4
    local memory=$5
    local vmid

    # Generate VMID based on node type and IP
    if [[ ${type} == "master" ]]; then
        vmid=3${ip##*.}
    else
        vmid=31${ip##*.}
    fi

    echo "Creating node ${name} (${ip})..."
    
    qm clone ${template_id} ${vmid} \
        --name ${name} \
        --full \
        --cores ${cores} \
        --memory ${memory}
        
    qm set ${vmid} --ipconfig0 ip=${ip}/24,gw=${CONFIG[CLUSTER_GW_IP]}
    qm set ${vmid} --onboot 1
    
    # Start the VM
    qm start ${vmid}
}

# K3s Installation
install_k3s() {
    local first_master=${MASTER_NODES[k3m-01]}
    
    # Install k3sup
    curl -sLS https://get.k3sup.dev | sh
    sudo install k3sup /usr/local/bin/

    # Install first master
    k3sup install \
        --ip ${first_master} \
        --user ${CONFIG[CLUSTER_USERNAME]} \
        --k3s-version ${K3S_VERSION} \
        --k3s-extra-args "--cluster-init --disable traefik --disable servicelb"

    # Install additional masters
    for node in "${!MASTER_NODES[@]}"; do
        if [[ ${MASTER_NODES[$node]} != ${first_master} ]]; then
            k3sup join \
                --ip ${MASTER_NODES[$node]} \
                --user ${CONFIG[CLUSTER_USERNAME]} \
                --server-ip ${first_master} \
                --k3s-version ${K3S_VERSION} \
                --server
        fi
    done

    # Install workers
    for node in "${!WORKER_NODES[@]}"; do
        k3sup join \
            --ip ${WORKER_NODES[$node]} \
            --user ${CONFIG[CLUSTER_USERNAME]} \
            --server-ip ${first_master} \
            --k3s-version ${K3S_VERSION}
    done
}

# Main execution
main() {
    setup_logging
    load_env
    create_template
    create_nodes
    install_k3s
    
    echo "K3s cluster bootstrap completed successfully!"
    echo "Access your cluster using: export KUBECONFIG=kubeconfig"
}

main "$@"
