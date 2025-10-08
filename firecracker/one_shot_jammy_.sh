#!/usr/bin/env bash
set -euo pipefail

#
# Firecracker One-Shot Development Environment ..testing..
# -------------------------------------------------------------
# Creates a Docker-based Firecracker environment on Ubuntu
# with KVM passthrough and bridged networking.
#

IMAGE_NAME="firecracker-dev"
CONTAINER_NAME="firecracker-container"
BRIDGE_NAME="fcbr0"
TAP_NAME="tap0"
UBUNTU_VERSION="22.04"

echo "==============================================================="
echo "Setting up Firecracker development container with KVM + bridge"
echo "==============================================================="

#--- Prerequisite checks ----------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found. Please install Docker first."
    exit 1
fi

if [ ! -e /dev/kvm ]; then
    echo "/dev/kvm not found. Ensure virtualization is enabled in BIOS or VM settings."
    exit 1
fi

if ! ip link show | grep -q "$BRIDGE_NAME"; then
    echo "Creating bridge interface $BRIDGE_NAME"
    sudo ip link add name $BRIDGE_NAME type bridge
    sudo ip addr add 172.16.0.1/24 dev $BRIDGE_NAME
    sudo ip link set $BRIDGE_NAME up
else
    echo "Bridge $BRIDGE_NAME already exists."
fi

if ! ip link show | grep -q "$TAP_NAME"; then
    echo "Creating tap interface $TAP_NAME"
    sudo ip tuntap add dev $TAP_NAME mode tap user "$USER"
    sudo ip link set $TAP_NAME master $BRIDGE_NAME
    sudo ip link set $TAP_NAME up
else
    echo "Tap $TAP_NAME already exists."
fi

echo "Enabling IP forwarding and NAT for outbound connectivity"
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo iptables -t nat -C POSTROUTING -s 172.16.0.0/24 ! -o $BRIDGE_NAME -j MASQUERADE 2>/dev/null \
  || sudo iptables -t nat -A POSTROUTING -s 172.16.0.0/24 ! -o $BRIDGE_NAME -j MASQUERADE

#--- Create temporary Dockerfile -------------------------------------------
cat > Dockerfile.firecracker <<'EOF'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake curl git jq wget unzip \
    libssl-dev pkg-config python3 python3-pip python3-venv \
    linux-headers-generic qemu-kvm bridge-utils net-tools acl \
    iptables iproute2 dnsmasq-base cpu-checker sudo vim \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -ms /bin/bash dev && echo "dev ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER dev
WORKDIR /home/dev

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/home/dev/.cargo/bin:${PATH}"

# Clone Firecracker
RUN git clone https://github.com/firecracker-microvm/firecracker.git
WORKDIR /home/dev/firecracker

CMD ["/bin/bash"]
EOF

#--- Build image ------------------------------------------------------------
echo "Building Firecracker container image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" -f Dockerfile.firecracker .

#--- Run container ----------------------------------------------------------
echo "Running Firecracker container with KVM and bridge networking"
docker run -it --rm \
  --name "$CONTAINER_NAME" \
  --device /dev/kvm \
  --cap-add NET_ADMIN \
  --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --tmpfs /tmp:exec,mode=1777 \
  --network host \
  -v "$(pwd)":/workspace \
  -w /workspace \
  -e FC_BRIDGE_NAME=$BRIDGE_NAME \
  -e FC_TAP_NAME=$TAP_NAME \
  "$IMAGE_NAME"
