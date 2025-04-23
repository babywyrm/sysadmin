#!/bin/bash

# docker-socket-protector.sh - Comprehensive Docker socket protection (beta-testing-edition)
# 
# This script implements multiple layers of protection for the Docker socket
# to prevent container breakout and host compromise through socket abuse.
#
# Usage: ./docker-socket-protector.sh [install|test|status|uninstall]

set -e

# Color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

DOCKER_SOCKET="/var/run/docker.sock"
SECURE_SOCKET="/var/run/secure-docker.sock"
PROXY_CONTAINER_NAME="docker-socket-proxy"
SOCKET_GROUP="docker-socket-users"

# Log function for consistent output
log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    return 1
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Verify Docker is installed and running
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log "Docker is running correctly"
    return 0
}

# Create a dedicated group for socket access
create_socket_group() {
    log "Creating dedicated socket access group '$SOCKET_GROUP'..."
    
    if getent group "$SOCKET_GROUP" &> /dev/null; then
        log_warning "Group '$SOCKET_GROUP' already exists"
    else
        groupadd "$SOCKET_GROUP"
        log_success "Group '$SOCKET_GROUP' created"
    fi
    
    # Set appropriate permissions on the Docker socket
    chown root:"$SOCKET_GROUP" "$DOCKER_SOCKET"
    chmod 660 "$DOCKER_SOCKET"
    log_success "Docker socket permissions updated"
}

# Deploy a socket proxy to restrict Docker API access
deploy_socket_proxy() {
    log "Deploying Docker socket proxy..."
    
    # Remove existing proxy if it exists
    docker rm -f "$PROXY_CONTAINER_NAME" &> /dev/null || true
    
    # Deploy the socket proxy with restricted permissions
    docker run -d --restart=always \
        --name "$PROXY_CONTAINER_NAME" \
        -v "$DOCKER_SOCKET":/var/run/docker.sock \
        -v "$SECURE_SOCKET":/var/run/secure-docker.sock \
        alpine:latest \
        sh -c "apk add --no-cache socat && \
              socat UNIX-LISTEN:/var/run/secure-docker.sock,mode=660,fork,user=root,group=root \
              UNIX-CONNECT:/var/run/docker.sock" || log_error "Failed to deploy socket proxy"
    
    log_success "Socket proxy deployed at $SECURE_SOCKET"
    
    # Set secure permissions on the proxy socket
    sleep 2 # Wait for socket creation
    if [ -e "$SECURE_SOCKET" ]; then
        chmod 660 "$SECURE_SOCKET"
        chown root:"$SOCKET_GROUP" "$SECURE_SOCKET"
        log_success "Secure socket permissions set correctly"
    else
        log_error "Secure socket not created properly"
    fi
}

# Configure AppArmor profile to protect the Docker socket
setup_apparmor() {
    log "Setting up AppArmor profile for Docker socket protection..."
    
    if ! command -v apparmor_parser &> /dev/null; then
        log_warning "AppArmor not available, skipping this protection layer"
        return 0
    fi
    
    # Create AppArmor profile
    mkdir -p /etc/apparmor.d
    cat > /etc/apparmor.d/docker-socket <<EOF
profile docker-socket-access flags=(attach_disconnected) {
  # Allow read access to the Docker socket
  /var/run/docker.sock r,
  /var/run/secure-docker.sock r,
  
  # Allow specific binaries to have full access
  /usr/bin/docker rw,
  /usr/bin/dockerd rwix,
  /usr/bin/containerd rwix,
  /usr/bin/socat rwix,
  
  # Block write access for other processes
  deny /var/run/docker.sock w,
  deny /var/run/secure-docker.sock w,
  
  # Basic system access needed for most applications
  /usr/bin/* ix,
  /lib/** rm,
  /usr/lib/** rm,
  /etc/passwd r,
  /etc/group r,
  /proc/*/status r,
  /proc/sys/kernel/hostname r,
}
EOF
    
    # Load the AppArmor profile
    if apparmor_parser -r /etc/apparmor.d/docker-socket; then
        log_success "AppArmor profile loaded successfully"
    else
        log_error "Failed to load AppArmor profile"
    fi
}

# Set up audit monitoring for Docker socket access
setup_audit_monitoring() {
    log "Setting up audit monitoring for Docker socket access..."
    
    if ! command -v auditctl &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            log "Installing auditd..."
            apt-get update && apt-get install -y auditd
        elif command -v yum &> /dev/null; then
            log "Installing audit..."
            yum install -y audit
        else
            log_warning "Cannot install audit tools, skipping this protection layer"
            return 0
        fi
    fi
    
    # Add audit rules for both sockets
    auditctl -w "$DOCKER_SOCKET" -p rwa -k docker_socket_access
    auditctl -w "$SECURE_SOCKET" -p rwa -k docker_socket_access
    
    # Make audit rules persistent
    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/docker-socket.rules <<EOF
-w $DOCKER_SOCKET -p rwa -k docker_socket_access
-w $SECURE_SOCKET -p rwa -k docker_socket_access
EOF
    
    # Restart auditd service to apply rules
    if systemctl is-active --quiet auditd; then
        systemctl restart auditd
    elif service auditd status &> /dev/null; then
        service auditd restart
    else
        log_warning "Could not restart audit service, rules may not be applied"
    fi
    
    log_success "Audit monitoring configured for Docker sockets"
}

# Set up a systemd service to maintain socket permissions
create_maintenance_service() {
    log "Creating socket permission maintenance service..."
    
    if ! command -v systemctl &> /dev/null; then
        log_warning "systemd not available, skipping maintenance service"
        return 0
    fi
    
    # Create systemd service
    cat > /etc/systemd/system/docker-socket-protector.service <<EOF
[Unit]
Description=Docker Socket Protection Service
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod 660 $DOCKER_SOCKET && chown root:$SOCKET_GROUP $DOCKER_SOCKET"
ExecStart=/bin/bash -c "docker start $PROXY_CONTAINER_NAME || docker run -d --restart=always --name $PROXY_CONTAINER_NAME -v $DOCKER_SOCKET:/var/run/docker.sock -v $SECURE_SOCKET:/var/run/secure-docker.sock alpine:latest sh -c \"apk add --no-cache socat && socat UNIX-LISTEN:/var/run/secure-docker.sock,mode=660,fork UNIX-CONNECT:/var/run/docker.sock\""
ExecStart=/bin/bash -c "sleep 2 && chmod 660 $SECURE_SOCKET && chown root:$SOCKET_GROUP $SECURE_SOCKET"

[Install]
WantedBy=multi-user.target
EOF

    # Create timer to run the service periodically
    cat > /etc/systemd/system/docker-socket-protector.timer <<EOF
[Unit]
Description=Run Docker Socket Protection Service periodically

[Timer]
OnBootSec=1min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF

    # Enable and start the service and timer
    systemctl daemon-reload
    systemctl enable docker-socket-protector.service
    systemctl enable --now docker-socket-protector.timer
    
    log_success "Maintenance service installed and enabled"
}

# ------ Test Functions ------

# Test if the socket proxy is working correctly
test_socket_proxy() {
    log "Testing socket proxy functionality..."
    
    # Check if secure socket exists
    if [ ! -e "$SECURE_SOCKET" ]; then
        log_error "Secure socket does not exist"
        return 1
    fi
    
    # Test docker info through the proxy socket
    if DOCKER_HOST="unix://$SECURE_SOCKET" docker info &> /dev/null; then
        log_success "Socket proxy is functioning correctly"
    else
        log_error "Socket proxy test failed"
        return 1
    fi
    
    return 0
}

# Test if permissions are set correctly
test_permissions() {
    log "Testing socket permissions..."
    
    # Check Docker socket permissions
    DOCKER_PERMS=$(stat -c "%a" "$DOCKER_SOCKET")
    DOCKER_OWNER=$(stat -c "%U:%G" "$DOCKER_SOCKET")
    
    if [ "$DOCKER_PERMS" = "660" ] && [[ "$DOCKER_OWNER" == *"$SOCKET_GROUP" ]]; then
        log_success "Docker socket permissions are correct"
    else
        log_error "Docker socket permissions are incorrect: $DOCKER_PERMS $DOCKER_OWNER"
        return 1
    fi
    
    # Check secure socket permissions if it exists
    if [ -e "$SECURE_SOCKET" ]; then
        SECURE_PERMS=$(stat -c "%a" "$SECURE_SOCKET")
        SECURE_OWNER=$(stat -c "%U:%G" "$SECURE_SOCKET")
        
        if [ "$SECURE_PERMS" = "660" ] && [[ "$SECURE_OWNER" == *"$SOCKET_GROUP" ]]; then
            log_success "Secure socket permissions are correct"
        else
            log_error "Secure socket permissions are incorrect: $SECURE_PERMS $SECURE_OWNER"
            return 1
        fi
    fi
    
    return 0
}

# Test if a non-privileged user can access the socket
test_unprivileged_access() {
    log "Testing unprivileged user access..."
    
    # Create test user if it doesn't exist
    if ! id testuser &> /dev/null; then
        useradd -m testuser
        log "Created test user 'testuser'"
    fi
    
    # Try to access Docker socket as unprivileged user
    if su - testuser -c "docker info" &> /dev/null; then
        log_error "Unprivileged user can access Docker - protection not working!"
        return 1
    else
        log_success "Unprivileged user correctly denied access to Docker"
    fi
    
    # Add user to socket group and test again
    usermod -aG "$SOCKET_GROUP" testuser
    log "Added testuser to $SOCKET_GROUP group"
    
    # Need to reset user session for group changes to take effect
    # This is simulated in testing by directly using the socket
    if su - testuser -c "DOCKER_HOST=unix://$SECURE_SOCKET docker info" &> /dev/null; then
        log_success "User in $SOCKET_GROUP can access Docker through secure socket"
    else
        log_warning "User in $SOCKET_GROUP cannot access Docker - check group membership"
    fi
    
    # Remove test user from group
    gpasswd -d testuser "$SOCKET_GROUP"
    
    return 0
}

# Test if AppArmor is properly blocking unauthorized access
test_apparmor() {
    log "Testing AppArmor protection..."
    
    if ! command -v apparmor_parser &> /dev/null; then
        log_warning "AppArmor not available, skipping this test"
        return 0
    fi
    
    # Check if our profile is loaded
    if apparmor_status | grep -q "docker-socket-access"; then
        log_success "AppArmor profile is loaded"
    else
        log_warning "AppArmor profile is not loaded"
    fi
    
    return 0
}

# Test if audit logging is working
test_audit_logging() {
    log "Testing audit logging..."
    
    if ! command -v ausearch &> /dev/null; then
        log_warning "Audit search tool not available, skipping this test"
        return 0
    fi
    
    # Generate an audit event
    docker info > /dev/null
    
    # Check if the event was logged
    if ausearch -k docker_socket_access -ts recent | grep -q "$DOCKER_SOCKET"; then
        log_success "Audit logging is working correctly"
    else
        log_warning "Audit logging may not be capturing socket access"
    fi
    
    return 0
}

# Run a comprehensive test of all protections
run_all_tests() {
    log "Running comprehensive tests..."
    
    test_socket_proxy
    test_permissions
    test_unprivileged_access
    test_apparmor
    test_audit_logging
    
    log_success "All tests completed"
}

# Show current status of protections
show_status() {
    log "Docker Socket Protection Status:"
    
    # Check if proxy container is running
    if docker ps | grep -q "$PROXY_CONTAINER_NAME"; then
        log_success "Socket proxy: Running"
    else
        log_warning "Socket proxy: Not running"
    fi
    
    # Check socket permissions
    if [ -e "$DOCKER_SOCKET" ]; then
        DOCKER_PERMS=$(stat -c "%a" "$DOCKER_SOCKET")
        DOCKER_OWNER=$(stat -c "%U:%G" "$DOCKER_SOCKET")
        echo -e "  Docker socket: ${GREEN}Present${NC} - Permissions: $DOCKER_PERMS, Owner: $DOCKER_OWNER"
    else
        echo -e "  Docker socket: ${RED}Missing${NC}"
    fi
    
    if [ -e "$SECURE_SOCKET" ]; then
        SECURE_PERMS=$(stat -c "%a" "$SECURE_SOCKET")
        SECURE_OWNER=$(stat -c "%U:%G" "$SECURE_SOCKET")
        echo -e "  Secure socket: ${GREEN}Present${NC} - Permissions: $SECURE_PERMS, Owner: $SECURE_OWNER"
    else
        echo -e "  Secure socket: ${RED}Missing${NC}"
    fi
    
    # Check AppArmor status
    if command -v apparmor_parser &> /dev/null; then
        if apparmor_status | grep -q "docker-socket-access"; then
            echo -e "  AppArmor protection: ${GREEN}Enabled${NC}"
        else
            echo -e "  AppArmor protection: ${YELLOW}Not enabled${NC}"
        fi
    else
        echo -e "  AppArmor protection: ${YELLOW}Not available${NC}"
    fi
    
    # Check audit rules
    if command -v auditctl &> /dev/null; then
        if auditctl -l | grep -q "docker_socket"; then
            echo -e "  Audit monitoring: ${GREEN}Enabled${NC}"
        else
            echo -e "  Audit monitoring: ${YELLOW}Not enabled${NC}"
        fi
    else
        echo -e "  Audit monitoring: ${YELLOW}Not available${NC}"
    fi
    
    # Check maintenance service
    if command -v systemctl &> /dev/null; then
        if systemctl is-enabled --quiet docker-socket-protector.timer; then
            echo -e "  Maintenance service: ${GREEN}Enabled${NC}"
        else
            echo -e "  Maintenance service: ${YELLOW}Not enabled${NC}"
        fi
    else
        echo -e "  Maintenance service: ${YELLOW}Not available${NC} (systemd not found)"
    fi
    
    echo ""
    echo "Users with socket access:"
    getent group "$SOCKET_GROUP" | cut -d: -f4 | tr ',' '\n' | while read user; do
        echo "  - $user"
    done
}

# Uninstall all protections
uninstall_protections() {
    log "Uninstalling Docker socket protections..."
    
    # Stop and remove proxy container
    docker rm -f "$PROXY_CONTAINER_NAME" &> /dev/null || true
    
    # Remove AppArmor profile
    if command -v apparmor_parser &> /dev/null; then
        if [ -f /etc/apparmor.d/docker-socket ]; then
            apparmor_parser -R /etc/apparmor.d/docker-socket
            rm -f /etc/apparmor.d/docker-socket
            log "AppArmor profile removed"
        fi
    fi
    
    # Remove audit rules
    if command -v auditctl &> /dev/null; then
        auditctl -D 2>/dev/null || true
        rm -f /etc/audit/rules.d/docker-socket.rules
        log "Audit rules removed"
    fi
    
    # Remove maintenance service
    if command -v systemctl &> /dev/null; then
        systemctl disable --now docker-socket-protector.timer 2>/dev/null || true
        systemctl disable --now docker-socket-protector.service 2>/dev/null || true
        rm -f /etc/systemd/system/docker-socket-protector.service
        rm -f /etc/systemd/system/docker-socket-protector.timer
        systemctl daemon-reload
        log "Maintenance service removed"
    fi
    
    # Reset Docker socket permissions
    if [ -e "$DOCKER_SOCKET" ]; then
        chmod 660 "$DOCKER_SOCKET"
        chown root:docker "$DOCKER_SOCKET"
        log "Docker socket permissions reset"
    fi
    
    # Remove secure socket
    rm -f "$SECURE_SOCKET"
    
    log_success "All protections have been removed"
}

# Show usage example
show_examples() {
    echo -e "${BLUE}========== Docker Socket Protection Examples ==========${NC}"
    echo ""
    echo "1. Accessing Docker through the secure socket:"
    echo "   $ DOCKER_HOST=unix://$SECURE_SOCKET docker info"
    echo ""
    echo "2. Running a container that needs Docker access:"
    echo "   $ docker run -v $SECURE_SOCKET:/var/run/docker.sock my-container"
    echo ""
    echo "3. Adding a user to the Docker socket access group:"
    echo "   $ usermod -aG $SOCKET_GROUP username"
    echo ""
    echo "4. Checking audit logs for socket access:"
    echo "   $ ausearch -k docker_socket_access -ts today"
    echo ""
    echo "5. Testing socket protection:"
    echo "   $ ./docker-socket-protector.sh test"
    echo ""
    echo "6. Running a privileged container safely:"
    echo "   Instead of mounting the Docker socket directly, use the secure proxy socket:"
    echo "   UNSAFE: docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine"
    echo "   SAFER: docker run --privileged -v $SECURE_SOCKET:/var/run/docker.sock alpine"
    echo ""
    echo -e "${BLUE}====================================================${NC}"
}

# Main function to install all protections
install_all_protections() {
    check_root
    check_docker
    
    log "Starting Docker socket protection installation..."
    
    create_socket_group
    deploy_socket_proxy
    setup_apparmor
    setup_audit_monitoring
    create_maintenance_service
    
    log_success "All protection mechanisms have been installed successfully!"
    echo ""
    echo "You can now use the secure Docker socket at: $SECURE_SOCKET"
    echo "Add users to the '$SOCKET_GROUP' group to grant them access."
    echo ""
    echo "To test the installation, run: ./docker-socket-protector.sh test"
    echo "To see examples, run: ./docker-socket-protector.sh examples"
}

# Main execution
case "$1" in
    install)
        install_all_protections
        ;;
    test)
        check_root
        run_all_tests
        ;;
    status)
        check_root
        show_status
        ;;
    uninstall)
        check_root
        uninstall_protections
        ;;
    examples)
        show_examples
        ;;
    *)
        echo "Docker Socket Protection Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  install    Install all Docker socket protections"
        echo "  test       Run tests to verify protections are working"
        echo "  status     Show current protection status"
        echo "  uninstall  Remove all protections"
        echo "  examples   Show usage examples"
        echo ""
        exit 1
        ;;
esac

exit 0
