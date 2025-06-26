#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Modern ModSecurity v3 Installer for CentOS/RHEL 7-9
#
#    - Installs Apache + ModSecurity + OWASP CRS via package manager
#    - Supports CentOS/RHEL 7 (EPEL), 8, and 9
#    - Customizable paths and settings via flags or environment variables
#    - Configures `fsadmin` user with SSH key access for rule management
#    - Optional host registration ping
#    - Enables log directory customization and logrotate integration
################################################################################

# Default configuration (override with env vars or -x flags)
APACHE_USER        = "apache"                              # Apache system user
HTTPD_SERVICE      = "httpd"                               # Apache service name\ 
PAKMAN_CMD         = ""                                    # auto-detected below
MODSEC_PKG         = "libmodsecurity"                     # ModSecurity core module
CRS_PKG            = "mod_security_crs"                   # OWASP CRS package
CRS_DIR            = "/etc/rhel/modsecurity-crs"          # Installed CRS directory
APACHE_CONF_DIR    = "/etc/httpd/conf.d"                 # Apache conf.d directory
USER_CONF_FILE     = "/etc/httpd/conf/modsec.user.conf"   # Custom user rules file
SSH_KEY_URL        = "http://SERVER/modsec/pubkey"        # fsadmin pubkey URL
REGISTER_URL       = "http://SERVER/modsec/register.php"  # Optional registration endpoint
LOG_DIR            = "/var/log/httpd/modsec"             # Directory to store ModSecurity logs
LOGROTATE_CONF     = "/etc/logrotate.d/modsec"           # Logrotate config path

print_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  -h            Show this help message and exit
  -p <cmd>      Package manager command (e.g. "dnf -y install" or "yum -y install")
  -u <user>     Apache service user (default: $APACHE_USER)
  -s <service>  Apache systemd service name (default: $HTTPD_SERVICE)
  -m <pkg>      ModSecurity package name (default: $MODSEC_PKG)
  -c <pkg>      CRS package name (default: $CRS_PKG)
  -r <dir>      CRS install directory (default: $CRS_DIR)
  -d <dir>      Apache conf.d directory (default: $APACHE_CONF_DIR)
  -f <file>     Custom rules file (default: $USER_CONF_FILE)
  -k <url>      fsadmin SSH public key URL
  -R <url>      Registration endpoint URL
  -l <dir>      ModSecurity log output directory (default: $LOG_DIR)
  -L <file>     Logrotate config path (default: $LOGROTATE_CONF)

Environment variables override defaults above.
EOF
}

# Parse command-line flags
while getopts ":hp:u:s:m:c:r:d:f:k:R:l:L:" opt; do
  case $opt in
    h) print_help; exit 0 ;;  
    p) PAKMAN_CMD="$OPTARG" ;;  
    u) APACHE_USER="$OPTARG" ;;  
    s) HTTPD_SERVICE="$OPTARG" ;;  
    m) MODSEC_PKG="$OPTARG" ;;  
    c) CRS_PKG="$OPTARG" ;;  
    r) CRS_DIR="$OPTARG" ;;  
    d) APACHE_CONF_DIR="$OPTARG" ;;  
    f) USER_CONF_FILE="$OPTARG" ;;  
    k) SSH_KEY_URL="$OPTARG" ;;  
    R) REGISTER_URL="$OPTARG" ;;  
    l) LOG_DIR="$OPTARG" ;;  
    L) LOGROTATE_CONF="$OPTARG" ;;  
    *) echo "Unknown option: -$OPTARG" >&2; print_help; exit 1 ;;
  esac
done

# Auto-detect package manager if unset or invalid
if [ -z "${PAKMAN_CMD}" ] || ! command -v ${PAKMAN_CMD%% *} &>/dev/null; then
  if command -v dnf &>/dev/null; then
    PAKMAN_CMD="dnf -y install"
  elif command -v yum &>/dev/null; then
    PAKMAN_CMD="yum -y install"
  else
    echo "ERROR: neither dnf nor yum found" >&2; exit 1
  fi
fi

# Enable EPEL for RHEL7 / CentOS7
if yum repolist enabled | grep -q "epel"; then
  echo "EPEL repository already enabled"
else
  echo "Enabling EPEL repository..."
  yum -y install epel-release
fi

# Install core packages
echo "Installing Apache, $MODSEC_PKG, and $CRS_PKG..."
${PAKMAN_CMD} httpd $MODSEC_PKG $CRS_PKG

# Create or validate log directory
echo "Configuring ModSecurity log directory: $LOG_DIR"
mkdir -p "$LOG_DIR"
chown "$APACHE_USER":"$APACHE_USER" "$LOG_DIR"
chmod 750 "$LOG_DIR"

# Optional: generate a basic logrotate config
cat > "$LOGROTATE_CONF" <<EOF
$LOG_DIR/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 640 $APACHE_USER $APACHE_USER
    sharedscripts
    postrotate
        systemctl reload $HTTPD_SERVICE >/dev/null 2>&1 || true
    endscript
}
EOF

# Enable and start Apache
echo "Enabling and starting service: $HTTPD_SERVICE"
systemctl enable "$HTTPD_SERVICE"
systemctl start  "$HTTPD_SERVICE"

# Link OWASP CRS rules into Apache conf.d
echo "Linking OWASP CRS rules from $CRS_DIR to $APACHE_CONF_DIR"
if [ -d "$CRS_DIR" ]; then
  ln -sf "$CRS_DIR/crs-setup.conf.example" "$APACHE_CONF_DIR/crs-setup.conf"
  for rule in "$CRS_DIR/rules/"*.conf; do
    ln -sf "$rule" "$APACHE_CONF_DIR/"
  done
else
  echo "WARNING: CRS directory not found: $CRS_DIR" >&2
fi

# Create fsadmin user for rule management
if ! id fsadmin &>/dev/null; then
  echo "Creating fsadmin user..."
  useradd --create-home --shell /bin/bash fsadmin
fi
FS_HOME=$(getent passwd fsadmin | cut -d: -f6)

# Provision fsadmin SSH access
echo "Deploying SSH key for fsadmin from $SSH_KEY_URL"
mkdir -p "$FS_HOME/.ssh"
curl -sfL "$SSH_KEY_URL" >> "$FS_HOME/.ssh/authorized_keys"
chmod 700 "$FS_HOME/.ssh"
chmod 600 "$FS_HOME/.ssh/authorized_keys"
chown -R fsadmin:fsadmin "$FS_HOME/.ssh"

# Generate main ModSecurity Apache include
MAIN_CONF="$APACHE_CONF_DIR/mod_security.conf"
echo "Writing main ModSecurity config to $MAIN_CONF"
cat > "$MAIN_CONF" <<EOF
<IfModule security3_module>
    # Enable engine and request body logging
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess Off

    # Log settings
    SecAuditEngine RelevantOnly
    SecAuditLogParts ABIJDEFHZ
    SecAuditLogType Serial
    SecAuditLog $LOG_DIR/audit.log

    # Include CRS and user rules
    IncludeOptional "$APACHE_CONF_DIR/crs-setup.conf"
    IncludeOptional "$APACHE_CONF_DIR/*.conf"
    Include "$USER_CONF_FILE"
</IfModule>
EOF

# Ensure custom rules file exists and is owned by fsadmin
echo "Ensuring custom rules file: $USER_CONF_FILE"
touch "$USER_CONF_FILE"
chown fsadmin:fsadmin "$USER_CONF_FILE"

# Test and reload Apache configuration
echo "Testing Apache configuration..."
apachectl configtest

echo "Reloading Apache service..."
systemctl reload "$HTTPD_SERVICE"

# Optional host registration ping
SSH_PORT=$(awk '/^Port/ {print \$2; exit}' /etc/ssh/sshd_config || echo 22)
echo "Registering host to $REGISTER_URL?port=$SSH_PORT"
curl -qs "$REGISTER_URL?port=$SSH_PORT" >/dev/null || true

# Completion message
echo -e "\nModSecurity v3 installation and configuration complete!"
##

