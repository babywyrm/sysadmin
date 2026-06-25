#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

################################################################################
# Modern ModSecurity v3 Installer (RHEL/CentOS 7-9 + Debian/Ubuntu)
#
# - Installs Apache + ModSecurity (libmodsecurity) + OWASP CRS via package manager
# - Supports CentOS/RHEL 7-9 (yum/dnf) and Debian/Ubuntu (apt)
# - Customizable via flags or environment variables
# - Configures `fsadmin` user with SSH key access for rule management
# - Optional host registration ping
# - Enables log directory customization and logrotate integration
################################################################################

# --- Defaults (override via env or flags) ---
APACHE_USER_DEFAULT_RHEL="apache"
APACHE_USER_DEFAULT_DEB="www-data"
HTTPD_SERVICE_RHEL="httpd"
HTTPD_SERVICE_DEB="apache2"

# package names (best-effort defaults — distro packaging varies)
MODSEC_PKG_RHEL="mod-security-v3"         # name may vary by repo; fallback handled below
MODSEC_PKG_DEB="modsecurity"             # Ubuntu/Debian package name (libmodsecurity / modsecurity)
CRS_PKG_DEB="modsecurity-crs"            # Ubuntu: modsecurity-crs exists in universe
CRS_PKG_RHEL="mod-security-crs"          # RHEL packaging varies; we will fallback to git clone
CRS_DIR_DEFAULT_RHEL="/etc/rhel/modsecurity-crs"
CRS_DIR_DEFAULT_DEB="/etc/modsecurity/crs"

APACHE_CONF_DIR_RHEL="/etc/httpd/conf.d"
APACHE_CONF_DIR_DEB="/etc/apache2/mods-enabled"   # note: Debian/Ubuntu layout differs
USER_CONF_FILE_DEFAULT="/etc/httpd/conf/modsec.user.conf"
LOG_DIR_DEFAULT="/var/log/httpd/modsec"
LOGROTATE_CONF_DEFAULT="/etc/logrotate.d/modsec"
SSH_KEY_URL_DEFAULT="http://SERVER/modsec/pubkey"
REGISTER_URL_DEFAULT="http://SERVER/modsec/register.php"

# runtime vars (can be overridden by flags/env)
PAKMAN_CMD=""
APACHE_USER=""
HTTPD_SERVICE=""
MODSEC_PKG=""
CRS_PKG=""
CRS_DIR=""
APACHE_CONF_DIR=""
USER_CONF_FILE="$USER_CONF_FILE_DEFAULT"
SSH_KEY_URL="$SSH_KEY_URL_DEFAULT"
REGISTER_URL="$REGISTER_URL_DEFAULT"
LOG_DIR="$LOG_DIR_DEFAULT"
LOGROTATE_CONF="$LOGROTATE_CONF_DEFAULT"

print_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  -h            Show help
  -p <cmd>      Package manager command string (e.g. "apt -y install" or "dnf -y install")
  -u <user>     Apache user
  -s <service>  Apache service name
  -m <pkg>      ModSecurity package name
  -c <pkg>      CRS package name
  -r <dir>      CRS directory
  -d <dir>      Apache conf.d directory
  -f <file>     Custom rules file
  -k <url>      fsadmin SSH public key URL
  -R <url>      Registration endpoint URL
  -l <dir>      ModSecurity log output directory
  -L <file>     Logrotate config path
EOF
}

# parse flags
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
    *) echo "Unknown option -$OPTARG" >&2; print_help; exit 1 ;;
  esac
done

# --- helper functions ---
log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

detect_distro() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "${ID:-unknown}"   # e.g. ubuntu, debian, centos, rhel, rocky, almalinux
  else
    uname -s
  fi
}

command_exists() { command -v "$1" &>/dev/null; }

# Establish distro and defaults
DISTRO="$(detect_distro)"
log "Detected distro: $DISTRO"

case "$DISTRO" in
  ubuntu|debian)
    : "${APACHE_USER:=$APACHE_USER_DEFAULT_DEB}"
    : "${HTTPD_SERVICE:=$HTTPD_SERVICE_DEB}"
    : "${MODSEC_PKG:=$MODSEC_PKG_DEB}"
    : "${CRS_PKG:=$CRS_PKG_DEB}"
    : "${CRS_DIR:=$CRS_DIR_DEFAULT_DEB}"
    : "${APACHE_CONF_DIR:=${APACHE_CONF_DIR_DEB:-/etc/apache2/conf-available}}"
    ;;
  centos|rhel|rocky|almalinux)
    : "${APACHE_USER:=$APACHE_USER_DEFAULT_RHEL}"
    : "${HTTPD_SERVICE:=$HTTPD_SERVICE_RHEL}"
    : "${MODSEC_PKG:=$MODSEC_PKG_RHEL}"
    : "${CRS_PKG:=$CRS_PKG_RHEL}"
    : "${CRS_DIR:=$CRS_DIR_DEFAULT_RHEL}"
    : "${APACHE_CONF_DIR:=$APACHE_CONF_DIR_RHEL}"
    ;;
  *)
    # Unknown distro: make reasonable defaults, let installer detect package manager
    : "${APACHE_USER:=$APACHE_USER_DEFAULT_RHEL}"
    : "${HTTPD_SERVICE:=$HTTPD_SERVICE_RHEL}"
    : "${MODSEC_PKG:=$MODSEC_PKG_DEB}"
    : "${CRS_PKG:=$CRS_PKG_DEB}"
    : "${CRS_DIR:=$CRS_DIR_DEFAULT_DEB}"
    : "${APACHE_CONF_DIR:=$APACHE_CONF_DIR_RHEL}"
    log "Warning: unrecognized distro, proceeding with conservative defaults."
    ;;
esac

# Setup package manager command if not provided
if [ -z "${PAKMAN_CMD:-}" ]; then
  if command_exists apt-get; then
    PAKMAN_CMD="apt-get -y install"
    USE_APT=1
  elif command_exists dnf; then
    PAKMAN_CMD="dnf -y install"
    USE_DNF=1
  elif command_exists yum; then
    PAKMAN_CMD="yum -y install"
    USE_YUM=1
  else
    die "No supported package manager found (apt, dnf, yum)"
  fi
fi

log "Using package manager command: $PAKMAN_CMD"
log "Apache user: $APACHE_USER  service: $HTTPD_SERVICE"
log "ModSecurity package: $MODSEC_PKG  CRS package: $CRS_PKG  CRS dir: $CRS_DIR"

# Update repositories & enable EPEL on RHEL if needed
if command_exists apt-get; then
  log "Updating apt repositories..."
  apt-get update -y
  # ensure 'universe' exists on Ubuntu for modsecurity/crs packages (best-effort)
  if [ -f /etc/lsb-release ] && grep -qi ubuntu /etc/lsb-release; then
    if ! grep -E "^[^#].*universe" /etc/apt/sources.list &>/dev/null; then
      log "Enabling 'universe' repository for Ubuntu (may require interactive apt-add-repository)."
      if command_exists add-apt-repository; then
        add-apt-repository -y universe || true
        apt-get update -y
      else
        log "Note: 'add-apt-repository' not available; ensure 'universe' is enabled manually if needed."
      fi
    fi
  fi
elif command_exists yum || command_exists dnf; then
  # Enable EPEL for RHEL/CentOS 7/8 if not already present
  if ! yum repolist enabled | grep -qi epel; then
    log "Attempting to enable EPEL repository..."
    if command_exists dnf; then
      dnf -y install epel-release || true
    else
      yum -y install epel-release || true
    fi
  else
    log "EPEL already enabled (or not required)."
  fi
fi

# Install Apache + ModSecurity + CRS (best-effort; package names differ across distros)
log "Installing Apache + ModSecurity + CRS..."
if command_exists apt-get; then
  # Debian/Ubuntu
  apt-get update -y
  # install apache and packages (allow failure to try alternative flows)
  set +e
  apt-get -y install apache2 "$MODSEC_PKG" "$CRS_PKG"
  RC=$?
  set -e
  if [ $RC -ne 0 ]; then
    log "apt install returned non-zero ($RC). Will attempt apache2 + modsecurity where available and fallback for CRS if necessary."
    # try installing apache + modsecurity only
    set +e
    apt-get -y install apache2 "$MODSEC_PKG"
    RC2=$?
    set -e
    if [ $RC2 -ne 0 ]; then
      die "Could not install Apache or ModSecurity via apt. Please inspect your repositories or install libmodsecurity manually."
    fi
  fi
else
  # RHEL/CentOS family
  if command_exists dnf; then
    set +e
    dnf -y install httpd "$MODSEC_PKG" "$CRS_PKG"
    RC=$?
    set -e
  else
    set +e
    yum -y install httpd "$MODSEC_PKG" "$CRS_PKG"
    RC=$?
    set -e
  fi

  if [ $RC -ne 0 ]; then
    log "Package install returned non-zero ($RC). Will continue but you may need to supply a repository that provides ModSecurity v3 (libmodsecurity) for your RHEL/CentOS."
    # Do not die: allow script to continue to configure files; user may install libmodsecurity via source or a repo.
  fi
fi

# Ensure apache service exists (systemd)
if ! systemctl list-unit-files | grep -q "^$HTTPD_SERVICE"; then
  log "Warning: service $HTTPD_SERVICE not found via systemctl. Continuing but service operations may fail."
fi

# Create or validate log directory
log "Configuring ModSecurity log directory: $LOG_DIR"
mkdir -p "$LOG_DIR"
chown "$APACHE_USER":"$APACHE_USER" "$LOG_DIR" || true
chmod 750 "$LOG_DIR" || true

# Create logrotate configuration
log "Writing logrotate config: $LOGROTATE_CONF"
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

# Enable & start Apache
log "Enabling and starting Apache service: $HTTPD_SERVICE"
systemctl enable "$HTTPD_SERVICE" >/dev/null 2>&1 || true
systemctl start  "$HTTPD_SERVICE" >/dev/null 2>&1 || true

# Link OWASP CRS rules into Apache conf dir (if package installed) or suggest git clone
log "Linking/ensuring OWASP CRS rules at: $CRS_DIR"
if [ -d "$CRS_DIR" ]; then
  # try to install CRS symlink(s) or conf file(s)
  if [ -f "$CRS_DIR/crs-setup.conf.example" ]; then
    ln -sf "$CRS_DIR/crs-setup.conf.example" "$APACHE_CONF_DIR/crs-setup.conf" || true
  fi
  if [ -d "$CRS_DIR/rules" ]; then
    for rule in "$CRS_DIR/rules/"*.conf; do
      [ -e "$rule" ] || continue
      ln -sf "$rule" "$APACHE_CONF_DIR/$(basename "$rule")" || true
    done
  fi
else
  log "CRS directory $CRS_DIR not present. Attempting to provision CRS via git clone into /etc/modsecurity/coreruleset (fallback)."
  if command_exists git; then
    mkdir -p /etc/modsecurity
    if [ ! -d /etc/modsecurity/coreruleset ]; then
      git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/coreruleset || log "git clone of coreruleset failed; please obtain CRS manually."
      if [ -f /etc/modsecurity/coreruleset/crs-setup.conf.example ]; then
        # copy example into place
        cp /etc/modsecurity/coreruleset/crs-setup.conf.example /etc/modsecurity/coreruleset/crs-setup.conf || true
        ln -sf /etc/modsecurity/coreruleset/crs-setup.conf "$APACHE_CONF_DIR/crs-setup.conf" || true
        for r in /etc/modsecurity/coreruleset/rules/*.conf; do
          [ -e "$r" ] || continue
          ln -sf "$r" "$APACHE_CONF_DIR/$(basename "$r")" || true
        done
      fi
    fi
  else
    log "git not available. Please install the OWASP CRS manually (see https://coreruleset.org/docs/1-getting-started/)."
  fi
fi

# Create fsadmin user for rule management
if ! id fsadmin &>/dev/null; then
  log "Creating fsadmin user..."
  useradd --create-home --shell /bin/bash fsadmin
else
  log "fsadmin user already exists."
fi
FS_HOME="$(getent passwd fsadmin | cut -d: -f6)"
[ -n "$FS_HOME" ] || FS_HOME="/home/fsadmin"

# Provision fsadmin SSH access (safe append if non-empty key)
if [ -n "${SSH_KEY_URL:-}" ]; then
  log "Attempting to fetch SSH public key from: $SSH_KEY_URL"
  mkdir -p "$FS_HOME/.ssh"
  tmpkey="$(mktemp)"
  if curl -fsSL --max-time 15 "$SSH_KEY_URL" -o "$tmpkey"; then
    # basic sanitation: ensure file has "ssh-" or "ecdsa-" or "ssh-rsa" prefix and not empty
    if grep -E '^(ssh-(rsa|ed25519)|ecdsa-sha2-)' "$tmpkey" >/dev/null 2>&1 && [ -s "$tmpkey" ]; then
      cat "$tmpkey" >> "$FS_HOME/.ssh/authorized_keys"
      chmod 700 "$FS_HOME/.ssh"
      chmod 600 "$FS_HOME/.ssh/authorized_keys"
      chown -R fsadmin:fsadmin "$FS_HOME/.ssh"
      log "Deployed SSH key to fsadmin account."
    else
      log "Downloaded key did not look like a valid SSH public key or was empty — skipping deployment."
    fi
  else
    log "Could not retrieve SSH key from $SSH_KEY_URL (curl failed)."
  fi
  rm -f "$tmpkey"
fi

# Generate main ModSecurity include (Apache conf)
# Determine target path depending on distro
if [ -d "$APACHE_CONF_DIR" ]; then
  if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
    # Debian/Ubuntu often places mod_security conf under /etc/modsecurity or conf-available
    MAIN_CONF="/etc/modsecurity/mod_security.conf"
    mkdir -p "$(dirname "$MAIN_CONF")"
  else
    MAIN_CONF="$APACHE_CONF_DIR/mod_security.conf"
  fi
else
  MAIN_CONF="/etc/modsecurity/mod_security.conf"
  mkdir -p "$(dirname "$MAIN_CONF")"
fi

log "Writing main ModSecurity config to $MAIN_CONF (best-effort)"
cat > "$MAIN_CONF" <<'EOF'
<IfModule security3_module>
    # Engine settings
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess Off

    # Audit log
    SecAuditEngine RelevantOnly
    SecAuditLogParts ABIJDEFHZ
    SecAuditLogType Serial
    SecAuditLog /var/log/httpd/modsec/audit.log

    # Include CRS and user rules (paths may vary per distro)
    IncludeOptional "/etc/modsecurity/crs/crs-setup.conf"
    IncludeOptional "/etc/modsecurity/crs/rules/*.conf"
    # Fallbacks for RHEL style
    IncludeOptional "/etc/rhel/modsecurity-crs/crs-setup.conf"
    IncludeOptional "/etc/rhel/modsecurity-crs/rules/*.conf"

    # Custom user rules file
    IncludeOptional "/etc/httpd/conf/modsec.user.conf"
    IncludeOptional "/etc/apache2/modsecurity.d/modsec.user.conf"
</IfModule>
EOF

# Ensure custom rules file exists and is owned by fsadmin if present
log "Ensuring custom rules file exists: $USER_CONF_FILE"
mkdir -p "$(dirname "$USER_CONF_FILE")"
touch "$USER_CONF_FILE"
chown fsadmin:fsadmin "$USER_CONF_FILE" || true
chmod 640 "$USER_CONF_FILE" || true

# Test Apache configuration
log "Testing Apache configuration..."
if command_exists apachectl; then
  apachectl configtest || log "apachectl configtest failed (check /var/log/apache2 or /var/log/httpd)"
elif command_exists apache2ctl; then
  apache2ctl configtest || log "apache2ctl configtest failed"
else
  log "No apachectl/apache2ctl found; skipping configtest."
fi

log "Reloading Apache service..."
systemctl reload "$HTTPD_SERVICE" >/dev/null 2>&1 || systemctl restart "$HTTPD_SERVICE" >/dev/null 2>&1 || log "Could not reload/restart $HTTPD_SERVICE (you may need to start it manually)."

# Optional host registration ping (best-effort)
if [ -n "${REGISTER_URL:-}" ]; then
  SSH_PORT="$(awk '/^Port/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || echo 22)"
  if command_exists curl; then
    log "Pinging registration endpoint: ${REGISTER_URL}?port=${SSH_PORT}"
    curl -qs "${REGISTER_URL}?port=${SSH_PORT}" >/dev/null || log "Registration ping failed (ignored)."
  fi
fi

log ""
log "=== ModSecurity v3 installation and configuration completed (best-effort) ==="
log "Notes:"
log " - If ModSecurity/libmodsecurity is not packaged for your distro, you may need to build libmodsecurity and connectors from source:"
log "   https://github.com/owasp-modsecurity/ModSecurity/wiki/Compilation-recipes-for-v3.x"
log " - OWASP CRS can be installed from packages or via git clone: https://github.com/coreruleset/coreruleset"
log ""
##
##
