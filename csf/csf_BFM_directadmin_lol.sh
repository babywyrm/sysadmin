#!/usr/bin/env bash
# ============================================================
# CSF + DirectAdmin Hardening Installer (Modernized)
# Original Author: Alex Grebenschikov
# Overhaul: Security / Reliability / Maintainability
# ============================================================

set -Eeuo pipefail
IFS=$'\n\t'

# =========================
# Constants
# =========================
CSF_BIN="/usr/sbin/csf"
CSF_CONF="/etc/csf/csf.conf"
CSF_PIGNORE="/etc/csf/csf.pignore"

DA_BIN="/usr/local/directadmin/directadmin"
DA_CONF="/usr/local/directadmin/conf/directadmin.conf"
DA_CUSTOM_DIR="/usr/local/directadmin/scripts/custom"

SRC_DIR="/usr/local/src"
CSF_URL="https://download.configserver.com/csf.tgz"
CSF_PIGNORE_URL="https://raw.githubusercontent.com/poralix/directadmin-bfm-csf/master/csf.pignore.custom"

TIMESTAMP="$(date +%s)"

# =========================
# Logging Helpers
# =========================
log()  { echo -e "[INFO] $*"; }
ok()   { echo -e "[OK]   $*"; }
warn() { echo -e "[WARN] $*" >&2; }
die()  { echo -e "[ERR]  $*" >&2; exit 1; }

trap 'die "Unexpected failure on line $LINENO"' ERR

# =========================
# Preconditions
# =========================
[[ $EUID -eq 0 ]] || die "This script must be run as root"
[[ -x "$DA_BIN" ]] || die "DirectAdmin not found. Install it first."

mkdir -p "$DA_CUSTOM_DIR"

# =========================
# Utilities
# =========================
backup_file() {
    local f="$1"
    [[ -f "$f" ]] && cp -p "$f" "${f}.bak.${TIMESTAMP}"
}

set_conf_value() {
    local file="$1" key="$2" value="$3"
    backup_file "$file"
    if grep -q "^${key}=" "$file"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

append_unique() {
    local file="$1"
    shift
    for entry in "$@"; do
        grep -qxF "$entry" "$file" || echo "$entry" >> "$file"
    done
}

# =========================
# CSF Installation
# =========================
install_csf() {
    log "CSF not detected, installing…"

    rm -rf "${SRC_DIR}/csf"
    cd "$SRC_DIR"

    curl -fsSL "$CSF_URL" -o csf.tgz
    tar -xzf csf.tgz
    cd csf

    if ! ./csftest.pl | grep -q "RESULT: csf should function"; then
        warn "CSF environment test failed"
        ./csftest.pl
        exit 2
    fi

    sh install.sh
    [[ -x "$CSF_BIN" ]] || die "CSF installation failed"

    log "Updating csf.pignore"
    curl -fsSL "$CSF_PIGNORE_URL" >> "$CSF_PIGNORE"
    sort -u "$CSF_PIGNORE" -o "$CSF_PIGNORE"

    ok "CSF installed successfully"
}

# =========================
# CSF Configuration
# =========================
configure_csf() {
    log "Configuring CSF"

    backup_file "$CSF_CONF"

    declare -A CSF_SETTINGS=(
        [LF_EMAIL_ALERT]="0"
        [LT_EMAIL_ALERT]="0"
        [LF_PERMBLOCK_ALERT]="0"
        [LF_TRIGGER]="0"
        [LF_SSHD]="0"
        [LF_FTPD]="0"
        [LF_SMTPAUTH]="0"
        [LF_EXIMSYNTAX]="0"
        [LF_POP3D]="0"
        [LF_IMAPD]="0"
        [LF_HTACCESS]="0"
        [LF_MODSEC]="0"
        [LF_DIRECTADMIN]="0"
        [TESTING]="0"
        [RESTRICT_SYSLOG]="3"
    )

    for key in "${!CSF_SETTINGS[@]}"; do
        sed -i "s|^${key} = \".*\"|${key} = \"${CSF_SETTINGS[$key]}\"|" "$CSF_CONF"
    done

    sed -i 's/^TCP_IN = "\(.*\)"/TCP_IN = "\1,35000:35999"/' "$CSF_CONF"
    sed -i 's/^TCP6_IN = "\(.*\)"/TCP6_IN = "\1,35000:35999"/' "$CSF_CONF"
    sed -i 's/^TCP_OUT = "\(.*\)"/TCP_OUT = "\1,35000:65535"/' "$CSF_CONF"
    sed -i 's/^TCP6_OUT = "\(.*\)"/TCP6_OUT = "\1,35000:65535"/' "$CSF_CONF"

    systemctl restart csf lfd 2>/dev/null || service csf restart
    ok "CSF configured"
}

# =========================
# DirectAdmin Configuration
# =========================
configure_directadmin() {
    log "Configuring DirectAdmin brute-force settings"

    backup_file "$DA_CONF"

    set_conf_value "$DA_CONF" bruteforce 1
    set_conf_value "$DA_CONF" brute_force_log_scanner 1
    set_conf_value "$DA_CONF" brute_force_scan_apache_logs 2
    set_conf_value "$DA_CONF" brute_force_time_limit 1200
    set_conf_value "$DA_CONF" clear_brute_log_time 48
    set_conf_value "$DA_CONF" hide_brute_force_notifications 1
    set_conf_value "$DA_CONF" ip_brutecount 30
    set_conf_value "$DA_CONF" unblock_brute_ip_time 2880
    set_conf_value "$DA_CONF" user_brutecount 30

    ok "DirectAdmin hardened"
}

# =========================
# Install Custom Scripts
# =========================
install_script() {
    local name="$1" url="$2"
    local path="${DA_CUSTOM_DIR}/${name}"

    log "Installing ${name}"
    backup_file "$path"

    curl -fsSL "$url" -o "$path"
    chmod 700 "$path"
    chown diradmin:diradmin "$path"
}

# =========================
# Main
# =========================
[[ -x "$CSF_BIN" ]] || install_csf

install_script block_ip.sh \
  "https://files.plugins-da.net/dl/csf_block_ip.sh.txt"

install_script unblock_ip.sh \
  "https://files.plugins-da.net/dl/csf_unblock_ip.sh.txt"

install_script show_blocked_ips.sh \
  "https://files.plugins-da.net/dl/csf_show_blocked_ips.sh.txt"

install_script brute_force_notice_ip.sh \
  "https://files.directadmin.com/services/all/brute_force_notice_ip.sh"

touch /root/{blocked_ips.txt,exempt_ips.txt}

configure_csf
configure_directadmin

echo
ok "Installation complete"
"$DA_BIN" c | sort | grep -E \
'bruteforce|brute_force|ip_brutecount|unblock_brute_ip_time'
echo
