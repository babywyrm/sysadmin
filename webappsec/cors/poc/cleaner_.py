import http.server
import socketserver
import urllib.parse
import base64

##
##

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PROPFIND')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Depth')
        self.send_header('Access-Control-Allow-Credentials', 'true')  # Allow credentials
        super().end_headers()

    def do_OPTIONS(self):
        # Respond to preflight OPTIONS request
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        # Handle POST request
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        try:
            # Save data to a file
            file_name = 'received_data.txt'
            with open(file_name, 'w') as file:
                file.write(post_data)

            # Decode URL-encoded data
            decoded_data = urllib.parse.unquote(post_data)
            print('Decoded data:', decoded_data)

            # Extract base64 content starting after the equals sign (=)
            base64_content = decoded_data.split('=')[1]

            # URL-decode the base64 content
            url_decoded_content = urllib.parse.unquote(base64_content)

            # Base64 decode and print
            decoded_base64 = base64.b64decode(url_decoded_content)
            print('Decoded base64:', decoded_base64.decode('utf-8'))

            # Process the decoded data as needed

            # Send a response
            response = 'Success'
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            # Handle other exceptions
            print('Error:', str(e))
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

# Set up the server
port = 80
httpd = socketserver.TCPServer(("0.0.0.0", port), MyHandler)

print(f"Serving at port {port}")
httpd.serve_forever()

##
##
