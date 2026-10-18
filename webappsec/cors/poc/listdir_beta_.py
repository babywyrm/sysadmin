from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request
import os

## 
## something something PROPFIND idk yet
##

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # Extract the URL from the query parameters
            url = self.path.split('?url=')[1]

            # Fetch data from the specified URL
            response = urllib.request.urlopen(url)
            data = response.read()

            # Get the directory listing
            if url.endswith('/'):
                directory_listing = '\n'.join(os.listdir(url))
                data += f'\n\nDirectory Listing:\n{directory_listing}'.encode('utf-8')

            # Send a response with CORS headers
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')  # Allow all origins for simplicity
            self.end_headers()
            self.wfile.write(data)

        except Exception as e:
            # Handle other exceptions
            print('Error:', str(e))
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    def do_POST(self):
        # Handle POST request
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')

            # Send a response with CORS headers
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')  # Allow all origins for simplicity
            self.end_headers()
            self.wfile.write(f'Received POST data:\n{post_data}'.encode('utf-8'))

        except Exception as e:
            # Handle other exceptions
            print('Error:', str(e))
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

# Set up the server
port = 8000
httpd = HTTPServer(("0.0.0.0", port), MyHandler)

print(f"Serving at port {port}")
httpd.serve_forever()

