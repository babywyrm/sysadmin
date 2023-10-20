import http.server
import base64
import os

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Extract the query string
        query_string = self.path.split('?', 1)[-1]

        # Parse the query string to get the value of the 'resp' parameter
        query_parameters = query_string.split('&')
        for param in query_parameters:
            if '=' in param:
                key, value = param.split('=', 1)
                if key == 'resp':
                    # Try to decode Base64 data
                    try:
                        decoded_data = base64.b64decode(value.encode('utf-8'))

                        # Save the decoded data to a file
                        with open('decoded_file.txt', 'ab') as file:
                            file.write(decoded_data)

                    except Exception as e:
                        pass

        # Serve the request as usual
        super().do_GET()

if __name__ == '__main__':
    server_address = ('', 443)
    httpd = http.server.HTTPServer(server_address, MyHTTPRequestHandler)
    httpd.serve_forever()

##
##
