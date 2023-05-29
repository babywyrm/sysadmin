
##
##

from http.server import SimpleHTTPRequestHandler, HTTPServer
import random
from urllib.parse import urlparse, parse_qs

class RequestHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        # print(self.headers)

        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            print(query_params['url'][0])

        # Handle POST request here
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # print(f'POST data: {post_data.decode()}')
        # if post_data.decode().isprintable():
        #     print(f'POST data: {post_data.decode()}')
        # else:
        
        filename = 'temp' + str(random.randint(0, 9999))
        with open(filename,'wb') as f:
            f.write(post_data)
        print("Non ascii characters detected!! Content written to ./{} file instead.".format(filename))

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'POST request received')

    def do_GET(self):
        # print(self.headers)
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            print(query_params['url'][0])

        SimpleHTTPRequestHandler.do_GET(self)

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RequestHandler)
    print('Server running on http://localhost:8000')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    print('Server stopped')

if __name__ == '__main__':
    run_server()
##
##
    
