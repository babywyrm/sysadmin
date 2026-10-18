##
##

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import argparse

class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.paths = kwargs.pop('paths', [])
        super().__init__(*args, **kwargs)

    def do_POST(self):
        if self.path in self.paths:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)

            # Mock response data
            response_data = {
                'status': '200',
                'cardnumber': data['cardnumber']
            }

            # Send response back
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000, paths=None):
    if paths is None:
        paths = ['/api/options/']
    server_address = ('', port)
    httpd = server_class(server_address, lambda *args, **kwargs: handler_class(*args, paths=paths, **kwargs))
    print(f'Starting httpd server on port {port} with paths {paths}')
    httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start an HTTP server to handle specific paths.')
    parser.add_argument('--port', type=int, default=8000, help='Port to run the HTTP server on')
    parser.add_argument('--paths', nargs='+', default=['/api/options/'], help='Paths to handle')
    args = parser.parse_args()

    run(port=args.port, paths=args.paths)

##
##
