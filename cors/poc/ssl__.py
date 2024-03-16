#!/usr/bin/python3

##
##

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import base64
import urllib.parse
import json
import csv
import ssl

class S(BaseHTTPRequestHandler):
    def _set_response(self, content_type='text/html'):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        decoded_data = base64.b64decode(post_data.decode('utf-8'))
        r = urllib.parse.unquote(decoded_data)
        if 'Invalid email or password' not in r:
            logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                    str(self.path), str(self.headers), r)
            # Determine content type and process accordingly
            if self.path == '/json':
                self.process_json(r)
            elif self.path == '/csv':
                self.process_csv(r)
            else:
                logging.info("Unsupported endpoint")
        else:
            logging.info("nothing")

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

    def process_json(self, data):
        # Example JSON processing
        try:
            json_data = json.loads(data)
            # Perform actions with JSON data
            logging.info("Received JSON data: %s", json_data)
            # Here you can implement the desired processing
        except json.JSONDecodeError as e:
            logging.error("Error decoding JSON: %s", e)

    def process_csv(self, data):
        # Example CSV processing
        decoded_data = data.decode('utf-8')
        csv_reader = csv.reader(decoded_data.splitlines())
        rows = list(csv_reader)
        # Perform actions with CSV data
        logging.info("Received CSV data: %s", rows)
        # Here you can implement the desired processing

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./server.pem', server_side=True) # <- Replace with your SSL certificate
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()

##      
##

##
##

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import base64
import urllib.parse
import json
import csv
import ssl

class S(BaseHTTPRequestHandler):
    def _set_response(self, content_type='text/html'):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        decoded_data = base64.b64decode(post_data.decode('utf-8'))
        r = urllib.parse.unquote(decoded_data)
        if 'Invalid email or password' not in r:
            logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                    str(self.path), str(self.headers), r)
            # Determine content type and process accordingly
            if self.path == '/json':
                self.process_json(r)
            elif self.path == '/csv':
                self.process_csv(r)
            elif self.path == '/text':
                self.process_text(r)
            elif self.path == '/xml':
                self.process_xml(r)
            else:
                logging.info("Unsupported endpoint")
        else:
            logging.info("nothing")

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

    def process_json(self, data):
        # Example JSON processing
        try:
            json_data = json.loads(data)
            # Perform actions with JSON data
            logging.info("Received JSON data: %s", json_data)
            # Here you can implement the desired processing
        except json.JSONDecodeError as e:
            logging.error("Error decoding JSON: %s", e)

    def process_csv(self, data):
        # Example CSV processing
        decoded_data = data.decode('utf-8')
        csv_reader = csv.reader(decoded_data.splitlines())
        rows = list(csv_reader)
        # Perform actions with CSV data
        logging.info("Received CSV data: %s", rows)
        # Here you can implement the desired processing
    
    def process_text(self, data):
        # Example text processing
        logging.info("Received text data: %s", data)
        # Here you can implement the desired processing

    def process_xml(self, data):
        # Example XML processing
        logging.info("Received XML data: %s", data)
        # Here you can implement the desired processing

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./server.pem', server_side=True) # <- Replace with your SSL certificate
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()


##
##
