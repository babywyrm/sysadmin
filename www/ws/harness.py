#!/usr/bin/python


##
## https://raw.githubusercontent.com/VDA-Labs/websocket-harness/master/websocket-harness.py
##

import socket,ssl
import argparse
import os
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from websocket import create_connection, WebSocket
from SocketServer import ThreadingMixIn
import threading
import websocket

class WSWebServer(BaseHTTPRequestHandler):

    # Handler for POST requests
    def do_POST(self):
        content_len = int(self.headers.getheader('content-length', 0))
        post_fuzz_body = self.rfile.read(content_len)
        fuzz_result = FuzzWebSocket(post_fuzz_body)
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write(fuzz_result)
        return

    # Handler for the GET requests
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write("WebSocket Fuzzing Harness: Please use POST request!")
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def FuzzWebSocket(fuzz_payload):
    # send and recieve a request
    try:
        ws.send(fuzz_payload)
        fuzz_result =  ws.recv()
        return fuzz_result
    except websocket.WebSocketConnectionClosedException as e:
        print 'Error:',e.args

parser = argparse.ArgumentParser(description='Web Socket Harness: Use traditional pentest tools to assess web sockets')
parser.add_argument('-u','--url', help='The remote WebSocket URL to target. Example: ws://127.0.0.1:8000/method-to-fuzz.', required=True)
parser.add_argument('-p','--port', help='The port to bind to.', required=True, default=8000)
args = parser.parse_args()

ws = create_connection(args.url,sslopt={"cert_reqs": ssl.CERT_NONE},header={},http_proxy_host="", http_proxy_port=8080)

try:
    # Setting up web harness/proxy server
    server = ThreadedHTTPServer(('', int(args.port)), WSWebServer)
    print 'WebSocket Harness: Successful bind on port', args.port
    
    # Wait forever for incoming http requests
    server.serve_forever()

except KeyboardInterrupt:
    print 'WebSocket Harness: Exit command recieved. Shutting down...'
    server.socket.close()
    ws.close()


##
##
