#!/usr/bin/python3
##
##
##

from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import argparse
 
 
def redirect_handler_factory(url):
    class RedirectHandler(BaseHTTPRequestHandler):
       def do_GET(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()
    return RedirectHandler
            
 
def main():
    parser = argparse.ArgumentParser(description='HTTP redirect server')
    parser.add_argument('--port', '-p', action="store", type=int, default=80, help='port to listen on')
    parser.add_argument('--ip', '-i', action="store", default="", help='host interface to listen on')
    parser.add_argument('redirect_url', action="store")
 
    myargs = parser.parse_args()
    redirect_url = myargs.redirect_url
    port = myargs.port
    host = myargs.ip
    redirectHandler = redirect_handler_factory(redirect_url)
    print("serving at port %s" % port)
    HTTPServer((host, int(port)), redirectHandler).serve_forever()
 
 
if __name__ == "__main__":
    main()
    
    
####################
####################
