#!/usr/bin/env python
"""
Simple HTTP URL redirector
Shreyas Cholia 10/01/2015
usage: redirect.py [-h] [--port PORT] [--ip IP] redirect_url
HTTP redirect server
positional arguments:
  redirect_url
optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -p PORT  port to listen on
  --ip IP, -i IP        host interface to listen on
"""
import SimpleHTTPServer
import SocketServer
import sys
import argparse



def redirect_handler_factory(url):
    """
    Returns a request handler class that redirects to supplied `url`
    """
    class RedirectHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
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
    
    handler = SocketServer.TCPServer((host, port), redirectHandler)
    print("serving at port %s" % port)
    handler.serve_forever()

if __name__ == "__main__":
    main()
    
###################
##
##    


######################
######################


#!/usr/bin/env python3

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print(f"THIS WAY: {sys.argv[0]} <port_number> <url>")
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.send_response(302)
       self.send_header('Location', sys.argv[2])
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()


######################
######################
