#!/usr/bin/python3
##
##
##

import os,sys,re
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
  def do_GET(self):
      self.send_response(302)
      self.send_header('Location', sys.argv[1])
      self.end_headers()

HTTPServer(("0.0.0.0", 80), Redirect).serve_forever()

#########################
##
##
