#!/usr/bin/env python

# Example server used to test Simple-CSRF-script.py and Advanced-CSRF-script.py
# GET creates the token
# POST verifies itand creates a new one

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser
import string, random, re



html = """
<!DOCTYPE html>
<html>
<body>
<form action="/" method="POST">
  Change address<br>
  <input type="text" name="street" placeholder="Street">
  <br>
  <input type="text" name="city" placeholder="City">
  <br>
  <input type="text" name="zip" placeholder="ZIP">
  <br>
  <small>
  <br>New Token<br>
  <input type="text" name="CSRFtoken" value="$token">
  <small>
  <br><br>
  <input type="submit" value="Submit">
  
  <br>Message<br>
  <textarea>$message</textarea>
</form> 
</body>
</html>
"""

class RequestHandler(BaseHTTPRequestHandler):
	token=""
	
	def do_GET(self):
		new_token = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])

		self.token = new_token
		print "token new "+self.token
		
		response = string.Template(html)
		response = response.substitute(token=new_token, message="")
		
		self.send_response(200)
		#self.send_header("Set-Cookie", "foo=bar")
		self.end_headers()
		self.wfile.write(response)
	
	def do_POST(self):
		
		request_path = self.path

		request_headers = self.headers
		content_length = request_headers.getheaders('content-length')
		length = int(content_length[0]) if content_length else 0
		
		post_body = self.rfile.read(length)
		
		print "token searched "+self.token

		search =  re.compile("CSRFtoken=\"("+self.token+")\"")
		match = search.findall(post_body) 
		
		self.send_response(200)

		
		if match:
			expired_token = match[0]
			print "token found "+expired_token
			message="Token was OK "+ expired_token
		else:
			message="No valid token found"
		
		new_token = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
		self.token = new_token
		
		response = string.Template(html)
		response = response.substitute(token=new_token, message=message)
		print "token rereshed "+self.token
		self.end_headers()
		self.wfile.write(response)
	
	do_PUT = do_POST
	do_DELETE = do_GET
		
def main():
	port = 9090

	print('Listening on :%s' % port)
	server = HTTPServer(('', port), RequestHandler)
	server.serve_forever()

		
if __name__ == "__main__":
	print("Main")
	
main()
