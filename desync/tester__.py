#!/usr/bin/env python3

##
## https://github.com/riramar/DesyncCL0
##

__version__ = '0.0.1'
import sys
import base64
import argparse
import socket
import ssl
import random
from urllib.parse import urlparse, parse_qsl
from http.client import HTTPResponse
from io import BytesIO


class FakeSocket():
	def __init__(self, response_bytes):
		self._file = BytesIO(response_bytes)
	def makefile(self, *args, **kwargs):
		return self._file


def send_request(sock, request):
	sock.sendall(request)
	response = b''
	while True:
		try:
			chunk = sock.recv(4096)
			if not chunk:
				break
			else:
				response = response + chunk
				source = FakeSocket(response)
				httpresponse = HTTPResponse(source)
				try:
					httpresponse.begin()
					if httpresponse.getheader('Content-Length'):
						CL = int(httpresponse.getheader('Content-Length'))
						body = httpresponse.read(CL)
						if CL == len(body):
							break
						else:
							continue
					elif httpresponse.getheader('Transfer-Encoding'):
						body = httpresponse.read(len(response))
						if b'0\r\n\r\n' in chunk:
							break
						else:
							continue
				except:
					continue
		except socket.error as err:
			print('ERROR! Raw Response:', response)
			print(err)
			exit(1)
	if response == b'':
		print('ERROR! Got a blank response from the server.')
		exit(1)
	elif 'body' not in locals():
		body = b''
	return httpresponse, body


def cl0_check(URL, SRL,user_agent, timeout, debug):
	hostname = URL.netloc
	if URL.path == '':
		path = '/'
	else:
		path = URL.path + ('?' + URL.query if URL.query else '')  + ('#' + URL.fragment if URL.fragment else '')

	# >>>>> request404
	requestSmuggled = SRL + '\r\n'
	requestSmuggled = requestSmuggled + 'Foo: x'
	requestRoot = 'GET / HTTP/1.1\r\n'
	requestRoot = requestRoot + 'Host: ' + hostname + '\r\n'
	requestRoot = requestRoot + 'User-Agent: ' + user_agent + '\r\n'
	requestRoot = requestRoot + 'Connection: close\r\n'
	requestRoot = requestRoot + '\r\n'
	request404 = requestSmuggled + requestRoot
	if debug:
		print(">>>>> request404")
		print(request404)
		print(">>>>> request404")
	sock = connect(URL, timeout)
	httpresponse404, body404 = send_request(sock, request404.encode('utf-8'))
	sock.close()
	if debug:
		print(">>>>> httpresponse404")
		print("status404:", httpresponse404.status)
		print("headers404:", httpresponse404.getheaders())
		print("body404:", body404)
		print("<<<<< httpresponse404")
	# <<<<< request404

	# >>>>> requestRoot
	if debug:
		print(">>>>> requestRoot")
		print(requestRoot)
		print("<<<<< requestRoot")
	sock = connect(URL, timeout)
	httpresponseRoot, bodyRoot = send_request(sock, requestRoot.encode('utf-8'))
	sock.close()
	if debug:
		print(">>>>> httpresponseRoot")
		print("statusRoot:", httpresponseRoot.status)
		print("headersRoot:", httpresponseRoot.getheaders())
		print("bodyRoot:", bodyRoot)
		print("<<<<< httpresponseRoot")
	# <<<<< requestRoot

	# >>>>> requestDesync
	requestDesync = 'POST ' + path + ' HTTP/1.1\r\n'
	requestDesync = requestDesync + 'Host: ' + hostname + '\r\n'
	requestDesync = requestDesync + 'User-Agent: ' + user_agent + '\r\n'
	requestDesync = requestDesync + 'Content-Length: ' + str(len(requestSmuggled)) + '\r\n'
	requestDesync = requestDesync + 'Connection: keep-alive\r\n'
	requestDesync = requestDesync + 'Content-Type: application/x-www-form-urlencoded\r\n'
	requestDesync = requestDesync + '\r\n'
	requestDesync = requestDesync + requestSmuggled
	if debug:
		print(">>>>> requestDesync")
		print(requestDesync)
		print("<<<<< requestDesync")
	sock = connect(URL, timeout)
	httpresponseDesync, bodyDesync = send_request(sock, requestDesync.encode('utf-8'))
	if debug:
		print(">>>>> httpresponseDesync")
		print("statusDesync:", httpresponseDesync.status)
		print("headersDesync:", httpresponseDesync.getheaders())
		print("bodyDesync:", bodyDesync)
		print("<<<<< httpresponseDesync")
	# <<<<< requestDesync

	# >>>>> requestRootSmuggled
	requestRootSmuggled = requestRoot
	if debug:
		print(">>>>> requestRootSmuggled")
		print(requestRootSmuggled)
		print("<<<<< requestRootSmuggled")
	httpresponseRootSmuggled, bodyRootSmuggled = send_request(sock, requestRootSmuggled.encode('utf-8'))
	sock.close()
	if debug:
		print(">>>>> httpresponseRootSmuggled")
		print("statusRootSmuggled:", httpresponseRootSmuggled.status)
		print("headersRootSmuggled:", httpresponseRootSmuggled.getheaders())
		print("bodyRootSmuggled:", bodyRootSmuggled)
		print("<<<<< httpresponseRootSmuggled")
	# <<<<< requestRootSmuggled

	if httpresponseRootSmuggled.status == httpresponse404.status and httpresponseRootSmuggled.status != httpresponseRoot.status:
		print('WARNING! Back-end server interpreted the body of the POST request as the start of another request.')
	elif httpresponseRootSmuggled.status == httpresponseRoot.status and httpresponseRootSmuggled.status == httpresponse404.status and str(httpresponseRootSmuggled.status).startswith('3') and httpresponseRootSmuggled.getheader('Location') != httpresponseRoot.getheader('Location'):
		print('WARNING! Probably vulnerable due different redirects.')
		print('httpresponse404', httpresponse404.getheader('Location'))
		print('httpresponseRoot', httpresponseRoot.getheader('Location'))
		print('httpresponseRootSmuggled', httpresponseRootSmuggled.getheader('Location'))
		if 'hopefully404' in httpresponseRootSmuggled.getheader('Location'):
			print('httpresponseRootSmuggled contains hopefully404')
	elif httpresponseRootSmuggled.status == httpresponseRoot.status and httpresponseRootSmuggled.status == httpresponse404.status and str(httpresponseRootSmuggled.status).startswith('3') and httpresponseRootSmuggled.getheader('Location') == httpresponseRoot.getheader('Location'):
		print('WARNING! All responses are redirects to the same location.', httpresponseRootSmuggled.getheaders())
		print('Try to debug with an invalid or HEAD method on the smuggled request line.')
	else:
		print('Not vulnerable.')


def connect(URL, timeout):
	hostname = URL.netloc.split(':')[0]
	if URL.scheme == 'https':
		port = 443 if URL.port is None else URL.port
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		sock = socket.create_connection((hostname, port), timeout)
		ssock = context.wrap_socket(sock, server_hostname=hostname)
		return ssock
	elif URL.scheme == 'http':
		port = 80 if URL.port is None else URL.port
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		sock.connect((hostname, port))
		return sock


def check_url(url):
	url_checked = urlparse(url)
	if ((url_checked.scheme != 'http') & (url_checked.scheme != 'https')) | (url_checked.netloc == ''):
		raise argparse.ArgumentTypeError('Invalid %s URL (example: https://www.example.com/path).' % url)
	return url_checked


def Desync():
	if sys.version_info < (3, 9):
		print("Error: requires Python 3.9.")
		sys.exit(1)

	banner = 'ICAgIF9fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9fX19fX19fICAgIF9fX18gCiAgIC8gX18gXF9fXyAgX19fX19fXyAgX19fX19fICBfX19fXy8gX19fXy8gLyAgIC8gX18gXAogIC8gLyAvIC8gXyBcLyBfX18vIC8gLyAvIF9fIFwvIF9fXy8gLyAgIC8gLyAgIC8gLyAvIC8KIC8gL18vIC8gIF9fKF9fICApIC9fLyAvIC8gLyAvIC9fXy8gL19fXy8gL19fXy8gL18vIC8gCi9fX19fXy9cX19fL19fX18vXF9fLCAvXy8gL18vXF9fXy9cX19fXy9fX19fXy9cX19fXy8gIAogICAgICAgICAgICAgICAgL19fX18vICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA='
	print(base64.b64decode(banner).decode('UTF-8'))
	print('version ' + __version__)

	parser = argparse.ArgumentParser(prog='DesyncCL0', description='Detects HTTP desync CL.0 vulnerabilities.')
	parser.add_argument('URL', type=check_url, help='The URL to be checked.')
	parser.add_argument('-s', '--smuggledrequestline', default='GET /hopefully404 HTTP/1.1', help='Set the smuggled request line (default "GET /hopefully404 HTTP/1.1").')
	parser.add_argument('-t', '--timeout', type=int, default=5, help='Set connection timeout for desync test (default 5).')
	parser.add_argument('-u', '--user_agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36', help='Set default User-Agent request header (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36").')
	parser.add_argument('-d', '--debug', action=argparse.BooleanOptionalAction, default=False, help='Print debug data.')
	args = parser.parse_args()
	URL = args.URL
	SRL = args.smuggledrequestline
	timeout = args.timeout
	user_agent = args.user_agent
	debug = args.debug

	print('Testing URL: ' + URL.scheme + '://' + URL.netloc + URL.path + ('?' + URL.query if URL.query else '')  + ('#' + URL.fragment if URL.fragment else ''))
	print('Testing for CL.0 vulnerability...')
	cl0_check(URL, SRL, user_agent, timeout, debug)


if __name__ == '__main__':
	Desync()

##
##
