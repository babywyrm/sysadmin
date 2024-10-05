#!/usr/bin/env python3

##
## OG__ https://github.com/riramar/DesyncCL0
##

#!/usr/bin/env python3

import sys
import base64
import argparse
import socket
import ssl
from urllib.parse import urlparse
from http.client import HTTPResponse
from io import BytesIO

__version__ = '0.0.2'


class FakeSocket():
    """A helper class to simulate a socket from response bytes."""
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file


def print_banner():
    """Prints the program banner and version."""
    banner = (
        'ICAgIF9fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9fX19fX19fICAgIF9fX18gCiAgIC8gX18gXF9fXyAgX19fX19fXyAgX19fX19f'
        'ICBfX19fXy8gX19fXy8gLyAgIC8gX18gXAogIC8gLyAvIC8gXyBcLyBfX18vIC8gLyAvIF9fIFwvIF9fXy8gLyAgIC8gLyAgIC8gLyAvIC8KIC8g'
        'L18vIC8gIF9fKF9fICApIC9fLyAvIC8gLyAvIC9fXy8gL19fXy8gL19fXy8gL18vIC8gCi9fX19fXy9cX19fL19fX18vXF9fLCAvXy8gL18vXF9f'
        'Xy9cX19fXy9fX19fXy9cX19fXy8gIAogICAgICAgICAgICAgICAgL19fX18vICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA='
    )
    print(base64.b64decode(banner).decode('UTF-8'))
    print('Version ' + __version__)


def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        prog='DesyncCL0', 
        description='Detects HTTP desync CL.0 vulnerabilities.'
    )
    parser.add_argument('URL', type=check_url, help='The URL to be checked.')
    parser.add_argument(
        '-s', '--smuggledrequestline',
        default='GET /hopefully404 HTTP/1.1',
        help='Set the smuggled request line (default "GET /hopefully404 HTTP/1.1").'
    )
    parser.add_argument(
        '-t', '--timeout', type=int, default=5, 
        help='Set connection timeout for desync test (default 5).'
    )
    parser.add_argument(
        '-u', '--user_agent', 
        default=('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                 '(KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'),
        help='Set default User-Agent request header.'
    )
    parser.add_argument(
        '-d', '--debug', 
        action=argparse.BooleanOptionalAction, default=False, 
        help='Print debug data.'
    )
    return parser.parse_args()


def check_url(url):
    """Validates and parses the given URL."""
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ['http', 'https'] or not parsed_url.netloc:
        raise argparse.ArgumentTypeError(f'Invalid URL: {url}. Example: https://www.example.com/path')
    return parsed_url


def connect(URL, timeout):
    """Creates a socket connection to the server (supports HTTP/HTTPS)."""
    hostname = URL.netloc.split(':')[0]
    port = URL.port if URL.port else (443 if URL.scheme == 'https' else 80)

    if URL.scheme == 'https':
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((hostname, port), timeout)
        return context.wrap_socket(sock, server_hostname=hostname)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((hostname, port))
        return sock


def send_request(sock, request, debug=False):
    """Sends an HTTP request and retrieves the response."""
    sock.sendall(request)
    response = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            fake_socket = FakeSocket(response)
            http_response = HTTPResponse(fake_socket)

            try:
                http_response.begin()
                content_length = http_response.getheader('Content-Length')
                if content_length:
                    body = http_response.read(int(content_length))
                    if len(body) == int(content_length):
                        break
                elif http_response.getheader('Transfer-Encoding'):
                    if b'0\r\n\r\n' in chunk:
                        break
            except:
                continue
        except socket.error as err:
            print(f'ERROR! Raw Response: {response}')
            print(err)
            sys.exit(1)

    if not response:
        print('ERROR! Got a blank response from the server.')
        sys.exit(1)
    return http_response, response


def cl0_check(URL, smuggled_request, user_agent, timeout, debug):
    """Performs HTTP Desync CL.0 vulnerability testing."""
    hostname = URL.netloc
    path = URL.path or '/'
    query = '?' + URL.query if URL.query else ''
    fragment = '#' + URL.fragment if URL.fragment else ''
    
    # Generate and send requests for testing desync
    request_smuggled = f"{smuggled_request}\r\nFoo: x\r\n"
    request_root = build_request('GET', '/', hostname, user_agent)

    if debug:
        print(f"Request 404 (Smuggled): {request_smuggled}")
        print(f"Request Root: {request_root}")
    
    # Test request with the smuggled request line
    sock = connect(URL, timeout)
    http_response_404, body_404 = send_request(sock, request_smuggled + request_root, debug)
    sock.close()

    # Test root request without smuggling
    sock = connect(URL, timeout)
    http_response_root, body_root = send_request(sock, request_root, debug)
    sock.close()

    # Check for HTTP desync vulnerability by comparing responses
    check_vulnerability(http_response_404, http_response_root, debug)


def build_request(method, path, host, user_agent, content_length=None):
    """Builds a standard HTTP request string."""
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Connection: close"
    ]
    if content_length:
        headers.append(f"Content-Length: {content_length}")
    headers.append('\r\n')
    return '\r\n'.join(headers)


def check_vulnerability(response_404, response_root, debug):
    """Checks if the server is vulnerable to HTTP desync attacks."""
    if response_404.status == response_root.status:
        print("Not vulnerable.")
    elif response_404.status != response_root.status:
        print("WARNING! Possible vulnerability detected. Inconsistent responses.")
        if debug:
            print(f"Response 404: {response_404.status}, Response Root: {response_root.status}")
    else:
        print("Further analysis is required.")


def main():
    """Main function to initiate the Desync CL.0 test."""
    if sys.version_info < (3, 9):
        print("Error: Requires Python 3.9 or later.")
        sys.exit(1)

    print_banner()
    args = parse_args()
    print(f'Testing URL: {args.URL.geturl()}')
    print('Testing for CL.0 vulnerability...')

    cl0_check(args.URL, args.smuggledrequestline, args.user_agent, args.timeout, args.debug)


if __name__ == '__main__':
    main()

##
##
