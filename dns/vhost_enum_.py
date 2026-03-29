#!/usr/bin/env python3

import argparse
import hashlib
import logging
import queue
import sys
import threading
import time
from dataclasses import dataclass, field

import requests
import urllib3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class CustomFormatter(logging.Formatter):
    _FORMATS = {
        logging.DEBUG:   "DEBUG: %(msg)s",
        logging.INFO:    "[+] %(msg)s",
        logging.WARNING: "[!] %(msg)s",
        logging.ERROR:   "[-] %(msg)s",
    }

    def format(self, record: logging.LogRecord) -> str:
        fmt = self._FORMATS.get(record.levelno, "%(msg)s")
        return logging.Formatter(fmt).format(record)


def setup_logging(verbose: bool) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CustomFormatter())
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.DEBUG if verbose else logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    ip: str
    domain: str
    wordlist: str = "./vhosts.txt"
    tls: bool = False
    port: str | None = None
    baseline: str = "www"
    threads: int = 10
    verbose: bool = False

    @property
    def prefix(self) -> str:
        return "https://" if self.tls else "http://"

    @property
    def base_url(self) -> str:
        url = f"{self.prefix}{self.ip}"
        return f"{url}:{self.port}" if self.port else url


def parse_args() -> Config:
    parser = argparse.ArgumentParser(description="Virtual host enumerator")
    parser.add_argument("-w", "--wordlist", default="./vhosts.txt")
    parser.add_argument("-s", "--tls", action="store_true", help="Use HTTPS")
    parser.add_argument("-i", "--ip", required=True)
    parser.add_argument("-p", "--port")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-b", "--baseline", default="www")
    parser.add_argument("-t", "--threads", default=10, type=int)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    return Config(**vars(args))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

@dataclass
class PageFingerprint:
    length: int
    digest: str

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PageFingerprint):
            return NotImplemented
        return self.length == other.length and self.digest == other.digest


def fetch_fingerprint(
    session: requests.Session,
    url: str,
    hostname: str,
) -> PageFingerprint | None:
    try:
        response = session.get(url, verify=False, headers={"Host": hostname})
    except requests.exceptions.SSLError:
        logging.error(f"{url} — SSL error (is the site actually using TLS?)")
        return None
    except requests.exceptions.ConnectionError as exc:
        logging.error(f"Connection failed for {url}:\n{exc}")
        return None
    except requests.exceptions.InvalidURL:
        logging.error(f"Invalid URL: {url}")
        return None

    if response.status_code != 200:
        logging.debug(f"{hostname} → HTTP {response.status_code}")
        return None

    digest = hashlib.sha256(response.content).hexdigest()
    return PageFingerprint(length=len(response.content), digest=digest)


# ---------------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------------

def load_wordlist(path: str) -> list[str]:
    try:
        text = open(path).read()
    except FileNotFoundError:
        logging.error(f"Wordlist not found: {path}")
        sys.exit(1)

    words = {w.lower() for w in text.splitlines() if w.strip()}
    return sorted(words)


def build_queue(words: list[str]) -> queue.Queue[str]:
    logging.info("Generating wordlist queue...")
    q: queue.Queue[str] = queue.Queue()
    for word in words:
        q.put(word)
    logging.info(f"Loaded {q.qsize()} words.")
    return q


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

@dataclass
class ScanState:
    confirmed: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, vhost: str) -> None:
        with self._lock:
            self.confirmed.append(vhost)


def worker(
    word_queue: queue.Queue[str],
    session: requests.Session,
    config: Config,
    baseline: PageFingerprint,
    state: ScanState,
) -> None:
    while True:
        try:
            word = word_queue.get_nowait()
        except queue.Empty:
            break

        hostname = f"{word}.{config.domain}"
        fp = fetch_fingerprint(session, config.base_url, hostname)

        if fp is None:
            continue

        if fp != baseline:
            logging.info(f"{hostname} → 200, unique content (possible vhost!)")
            state.add(hostname)
        else:
            logging.debug(f"{hostname} → 200, same content as baseline")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    config = parse_args()
    setup_logging(config.verbose)

    words = load_wordlist(config.wordlist)
    word_queue = build_queue(words)

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=100,
        pool_maxsize=max(len(words), config.threads),
    )
    session.mount(config.prefix, adapter)

    logging.info(f"Establishing baseline via {config.baseline}.{config.domain}...")
    baseline = fetch_fingerprint(
        session, config.base_url, f"{config.baseline}.{config.domain}"
    )
    if baseline is None:
        logging.error(
            f"Baseline failed — check that {config.baseline}.{config.domain} "
            f"is reachable and the port/protocol is correct."
        )
        sys.exit(1)

    logging.info(
        f"Baseline: {config.baseline}.{config.domain} → "
        f"{baseline.length} bytes, sha256={baseline.digest}"
    )

    state = ScanState()
    logging.info(f"Spawning {config.threads} thread(s)...")
    start = time.perf_counter()

    threads = [
        threading.Thread(
            target=worker,
            args=(word_queue, session, config, baseline, state),
            daemon=True,
        )
        for _ in range(config.threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = time.perf_counter() - start
    logging.info(f"Finished in {elapsed:.2f}s")

    unique = sorted(set(state.confirmed))
    if unique:
        logging.info("Discovered virtual hosts:")
        for vhost in unique:
            print(f"  * {vhost}")
    else:
        logging.warning("No virtual hosts discovered.")


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
