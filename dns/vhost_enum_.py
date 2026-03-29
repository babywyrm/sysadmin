#!/usr/bin/env python3
"""
vhost_enum.py — Virtual Host Enumerator
========================================

A multithreaded tool for discovering virtual hosts on a target server by
sending HTTP requests with different Host headers and comparing responses
against a known-good baseline fingerprint.

How it works
------------
1. A baseline fingerprint (content length + SHA-256 hash) is captured from
   a known subdomain (default: ``www.<domain>``).
2. Words from a wordlist are distributed across a thread pool.
3. Each thread sends a request with ``Host: <word>.<domain>`` to the target IP.
4. If the response differs from the baseline, the subdomain is flagged.

Requirements
------------
    pip install requests urllib3

Basic usage
-----------
Enumerate vhosts on 10.10.10.10 for domain example.com over HTTP::

    python vhost_enum.py -i 10.10.10.10 -d example.com

Use HTTPS on a non-standard port with a custom wordlist and 20 threads::

    python vhost_enum.py -i 10.10.10.10 -d example.com -s -p 8443 \\
        -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\
        -t 20

Use a different baseline subdomain (default is ``www``)::

    python vhost_enum.py -i 10.10.10.10 -d example.com -b portal

Enable verbose/debug output::

    python vhost_enum.py -i 10.10.10.10 -d example.com -v

Tips & common pitfalls
----------------------
- **Wordlist quality matters.** Tools like SecLists provide well-curated
  wordlists. Avoid using raw DNS zone dumps as they can contain invalid
  hostnames that skew results.

- **Baseline choice.** The baseline subdomain must return HTTP 200. If your
  target doesn't have a ``www`` subdomain, use ``-b`` to set one that does,
  e.g. ``-b mail``.

- **False positives.** Some servers return unique content per request (e.g.
  CSRF tokens embedded in the page). In that case, length-only comparison may
  be more reliable — consider filtering by length delta rather than exact hash.

- **Self-signed / internal TLS.** Use ``-s`` for HTTPS targets. Certificate
  verification is intentionally disabled (``verify=False``) for internal/lab
  use. Do not use this tool against production systems you do not own or have
  explicit written permission to test.

- **Rate limiting / WAFs.** Reduce thread count (``-t 1``) and add a delay
  if the target rate-limits or blocks you. This tool does not implement
  request throttling by default.

- **IPv6 targets.** Wrap the address in brackets, e.g. ``-i [::1]``.

Exit codes
----------
0   Completed successfully (vhosts may or may not have been found).
1   Fatal error (bad wordlist path, unreachable baseline, etc.).

Legal notice
------------
This tool is intended for authorised security assessments and CTF/lab
environments only. Unauthorised use against systems you do not own or have
explicit written permission to test may be illegal in your jurisdiction.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import queue
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, NamedTuple

import requests
import requests.adapters
import urllib3

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WORDLIST: Final[str] = "./vhosts.txt"
DEFAULT_BASELINE: Final[str] = "www"
DEFAULT_THREADS: Final[int] = 10
DEFAULT_TIMEOUT: Final[float] = 10.0  # seconds per request

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class CustomFormatter(logging.Formatter):
    """
    Emit log lines with a short prefix based on severity.

    Level   Prefix   Intended audience
    ------  -------  -----------------------------------------
    DEBUG   DEBUG:   Internal state; enabled with ``-v``
    INFO    [+]      Normal progress and discoveries
    WARNING [!]      Non-fatal issues worth noting
    ERROR   [-]      Failures that affect results
    """

    _FORMATS: Final[dict[int, str]] = {
        logging.DEBUG:   "DEBUG: %(msg)s",
        logging.INFO:    "[+] %(msg)s",
        logging.WARNING: "[!] %(msg)s",
        logging.ERROR:   "[-] %(msg)s",
    }

    def format(self, record: logging.LogRecord) -> str:
        fmt = self._FORMATS.get(record.levelno, "%(msg)s")
        return logging.Formatter(fmt).format(record)


def setup_logging(*, verbose: bool) -> None:
    """Configure the root logger. Must be called once before any logging."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CustomFormatter())
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Suppress noisy connection-pool messages from urllib3
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Config:
    """
    Immutable, validated runtime configuration.

    Attributes
    ----------
    ip:
        Target IP address (or hostname). IPv6 addresses must include brackets,
        e.g. ``[::1]``.
    domain:
        The apex domain to enumerate, e.g. ``example.com``.
    wordlist:
        Path to a newline-delimited list of subdomain candidates.
    tls:
        When ``True``, use HTTPS. Certificate verification is skipped for
        internal/lab targets.
    port:
        Optional non-standard port. When ``None`` the scheme default is used.
    baseline:
        Subdomain used to capture the baseline fingerprint. Must return
        HTTP 200. Defaults to ``www``.
    threads:
        Worker thread count. Keep this reasonable — very high values may
        trigger rate-limiting on the target.
    verbose:
        Enable DEBUG-level logging.
    timeout:
        Per-request timeout in seconds.
    """

    ip: str
    domain: str
    wordlist: str = DEFAULT_WORDLIST
    tls: bool = False
    port: str | None = None
    baseline: str = DEFAULT_BASELINE
    threads: int = DEFAULT_THREADS
    verbose: bool = False
    timeout: float = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if self.threads < 1:
            raise ValueError(f"threads must be >= 1, got {self.threads}")
        if self.timeout <= 0:
            raise ValueError(f"timeout must be > 0, got {self.timeout}")
        if not self.ip:
            raise ValueError("ip must not be empty")
        if not self.domain:
            raise ValueError("domain must not be empty")

    @property
    def prefix(self) -> str:
        """URL scheme prefix, e.g. ``'https://'``."""
        return "https://" if self.tls else "http://"

    @property
    def base_url(self) -> str:
        """
        Fully-formed base URL to send requests to.

        Examples::

            http://10.10.10.10
            https://10.10.10.10:8443
        """
        url = f"{self.prefix}{self.ip}"
        return f"{url}:{self.port}" if self.port else url


def parse_args() -> Config:
    """Parse ``sys.argv`` and return a validated :class:`Config`."""
    parser = argparse.ArgumentParser(
        prog="vhost_enum.py",
        description="Multithreaded virtual host enumerator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -i 10.10.10.10 -d example.com\n"
            "  %(prog)s -i 10.10.10.10 -d example.com -s -p 8443 -t 20\n"
            "  %(prog)s -i 10.10.10.10 -d example.com -b portal -v\n"
        ),
    )
    parser.add_argument(
        "-w", "--wordlist",
        default=DEFAULT_WORDLIST,
        metavar="PATH",
        help=f"Wordlist file (default: {DEFAULT_WORDLIST})",
    )
    parser.add_argument(
        "-s", "--tls",
        action="store_true",
        help="Use HTTPS (certificate verification is skipped)",
    )
    parser.add_argument(
        "-i", "--ip",
        required=True,
        metavar="ADDR",
        help="Target IP address (IPv6: use bracket notation, e.g. [::1])",
    )
    parser.add_argument(
        "-p", "--port",
        metavar="PORT",
        help="Custom port (default: 80 for HTTP, 443 for HTTPS)",
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        metavar="DOMAIN",
        help="Apex domain to enumerate (e.g. example.com)",
    )
    parser.add_argument(
        "-b", "--baseline",
        default=DEFAULT_BASELINE,
        metavar="SUB",
        help=f"Baseline subdomain that must return HTTP 200 (default: {DEFAULT_BASELINE})",
    )
    parser.add_argument(
        "-t", "--threads",
        default=DEFAULT_THREADS,
        type=int,
        metavar="N",
        help=f"Worker thread count (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout",
        default=DEFAULT_TIMEOUT,
        type=float,
        metavar="SECS",
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG output",
    )

    args = parser.parse_args()
    try:
        return Config(**vars(args))
    except ValueError as exc:
        parser.error(str(exc))


# ---------------------------------------------------------------------------
# HTTP / fingerprinting
# ---------------------------------------------------------------------------


class PageFingerprint(NamedTuple):
    """
    Immutable snapshot of a page's identity.

    Two fingerprints are equal only when *both* the content length and the
    SHA-256 digest match — i.e. the page bytes are identical.

    Attributes
    ----------
    length:
        ``Content-Length`` in bytes (derived from the actual response body).
    digest:
        Lowercase hex-encoded SHA-256 of the response body.
    """

    length: int
    digest: str


def _sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def fetch_fingerprint(
    session: requests.Session,
    url: str,
    hostname: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> PageFingerprint | None:
    """
    Fetch *url* with a spoofed ``Host`` header and return a fingerprint.

    Returns ``None`` on any network error or non-200 response so callers
    can treat ``None`` as "no usable result" without extra branching.

    Parameters
    ----------
    session:
        A shared :class:`requests.Session` (connection pooling).
    url:
        The raw URL to request, e.g. ``http://10.10.10.10:8080``.
    hostname:
        The value to send in the ``Host`` header, e.g. ``admin.example.com``.
    timeout:
        Seconds to wait before aborting the request.
    """
    try:
        response = session.get(
            url,
            verify=False,
            headers={"Host": hostname},
            timeout=timeout,
            allow_redirects=False,  # don't follow redirects — they skew results
        )
    except requests.exceptions.SSLError:
        logging.error(
            f"{url} — SSL error. "
            "Is the target actually using TLS? Try adding or removing -s."
        )
        return None
    except requests.exceptions.ConnectionError as exc:
        logging.error(f"Connection failed for {url}: {exc}")
        return None
    except requests.exceptions.Timeout:
        logging.error(f"Request to {url} timed out after {timeout}s")
        return None
    except requests.exceptions.InvalidURL:
        logging.error(f"Invalid URL: {url!r}")
        return None

    if response.status_code != 200:
        logging.debug(f"{hostname} → HTTP {response.status_code} (skipping)")
        return None

    return PageFingerprint(
        length=len(response.content),
        digest=_sha256_hex(response.content),
    )


# ---------------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------------


def load_wordlist(path: str) -> list[str]:
    """
    Read *path* and return a de-duplicated, sorted list of candidate words.

    - Empty lines and whitespace-only lines are stripped.
    - All words are lowercased.
    - Duplicates are removed via a set before sorting.

    Exits with code 1 if the file cannot be found.
    """
    resolved = Path(path)
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logging.error(f"Wordlist not found: {resolved}")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied reading wordlist: {resolved}")
        sys.exit(1)

    words = sorted({w.lower() for w in text.splitlines() if w.strip()})
    logging.debug(f"Read {len(words)} unique words from {resolved}")
    return words


def build_queue(words: list[str]) -> queue.Queue[str]:
    """Populate and return a :class:`queue.Queue` from *words*."""
    logging.info("Generating wordlist queue...")
    q: queue.Queue[str] = queue.Queue()
    for word in words:
        q.put(word)
    logging.info(f"Loaded {q.qsize()} words.")
    return q


# ---------------------------------------------------------------------------
# Scan state
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ScanState:
    """
    Thread-safe container for scan results.

    Attributes
    ----------
    confirmed:
        Hostnames that returned a response fingerprint differing from the
        baseline. Access via :meth:`add` and :meth:`results`.
    """

    _confirmed: list[str] = field(default_factory=list, init=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    def add(self, vhost: str) -> None:
        """Append *vhost* to the confirmed list (thread-safe)."""
        with self._lock:
            self._confirmed.append(vhost)

    @property
    def results(self) -> list[str]:
        """Return a sorted, de-duplicated snapshot of confirmed vhosts."""
        with self._lock:
            return sorted(set(self._confirmed))


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


def worker(
    word_queue: queue.Queue[str],
    session: requests.Session,
    config: Config,
    baseline: PageFingerprint,
    state: ScanState,
) -> None:
    """
    Drain *word_queue* and probe each candidate subdomain.

    Each iteration:
    1. Pops a word from the queue (exits cleanly when the queue is empty).
    2. Fetches ``<word>.<domain>`` via the spoofed Host header.
    3. Compares the fingerprint against *baseline*.
    4. Records any differing fingerprints in *state*.

    This function is designed to be the ``target`` of a :class:`threading.Thread`.
    """
    while True:
        try:
            word = word_queue.get_nowait()
        except queue.Empty:
            break

        hostname = f"{word}.{config.domain}"
        fp = fetch_fingerprint(
            session, config.base_url, hostname, timeout=config.timeout
        )

        if fp is None:
            continue

        if fp != baseline:
            logging.info(
                f"{hostname} → 200, content differs from baseline "
                f"(len={fp.length}, sha256={fp.digest[:12]}…)"
            )
            state.add(hostname)
        else:
            logging.debug(f"{hostname} → 200, matches baseline (skipping)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    config = parse_args()
    setup_logging(verbose=config.verbose)

    words = load_wordlist(config.wordlist)
    if not words:
        logging.error("Wordlist is empty after de-duplication. Aborting.")
        sys.exit(1)

    word_queue = build_queue(words)

    # Build a shared session with a pool large enough for all threads
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=config.threads,
        pool_maxsize=config.threads,
    )
    session.mount(config.prefix, adapter)

    # Establish baseline
    baseline_host = f"{config.baseline}.{config.domain}"
    logging.info(f"Establishing baseline via {baseline_host} ...")
    baseline = fetch_fingerprint(
        session, config.base_url, baseline_host, timeout=config.timeout
    )
    if baseline is None:
        logging.error(
            f"Baseline failed for {baseline_host}. "
            "Verify the subdomain exists, the port is correct, "
            "and that you have included/omitted -s appropriately."
        )
        sys.exit(1)

    logging.info(
        f"Baseline established: {baseline_host} → "
        f"{baseline.length} bytes, sha256={baseline.digest}"
    )

    state = ScanState()
    logging.info(f"Spawning {config.threads} worker thread(s) ...")
    start = time.perf_counter()

    threads = [
        threading.Thread(
            target=worker,
            args=(word_queue, session, config, baseline, state),
            daemon=True,
            name=f"vhost-worker-{i}",
        )
        for i in range(config.threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = time.perf_counter() - start
    logging.info(f"Scan completed in {elapsed:.2f}s")

    found = state.results
    if found:
        logging.info(f"Discovered {len(found)} virtual host(s):")
        for vhost in found:
            print(f"  * {vhost}")
    else:
        logging.warning("No virtual hosts discovered.")

    sys.exit(0)


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
