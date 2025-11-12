#!/usr/bin/env python3
"""
ffufkit.py — Stage 2 (Part 1)
Secure, typed ffuf wrapper with advanced help and examples.

Author: ChatGPT (Team Refactor)
"""

from __future__ import annotations
import argparse
import csv
import json
import logging
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
def setup_logger(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("ffufkit")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        fmt = "%(asctime)s [%(levelname)s] %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


log = setup_logger()

# ---------------------------------------------------------------------
# Constants / Colors / Helpers
# ---------------------------------------------------------------------
RESET = "\033[0m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
WHITE = "\033[1;37m"

FFUF_BIN = "ffuf"
DEFAULT_THREADS = 40
DEFAULT_OUTDIR = Path("./ffufkit_results")

HELP_EXAMPLES = """
Examples:
  ffufkit run -w common.txt -u https://example.com/FUZZ
  ffufkit run -w params.txt -u "https://example.com/search?q=FUZZ"
  ffufkit run -w payloads.txt -u https://target/login -X POST -d "username=FUZZ&pw=pass"
  ffufkit run -w dirs.txt -u https://target/FUZZ -t 100 -e php,html,txt
  ffufkit presets list
  ffufkit examples show
"""

# ---------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------
def iso_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def safe_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)[:200]


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")


def which(executable: str) -> str:
    from shutil import which as _which
    path = _which(executable)
    if not path:
        raise FileNotFoundError(f"{executable} not found in PATH")
    return path


# ---------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------
@dataclass(slots=True)
class FFufJob:
    wordlist: Path
    target: str
    threads: int = DEFAULT_THREADS
    extensions: List[str] = field(default_factory=list)
    extra_args: List[str] = field(default_factory=list)
    outdir: Path = DEFAULT_OUTDIR
    name: str = field(default_factory=lambda: f"ffufrun-{iso_ts()}")

    def build_cmd(self, json_out: Path) -> List[str]:
        cmd: List[str] = [
            FFUF_BIN,
            "-c",
            "-w",
            str(self.wordlist),
            "-u",
            self.target,
            "-t",
            str(self.threads),
            "-o",
            str(json_out),
            "-of",
            "json",
        ]
        for e in self.extensions:
            if e:
                cmd += ["-e", e]
        if self.extra_args:
            cmd.extend(self.extra_args)
        return cmd


@dataclass(slots=True)
class FFufResult:
    input: str
    url: str
    status: int
    length: int
    words: int
    lines: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------
class FFufRunner:
    def __init__(self) -> None:
        self.path = which(FFUF_BIN)

    def run(self, job: FFufJob) -> Path:
        ensure_dir(job.outdir)
        json_out = job.outdir / f"{safe_filename(job.name)}.json"
        cmd = job.build_cmd(json_out)

        log.info("Running ffuf: %s", shlex.join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            log.error("ffuf binary not found")
            raise

        if proc.returncode != 0:
            log.warning("ffuf exited code %s", proc.returncode)
            if proc.stderr:
                log.debug("stderr: %s", proc.stderr.strip())

        # fallback if ffuf writes JSON to stdout
        if not json_out.exists() and proc.stdout.strip().startswith("{"):
            try:
                data = json.loads(proc.stdout)
                json_out.write_text(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                log.error("Failed to parse ffuf stdout")
        return json_out


# ---------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------
class Parser:
    @staticmethod
    def parse_json(path: Path) -> List[FFufResult]:
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            log.error("JSON parse error: %s", e)
            return []
        hits = data.get("results", [])
        results: List[FFufResult] = []
        for r in hits:
            results.append(
                FFufResult(
                    input=str(r.get("input", "")),
                    url=str(r.get("url", "")),
                    status=int(r.get("status", 0)),
                    length=int(r.get("length", 0)),
                    words=int(r.get("words", 0)),
                    lines=r.get("lines"),
                    raw=r,
                )
            )
        return results


# ---------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------
class Reporter:
    def __init__(self, color: bool = True) -> None:
        self.color = color

    def colorize(self, s: str, color: str) -> str:
        return f"{color}{s}{RESET}" if self.color else s

    def render(self, results: Sequence[FFufResult]) -> str:
        lines: List[str] = []
        for r in sorted(results, key=lambda x: (x.status, -x.length)):
            if 200 <= r.status < 300:
                c = GREEN
            elif 300 <= r.status < 400:
                c = BLUE
            elif 400 <= r.status < 500:
                c = MAGENTA
            elif 500 <= r.status < 600:
                c = RED
            else:
                c = RESET
            lines.append(
                f"{r.url} [Status: {self.colorize(str(r.status), c)}, Size: {r.length}]"
            )
        return "\n".join(lines)

    def summary(self, results: Sequence[FFufResult]) -> Dict[str, int]:
        counts = {"total": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
        for r in results:
            counts["total"] += 1
            if 200 <= r.status < 300:
                counts["2xx"] += 1
            elif 300 <= r.status < 400:
                counts["3xx"] += 1
            elif 400 <= r.status < 500:
                counts["4xx"] += 1
            elif 500 <= r.status < 600:
                counts["5xx"] += 1
        return counts


# ---------------------------------------------------------------------
# Presets & Examples
# ---------------------------------------------------------------------
PRESETS: Dict[str, str] = {
    "xss": "Reflected XSS testing with query fuzzing and header injection.",
    "sqli": "SQL injection payload fuzzing on parameters or POST bodies.",
    "lfi": "Local File Inclusion / path traversal on file parameters.",
    "dir": "Directory and file discovery using extension brute force.",
}


def show_presets() -> None:
    print("Available presets:")
    for k, v in PRESETS.items():
        print(f"  {k:6s} - {v}")
    print("\nUse: ffufkit presets --show <name> to learn more.")


def explain_preset(name: str) -> None:
    info = PRESETS.get(name)
    if not info:
        print(f"Preset not found: {name}")
        return
    print(f"\nPreset '{name}': {info}\n")
    if name == "xss":
        print("Example:")
        print("  ffufkit run -w xss.txt -u 'https://app/test?q=FUZZ'")
    elif name == "sqli":
        print("Example:")
        print("  ffufkit run -w sqli.txt -u 'https://app/item?id=FUZZ'")
    elif name == "lfi":
        print("Example:")
        print("  ffufkit run -w lfi.txt -u 'https://app/view?file=FUZZ'")
    elif name == "dir":
        print("Example:")
        print("  ffufkit run -w dirs.txt -u https://app/FUZZ -e php,html,txt")


def show_examples() -> None:
    print("FFUFKIT EXAMPLES\n")
    print(HELP_EXAMPLES)


# ---------------------------------------------------------------------
# CLI main
# ---------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ffufkit",
        description="Secure, typed ffuf wrapper for pentests",
        epilog="Run `ffufkit examples show` for practical examples.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    # run
    runp = sub.add_parser("run", help="Run ffuf scan with safe defaults")
    runp.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    runp.add_argument("-u", "--url", required=True, help="Target URL (must contain FUZZ)")
    runp.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS)
    runp.add_argument("-e", "--exts", help="Comma-separated extensions (php,html,txt)")
    runp.add_argument("-o", "--outdir", default=str(DEFAULT_OUTDIR))
    runp.add_argument("--extra", nargs=argparse.REMAINDER, help="Extra ffuf args (after --)")
    runp.add_argument("--no-color", action="store_true")
    runp.add_argument("--debug", action="store_true")

    # presets
    pre = sub.add_parser("presets", help="Show built-in fuzzing presets")
    pre.add_argument("--list", action="store_true", help="List presets")
    pre.add_argument("--show", help="Explain a specific preset")

    # examples
    ex = sub.add_parser("examples", help="Show usage examples")
    ex.add_argument("show", nargs="?", default="show", help="Display examples")

    return ap


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "examples":
        show_examples()
        return
    if args.command == "presets":
        if args.list:
            show_presets()
            return
        if args.show:
            explain_preset(args.show)
            return
        show_presets()
        return
    if args.command == "run":
        if args.debug:
            log.setLevel(logging.DEBUG)
        try:
            validate_url(args.url)
        except ValueError as e:
            log.error(str(e))
            sys.exit(2)

        wordlist = Path(args.wordlist)
        if not wordlist.exists():
            log.error("Wordlist not found: %s", wordlist)
            sys.exit(3)

        exts = args.exts.split(",") if args.exts else []
        job = FFufJob(
            wordlist=wordlist,
            target=args.url,
            threads=args.threads,
            extensions=exts,
            extra_args=args.extra or [],
            outdir=Path(args.outdir),
        )
        runner = FFufRunner()
        json_path = runner.run(job)
        results = Parser.parse_json(json_path)
        rep = Reporter(color=not args.no_color)
        output = rep.render(results)
        print(output)
        print()
        print("Summary:", rep.summary(results))
        return


if __name__ == "__main__":
    main()
