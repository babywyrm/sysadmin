#!/usr/bin/env python3
"""
ffufkit.py — Stage 1 refactor (secure & strongly-typed)

Purpose:
    Secure, typed, maintainable wrapper around ffuf for pentesting.

Features:
    • Strong type hints & dataclasses
    • Structured logging (DEBUG/INFO/WARN/ERROR)
    • Safe subprocess invocation (no shell=True)
    • URL & path validation
    • Exception-safe parsing of ffuf JSON/CSV
    • Clean architecture ready for multi-module split

Next steps (Stage 2+):
    - Add multi-FUZZ token coordination
    - Add HTML/Markdown dashboards
    - Add plugin interface for validators/reporters
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple, Dict
from urllib.parse import urlparse

# ---------------------------------------------------------------------
# Logging setup
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
# Constants / helpers
# ---------------------------------------------------------------------

RESET = "\033[0m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"

FFUF_BIN = "ffuf"
DEFAULT_THREADS = 40
DEFAULT_OUTDIR = Path("./ffufkit_results")


def iso_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def safe_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)[:200]


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


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
    save_json: bool = True
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
# Core runner
# ---------------------------------------------------------------------

class FFufRunner:
    def __init__(self) -> None:
        self.bin_path = shutil_which(FFUF_BIN)

    def run(self, job: FFufJob) -> Path:
        ensure_dir(job.outdir)
        json_out = job.outdir / f"{safe_filename(job.name)}.json"
        cmd = job.build_cmd(json_out)

        log.info("Running ffuf job: %s", shlex.join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
        except FileNotFoundError:
            log.error("ffuf binary not found: %s", FFUF_BIN)
            raise

        if proc.returncode != 0:
            log.warning("ffuf exited with code %s", proc.returncode)
            if proc.stderr:
                log.debug("stderr: %s", proc.stderr.strip())

        # fallback: if JSON written to stdout
        if not json_out.exists() and proc.stdout.strip().startswith("{"):
            try:
                data = json.loads(proc.stdout)
                json_out.write_text(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                log.error("Failed to parse ffuf stdout as JSON.")
        return json_out


def shutil_which(executable: str) -> str:
    from shutil import which
    path = which(executable)
    if not path:
        raise FileNotFoundError(f"{executable} not found in PATH")
    return path


# ---------------------------------------------------------------------
# Parsing utilities
# ---------------------------------------------------------------------

class Parser:
    @staticmethod
    def parse_json(path: Path) -> List[FFufResult]:
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            log.error("JSON parse error on %s: %s", path, e)
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

    @staticmethod
    def parse_csv(path: Path) -> List[FFufResult]:
        results: List[FFufResult] = []
        try:
            with path.open(newline="", encoding="utf8") as fh:
                reader = csv.reader(fh)
                for row in reader:
                    if not row or "URL" in row[0]:
                        continue
                    joined = ",".join(row)
                    if not re.search(r"\d{3}", joined):
                        continue
                    url = next((c for c in row if c.startswith("http")), "")
                    status = next((int(c) for c in row if re.fullmatch(r"\d{3}", c)), 0)
                    length = next(
                        (int(c) for c in row if c.isdigit() and len(c) > 3), 0
                    )
                    results.append(
                        FFufResult(
                            input=row[0],
                            url=url,
                            status=status,
                            length=length,
                            words=0,
                        )
                    )
        except Exception as e:
            log.error("CSV parse error on %s: %s", path, e)
        return results


# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------

class Reporter:
    def __init__(self, color: bool = True) -> None:
        self.color = color

    def _colorize(self, text: str, color: str) -> str:
        return f"{color}{text}{RESET}" if self.color else text

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
            line = f"{r.url} [Status: {self._colorize(str(r.status), c)}, Size: {r.length}]"
            lines.append(line)
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
# CLI
# ---------------------------------------------------------------------

def run_cli(argv: Optional[Sequence[str]] = None) -> None:
    ap = argparse.ArgumentParser(description="ffufkit — secure ffuf wrapper")
    ap.add_argument("-w", "--wordlist", required=True, help="Wordlist path")
    ap.add_argument("-u", "--url", required=True, help="Target URL (must contain FUZZ)")
    ap.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS)
    ap.add_argument("-e", "--exts", help="Comma-separated extensions (php,html)")
    ap.add_argument("-o", "--outdir", default=str(DEFAULT_OUTDIR))
    ap.add_argument("--extra", nargs=argparse.REMAINDER, help="Extra ffuf args")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--debug", action="store_true")

    args = ap.parse_args(argv)
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

    parser = Parser()
    results = parser.parse_json(json_path)
    reporter = Reporter(color=not args.no_color)

    report_text = reporter.render(results)
    print(report_text)
    print()
    print("Summary:", reporter.summary(results))


if __name__ == "__main__":
    run_cli()
