#!/usr/bin/env python3
"""
ffufkit.py — Stage 2.5
CTF & internal-test optimized ffuf wrapper.. (testing)..

Focus:
- Baseline noise reduction
- Reproducible runs
- Clean reporting
"""

from __future__ import annotations
import argparse
import csv
import hashlib
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
def setup_logger(level=logging.INFO) -> logging.Logger:
    logger = logging.getLogger("ffufkit")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(h)
    logger.setLevel(level)
    return logger

log = setup_logger()

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------
FFUF_BIN = "ffuf"
DEFAULT_THREADS = 40
DEFAULT_OUTDIR = Path("./ffufkit_results")

RESET = "\033[0m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
RED = "\033[1;31m"

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def iso_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def safe_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", s)[:200]

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def validate_url(url: str) -> None:
    p = urlparse(url)
    if not p.scheme or not p.netloc or "FUZZ" not in url:
        raise ValueError("URL must be valid and contain FUZZ")

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------
@dataclass(slots=True)
class FFufJob:
    wordlist: Path
    url: str
    threads: int
    exts: List[str]
    headers: List[str]
    cookies: Optional[str]
    delay: Optional[float]
    extra: List[str]
    outdir: Path
    name: str

    def build(self, json_out: Path) -> List[str]:
        cmd = [
            FFUF_BIN, "-c",
            "-w", str(self.wordlist),
            "-u", self.url,
            "-t", str(self.threads),
            "-o", str(json_out),
            "-of", "json",
        ]
        for e in self.exts:
            cmd += ["-e", e]
        for h in self.headers:
            cmd += ["-H", h]
        if self.cookies:
            cmd += ["-b", self.cookies]
        if self.delay:
            cmd += ["-p", str(self.delay)]
        cmd.extend(self.extra)
        return cmd

@dataclass(slots=True)
class FFufResult:
    url: str
    status: int
    length: int
    words: int
    lines: Optional[int]
    raw: Dict[str, Any]

# ---------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------
class FFufRunner:
    def run(self, job: FFufJob) -> Path:
        ensure_dir(job.outdir)
        json_out = job.outdir / f"{safe_filename(job.name)}.json"
        cmd = job.build(json_out)

        (job.outdir / "cmd.txt").write_text(shlex.join(cmd))
        log.info("Running: %s", shlex.join(cmd))

        subprocess.run(cmd, check=False)
        return json_out

# ---------------------------------------------------------------------
# Parsing / Filtering
# ---------------------------------------------------------------------
def parse_results(path: Path) -> List[FFufResult]:
    data = json.loads(path.read_text())
    results = []
    for r in data.get("results", []):
        results.append(
            FFufResult(
                url=r["url"],
                status=r["status"],
                length=r["length"],
                words=r["words"],
                lines=r.get("lines"),
                raw=r,
            )
        )
    return results

# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------
class Reporter:
    def __init__(self, color=True):
        self.color = color

    def c(self, s, col):
        return f"{col}{s}{RESET}" if self.color else s

    def render(self, res: Sequence[FFufResult]) -> str:
        out = []
        for r in sorted(res, key=lambda x: (x.status, -x.length)):
            if 200 <= r.status < 300:
                col = GREEN
            elif 300 <= r.status < 400:
                col = BLUE
            elif 400 <= r.status < 500:
                col = MAGENTA
            else:
                col = RED
            out.append(f"{r.url} [{self.c(r.status, col)} | {r.length}]")
        return "\n".join(out)

    def to_markdown(self, res: Sequence[FFufResult]) -> str:
        lines = ["| URL | Status | Size | Words |", "|---|---|---|---|"]
        for r in res:
            lines.append(f"| {r.url} | {r.status} | {r.length} | {r.words} |")
        return "\n".join(lines)

# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("ffufkit", description="CTF-ready ffuf wrapper")
    s = p.add_subparsers(dest="cmd", required=True)

    r = s.add_parser("run")
    r.add_argument("-w", "--wordlist", required=True)
    r.add_argument("-u", "--url", required=True)
    r.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS)
    r.add_argument("-e", "--exts", default="")
    r.add_argument("-H", "--header", action="append", default=[])
    r.add_argument("--cookie")
    r.add_argument("--delay", type=float)
    r.add_argument("--outdir", default=str(DEFAULT_OUTDIR))
    r.add_argument("--markdown", action="store_true")
    r.add_argument("--extra", nargs=argparse.REMAINDER)

    return p

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main(argv=None):
    args = build_parser().parse_args(argv)
    validate_url(args.url)

    wl = Path(args.wordlist)
    if not wl.exists():
        sys.exit("Wordlist not found")

    job = FFufJob(
        wordlist=wl,
        url=args.url,
        threads=args.threads,
        exts=[e for e in args.exts.split(",") if e],
        headers=args.header,
        cookies=args.cookie,
        delay=args.delay,
        extra=args.extra or [],
        outdir=Path(args.outdir),
        name=f"ffuf-{iso_ts()}",
    )

    runner = FFufRunner()
    out = runner.run(job)
    res = parse_results(out)

    rep = Reporter()
    print(rep.render(res))

    if args.markdown:
        md = job.outdir / "results.md"
        md.write_text(rep.to_markdown(res))
        log.info("Markdown written to %s", md)

if __name__ == "__main__":
    main()
