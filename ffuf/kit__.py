#!/usr/bin/env python3
"""
ffufkit.py — modern, extensible ffuf wrapper for deep webapp fuzzing and pentests.

Goals:
 - Run ffuf with sane defaults, multiple targets, and parameter fuzzing (paths, query params, POST bodies, headers)
 - Canonicalize ffuf JSON output and provide human-readable colorized reports
 - Provide presets and helper functions to reduce friction during pentest runs
 - Modular: add new reporters/postprocessors by subclassing Reporter / ResultProcessor
 - Keep a clear CLI with examples and guidance

Requirements:
 - Python 3.8+
 - ffuf installed and in PATH
 - Optional: jq (if you want to post-process JSON externally)

Usage examples:
  ./ffufkit.py run -w common.txt -u https://example.com
  ./ffufkit.py run -w sqli.txt -u 'https://example.com/search?q=FUZZ' -t 200 --save-json
  ./ffufkit.py run -w params.txt -u https://example.com -P id,name --param-template '?id=FUZZ&name=FUZZ2'
  ./ffufkit.py run -w wl.txt -u https://example.com -p POST -d 'username=FUZZ&pw=pass' -H 'Content-Type:application/x-www-form-urlencoded'
  ./ffufkit.py presets list
  ./ffufkit.py presets explain xss
  ./ffufkit.py merge results/*.json -o merged.json

Author: ChatGPT (assistant)
"""

from __future__ import annotations
import argparse
import csv
import json
import shutil
import os
import re
import sys
import tempfile
import subprocess
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Iterable

# ---------- Colors ----------
RESET = "\033[0m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"

# ---------- Constants ----------
DEFAULT_THREADS = 40
DEFAULT_OUTDIR = Path("./ffufkit_results")
FFUF_BIN = shutil.which("ffuf") or "ffuf"
ISO_TS = lambda: datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

# ---------- Helper utilities ----------
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def safe_filename(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z._-]+", "_", s)[:200]

def abbrev(s: str, n=80) -> str:
    return (s[:n] + "...") if len(s) > n else s

# ---------- Presets & Guidance ----------
PRESETS: Dict[str, Dict[str, Any]] = {
    "xss": {
        "desc": "Typical payloads & headers for reflected XSS discovery (use with query param fuzzing).",
        "wordlist_hint": "/path/to/xss_payloads.txt",
        "example_flags": ["-H", "User-Agent:Mozilla/5.0", "--chunked"],
    },
    "sqli": {
        "desc": "SQLi-focused payloads; pair with query param or POST body fuzzing.",
        "wordlist_hint": "/path/to/sqli_payloads.txt",
    },
    "lfi": {
        "desc": "Local file inclusion payloads; try with path fuzzing and traversal patterns.",
        "wordlist_hint": "/path/to/lfi.txt",
    },
    "dir": {
        "desc": "Directory / file discovery — use common wordlists, test extensions.",
        "wordlist_hint": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    },
}

# Guidance text used in CLI
GUIDANCE = """
ffufkit quick tips:
 - Prefer ffuf JSON output for reliable parsing (--save-json).
 - Use -P / --params or give a target URL containing FUZZ for simple path fuzzing.
 - To fuzz query params: pass a URL like 'https://host/search?q=FUZZ' or supply --params id,name
 - To fuzz POST bodies: use -p POST -d 'id=FUZZ&token=static'
 - To fuzz multiple fuzz points concurrently, use the --param-template option:
     --param-template '?id=FUZZ&name=FUZZ2' and provide two wordlists via --wordlists w1,w2 or repeat -w
 - Use presets: 'ffufkit presets explain xss' for recipe suggestions
"""

# ---------- Data classes ----------
@dataclass
class FFufJob:
    wordlist: Path
    target: str  # contains FUZZ tokens, e.g. /FUZZ or ?id=FUZZ
    threads: int = DEFAULT_THREADS
    extensions: List[str] = field(default_factory=list)
    extra_args: List[str] = field(default_factory=list)
    save_json: bool = False
    save_csv: bool = False
    outdir: Path = DEFAULT_OUTDIR
    name: str = field(default_factory=lambda: f"ffufrun-{ISO_TS()}")

    def build_cmd(self, json_out: Optional[Path] = None, csv_out: Optional[Path] = None) -> List[str]:
        cmd = [FFUF_BIN, "-c", "-w", str(self.wordlist), "-u", self.target, "-t", str(self.threads)]
        for ext in self.extensions:
            if ext:
                cmd += ["-e", ext]
        if self.save_json and json_out:
            cmd += ["-o", str(json_out), "-of", "json"]
        if self.save_csv and csv_out:
            cmd += ["-o", str(csv_out), "-of", "csv"]
        # append user-specified raw ffuf args last so they can override
        if self.extra_args:
            cmd += self.extra_args
        return cmd

@dataclass
class FFufResult:
    # canonical result extracted from ffuf JSON
    input: str
    url: str
    status: int
    length: int
    words: int
    lines: Optional[int] = None
    redirect_location: Optional[str] = None
    matcher_name: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

# ---------- Runner ----------
class FFufRunner:
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers

    def run_job(self, job: FFufJob) -> Tuple[FFufJob, Optional[Path], Optional[Path]]:
        """
        Run a single ffuf job synchronously, returning paths to json/csv (if created).
        """
        ensure_dir(job.outdir)
        safe_name = safe_filename(job.name)
        json_out = job.outdir / f"{safe_name}.json" if job.save_json else None
        csv_out = job.outdir / f"{safe_name}.csv" if job.save_csv else None
        cmd = job.build_cmd(json_out=json_out, csv_out=csv_out)
        eprint(f"{CYAN}RUNNING:{RESET} {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except FileNotFoundError:
            eprint(f"{RED}ffuf binary not found (expected '{FFUF_BIN}'). Please install ffuf and ensure it's on PATH.{RESET}")
            raise

        # ffuf may write JSON/CSV to disk; we also capture stdout/stderr for diagnostics
        if proc.returncode != 0:
            eprint(f"{MAGENTA}ffuf exited with code {proc.returncode}; stderr below:{RESET}")
            eprint(proc.stderr.strip() or "(no stderr)")
            # continue: sometimes ffuf returns non-zero but still wrote JSON
        # attempt to fallback: if ffuf produced json on stdout (rare), save it
        if json_out and not json_out.exists():
            # try parse stdout as json
            try:
                doc = json.loads(proc.stdout)
                with open(json_out, "w", encoding="utf8") as fh:
                    json.dump(doc, fh, indent=2)
            except Exception:
                pass
        return job, json_out, csv_out

    def run_jobs_parallel(self, jobs: Iterable[FFufJob]) -> List[Tuple[FFufJob, Optional[Path], Optional[Path]]]:
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self.run_job, j): j for j in jobs}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    eprint(f"{RED}Job failed: {exc}{RESET}")
        return results

# ---------- Parser ----------
class ResultParser:
    @staticmethod
    def parse_ffuf_json(path: Path) -> List[FFufResult]:
        """
        Parse ffuf JSON output into a list of FFufResult objects.
        """
        if not path or not path.exists():
            return []
        with open(path, "r", encoding="utf8") as fh:
            doc = json.load(fh)
        results: List[FFufResult] = []
        # ffuf often writes results under "results" key or top-level array
        hits = doc.get("results") if isinstance(doc, dict) else doc
        if hits is None:
            hits = []
        for r in hits:
            # normalization with graceful fallbacks
            input_val = r.get("input") or r.get("word") or r.get("i", "")
            url = r.get("url") or r.get("uri") or ""
            status = int(r.get("status", 0) or 0)
            length = int(r.get("length", 0) or 0)
            words = int(r.get("words", 0) or 0)
            lines = r.get("lines")
            redirect = r.get("redirectlocation") or r.get("redirect_location") or None
            matcher = r.get("matchername") or None
            results.append(FFufResult(
                input=str(input_val),
                url=str(url),
                status=status,
                length=length,
                words=words,
                lines=lines,
                redirect_location=redirect,
                matcher_name=matcher,
                raw=r
            ))
        return results

    @staticmethod
    def parse_csv(path: Path) -> List[FFufResult]:
        # Best-effort CSV parsing (ffuf CSV layout varies)
        if not path or not path.exists():
            return []
        results: List[FFufResult] = []
        with open(path, "r", encoding="utf8") as fh:
            reader = csv.reader(fh)
            rows = list(reader)
        # skip header rows
        # common expected headers: url, input, status, length, words or similar
        # attempt to find numeric status column by scanning first data row
        for r in rows:
            joined = ",".join(r)
            if "URL" in joined or "url" in joined or "Referrer" in joined or "Input" in joined or "input" in joined:
                continue
            # try to identify columns
            # simple heuristic: find first 3-digit field -> status
            status = None
            length = 0
            input_field = r[0] if r else ""
            url_field = ""
            for c in r:
                if re.fullmatch(r"\d{3}", c):
                    status = int(c)
                elif re.fullmatch(r"\d+", c) and length == 0:
                    length = int(c)
                elif c.startswith("http"):
                    url_field = c
            if status is None:
                status = 0
            results.append(FFufResult(input=input_field, url=url_field, status=status, length=length, words=0, raw={"csv_row": r}))
        return results

# ---------- Reporter ----------
class Reporter:
    def __init__(self, outdir: Path, color: bool = True):
        self.outdir = outdir
        ensure_dir(outdir)
        self.color = color

    def colorize(self, s: str, color_code: str) -> str:
        if not self.color:
            return s
        return f"{color_code}{s}{RESET}"

    def summarize(self, results: List[FFufResult]) -> Dict[str, int]:
        counts = {"total": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
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
            else:
                counts["other"] += 1
        return counts

    def to_text(self, results: List[FFufResult], fname: Path) -> Path:
        """
        Produce a colorized human-friendly text report and a plain-text variant.
        """
        lines = [f"Results {ISO_TS()}"]
        for r in sorted(results, key=lambda x: (x.status, -x.length, x.url)):
            status_colored = r.status
            if 200 <= r.status < 300:
                status_str = self.colorize(str(r.status), GREEN)
            elif 300 <= r.status < 400:
                status_str = self.colorize(str(r.status), BLUE)
            elif 400 <= r.status < 500:
                status_str = self.colorize(str(r.status), MAGENTA)
            elif 500 <= r.status < 600:
                status_str = self.colorize(str(r.status), RED)
            else:
                status_str = str(r.status)
            line = f"{r.url} [Status: {status_str}, Size: {r.length}, Words: {r.words}]"
            lines.append(line)
        # write colored file for terminal (contains escape codes)
        with open(fname, "w", encoding="utf8") as fh:
            fh.write("\n".join(lines))
        # plain variant
        plain = fname.with_suffix(".plain.txt")
        with open(plain, "w", encoding="utf8") as fh:
            fh.write("\n".join([re.sub(r"\x1b\\[[0-9;]*m", "", l) for l in lines]))
        return fname

    def to_json(self, results: List[FFufResult], fname: Path) -> Path:
        arr = [r.raw for r in results]
        with open(fname, "w", encoding="utf8") as fh:
            json.dump({"generated": ISO_TS(), "results": arr}, fh, indent=2)
        return fname

    def to_markdown(self, results: List[FFufResult], fname: Path) -> Path:
        header = ["|URL|Status|Size|Words|Notes|", "|---|---:|---:|---:|---|"]
        rows = []
        for r in sorted(results, key=lambda x: (-x.status, -x.length)):
            note = f"matcher={r.matcher_name or ''}"
            rows.append(f"|{r.url}|{r.status}|{r.length}|{r.words}|{note}|")
        with open(fname, "w", encoding="utf8") as fh:
            fh.write("\n".join(["# ffufkit report", f"Generated: {ISO_TS()}", ""] + header + rows))
        return fname

# ---------- CLI & Utilities ----------
def build_paramized_targets(base_url: str, params: Optional[List[str]] = None, template: Optional[str] = None) -> List[str]:
    """
    Given a base_url and a list of param names, build target URLs containing FUZZ tokens.
    If template is supplied, substitute occurrences of FUZZ, FUZZ2, ... in template.
    Example:
      base_url='https://host/search'
      params=['q','id']
      -> ['https://host/search?q=FUZZ','https://host/search?id=FUZZ']
    Example with template:
      template='?id=FUZZ&name=FUZZ2'
      -> ['https://host/search?id=FUZZ&name=FUZZ2']
    """
    targets = []
    if template:
        # allow multiple FUZZ tokens in template (FUZZ, FUZZ2, FUZZ3...)
        targets.append(base_url.rstrip("/") + template)
        return targets
    if not params:
        # default to fuzz path
        targets.append(base_url.rstrip("/") + "/FUZZ")
        return targets
    # build one target per param
    for p in params:
        q = f"?{p}=FUZZ"
        targets.append(base_url.rstrip("/") + q)
    return targets

def merge_json_files(paths: List[Path], out: Path):
    merged = {"generated": ISO_TS(), "results": []}
    for p in paths:
        if not p.exists():
            continue
        with open(p, "r", encoding="utf8") as fh:
            try:
                doc = json.load(fh)
                hits = doc.get("results") if isinstance(doc, dict) else doc
                if isinstance(hits, list):
                    merged["results"].extend(hits)
            except Exception:
                eprint(f"warning: failed to parse {p}")
    # dedupe by url+status+length
    seen = set()
    dedup = []
    for r in merged["results"]:
        key = (r.get("url"), r.get("status"), r.get("length"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(r)
    merged["results"] = dedup
    with open(out, "w", encoding="utf8") as fh:
        json.dump(merged, fh, indent=2)
    eprint(f"merged {len(paths)} -> {out} (unique {len(dedup)})")

# ---------- CLI Implementation ----------
def cli_run(args: argparse.Namespace):
    # prepare jobs
    wordlists: List[Path] = []
    if args.wordlists:
        for p in args.wordlists.split(","):
            wordlists.append(Path(p).expanduser())
    else:
        wordlists = [Path(args.wordlist).expanduser()]

    jobs: List[FFufJob] = []
    # build targets depending on params/template
    targets = build_paramized_targets(args.url, params=args.params.split(",") if args.params else None, template=args.param_template)
    # if multiple wordlists and multiple targets, create cartesian product
    for w in wordlists:
        if not w.exists():
            eprint(f"{RED}wordlist not found: {w}{RESET}")
            continue
        for t in targets:
            name = f"{Path(t).parts[-1] if '/' in t else t}-{w.name}-{ISO_TS()}"
            job = FFufJob(
                wordlist=w,
                target=t,
                threads=args.threads,
                extensions=args.exts.split(",") if args.exts else [],
                extra_args=args.extra or [],
                save_json=args.save_json,
                save_csv=args.save_csv,
                outdir=Path(args.outdir).expanduser(),
                name=name
            )
            jobs.append(job)
    if not jobs:
        eprint(f"{RED}no jobs to run{RESET}")
        return

    runner = FFufRunner(max_workers=args.max_workers or min(4, len(jobs)))
    results = runner.run_jobs_parallel(jobs)

    # collect parsed results and report
    all_results: List[FFufResult] = []
    parser = ResultParser()
    for job, json_p, csv_p in results:
        if json_p and json_p.exists():
            parsed = parser.parse_ffuf_json(json_p)
            all_results.extend(parsed)
        elif csv_p and csv_p.exists():
            parsed = parser.parse_csv(csv_p)
            all_results.extend(parsed)
    reporter = Reporter(Path(args.outdir).expanduser(), color=not args.no_color)
    ts = ISO_TS()
    textfile = Path(args.outdir).expanduser() / f"report-{safe_filename(args.url)}-{ts}.txt"
    mdfile = Path(args.outdir).expanduser() / f"report-{safe_filename(args.url)}-{ts}.md"
    jsonfile = Path(args.outdir).expanduser() / f"report-{safe_filename(args.url)}-{ts}.json"
    reporter.to_text(all_results, textfile)
    reporter.to_markdown(all_results, mdfile)
    reporter.to_json(all_results, jsonfile)
    eprint(f"{GREEN}Reports written to:{RESET}")
    eprint(f"  text: {textfile}")
    eprint(f"  md:   {mdfile}")
    eprint(f"  json: {jsonfile}")
    # print short summary
    s = reporter.summarize(all_results)
    eprint(f"{BLUE}Summary:{RESET} total={s['total']} 2xx={s['2xx']} 3xx={s['3xx']} 4xx={s['4xx']} 5xx={s['5xx']}")

def cli_merge(args: argparse.Namespace):
    files = [Path(p).expanduser() for p in args.inputs]
    out = Path(args.output).expanduser()
    merge_json_files(files, out)

def cli_presets(args: argparse.Namespace):
    if args.list:
        eprint("Available presets:")
        for k, v in PRESETS.items():
            eprint(f" - {k}: {v.get('desc')}")
        return
    if args.explain:
        p = args.explain
        if p not in PRESETS:
            eprint(f"{RED}unknown preset: {p}{RESET}")
            return
        v = PRESETS[p]
        eprint(f"{CYAN}{p}{RESET}: {v.get('desc')}")
        eprint(f"Recommended wordlist: {v.get('wordlist_hint')}")
        if v.get("example_flags"):
            eprint("Example ffuf flags: " + " ".join(v["example_flags"]))

def build_cli():
    ap = argparse.ArgumentParser(prog="ffufkit", description="ffufkit — modern ffuf wrapper for pentests")
    sub = ap.add_subparsers(dest="cmd", required=True)

    runp = sub.add_parser("run", help="Run ffuf jobs with helpful defaults")
    runp.add_argument("-w", "--wordlist", help="Single wordlist file (deprecated if --wordlists used)")
    runp.add_argument("--wordlists", help="Comma-separated wordlist paths (cartesian with targets)")
    runp.add_argument("-u", "--url", required=True, help="Base URL (must include scheme). Use FUZZ in URL for simple path fuzzing.")
    runp.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"ffuf threads (default {DEFAULT_THREADS})")
    runp.add_argument("-T", "--max-workers", type=int, help="Max parallel ffuf processes (default small)")
    runp.add_argument("-e", "--exts", help="Comma-separated extensions to try (eg: php,html)")
    runp.add_argument("-P", "--params", help="Comma-separated param names to fuzz (eg: id,q,name)")
    runp.add_argument("--param-template", help="Custom query string template with FUZZ and FUZZ2 placeholders (eg '?id=FUZZ&name=FUZZ2')")
    runp.add_argument("-p", "--method", choices=["GET", "POST"], default="GET", help="HTTP method for the ffuf run (POST requires -d)")
    runp.add_argument("-d", "--data", help="POST data template (contains FUZZ)")
    runp.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers (can be repeated)")
    runp.add_argument("-o", "--outdir", default=str(DEFAULT_OUTDIR), help=f"Output directory (default: {DEFAULT_OUTDIR})")
    runp.add_argument("--save-json", action="store_true", help="Ask ffuf to save JSON outputs per job")
    runp.add_argument("--save-csv", action="store_true", help="Ask ffuf to save CSV outputs per job")
    runp.add_argument("--no-color", action="store_true", help="Disable colorized output writes")
    runp.add_argument("--param-template-wordlists", help="Comma-separated wordlists for multiple FUZZ points (aligns with FUZZ, FUZZ2...)")
    runp.add_argument("--extra", nargs=argparse.REMAINDER, help="Extra ffuf args passed through (place after --).")

    mergep = sub.add_parser("merge", help="Merge multiple ffuf JSON outputs into one")
    mergep.add_argument("inputs", nargs="+", help="JSON input files")
    mergep.add_argument("-o", "--output", required=True, help="Output JSON file")

    presetp = sub.add_parser("presets", help="Show built-in presets and guidance")
    presetp.add_argument("--list", action="store_true", help="List presets")
    presetp.add_argument("--explain", help="Explain a preset name (eg xss)")

    help_p = sub.add_parser("help-guidance", help="Show guidance and tips")
    # parse
    return ap

def main(argv: Optional[List[str]] = None):
    if argv is None:
        argv = sys.argv[1:]
    ap = build_cli()
    if not argv:
        ap.print_help()
        eprint(GUIDANCE)
        sys.exit(0)
    args = ap.parse_args(argv)
    if args.cmd == "run":
        # reformat extra args
        if hasattr(args, "extra") and isinstance(args.extra, list) and args.extra:
            extra = [x for x in args.extra]
            # remove leading '--' if present
            if extra and extra[0] == "--":
                extra = extra[1:]
            args.extra = extra
        else:
            args.extra = []
        # simple guidance output
        eprint(f"{BLUE}ffufkit: running with {args.threads} threads; saving to: {args.outdir}{RESET}")
        # If URL contains FUZZ already, we use it directly; else we'll use param/template helpers inside run
        # Normalize headers into extra args for ffuf (ffuf header arg is -H 'Name:Value')
        if args.headers:
            for h in args.headers:
                args.extra.extend(["-H", h])
        # If using POST data, pass -X POST and -d
        if args.method and args.method.upper() == "POST":
            args.extra.extend(["-X", "POST"])
            if args.data:
                args.extra.extend(["-d", args.data])
        cli_run(args)
    elif args.cmd == "merge":
        cli_merge(args)
    elif args.cmd == "presets":
        cli_presets(args)
    elif args.cmd == "help-guidance":
        eprint(GUIDANCE)
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
