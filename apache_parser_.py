#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
advanced_apache_parser.py
High-performance Apache log parser with enrichment, filtering,
parallel processing, and multiple output formats.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from collections import Counter
from dataclasses import dataclass
from functools import reduce
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, Generator, Iterable, List, Optional, TypedDict

import pandas as pd
import user_agents
from tqdm import tqdm

# --- Optional GeoIP ---
try:
    import geoip2.database
    import geoip2.errors

    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# --- Regex ---
LOG_PATTERN = re.compile(
    r'(?P<ip>[0-9a-fA-F:.]+)\s+-\s+-\s+\[(?P<time>[^\]]+)]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>[^"]+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status_code>\d{3})\s+\d+\s+'
    r'"(?P<referral>[^"]*)"\s+"(?P<agent>[^"]*)"'
)

CHUNK_SIZE = 100_000


# --- Typed structures ---

class LogEntry(TypedDict):
    ip: str
    time: str
    method: str
    uri: str
    status_code: str
    referral: str
    agent: str
    country: str
    city: str
    browser: str
    os: str
    device: str


CounterMap = Dict[str, Counter[str]]


# --- Helpers ---

def read_chunks(path: Path, size: int) -> Generator[List[str], None, None]:
    """Yield fixed-size chunks of lines."""
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        buf: List[str] = []
        for line in fh:
            buf.append(line)
            if len(buf) >= size:
                yield buf
                buf = []
        if buf:
            yield buf


def init_geoip(db_path: Optional[str]):
    """Initialize GeoIP reader per process."""
    if not (GEOIP_AVAILABLE and db_path):
        return None
    try:
        return geoip2.database.Reader(db_path)
    except Exception:
        return None


# --- Core logic ---

def enrich_entry(entry: LogEntry, geoip_db: Optional[str]) -> LogEntry:
    """Add UA + GeoIP enrichment."""
    ua = user_agents.parse(entry["agent"])
    entry["browser"] = ua.browser.family
    entry["os"] = ua.os.family
    entry["device"] = ua.device.family

    reader = init_geoip(geoip_db)
    if reader:
        try:
            resp = reader.city(entry["ip"])
            entry["country"] = resp.country.name or "Unknown"
            entry["city"] = resp.city.name or "Unknown"
        except geoip2.errors.AddressNotFoundError:
            entry["country"] = "Unknown"
            entry["city"] = "Unknown"

    return entry


def process_chunk(
    lines: List[str],
    enrich: bool,
    filters: Dict[str, str],
    geoip_db: Optional[str],
) -> CounterMap:
    counters: CounterMap = {
        k: Counter()
        for k in (
            "uri",
            "ip",
            "status_code",
            "agent",
            "referral",
            "country",
            "browser",
            "os",
        )
    }

    for line in lines:
        m = LOG_PATTERN.search(line)
        if not m:
            continue

        entry: LogEntry = {
            **m.groupdict(),
            "country": "",
            "city": "",
            "browser": "",
            "os": "",
            "device": "",
        }

        # Filters (string-safe)
        if any(entry.get(k, "") != v for k, v in filters.items()):
            continue

        if enrich:
            entry = enrich_entry(entry, geoip_db)

        for key in counters:
            val = entry.get(key)
            if val:
                counters[key][val] += 1

    return counters


def parse_parallel(
    path: Path,
    enrich: bool,
    filters: Dict[str, str],
    workers: int,
    geoip_db: Optional[str],
) -> CounterMap:
    chunks = list(read_chunks(path, CHUNK_SIZE))

    with Pool(processes=workers) as pool:
        results = list(
            tqdm(
                pool.starmap(
                    process_chunk,
                    [(c, enrich, filters, geoip_db) for c in chunks],
                ),
                total=len(chunks),
                desc="Processing",
            )
        )

    return reduce(
        lambda a, b: {k: a[k] + b[k] for k in a},
        results,
    )


def generate_report(
    counters: CounterMap,
    key: str,
    limit: Optional[int],
    cutoff: Optional[int],
) -> pd.DataFrame:
    data = counters.get(key, Counter()).most_common()
    if cutoff:
        data = [x for x in data if x[1] >= cutoff]
    if limit:
        data = data[:limit]
    return pd.DataFrame(data, columns=["Item", "Hits"])


def save_output(df: pd.DataFrame, path: Path, fmt: str) -> None:
    if fmt == "csv":
        df.to_csv(path, index=False)
    elif fmt == "json":
        df.to_json(path, orient="records", indent=2)
    elif fmt == "jsonl":
        df.to_json(path, orient="records", lines=True)
    elif fmt == "html":
        safe = df.copy()
        safe["Item"] = safe["Item"].map(lambda x: html.escape(str(x)))
        html_doc = f"""
        <html>
        <head><meta charset="utf-8"><title>Apache Log Report</title></head>
        <body>
        <h1>Apache Log Report</h1>
        {safe.to_html(index=False, escape=False)}
        </body>
        </html>
        """
        path.write_text(html_doc, encoding="utf-8")


# --- CLI ---

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("--parallel", type=int, nargs="?", const=cpu_count(), default=1)
    parser.add_argument("--enrich", action="store_true")
    parser.add_argument("--geoip-db", default=None)
    parser.add_argument("--filter", action="append")

    subs = parser.add_subparsers(dest="report", required=True)
    for key in ("uri", "ip", "status_code", "agent", "referral", "country", "browser", "os"):
        sp = subs.add_parser(key)
        sp.add_argument("-o", "--output", default="stdout")
        sp.add_argument("-f", "--format", choices=("csv", "json", "jsonl", "html"))
        sp.add_argument("-q", "--quantity", type=int)
        sp.add_argument("-c", "--cutoff", type=int)

    args = parser.parse_args()
    path = Path(args.filename)

    filters = dict(f.split("=", 1) for f in args.filter) if args.filter else {}

    if args.parallel > 1:
        counters = parse_parallel(
            path, args.enrich, filters, args.parallel, args.geoip_db
        )
    else:
        counters = process_chunk(
            list(path.read_text(encoding="utf-8", errors="ignore").splitlines()),
            args.enrich,
            filters,
            args.geoip_db,
        )

    df = generate_report(counters, args.report, args.quantity, args.cutoff)

    if df.empty:
        print("No results.")
        return

    if args.output == "stdout":
        print(df.to_string(index=False))
    else:
        fmt = args.format or args.output.split(".")[-1]
        save_output(df, Path(args.output), fmt)


if __name__ == "__main__":
    main()
