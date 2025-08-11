#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
tls_ciphertest.py - enumerate and test TLS ciphers/protocols against a target using OpenSSL.

Features:
- Tests TLS 1.0/1.1/1.2/1.3 independently
- Proper TLS 1.3 handling via -ciphersuites
- Parses 'openssl ciphers -v' for metadata (Kx/Auth/Enc/Bits)
- Concurrency for faster scans
- Output as table/CSV/JSON
- SNI, ALPN, verification controls
"""

import argparse
import concurrent.futures as futures
import csv
import json
import os
import re
import shlex
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

# Known TLS 1.3 suites (OpenSSL names)
TLS13_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
]

OPENSSL_MIN_VERSION_TLS13 = (1, 1, 1)

def run_cmd(cmd: List[str], input_data: Optional[str] = None, timeout: int = 10) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            input=input_data if input_data is not None else "",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", "openssl not found"
    except Exception as e:
        return 1, "", f"error: {e}"

def get_openssl_version_tuple() -> Tuple[int, int, int]:
    rc, out, _ = run_cmd(["openssl", "version"])
    if rc != 0:
        sys.exit("[!] OpenSSL not available")
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", out)
    if not m:
        return (0, 0, 0)
    return tuple(map(int, m.groups()))

def openssl_supports_tls13() -> bool:
    v = get_openssl_version_tuple()
    return v >= OPENSSL_MIN_VERSION_TLS13

def get_ciphers_verbose(spec: str) -> List[Dict[str, str]]:
    """
    returns list of dicts with keys: name, version, kx, auth, enc, bits
    """
    rc, out, err = run_cmd(["openssl", "ciphers", "-v", spec])
    if rc != 0:
        sys.exit(f"[!] Error fetching cipher list: {err or out}")
    ciphers = []
    # Example line:
    # ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
    for line in out.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        version = parts[1] if len(parts) > 1 else "?"
        fields = {"kx": "?", "auth": "?", "enc": "?", "bits": "?"}
        for token in parts[2:]:
            if token.startswith("Kx="):
                fields["kx"] = token[3:]
            elif token.startswith("Au="):
                fields["auth"] = token[3:]
            elif token.startswith("Enc="):
                fields["enc"] = token[4:]
            elif token.startswith("Mac="):
                # Not stored; AEAD implies MAC is part of cipher
                pass
        # extract bits from enc if present like AESGCM(128)
        m = re.search(r"\((\d+)\)", fields["enc"])
        if m:
            fields["bits"] = m.group(1)
        ciphers.append({
            "name": name,
            "version": version,
            "kx": fields["kx"],
            "auth": fields["auth"],
            "enc": fields["enc"],
            "bits": fields["bits"],
        })
    return ciphers

def filter_ciphers(ciphers: List[Dict[str, str]], only: List[str], exclude: List[str]) -> List[Dict[str, str]]:
    import fnmatch
    def include_name(n: str) -> bool:
        if only:
            return any(fnmatch.fnmatch(n, pat) for pat in only)
        return True
    def exclude_name(n: str) -> bool:
        return any(fnmatch.fnmatch(n, pat) for pat in exclude)
    result = []
    for c in ciphers:
        n = c["name"]
        if include_name(n) and not exclude_name(n):
            result.append(c)
    return result

def test_single_cipher(
    host: str,
    port: int,
    cipher: str,
    protocol: str,
    servername: Optional[str],
    alpn: Optional[str],
    timeout: int,
    verify_hostname: Optional[str],
    cafile: Optional[str],
    insecure: bool,
) -> Dict[str, str]:
    """
    protocol: one of tls1, tls1_1, tls1_2, tls1_3
    """
    # Base s_client command
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-quiet"]
    # Protocol flags
    proto_flag = {
        "tls1": "-tls1",
        "tls1_1": "-tls1_1",
        "tls1_2": "-tls1_2",
        "tls1_3": "-tls1_3",
    }[protocol]
    cmd.append(proto_flag)

    # Cipher vs ciphersuites
    if protocol == "tls1_3":
        cmd += ["-ciphersuites", cipher]
    else:
        cmd += ["-cipher", cipher]

    if servername:
        cmd += ["-servername", servername]
    if alpn:
        cmd += ["-alpn", alpn]

    # Verification settings
    if insecure:
        cmd += ["-verify", "0"]
    else:
        # If verify_hostname is set, prefer -verify_hostname (OpenSSL 1.1.1+)
        if verify_hostname:
            cmd += ["-verify_hostname", verify_hostname]
        if cafile:
            cmd += ["-CAfile", cafile]
        # Fail if verification fails
        cmd += ["-verify_return_error"]

    # For speed, don't request/print cert chain
    cmd += ["-brief"]

    start = time.time()
    rc, out, err = run_cmd(cmd, input_data="\n", timeout=timeout)
    elapsed = f"{(time.time() - start):.2f}"

    # Heuristics for success/failure:
    # On success, output typically includes "Protocol  : TLSv1.x" and "Cipher    : <NAME>"
    protocol_used = None
    cipher_used = None

    # Combine streams for parsing errors
    combined = (out or "") + "\n" + (err or "")

    mprot = re.search(r"Protocol\s*:\s*(TLSv[^\s]+)", combined)
    if mprot:
        protocol_used = mprot.group(1)
    mciph = re.search(r"Cipher\s*:\s*([A-Za-z0-9_\-]+)", combined)
    if mciph:
        cipher_used = mciph.group(1)

    # Common error indicators
    status = "NO"
    error = ""
    if rc == 0 and protocol_used and cipher_used:
        status = "YES"
    else:
        # Look for reasons
        patterns = [
            r"handshake failure",
            r"no cipher match",
            r"wrong version number",
            r"alert\s+\w+",
            r"unsupported protocol",
            r"sslv3 alert handshake failure",
            r"internal error",
            r"unexpected message",
            r"timeout",
        ]
        for pat in patterns:
            m = re.search(pat, combined, re.IGNORECASE)
            if m:
                error = m.group(0)
                break
        if not error:
            error = (err or out).strip().splitlines()[-1] if (err or out) else "unknown"

    return {
        "target": f"{host}:{port}",
        "sni": servername or "",
        "alpn": alpn or "",
        "protocol_requested": protocol.upper().replace("_", "."),
        "protocol_used": protocol_used or "",
        "cipher_requested": cipher,
        "cipher_used": cipher_used or "",
        "status": status,
        "error": "" if status == "YES" else error,
        "time_s": elapsed,
    }

def main():
    parser = argparse.ArgumentParser(
        description="Enumerate and test TLS ciphers/protocols supported by a remote server (via OpenSSL s_client)."
    )
    parser.add_argument("-H", "--host", default="localhost", help="Target host/IP (default: localhost)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("-s", "--servername", help="SNI server name (default: use --host)")
    parser.add_argument("--alpn", help="ALPN protocols (e.g. 'h2,http/1.1')")

    parser.add_argument("--no-tls10", action="store_true", help="Skip TLS 1.0")
    parser.add_argument("--no-tls11", action="store_true", help="Skip TLS 1.1")
    parser.add_argument("--no-tls12", action="store_true", help="Skip TLS 1.2")
    parser.add_argument("--no-tls13", action="store_true", help="Skip TLS 1.3")

    parser.add_argument("--only", action="append", default=[], help="Only test ciphers matching pattern (can repeat)")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude ciphers matching pattern (can repeat)")

    parser.add_argument("--timeout", type=int, default=7, help="Per-connection timeout seconds (default: 7)")
    parser.add_argument("--concurrency", type=int, default=8, help="Parallel workers (default: 8)")
    parser.add_argument("--retries", type=int, default=0, help="Retries per test on failure/timeout (default: 0)")

    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format")
    parser.add_argument("--out", help="Write results to file (csv/json); defaults to stdout for table")

    # Verification
    parser.add_argument("--verify-hostname", help="Verify certificate for this hostname (implies verification)")
    parser.add_argument("--cafile", help="Path to CA bundle for verification")
    parser.add_argument("--insecure", action="store_true", help="Do not verify certificates")

    args = parser.parse_args()

    sni = args.servername or args.host

    print(f"[+] OpenSSL: {' '.join(subprocess.check_output(['openssl','version'], text=True).split())}")
    print(f"[+] Target:  {args.host}:{args.port} (SNI: {sni})")

    supports_tls13 = openssl_supports_tls13()
    if not supports_tls13 and not args.no_tls13:
        print("[!] Your OpenSSL likely lacks TLS 1.3; skipping TLS 1.3 tests.", file=sys.stderr)

    # Build protocol list
    protos = []
    if not args.no_tls10: protos.append("tls1")
    if not args.no_tls11: protos.append("tls1_1")
    if not args.no_tls12: protos.append("tls1_2")
    if not args.no_tls13 and supports_tls13: protos.append("tls1_3")

    # Gather ciphers
    # For TLS<=1.2 use verbose list from openssl; for TLS1.3 we use known ciphersuites and filter to what OpenSSL knows
    ciphers_12 = get_ciphers_verbose("ALL:!eNULL")
    ciphers_12 = filter_ciphers(ciphers_12, args.only, args.exclude)

    # Determine which TLS1.3 suites are recognized by our OpenSSL
    tls13_available = []
    if "tls1_3" in protos:
        rc, out, err = run_cmd(["openssl", "ciphers", "-v", "TLSv1.3"])
        if rc == 0:
            names = [line.split()[0] for line in out.strip().splitlines() if line.strip()]
            for s in TLS13_SUITES:
                if s in names:
                    tls13_available.append({"name": s, "version": "TLSv1.3", "kx": "?", "auth": "?", "enc": "AEAD", "bits": "?"})
        else:
            # Fallback: trust known list
            tls13_available = [{"name": s, "version": "TLSv1.3", "kx": "?", "auth": "?", "enc": "AEAD", "bits": "?"} for s in TLS13_SUITES]

        # Apply filters
        tls13_available = filter_ciphers(tls13_available, args.only, args.exclude)

    # Build work items
    work = []
    for proto in protos:
        if proto == "tls1_3":
            for c in tls13_available:
                work.append((proto, c["name"], c))
        else:
            for c in ciphers_12:
                work.append((proto, c["name"], c))

    print(f"[+] Testing {len(work)} (protocol,cipher) combinations with concurrency={args.concurrency}\n")

    results: List[Dict[str, str]] = []

    def do_test(item):
        proto, cipher_name, meta = item
        attempts = args.retries + 1
        last = None
        for _ in range(attempts):
            last = test_single_cipher(
                host=args.host,
                port=args.port,
                cipher=cipher_name,
                protocol=proto,
                servername=sni,
                alpn=args.alpn,
                timeout=args.timeout,
                verify_hostname=args.verify_hostname,
                cafile=args.cafile,
                insecure=args.insecure,
            )
            if last["status"] == "YES":
                break
        # include metadata
        last.update({
            "kx": meta.get("kx", ""),
            "auth": meta.get("auth", ""),
            "enc": meta.get("enc", ""),
            "bits": meta.get("bits", ""),
        })
        return last

    with futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for r in ex.map(do_test, work):
            results.append(r)

    # Sort: successful first, then by protocol then cipher
    def sort_key(r):
        return (0 if r["status"] == "YES" else 1, r["protocol_requested"], r["cipher_requested"])
    results.sort(key=sort_key)

    # Output
    if args.format == "json":
        out_data = json.dumps(results, indent=2)
        if args.out:
            with open(args.out, "w") as f:
                f.write(out_data)
            print(f"[+] Wrote JSON to {args.out}")
        else:
            print(out_data)
    elif args.format == "csv":
        headers = ["target","sni","alpn","protocol_requested","protocol_used","cipher_requested","cipher_used","status","error","time_s","kx","auth","enc","bits"]
        if args.out:
            with open(args.out, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=headers)
                w.writeheader()
                w.writerows(results)
            print(f"[+] Wrote CSV to {args.out}")
        else:
            w = csv.DictWriter(sys.stdout, fieldnames=headers)
            w.writeheader()
            w.writerows(results)
    else:
        # Pretty table
        headers = ["PROTO(req)","PROTO(used)","CIPHER(req)","CIPHER(used)","Kx","Au","Enc(bits)","OK","Time(s)","Error"]
        print("".join([
            f"{headers[0]:<11} {headers[1]:<11} {headers[2]:<30} {headers[3]:<30} {headers[4]:<8} {headers[5]:<8} {headers[6]:<14} {headers[7]:<3} {headers[8]:<7} {headers[9]}"
        ]))
        for r in results:
            encbits = f"{r.get('enc','')}"
            if r.get("bits"):
                encbits += f"({r['bits']})"
            line = f"{r['protocol_requested']:<11} {r['protocol_used']:<11} {r['cipher_requested']:<30} {r['cipher_used']:<30} {r.get('kx',''):<8} {r.get('auth',''):<8} {encbits:<14} {('Y' if r['status']=='YES' else 'N'):<3} {r['time_s']:<7} {r['error']}"
            print(line)

if __name__ == "__main__":
    main()
