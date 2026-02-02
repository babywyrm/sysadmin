#!/usr/bin/env python3
"""
DPoP demo CLI (zero pip deps; requires openssl in PATH)

Improvements vs your current version:
  - Optional DPoP-Nonce auto-retry (reads DPoP-Nonce response header and retries once)
  - Clear replay vs fresh-proof behavior on second call
  - Hardened DER->raw(r||s) conversion with bounds/length handling
  - Robust OpenSSL execution wrapper + safer key temp handling

Usage:
  python3 cli.py
  python3 cli.py --no-replay
  python3 cli.py --fresh-proof-second-call
  python3 cli.py --require-nonce
  python3 cli.py --bad-htu --no-replay
  python3 cli.py --url http://dpop-demo:8080/api/hello --fresh-proof-second-call
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import time
import uuid
import urllib.request
import urllib.error
from typing import Dict, Tuple, Optional, List
from urllib.parse import urlsplit, urlunsplit


# ----------------------------
# base64url / json helpers
# ----------------------------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_json(obj: object) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ----------------------------
# HS256 JWT for access token (demo)
# ----------------------------
def hs256_jwt(header: Dict, payload: Dict, secret: bytes) -> str:
    h = b64u_json(header)
    p = b64u_json(payload)
    signing_input = f"{h}.{p}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"


# ----------------------------
# openssl helpers for ES256 proof signing
# ----------------------------
def _run_openssl(args: List[str], *, input_bytes: Optional[bytes] = None) -> bytes:
    try:
        return subprocess.check_output(args, input=input_bytes, stderr=subprocess.STDOUT)
    except FileNotFoundError as e:
        raise RuntimeError("openssl not found in PATH") from e
    except subprocess.CalledProcessError as e:
        out = e.output.decode("utf-8", "replace") if e.output else ""
        raise RuntimeError(f"openssl failed: {' '.join(args)}\n{out}") from e


def openssl_gen_p256_key() -> Tuple[bytes, Dict[str, str]]:
    """
    Returns (private_key_pem, public_jwk).
    Extracts uncompressed public point from openssl text output.
    """
    priv = _run_openssl(["openssl", "ecparam", "-name", "prime256v1", "-genkey"])
    pub = _run_openssl(["openssl", "ec", "-pubout"], input_bytes=priv)

    # Force uncompressed point output in text and parse the "pub:" bytes.
    text = _run_openssl(["openssl", "ec", "-pubin", "-text", "-noout"], input_bytes=pub).decode("utf-8", "replace")
    lines = text.splitlines()

    pub_hex = ""
    in_pub = False
    for line in lines:
        s = line.strip()
        if s.startswith("pub:"):
            in_pub = True
            continue
        if in_pub:
            if s.startswith("ASN1 OID") or s.startswith("NIST CURVE"):
                break
            pub_hex += s.replace(":", "")

    if not pub_hex:
        raise RuntimeError("Failed to parse public key point from openssl output")

    pub_bytes = bytes.fromhex(pub_hex)

    # Uncompressed point = 0x04 || X(32) || Y(32)
    if len(pub_bytes) < 65 or pub_bytes[0] != 0x04:
        raise RuntimeError(f"Unexpected EC public key format (len={len(pub_bytes)} first={pub_bytes[:1].hex()})")

    x = pub_bytes[1:33]
    y = pub_bytes[33:65]
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y)}
    return priv, jwk


def jwk_thumbprint(jwk: Dict[str, str]) -> str:
    """
    RFC 7638 thumbprint for EC keys: hash of canonical JSON of {crv,kty,x,y}.
    """
    canon = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return b64u(sha256(canon))


def _read_der_len(buf: bytes, idx: int) -> Tuple[int, int]:
    """
    Read DER length at buf[idx]. Returns (length, new_idx_after_lenbytes).
    """
    if idx >= len(buf):
        raise RuntimeError("DER parse: truncated length")
    first = buf[idx]
    idx += 1
    if (first & 0x80) == 0:
        return first, idx
    n = first & 0x7F
    if n == 0 or n > 4:
        raise RuntimeError("DER parse: invalid long-form length")
    if idx + n > len(buf):
        raise RuntimeError("DER parse: truncated long-form length")
    length = int.from_bytes(buf[idx:idx + n], "big")
    idx += n
    return length, idx


def der_ecdsa_to_raw_rs(der: bytes) -> bytes:
    """
    Convert ASN.1 DER ECDSA signature into raw (r||s) 64-byte form required by JWS ES256.
    DER: SEQUENCE { INTEGER r, INTEGER s }
    """
    if not der or der[0] != 0x30:
        raise RuntimeError("Bad DER ECDSA signature (not a SEQUENCE)")
    idx = 1
    seq_len, idx = _read_der_len(der, idx)
    end = idx + seq_len
    if end > len(der):
        raise RuntimeError("Bad DER ECDSA signature (SEQUENCE length out of bounds)")

    # INTEGER r
    if idx >= end or der[idx] != 0x02:
        raise RuntimeError("Bad DER ECDSA signature (missing r INTEGER)")
    idx += 1
    rlen, idx = _read_der_len(der, idx)
    if idx + rlen > end:
        raise RuntimeError("Bad DER ECDSA signature (r length out of bounds)")
    r = der[idx:idx + rlen]
    idx += rlen

    # INTEGER s
    if idx >= end or der[idx] != 0x02:
        raise RuntimeError("Bad DER ECDSA signature (missing s INTEGER)")
    idx += 1
    slen, idx = _read_der_len(der, idx)
    if idx + slen > end:
        raise RuntimeError("Bad DER ECDSA signature (s length out of bounds)")
    s = der[idx:idx + slen]

    # Strip leading sign 0x00, then left-pad to 32 bytes
    r = r.lstrip(b"\x00")
    s = s.lstrip(b"\x00")
    r = (b"\x00" * 32 + r)[-32:]
    s = (b"\x00" * 32 + s)[-32:]
    return r + s


def es256_jws(priv_pem: bytes, header: Dict, payload: Dict) -> str:
    """
    Sign header+payload using ES256 with openssl.
    Produces compact JWS with raw r||s signature.
    """
    h = b64u_json(header)
    p = b64u_json(payload)
    signing_input = f"{h}.{p}".encode("ascii")

    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(priv_pem)
        key_path = f.name

    try:
        der_sig = _run_openssl(["openssl", "dgst", "-sha256", "-sign", key_path], input_bytes=signing_input)
    finally:
        try:
            os.unlink(key_path)
        except OSError:
            pass

    raw_sig = der_ecdsa_to_raw_rs(der_sig)
    return f"{h}.{p}.{b64u(raw_sig)}"


# ----------------------------
# URL normalization (optional)
# ----------------------------
def normalize_htu(url: str) -> str:
    """
    DPoP 'htu' MUST be the URI you are calling (no fragment).
    Some servers normalize away fragments; keep scheme/host/path/query as-provided.
    """
    parts = urlsplit(url)
    parts = parts._replace(fragment="")
    return urlunsplit(parts)


# ----------------------------
# HTTP
# ----------------------------
def http_call(
    url: str,
    method: str,
    auth_scheme: str,
    access_token: str,
    dpop_proof: str,
    timeout: int,
    *,
    missing_auth: bool = False,
    missing_dpop: bool = False,
    verbose: bool = False,
) -> Tuple[int, Dict[str, str], str]:
    req = urllib.request.Request(url, method=method)
    if not missing_auth:
        req.add_header("Authorization", f"{auth_scheme} {access_token}")
    if not missing_dpop:
        req.add_header("DPoP", dpop_proof)

    if verbose:
        print("\n--- REQUEST ---")
        print(f"{method} {url}")
        print(f"Authorization: {'<MISSING>' if missing_auth else auth_scheme + ' <token>'}")
        print(f"DPoP: {'<MISSING>' if missing_dpop else '<proof>'}")
        print("---------------")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in r.headers.items()}
            return r.status, headers, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, headers, body


# ----------------------------
# DPoP builders
# ----------------------------
def build_access_token(secret: bytes, sub: str, jkt: str, now: int, exp_seconds: int) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "iat": now,
        "exp": now + exp_seconds,
        "scope": "demo",
        "cnf": {"jkt": jkt},
    }
    return hs256_jwt(header, payload, secret)


def build_dpop_proof(
    priv_pem: bytes,
    jwk: Dict[str, str],
    *,
    method: str,
    url: str,
    now: int,
    access_token: str,
    jti: Optional[str] = None,
    nonce: Optional[str] = None,
    bad_htu: bool = False,
    bad_htm: bool = False,
    bad_ath: bool = False,
    old_iat: bool = False,
) -> Tuple[Dict, Dict, str]:
    htu = normalize_htu(url)
    if bad_htu:
        htu = htu + "/nope" if not htu.endswith("/nope") else htu.replace("/nope", "/api/hello")
    htm = "POST" if bad_htm else method
    iat = (now - 9999) if old_iat else now
    jti_val = jti or str(uuid.uuid4())

    ath = b64u(sha256(access_token.encode("ascii")))
    if bad_ath:
        ath = b64u(sha256(b"not-the-token"))

    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"htm": htm, "htu": htu, "iat": iat, "jti": jti_val, "ath": ath}
    if nonce is not None:
        payload["nonce"] = nonce

    proof = es256_jws(priv_pem, header, payload)
    return header, payload, proof


# ----------------------------
# Main
# ----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="DPoP demo CLI (HS256 AT + ES256 proof).")

    # Core
    ap.add_argument("--url", default=os.environ.get("DPOP_URL", "http://127.0.0.1:8080/api/hello"))
    ap.add_argument("--secret", default=os.environ.get("DPOP_SECRET", "super-secret-demo-key-change-me-please-123456"))
    ap.add_argument("--method", default="GET")
    ap.add_argument("--timeout", type=int, default=5)
    ap.add_argument("--auth-scheme", default="DPoP", choices=["DPoP", "Bearer"])
    ap.add_argument("--exp-seconds", type=int, default=300)
    ap.add_argument("--sub", default="htb-user")

    # Behavior
    ap.add_argument("--no-replay", action="store_true", help="Only make one call")
    ap.add_argument("--fresh-proof-second-call", action="store_true",
                    help="Second call uses a NEW proof (new jti, new signature) instead of replaying the first proof.")
    ap.add_argument("--require-nonce", action="store_true",
                    help="If server challenges with DPoP-Nonce, retry once with nonce claim included.")
    ap.add_argument("--verbose", action="store_true")

    # Negative tests
    ap.add_argument("--bad-ath", action="store_true")
    ap.add_argument("--bad-htu", action="store_true")
    ap.add_argument("--bad-htm", action="store_true")
    ap.add_argument("--old-iat", action="store_true")
    ap.add_argument("--wrong-secret", action="store_true")
    ap.add_argument("--wrong-jkt", action="store_true")
    ap.add_argument("--missing-auth", action="store_true")
    ap.add_argument("--missing-dpop", action="store_true")

    args = ap.parse_args()

    url = args.url
    method = args.method.upper()
    secret = args.secret.encode("utf-8")
    now = int(time.time())

    # Proof keypair
    priv, jwk = openssl_gen_p256_key()
    jkt = jwk_thumbprint(jwk)

    jkt_for_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" if args.wrong_jkt else jkt
    secret_used = b"definitely-wrong-secret" if args.wrong_secret else secret

    access_token = build_access_token(secret_used, args.sub, jkt_for_token, now, args.exp_seconds)

    # Build proof #1
    proof_hdr, proof_pl, proof = build_dpop_proof(
        priv,
        jwk,
        method=method,
        url=url,
        now=now,
        access_token=access_token,
        bad_htu=args.bad_htu,
        bad_htm=args.bad_htm,
        bad_ath=args.bad_ath,
        old_iat=args.old_iat,
    )

    if args.verbose:
        print("\n--- ACCESS TOKEN (claims only) ---")
        print(json.dumps({"sub": args.sub, "iat": now, "exp": now + args.exp_seconds, "cnf": {"jkt": jkt_for_token}}, indent=2))
        print("\n--- DPoP PROOF #1 ---")
        print(json.dumps({"header": proof_hdr, "payload": proof_pl}, indent=2))
        print("\n--- JWK ---")
        print(json.dumps(jwk, indent=2))

    # Call #1
    status, headers, body = http_call(
        url,
        method,
        args.auth_scheme,
        access_token,
        proof,
        args.timeout,
        missing_auth=args.missing_auth,
        missing_dpop=args.missing_dpop,
        verbose=args.verbose,
    )

    # Optional nonce retry
    if args.require_nonce and status in (400, 401) and "dpop-nonce" in headers and not args.missing_dpop:
        nonce = headers["dpop-nonce"]
        if args.verbose:
            print(f"\n[NONCE] Server requested nonce: {nonce}")
        _, proof_pl2, proof2 = build_dpop_proof(
            priv,
            jwk,
            method=method,
            url=url,
            now=int(time.time()),
            access_token=access_token,
            nonce=nonce,
            bad_htu=args.bad_htu,
            bad_htm=args.bad_htm,
            bad_ath=args.bad_ath,
            old_iat=args.old_iat,
        )
        if args.verbose:
            print("\n--- DPoP PROOF #1 RETRY (with nonce) ---")
            print(json.dumps(proof_pl2, indent=2))

        status, headers, body = http_call(
            url,
            method,
            args.auth_scheme,
            access_token,
            proof2,
            args.timeout,
            missing_auth=args.missing_auth,
            missing_dpop=args.missing_dpop,
            verbose=args.verbose,
        )

        proof = proof2  # if we proceed to call #2, keep the last proof used

    print(f"\n[FIRST CALL] HTTP {status}")
    if body:
        print(body)

    if args.no_replay:
        return 0

    # Call #2
    proof_to_use = proof
    if args.fresh_proof_second_call and not args.missing_dpop:
        _, _, proof_to_use = build_dpop_proof(
            priv,
            jwk,
            method=method,
            url=url,
            now=int(time.time()),
            access_token=access_token,
            # Fresh proof; for replay behavior we reuse the prior proof
        )

    status2, headers2, body2 = http_call(
        url,
        method,
        args.auth_scheme,
        access_token,
        proof_to_use,
        args.timeout,
        missing_auth=args.missing_auth,
        missing_dpop=args.missing_dpop,
        verbose=args.verbose,
    )

    # Optional nonce retry on call #2 as well
    if args.require_nonce and status2 in (400, 401) and "dpop-nonce" in headers2 and not args.missing_dpop:
        nonce2 = headers2["dpop-nonce"]
        if args.verbose:
            print(f"\n[NONCE] Server requested nonce (call #2): {nonce2}")
        _, _, proof_retry2 = build_dpop_proof(
            priv,
            jwk,
            method=method,
            url=url,
            now=int(time.time()),
            access_token=access_token,
            nonce=nonce2,
        )
        status2, headers2, body2 = http_call(
            url,
            method,
            args.auth_scheme,
            access_token,
            proof_retry2,
            args.timeout,
            missing_auth=args.missing_auth,
            missing_dpop=args.missing_dpop,
            verbose=args.verbose,
        )

    label = "SECOND CALL (fresh proof)" if args.fresh_proof_second_call else "REPLAY (same proof)"
    print(f"\n[{label}] HTTP {status2}")
    if body2:
        print(body2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
