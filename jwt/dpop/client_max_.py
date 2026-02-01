#!/usr/bin/env python3
"""
DPoP demo CLI (zero pip deps; requires openssl in PATH)

PRO NOTES (what this tool is good for):
  • Deterministic negative testing: flip ONE claim/header at a time and verify the RS rejects it.
  • Matches typical DPoP validations: htm/htu/iat/jti/ath + cnf.jkt binding.
  • Works both locally (localhost) and in k8s (service DNS) as long as htu matches the URL you call.
  • Uses openssl for real ES256 signing (JWS wants raw r||s, not DER).
  • Default behavior remains: first call should succeed, second call replays same proof (jti reused) and should fail.

Usage quickies:
  python3 cli.py
  python3 cli.py --no-replay
  python3 cli.py --bad-htu --no-replay
  python3 cli.py --wrong-secret --no-replay
  python3 cli.py --url http://dpop-demo:8080/api/hello --no-replay
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
from typing import Dict, Tuple, Optional


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
# HS256 JWT for access token
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
def _run_openssl(args: list[str], *, input_bytes: Optional[bytes] = None) -> bytes:
    try:
        return subprocess.check_output(args, input=input_bytes)
    except FileNotFoundError as e:
        raise RuntimeError("openssl not found in PATH") from e
    except subprocess.CalledProcessError as e:
        msg = e.output.decode("utf-8", "replace") if e.output else str(e)
        raise RuntimeError(f"openssl failed: {' '.join(args)}\n{msg}") from e


def openssl_gen_p256_key() -> Tuple[bytes, Dict[str, str]]:
    """
    Returns (private_key_pem, public_jwk).
    Public coordinates are extracted from `openssl ec -text` output.
    """
    priv = _run_openssl(["openssl", "ecparam", "-name", "prime256v1", "-genkey"])
    pub = _run_openssl(["openssl", "ec", "-pubout"], input_bytes=priv)

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

    pub_bytes = bytes.fromhex(pub_hex)

    # Uncompressed point = 0x04 || X(32) || Y(32)
    if len(pub_bytes) < 65 or pub_bytes[0] != 0x04:
        raise RuntimeError("Unexpected EC public key format from openssl output")

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


def der_ecdsa_to_raw_rs(der: bytes) -> bytes:
    """
    Convert ASN.1 DER ECDSA signature into raw (r||s) 64-byte form required by JWS ES256.
    Minimal parser:
      SEQUENCE { INTEGER r, INTEGER s }
    """
    if len(der) < 8 or der[0] != 0x30:
        raise RuntimeError("Bad DER ECDSA signature (not a SEQUENCE)")

    idx = 2
    # long-form length
    if der[1] & 0x80:
        n = der[1] & 0x7F
        idx = 2 + n

    if idx >= len(der) or der[idx] != 0x02:
        raise RuntimeError("Bad DER ECDSA signature (missing r INTEGER)")
    rlen = der[idx + 1]
    r = der[idx + 2 : idx + 2 + rlen]
    idx = idx + 2 + rlen

    if idx >= len(der) or der[idx] != 0x02:
        raise RuntimeError("Bad DER ECDSA signature (missing s INTEGER)")
    slen = der[idx + 1]
    s = der[idx + 2 : idx + 2 + slen]

    # Strip leading sign 0x00, then left-pad to 32 bytes
    r = r.lstrip(b"\x00")
    s = s.lstrip(b"\x00")
    r = (b"\x00" * 32 + r)[-32:]
    s = (b"\x00" * 32 + s)[-32:]
    return r + s


def es256_jws(priv_pem: bytes, header: Dict, payload: Dict) -> str:
    """
    Sign header+payload using ES256 (P-256 + SHA-256) with openssl.
    Produces compact JWS with raw r||s signature.
    """
    h = b64u_json(header)
    p = b64u_json(payload)
    signing_input = f"{h}.{p}".encode("ascii")

    with tempfile.NamedTemporaryFile(delete=False) as f:
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
) -> Tuple[int, str]:
    req = urllib.request.Request(url, method=method)

    if not missing_auth:
        req.add_header("Authorization", f"{auth_scheme} {access_token}")
    if not missing_dpop:
        req.add_header("DPoP", dpop_proof)

    if verbose:
        print("\n--- REQUEST ---")
        print(f"{method} {url}")
        if missing_auth:
            print("Authorization: <MISSING>")
        else:
            print(f"Authorization: {auth_scheme} <token>")
        if missing_dpop:
            print("DPoP: <MISSING>")
        else:
            print("DPoP: <proof>")
        print("---------------")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        raise RuntimeError(f"HTTP request failed: {e}") from e


# ----------------------------
# Main
# ----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="DPoP demo CLI (HS256 AT + ES256 proof).")

    # Core
    ap.add_argument("--url", default=os.environ.get("DPOP_URL", "http://127.0.0.1:8080/api/hello"), help="Resource URL")
    ap.add_argument("--secret", default=os.environ.get("DPOP_SECRET", "super-secret-demo-key-change-me-please-123456"),
                    help="HS256 HMAC secret (must match server)")
    ap.add_argument("--method", default="GET", help="HTTP method (default GET)")
    ap.add_argument("--timeout", type=int, default=5, help="HTTP timeout seconds")
    ap.add_argument("--auth-scheme", default="DPoP", choices=["DPoP", "Bearer"],
                    help="Authorization scheme (your resolver accepts both)")
    ap.add_argument("--exp-seconds", type=int, default=300, help="Access token lifetime")

    # Precision toggles (flip one check at a time)
    ap.add_argument("--no-replay", action="store_true", help="Do not send the replay request")
    ap.add_argument("--reuse-jti", action="store_true",
                    help="Explicitly reuse proof jti on second call (default behavior unless you generate a new proof)")
    ap.add_argument("--bad-ath", action="store_true", help="Make ath mismatch (proof not bound to token)")
    ap.add_argument("--bad-htu", action="store_true", help="Make htu mismatch (proof bound to different URL)")
    ap.add_argument("--bad-htm", action="store_true", help="Make htm mismatch (proof bound to different method)")
    ap.add_argument("--old-iat", action="store_true", help="Make iat stale (outside skew window)")
    ap.add_argument("--wrong-secret", action="store_true", help="Sign AT with a wrong HMAC secret (invalid token)")
    ap.add_argument("--wrong-jkt", action="store_true", help="Put wrong cnf.jkt in AT (break key binding)")
    ap.add_argument("--missing-auth", action="store_true", help="Omit Authorization header")
    ap.add_argument("--missing-dpop", action="store_true", help="Omit DPoP header")
    ap.add_argument("--verbose", action="store_true", help="Verbose output (prints claims and request debug)")

    args = ap.parse_args()

    url = args.url
    method = args.method.upper()
    secret = args.secret.encode("utf-8")

    # Generate proof keypair
    priv, jwk = openssl_gen_p256_key()
    jkt = jwk_thumbprint(jwk)

    # Optionally break jkt binding (cnf.jkt != proof jwk thumbprint)
    jkt_for_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" if args.wrong_jkt else jkt

    now = int(time.time())

    # Access token (HS256)
    access_header = {"alg": "HS256", "typ": "JWT"}
    access_payload = {
        "sub": "htb-user",
        "iat": now,
        "exp": now + args.exp_seconds,
        "scope": "demo",
        "cnf": {"jkt": jkt_for_token},
    }

    secret_used = b"definitely-wrong-secret" if args.wrong_secret else secret
    access_token = hs256_jwt(access_header, access_payload, secret_used)

    # Proof controls
    proof_iat = now - 9999 if args.old_iat else now
    proof_method = "POST" if args.bad_htm else method
    proof_url = url.replace("/api/hello", "/api/nope") if args.bad_htu else url

    # RFC 9449: ath = base64url(SHA-256(ASCII(access_token)))
    ath = b64u(sha256(access_token.encode("ascii")))
    if args.bad_ath:
        ath = b64u(sha256(b"not-the-token"))

    proof_header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    proof_payload = {
        "htm": proof_method,
        "htu": proof_url,
        "iat": proof_iat,
        "jti": str(uuid.uuid4()),
        "ath": ath,
    }
    proof = es256_jws(priv, proof_header, proof_payload)

    if args.verbose:
        print("\n--- ACCESS TOKEN CLAIMS ---")
        print(json.dumps(access_payload, indent=2))
        print("\n--- DPoP PROOF CLAIMS ---")
        print(json.dumps(proof_payload, indent=2))
        print("\n--- JWK (public) ---")
        print(json.dumps(jwk, indent=2))

    # Call #1
    status, body = http_call(
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
    print(f"\n[FIRST CALL] HTTP {status}")
    if body:
        print(body)

    if args.no_replay:
        return 0

    # Call #2: replay by default (same proof). If you want "non-replay" behavior,
    # you'd regenerate proof_payload['jti'] and sign again here.
    if not args.reuse_jti:
        # Keep default replay semantics unless user explicitly asked otherwise.
        # (This is here for future extension; currently it still replays.)
        pass

    status2, body2 = http_call(
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
    print(f"\n[REPLAY] HTTP {status2}")
    if body2:
        print(body2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
