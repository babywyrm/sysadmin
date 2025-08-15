#!/usr/bin/env python3
"""
JWT Utility: sign, verify, parse, and manage keys.

Features
- Sign: HS256, RS256, ES256 (P-256), EdDSA (Ed25519)
- Verify: local key or JWKS URL (kid-aware), optional aud/iss/leeway
- Parse: inspect header/payload without verification (with warnings)
- Keys: generate RSA/EC/Ed25519 keypairs; HMAC secret generation
- Re-sign: mint a new token with a known key (no signature skipping)

Requires:
  - PyJWT (jwt)
  - cryptography
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    InvalidSignatureError,
    ExpiredSignatureError,
    PyJWTError,
)

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization


ALGS_ALLOWED_SIGN = ["HS256", "RS256", "ES256", "EdDSA"]
ALGS_ALLOWED_VERIFY = ["HS256", "RS256", "ES256", "EdDSA"]  # strict allow-list

# ----------------------------
# Utilities
# ----------------------------

def _now() -> int:
    return int(time.time())

def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))

def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _write_text(path: str, data: str, mode: str = "w") -> None:
    with open(path, mode, encoding="utf-8") as f:
        f.write(data)

def _maybe_parse_json(s: Optional[str]) -> Dict[str, Any]:
    if not s:
        return {}
    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] Invalid JSON: {e}")

def _with_standard_claims(payload: Dict[str, Any], exp_seconds: Optional[int]) -> Dict[str, Any]:
    p = dict(payload)
    now = _now()
    if "iat" not in p:
        p["iat"] = now
    if exp_seconds is not None and "exp" not in p:
        p["exp"] = now + int(exp_seconds)
    return p

def _load_private_key_pem(path: str) -> Any:
    data = _read_text(path).encode("utf-8")
    return serialization.load_pem_private_key(data, password=None)

def _load_public_key_pem(path: str) -> Any:
    data = _read_text(path).encode("utf-8")
    return serialization.load_pem_public_key(data)

def _key_for_alg(alg: str, key_file: Optional[str], secret: Optional[str]) -> Any:
    if alg.startswith("HS"):
        if secret is None and key_file:
            secret = _read_text(key_file).strip()
        if not secret:
            raise SystemExit("[!] HS* algorithms require --secret or --key-file (containing the secret).")
        return secret
    # asymmetric:
    if not key_file:
        raise SystemExit("[!] RS*/ES*/EdDSA require --key-file pointing to a PEM private (sign) or public (verify) key.")
    if alg in ("RS256",):
        return _load_private_key_pem(key_file)
    if alg in ("ES256", "EdDSA"):
        return _load_private_key_pem(key_file)
    raise SystemExit(f"[!] Unsupported alg: {alg}")

def _pubkey_for_alg(alg: str, key_file: str) -> Any:
    if alg.startswith("HS"):
        # For HS*, verification uses the same secret
        return _read_text(key_file).strip()
    return _load_public_key_pem(key_file)

# ----------------------------
# Key generation
# ----------------------------

def generate_rsa_keypair(bits: int = 2048) -> Tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem

def generate_ec_keypair() -> Tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem

def generate_eddsa_keypair() -> Tuple[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem

def write_keypair(priv_path: str, pub_path: str, priv_pem: str, pub_pem: str) -> None:
    _write_text(priv_path, priv_pem)
    _write_text(pub_path, pub_pem)
    print(f"[+] Wrote private key: {priv_path}")
    print(f"[+] Wrote public key : {pub_path}")

# ----------------------------
# Sign / Verify / Parse
# ----------------------------

@dataclass
class VerifyOptions:
    audience: Optional[str] = None
    issuer: Optional[str] = None
    leeway: int = 0

def sign_token(
    payload: Dict[str, Any],
    alg: str,
    key_file: Optional[str],
    secret: Optional[str],
    headers: Optional[Dict[str, Any]] = None,
    exp_seconds: Optional[int] = 3600,
) -> str:
    if alg not in ALGS_ALLOWED_SIGN:
        raise SystemExit(f"[!] alg must be one of: {ALGS_ALLOWED_SIGN}")
    key = _key_for_alg(alg, key_file, secret)
    final_payload = _with_standard_claims(payload, exp_seconds)
    return jwt.encode(final_payload, key, algorithm=alg, headers=headers or {})

def verify_token_local(
    token: str,
    algs: List[str],
    key_file: Optional[str],
    secret: Optional[str],
    opts: VerifyOptions,
) -> Dict[str, Any]:
    if not algs:
        raise SystemExit("[!] At least one --alg must be provided for verification.")
    for a in algs:
        if a not in ALGS_ALLOWED_VERIFY:
            raise SystemExit(f"[!] Unsupported verify alg '{a}'. Allowed: {ALGS_ALLOWED_VERIFY}")

    if algs[0].startswith("HS"):
        key = secret if secret is not None else (_read_text(key_file).strip() if key_file else None)
        if not key:
            raise SystemExit("[!] HS* verification requires --secret or --key-file.")
    else:
        if not key_file:
            raise SystemExit("[!] RS*/ES*/EdDSA verification requires --key-file (public key).")
        key = _pubkey_for_alg(algs[0], key_file)

    options = {"require": [], "verify_signature": True}
    return jwt.decode(
        token,
        key=key,
        algorithms=algs,
        audience=opts.audience,
        issuer=opts.issuer,
        leeway=opts.leeway,
        options=options,
    )

def verify_token_jwks(
    token: str,
    jwks_url: str,
    algs: List[str],
    opts: VerifyOptions,
) -> Dict[str, Any]:
    for a in algs:
        if a not in ALGS_ALLOWED_VERIFY:
            raise SystemExit(f"[!] Unsupported verify alg '{a}'. Allowed: {ALGS_ALLOWED_VERIFY}")
    jwk_client = PyJWKClient(jwks_url)
    signing_key = jwk_client.get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key=signing_key,
        algorithms=algs,
        audience=opts.audience,
        issuer=opts.issuer,
        leeway=opts.leeway,
        options={"verify_signature": True},
    )

def parse_unverified(token: str) -> Dict[str, Any]:
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    return {"header": header, "payload": payload}

# ----------------------------
# Re-sign (your "forge" flow)
# ----------------------------

def resign_token(
    existing_token: str,
    new_payload: Dict[str, Any],
    alg: str,
    key_file: Optional[str],
    secret: Optional[str],
    headers: Optional[Dict[str, Any]] = None,
    exp_seconds: Optional[int] = None,
) -> str:
    """
    Re-sign a token with a known key. We DO NOT disable verification; instead,
    we read header fields (like kid) unverified, merge safely, and sign new payload.
    """
    _ = jwt.get_unverified_header(existing_token)  # ensure header parseable
    payload = _with_standard_claims(new_payload, exp_seconds)
    return sign_token(payload, alg=alg, key_file=key_file, secret=secret, headers=headers)

# ----------------------------
# CLI
# ----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="JWT Utility")
    sub = p.add_subparsers(dest="cmd", required=True)

    # sign
    sp = sub.add_parser("sign", help="Sign a JWT")
    sp.add_argument("--alg", required=True, choices=ALGS_ALLOWED_SIGN)
    sp.add_argument("--key-file", help="PEM private key (RS/ES/EdDSA) or secret file (HS).")
    sp.add_argument("--secret", help="HMAC secret (HS*).")
    sp.add_argument("--payload", required=True, help="JSON payload.")
    sp.add_argument("--headers", help='JSON headers (e.g., {"kid": "..."}).')
    sp.add_argument("--exp", type=int, default=3600, help="exp seconds from now (default: 3600).")

    # verify
    vp = sub.add_parser("verify", help="Verify a JWT")
    vp.add_argument("--token", required=True)
    vp.add_argument("--alg", action="append", required=True, help="Allowed alg(s). Repeat for multiple.")
    src = vp.add_mutually_exclusive_group(required=True)
    src.add_argument("--key-file", help="PEM public key (RS/ES/EdDSA) or secret file (HS).")
    src.add_argument("--secret", help="HMAC secret content.")
    src.add_argument("--jwks", help="JWKS URL.")
    vp.add_argument("--aud", help="Expected audience.")
    vp.add_argument("--iss", help="Expected issuer.")
    vp.add_argument("--leeway", type=int, default=0, help="Leeway in seconds.")

    # parse
    pp = sub.add_parser("parse", help="Parse header and payload WITHOUT verification")
    pp.add_argument("--token", required=True)

    # resign
    rp = sub.add_parser("resign", help="Re-sign a JWT with a known key")
    rp.add_argument("--existing-token", required=True)
    rp.add_argument("--alg", required=True, choices=ALGS_ALLOWED_SIGN)
    rp.add_argument("--key-file", help="PEM private (RS/ES/EdDSA) or secret file (HS).")
    rp.add_argument("--secret", help="HMAC secret (HS*).")
    rp.add_argument("--new-payload", required=True, help="JSON payload for the new token.")
    rp.add_argument("--headers", help="JSON headers for the new token.")
    rp.add_argument("--exp", type=int, help="exp seconds from now (optional).")

    # keys gen
    kg = sub.add_parser("keys", help="Generate keypairs")
    ksub = kg.add_subparsers(dest="keys_cmd", required=True)

    kr = ksub.add_parser("gen-rsa", help="Generate RSA keypair")
    kr.add_argument("--bits", type=int, default=2048)
    kr.add_argument("--out-priv", required=True)
    kr.add_argument("--out-pub", required=True)

    ke = ksub.add_parser("gen-ec", help="Generate EC (P-256) keypair")
    ke.add_argument("--out-priv", required=True)
    ke.add_argument("--out-pub", required=True)

    kd = ksub.add_parser("gen-eddsa", help="Generate Ed25519 keypair")
    kd.add_argument("--out-priv", required=True)
    kd.add_argument("--out-pub", required=True)

    # hmac secret
    hs = sub.add_parser("hmac", help="HMAC helpers")
    hsub = hs.add_subparsers(dest="hmac_cmd", required=True)
    hg = hsub.add_parser("gen-secret", help="Generate random HMAC secret")
    hg.add_argument("--bytes", type=int, default=32, help="Secret length (default 32).")
    hg.add_argument("--out", required=True, help="Write secret to file.")

    return p

def main(argv: Optional[List[str]] = None) -> None:
    args = build_parser().parse_args(argv)

    try:
        if args.cmd == "sign":
            payload = _maybe_parse_json(args.payload)
            headers = _maybe_parse_json(args.headers)
            token = sign_token(
                payload=payload,
                alg=args.alg,
                key_file=args.key_file,
                secret=args.secret,
                headers=headers,
                exp_seconds=args.exp,
            )
            print(token)

        elif args.cmd == "verify":
            opts = VerifyOptions(audience=args.aud, issuer=args.iss, leeway=args.leeway)
            if args.jwks:
                out = verify_token_jwks(token=args.token, jwks_url=args.jwks, algs=args.alg, opts=opts)
            else:
                out = verify_token_local(
                    token=args.token,
                    algs=args.alg,
                    key_file=args.key_file,
                    secret=args.secret,
                    opts=opts,
                )
            _print_json({"valid": True, "claims": out})

        elif args.cmd == "parse":
            info = parse_unverified(args.token)
            _print_json({"warning": "UNVERIFIED", **info})

        elif args.cmd == "resign":
            new_payload = _maybe_parse_json(args.new_payload)
            headers = _maybe_parse_json(args.headers)
            token = resign_token(
                existing_token=args.existing_token,
                new_payload=new_payload,
                alg=args.alg,
                key_file=args.key_file,
                secret=args.secret,
                headers=headers,
                exp_seconds=args.exp,
            )
            print(token)

        elif args.cmd == "keys":
            if args.keys_cmd == "gen-rsa":
                priv, pub = generate_rsa_keypair(bits=args.bits)
                write_keypair(args.out_priv, args.out_pub, priv, pub)
            elif args.keys_cmd == "gen-ec":
                priv, pub = generate_ec_keypair()
                write_keypair(args.out_priv, args.out_pub, priv, pub)
            elif args.keys_cmd == "gen-eddsa":
                priv, pub = generate_eddsa_keypair()
                write_keypair(args.out_priv, args.out_pub, priv, pub)

        elif args.cmd == "hmac" and args.hmac_cmd == "gen-secret":
            secret_bytes = secrets.token_bytes(args.bytes)
            _write_text(args.out, secret_bytes.hex() + "\n")
            print(f"[+] Wrote {args.bytes}-byte hex secret to {args.out}")

        else:
            raise SystemExit("[!] Unknown command")

    except ExpiredSignatureError:
        _print_json({"valid": False, "error": "expired"})
        sys.exit(1)
    except InvalidSignatureError:
        _print_json({"valid": False, "error": "invalid_signature"})
        sys.exit(1)
    except PyJWTError as e:
        _print_json({"valid": False, "error": f"jwt_error: {e}"})
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
