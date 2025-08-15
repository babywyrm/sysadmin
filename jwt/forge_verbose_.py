#!/usr/bin/env python3
"""
JWT Utility (compact, class-based)

Features
- sign: HS256, RS256, ES256 (P-256), EdDSA (Ed25519)
- verify: local key/secret or JWKS URL (kid-aware), with aud/iss/leeway
- parse: header + payload (unverified; for debugging)
- resign: re-sign with a known key (no signature skipping anywhere)
- keys: gen-rsa|gen-ec|gen-eddsa; hmac gen-secret

Examples
  # Generate RSA keys
  python jwt_tool.py keys gen-rsa --out-priv rsa_priv.pem --out-pub rsa_pub.pem

  # Sign RS256 with kid and short expiry
  python jwt_tool.py sign --alg RS256 --key-file rsa_priv.pem \
    --payload '{"sub":"123","scope":"read"}' --headers '{"kid":"key-1"}' --exp 900

  # Verify with public key + audience/issuer
  python jwt_tool.py verify --token "$TOKEN" --alg RS256 --key-file rsa_pub.pem \
    --aud myapi --iss https://issuer.example

  # Verify via JWKS
  python jwt_tool.py verify --token "$TOKEN" --alg RS256 \
    --jwks https://example.com/.well-known/jwks.json

  # Parse (unverified)
  python jwt_tool.py parse --token "$TOKEN"

  # Re-sign (mint a new token with a known key)
  python jwt_tool.py resign --existing-token "$OLD" --alg HS256 --secret "$(cat secret.hex)" \
    --new-payload '{"sub":"123","scope":"write"}' --exp 600

  # HMAC secret
  python jwt_tool.py hmac gen-secret --bytes 48 --out secret.hex
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple, Union, Iterable

import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError, PyJWTError

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519


ALGS_SIGN: Tuple[str, ...] = ("HS256", "RS256", "ES256", "EdDSA")
ALGS_VERIFY: Tuple[str, ...] = ("HS256", "RS256", "ES256", "EdDSA")


# ---------- Small shared helpers ----------

def _now() -> int:
    return int(time.time())

def _j(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))

def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _write(path: str, data: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

def _parse_json(s: Optional[str]) -> Dict[str, Any]:
    if not s:
        return {}
    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] Invalid JSON: {e}")

def _with_std_claims(payload: Dict[str, Any], exp_s: Optional[int]) -> Dict[str, Any]:
    p = dict(payload)
    now = _now()
    p.setdefault("iat", now)
    if exp_s is not None:
        p.setdefault("exp", now + int(exp_s))
    return p


# ---------- Key management ----------

class KeyManager:
    """Generate/load keys and map them to the selected algorithm."""

    @staticmethod
    def gen_rsa(bits: int = 2048) -> Tuple[str, str]:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return (
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )

    @staticmethod
    def gen_ec() -> Tuple[str, str]:
        priv = ec.generate_private_key(ec.SECP256R1())
        return (
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )

    @staticmethod
    def gen_eddsa() -> Tuple[str, str]:
        priv = ed25519.Ed25519PrivateKey.generate()
        return (
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )

    @staticmethod
    def load_sign_key(alg: str, key_file: Optional[str], secret: Optional[str]) -> Union[str, Any]:
        if alg.startswith("HS"):
            if secret is not None:
                return secret
            if key_file:
                return _read(key_file).strip()
            raise SystemExit("[!] HS* requires --secret or --key-file containing the secret.")
        if not key_file:
            raise SystemExit("[!] RS*/ES*/EdDSA require --key-file (PEM private key).")
        data = _read(key_file).encode()
        return serialization.load_pem_private_key(data, password=None)

    @staticmethod
    def load_verify_key(alg: str, key_file: Optional[str], secret: Optional[str]) -> Union[str, Any]:
        if alg.startswith("HS"):
            if secret is not None:
                return secret
            if key_file:
                return _read(key_file).strip()
            raise SystemExit("[!] HS* verification requires --secret or --key-file.")
        if not key_file:
            raise SystemExit("[!] RS*/ES*/EdDSA verification requires --key-file (PEM public key).")
        data = _read(key_file).encode()
        return serialization.load_pem_public_key(data)


# ---------- JWT operations ----------

@dataclass
class VerifyOpts:
    audience: Optional[str] = None
    issuer: Optional[str] = None
    leeway: int = 0

class JWTTool:
    """Core JWT operations."""

    @staticmethod
    def sign(payload: Dict[str, Any], alg: str, key_file: Optional[str], secret: Optional[str],
             headers: Optional[Dict[str, Any]], exp_s: Optional[int]) -> str:
        if alg not in ALGS_SIGN:
            raise SystemExit(f"[!] alg must be one of {ALGS_SIGN}")
        key = KeyManager.load_sign_key(alg, key_file, secret)
        return jwt.encode(_with_std_claims(payload, exp_s), key, algorithm=alg, headers=headers or {})

    @staticmethod
    def verify_local(token: str, algs: Iterable[str], key_file: Optional[str], secret: Optional[str],
                     opts: VerifyOpts) -> Dict[str, Any]:
        algs = list(algs)
        if not algs or any(a not in ALGS_VERIFY for a in algs):
            raise SystemExit(f"[!] Allowed verify algs: {ALGS_VERIFY}")
        key = KeyManager.load_verify_key(algs[0], key_file, secret)
        return jwt.decode(
            token, key=key, algorithms=algs, audience=opts.audience,
            issuer=opts.issuer, leeway=opts.leeway, options={"verify_signature": True}
        )

    @staticmethod
    def verify_jwks(token: str, jwks_url: str, algs: Iterable[str], opts: VerifyOpts) -> Dict[str, Any]:
        algs = list(algs)
        if not algs or any(a not in ALGS_VERIFY for a in algs):
            raise SystemExit(f"[!] Allowed verify algs: {ALGS_VERIFY}")
        key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key
        return jwt.decode(
            token, key=key, algorithms=algs, audience=opts.audience,
            issuer=opts.issuer, leeway=opts.leeway, options={"verify_signature": True}
        )

    @staticmethod
    def parse_unverified(token: str) -> Dict[str, Any]:
        return {
            "warning": "UNVERIFIED",
            "header": jwt.get_unverified_header(token),
            "payload": jwt.decode(token, options={"verify_signature": False}),
        }

    @staticmethod
    def resign(existing_token: str, new_payload: Dict[str, Any], alg: str,
               key_file: Optional[str], secret: Optional[str],
               headers: Optional[Dict[str, Any]], exp_s: Optional[int]) -> str:
        # ensure header parseable (and allow caller to copy kid if desired)
        _ = jwt.get_unverified_header(existing_token)
        return JWTTool.sign(new_payload, alg, key_file, secret, headers, exp_s)


# ---------- CLI wiring ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Slim JWT tool (sign/verify/parse/resign/keys/hmac).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Tip: run `python jwt_tool.py examples` for runnable examples."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # sign
    sp = sub.add_parser("sign", help="Sign a JWT")
    sp.add_argument("--alg", required=True, choices=ALGS_SIGN)
    sp.add_argument("--key-file", help="PEM private key (RS/ES/EdDSA) or secret file (HS).")
    sp.add_argument("--secret", help="HMAC secret (HS*).")
    sp.add_argument("--payload", required=True, help="JSON payload.")
    sp.add_argument("--headers", help="JSON header (e.g., {\"kid\":\"...\"}).")
    sp.add_argument("--exp", type=int, default=3600, help="exp seconds from now (default 3600).")

    # verify
    vp = sub.add_parser("verify", help="Verify a JWT")
    vp.add_argument("--token", required=True)
    vp.add_argument("--alg", action="append", required=True, help="Allowed alg(s); repeatable.")
    src = vp.add_mutually_exclusive_group(required=True)
    src.add_argument("--key-file", help="PEM public key (RS/ES/EdDSA) or secret file (HS).")
    src.add_argument("--secret", help="HMAC secret.")
    src.add_argument("--jwks", help="JWKS URL.")
    vp.add_argument("--aud", help="Expected audience.")
    vp.add_argument("--iss", help="Expected issuer.")
    vp.add_argument("--leeway", type=int, default=0)

    # parse
    pp = sub.add_parser("parse", help="Parse header & payload without verification")
    pp.add_argument("--token", required=True)

    # resign
    rp = sub.add_parser("resign", help="Re-sign a JWT with a known key")
    rp.add_argument("--existing-token", required=True)
    rp.add_argument("--alg", required=True, choices=ALGS_SIGN)
    rp.add_argument("--key-file", help="PEM private (RS/ES/EdDSA) or secret file (HS).")
    rp.add_argument("--secret", help="HMAC secret (HS*).")
    rp.add_argument("--new-payload", required=True, help="JSON payload for the new token.")
    rp.add_argument("--headers", help="JSON headers for the new token.")
    rp.add_argument("--exp", type=int, help="exp seconds from now (optional).")

    # keys
    kg = sub.add_parser("keys", help="Keypair generation")
    ksub = kg.add_subparsers(dest="kcmd", required=True)
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
    hsub = hs.add_subparsers(dest="hcmd", required=True)
    hg = hsub.add_parser("gen-secret", help="Generate random HMAC secret (hex)")
    hg.add_argument("--bytes", type=int, default=32)
    hg.add_argument("--out", required=True)

    # examples
    sub.add_parser("examples", help="Print runnable examples")

    return p


def print_examples() -> None:
    examples = ( __doc__ or "" ).split("Examples", 1)[-1].strip()
    print("Examples" + ("\n" + examples if examples else ""))


def main(argv: Optional[List[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "sign":
            token = JWTTool.sign(
                payload=_parse_json(args.payload),
                alg=args.alg,
                key_file=args.key_file,
                secret=args.secret,
                headers=_parse_json(args.headers),
                exp_s=args.exp,
            )
            print(token)

        elif args.cmd == "verify":
            opts = VerifyOpts(audience=args.aud, issuer=args.iss, leeway=args.leeway)
            out = (JWTTool.verify_jwks(args.token, args.jwks, args.alg, opts)
                   if getattr(args, "jwks", None)
                   else JWTTool.verify_local(args.token, args.alg, args.key_file, args.secret, opts))
            _j({"valid": True, "claims": out})

        elif args.cmd == "parse":
            _j(JWTTool.parse_unverified(args.token))

        elif args.cmd == "resign":
            token = JWTTool.resign(
                existing_token=args.existing_token,
                new_payload=_parse_json(args.new_payload),
                alg=args.alg,
                key_file=args.key_file,
                secret=args.secret,
                headers=_parse_json(args.headers),
                exp_s=args.exp,
            )
            print(token)

        elif args.cmd == "keys":
            if args.kcmd == "gen-rsa":
                priv, pub = KeyManager.gen_rsa(args.bits)
            elif args.kcmd == "gen-ec":
                priv, pub = KeyManager.gen_ec()
            else:
                priv, pub = KeyManager.gen_eddsa()
            _write(args.out_priv, priv); _write(args.out_pub, pub)
            print(f"[+] Wrote private: {args.out_priv}\n[+] Wrote public : {args.out_pub}")

        elif args.cmd == "hmac" and args.hcmd == "gen-secret":
            _write(args.out, secrets.token_bytes(args.bytes).hex() + "\n")
            print(f"[+] Wrote {args.bytes}-byte hex secret to {args.out}")

        elif args.cmd == "examples":
            print_examples()

        else:
            raise SystemExit("[!] Unknown command")

    except ExpiredSignatureError:
        _j({"valid": False, "error": "expired"}); sys.exit(1)
    except InvalidSignatureError:
        _j({"valid": False, "error": "invalid_signature"}); sys.exit(1)
    except PyJWTError as e:
        _j({"valid": False, "error": f"jwt_error: {e}"}); sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr); sys.exit(2)


if __name__ == "__main__":
    main()
