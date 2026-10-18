#!/usr/bin/env python3
"""
JWT Utility — sign / verify / parse / resign / DPoP / introspect / keys / hmac

Supported algorithms
  Sign/Verify : HS256  RS256  ES256  EdDSA
  DPoP proofs : RS256  ES256  EdDSA   (per RFC 9449 §4.2 — no HS*)

Key helpers   : gen-rsa  gen-ec  gen-eddsa  (keys sub-command)
HMAC helpers  : gen-secret                  (hmac sub-command)

Quick examples
──────────────
# Generate an ES256 keypair
python jwt_tool.py keys gen-ec --out-priv ec_priv.pem --out-pub ec_pub.pem

# Sign with kid + 15-minute expiry
python jwt_tool.py sign --alg ES256 --key-file ec_priv.pem \\
  --payload '{"sub":"u1","scope":"read"}' --headers '{"kid":"k1"}' --exp 900

# Sign without exp (negative-testing)
python jwt_tool.py sign --alg HS256 --secret deadbeef \\
  --payload '{"sub":"u1"}' --no-exp

# Verify locally
python jwt_tool.py verify --token "$T" --alg ES256 --key-file ec_pub.pem \\
  --aud myapi --iss https://issuer.example

# Verify via JWKS endpoint
python jwt_tool.py verify --token "$T" --alg RS256 \\
  --jwks https://example.com/.well-known/jwks.json

# Parse two tokens and diff their payloads
python jwt_tool.py parse --token "$T1" --diff "$T2"

# Compute JWK Thumbprint of a public key
python jwt_tool.py thumbprint --key-file ec_pub.pem

# Generate a DPoP proof (ES256)
python jwt_tool.py dpop --alg ES256 --key-file ec_priv.pem \\
  --htm POST --htu https://api.example/resource

# Generate a DPoP proof bound to an access token (ath)
python jwt_tool.py dpop --alg ES256 --key-file ec_priv.pem \\
  --htm GET --htu https://api.example/data --access-token "$AT"

# Verify a DPoP proof you received
python jwt_tool.py dpop-verify --token "$DPOP" --key-file ec_pub.pem \\
  --htm POST --htu https://api.example/resource

# Introspect a token (RFC 7662)
python jwt_tool.py introspect --token "$AT" \\
  --endpoint https://as.example/introspect \\
  --client-id myapp --client-secret s3cr3t
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
import secrets
import urllib.request
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidSignatureError,
    PyJWTError,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

ALGS_SIGN: Tuple[str, ...] = ("HS256", "RS256", "ES256", "EdDSA")
ALGS_VERIFY: Tuple[str, ...] = ("HS256", "RS256", "ES256", "EdDSA")
# RFC 9449 §4.2 — DPoP proofs MUST use an asymmetric algorithm
ALGS_DPOP: Tuple[str, ...] = ("RS256", "ES256", "EdDSA")

# Headers that can redirect signature verification to an attacker-controlled
# source — we reject them outright (common pentest vector).
_DANGEROUS_HEADERS = frozenset({"jku", "x5u"})


# ──────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────

def _now() -> int:
    return int(time.time())


def _j(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _write(path: str, data: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def _parse_json(s: Optional[str]) -> Dict[str, Any]:
    if not s:
        return {}
    try:
        return json.loads(s)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[!] Invalid JSON: {exc}") from exc


def _b64url(data: bytes) -> str:
    """URL-safe base-64, no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _with_std_claims(
    payload: Dict[str, Any],
    exp_s: Optional[int],
    nbf_s: Optional[int],
    include_exp: bool = True,
) -> Dict[str, Any]:
    p = dict(payload)
    now = _now()
    p.setdefault("iat", now)
    if include_exp and exp_s is not None:
        p.setdefault("exp", now + int(exp_s))
    if nbf_s is not None:
        p.setdefault("nbf", now + int(nbf_s))
    return p


def _guard_dangerous_headers(headers: Dict[str, Any]) -> None:
    found = _DANGEROUS_HEADERS & headers.keys()
    if found:
        raise SystemExit(
            f"[!] Refusing token with dangerous header(s): {sorted(found)}. "
            "These can redirect signature verification to an attacker-controlled "
            "URL (classic JWT confusion attack)."
        )


# ──────────────────────────────────────────────
# JWK Thumbprint  (RFC 7638)
# ──────────────────────────────────────────────

class JWKThumbprint:
    """
    Compute the JWK Thumbprint (SHA-256) of a public key.

    The thumbprint is the base64url-encoded SHA-256 of the canonical JWK
    JSON (lexicographically sorted, no extra members).  It is used in DPoP
    (`cnf.jkt`) and as a stable key identifier.
    """

    @staticmethod
    def _public_key_to_jwk_members(pub_key: Any) -> Dict[str, str]:
        """Return only the required JWK members for each key type."""
        if isinstance(pub_key, RSAPublicKey):
            nums = pub_key.public_numbers()
            e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
            n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            return {"e": _b64url(e_bytes), "kty": "RSA", "n": _b64url(n_bytes)}

        if isinstance(pub_key, EllipticCurvePublicKey):
            nums = pub_key.public_numbers()
            size = (pub_key.key_size + 7) // 8
            return {
                "crv": "P-256",
                "kty": "EC",
                "x": _b64url(nums.x.to_bytes(size, "big")),
                "y": _b64url(nums.y.to_bytes(size, "big")),
            }

        if isinstance(pub_key, Ed25519PublicKey):
            raw = pub_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return {"crv": "Ed25519", "kty": "OKP", "x": _b64url(raw)}

        raise SystemExit(f"[!] Unsupported key type for thumbprint: {type(pub_key)}")

    @staticmethod
    def from_public_key(pub_key: Any) -> str:
        members = JWKThumbprint._public_key_to_jwk_members(pub_key)
        # RFC 7638 §3: canonical JSON = sorted keys, no spaces
        canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(canonical.encode()).digest()
        return _b64url(digest)

    @staticmethod
    def from_pem_file(path: str) -> str:
        raw = _read(path).encode()
        # Try public key first; fall back to extracting from private key
        try:
            pub = serialization.load_pem_public_key(raw)
        except Exception:
            priv = serialization.load_pem_private_key(raw, password=None)
            pub = priv.public_key()  # type: ignore[attr-defined]
        return JWKThumbprint.from_public_key(pub)


# ──────────────────────────────────────────────
# Key management
# ──────────────────────────────────────────────

class KeyManager:
    """Generate and load cryptographic keys."""

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
    def load_sign_key(
        alg: str, key_file: Optional[str], secret: Optional[str]
    ) -> Union[str, Any]:
        if alg.startswith("HS"):
            if secret is not None:
                return secret
            if key_file:
                return _read(key_file).strip()
            raise SystemExit("[!] HS* requires --secret or --key-file.")
        if not key_file:
            raise SystemExit("[!] RS*/ES*/EdDSA require --key-file (PEM private key).")
        return serialization.load_pem_private_key(
            _read(key_file).encode(), password=None
        )

    @staticmethod
    def load_verify_key(
        alg: str, key_file: Optional[str], secret: Optional[str]
    ) -> Union[str, Any]:
        if alg.startswith("HS"):
            if secret is not None:
                return secret
            if key_file:
                return _read(key_file).strip()
            raise SystemExit("[!] HS* verification requires --secret or --key-file.")
        if not key_file:
            raise SystemExit(
                "[!] RS*/ES*/EdDSA verification requires --key-file (PEM public key)."
            )
        return serialization.load_pem_public_key(_read(key_file).encode())


# ──────────────────────────────────────────────
# Verify options
# ──────────────────────────────────────────────

@dataclass
class VerifyOpts:
    audience: Optional[str] = None
    issuer: Optional[str] = None
    leeway: int = 0


# ──────────────────────────────────────────────
# DPoP  (RFC 9449)
# ──────────────────────────────────────────────

class DPoP:
    """
    DPoP proof JWT helpers.

    A DPoP proof is a short-lived, single-use JWT that binds an HTTP request
    to a specific key-pair.  The proof is sent in the `DPoP` request header.

    Required claims (§4.2):
      jti  — unique identifier (replay detection)
      htm  — HTTP method (uppercase)
      htu  — HTTP URI (no fragment, no query string per §4.2)
      iat  — issued-at  (servers SHOULD reject proofs older than a few seconds)

    Optional / conditional claims:
      ath  — base64url(SHA-256(ASCII(access_token)))  — required when the
             proof accompanies a Bearer-bound access token (§4.2 & §9)
      nonce— server-supplied nonce (§8)

    The JOSE header MUST contain:
      typ  → "dpop+jwt"
      alg  → asymmetric algorithm (no HS*)
      jwk  → public key in JWK form (embedded, not a reference)
    """

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _private_key_to_public_jwk(priv_key: Any) -> Dict[str, Any]:
        """Embed the public key as a JWK in the DPoP header."""
        pub = priv_key.public_key()

        if isinstance(pub, RSAPublicKey):
            nums = pub.public_numbers()
            e_b = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
            n_b = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            return {"kty": "RSA", "e": _b64url(e_b), "n": _b64url(n_b)}

        if isinstance(pub, EllipticCurvePublicKey):
            nums = pub.public_numbers()
            size = (pub.key_size + 7) // 8
            return {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64url(nums.x.to_bytes(size, "big")),
                "y": _b64url(nums.y.to_bytes(size, "big")),
            }

        if isinstance(pub, Ed25519PublicKey):
            raw = pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}

        raise SystemExit(f"[!] Unsupported key type for DPoP: {type(priv_key)}")

    @staticmethod
    def _ath(access_token: str) -> str:
        """SHA-256 of the ASCII access token, base64url-encoded (§9)."""
        return _b64url(hashlib.sha256(access_token.encode("ascii")).digest())

    # ── Public API ────────────────────────────────────────────────────────

    @staticmethod
    def create_proof(
        alg: str,
        key_file: str,
        htm: str,
        htu: str,
        access_token: Optional[str] = None,
        nonce: Optional[str] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Mint a DPoP proof JWT.

        Parameters
        ----------
        alg          : Algorithm — must be in ALGS_DPOP.
        key_file     : Path to PEM private key.
        htm          : HTTP method (e.g. "POST").
        htu          : Target URI (e.g. "https://api.example/resource").
        access_token : If provided, adds `ath` claim (token binding).
        nonce        : Server-issued nonce, if any.
        extra_claims : Any additional payload claims.
        """
        if alg not in ALGS_DPOP:
            raise SystemExit(
                f"[!] DPoP requires an asymmetric alg; got '{alg}'. "
                f"Choose from {ALGS_DPOP}."
            )

        priv_key = serialization.load_pem_private_key(
            _read(key_file).encode(), password=None
        )
        pub_jwk = DPoP._private_key_to_public_jwk(priv_key)

        headers: Dict[str, Any] = {
            "typ": "dpop+jwt",
            "alg": alg,
            "jwk": pub_jwk,
        }

        now = _now()
        payload: Dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": htm.upper(),
            "htu": htu,
            "iat": now,
            # Short-lived by design — 120 s is generous; many servers use 30 s
            "exp": now + 120,
        }
        if access_token:
            payload["ath"] = DPoP._ath(access_token)
        if nonce:
            payload["nonce"] = nonce
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, priv_key, algorithm=alg, headers=headers)

    @staticmethod
    def verify_proof(
        token: str,
        alg: str,
        key_file: str,
        htm: str,
        htu: str,
        access_token: Optional[str] = None,
        nonce: Optional[str] = None,
        leeway: int = 5,
    ) -> Dict[str, Any]:
        """
        Verify a DPoP proof.

        Checks performed
        ─────────────────
        1. `typ` header == "dpop+jwt"
        2. Algorithm is an asymmetric DPoP alg (no HS*)
        3. `jwk` header is present and the proof is signed with that key
        4. Signature is valid using the supplied key file
        5. `htm` matches (case-insensitive)
        6. `htu` matches exactly
        7. `iat` is within [now-leeway, now+leeway]  (replay detection)
        8. `ath` matches the access token hash, if both are provided
        9. `nonce` matches, if provided
        """
        if alg not in ALGS_DPOP:
            raise SystemExit(f"[!] Not a DPoP alg: {alg}")

        unverified_header = jwt.get_unverified_header(token)

        # 1 & 2
        if unverified_header.get("typ") != "dpop+jwt":
            raise SystemExit(
                "[!] DPoP proof must have typ=dpop+jwt; "
                f"got {unverified_header.get('typ')!r}"
            )
        if unverified_header.get("alg") not in ALGS_DPOP:
            raise SystemExit(
                f"[!] DPoP proof alg must be asymmetric; "
                f"got {unverified_header.get('alg')!r}"
            )

        # 3 — jwk present
        if "jwk" not in unverified_header:
            raise SystemExit("[!] DPoP proof header must contain 'jwk'.")

        # 4 — signature
        verify_key = KeyManager.load_verify_key(alg, key_file, None)
        claims = jwt.decode(
            token,
            key=verify_key,
            algorithms=[alg],
            leeway=leeway,
            options={"verify_signature": True},
        )

        # 5 — htm
        if claims.get("htm", "").upper() != htm.upper():
            raise SystemExit(
                f"[!] htm mismatch: proof={claims.get('htm')!r} != expected={htm!r}"
            )

        # 6 — htu
        if claims.get("htu") != htu:
            raise SystemExit(
                f"[!] htu mismatch: proof={claims.get('htu')!r} != expected={htu!r}"
            )

        # 7 — iat freshness (beyond PyJWT's leeway check on exp)
        iat = claims.get("iat", 0)
        if abs(_now() - iat) > leeway + 120:
            raise SystemExit(f"[!] DPoP proof is stale (iat={iat}).")

        # 8 — ath
        if access_token and "ath" not in claims:
            raise SystemExit(
                "[!] access_token supplied for verification but proof lacks 'ath'."
            )
        if access_token and claims.get("ath") != DPoP._ath(access_token):
            raise SystemExit("[!] ath mismatch — access token hash does not match.")

        # 9 — nonce
        if nonce and claims.get("nonce") != nonce:
            raise SystemExit(
                f"[!] nonce mismatch: {claims.get('nonce')!r} != {nonce!r}"
            )

        return claims


# ──────────────────────────────────────────────
# Token introspection  (RFC 7662)
# ──────────────────────────────────────────────

class Introspect:
    """
    RFC 7662 token introspection client.

    Sends the token to the AS introspection endpoint and returns the
    JSON response.  Basic-auth (client_id/client_secret) is the most
    common credential scheme; bearer-auth is also supported.
    """

    @staticmethod
    def call(
        token: str,
        endpoint: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        bearer: Optional[str] = None,
        token_type_hint: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        body: Dict[str, str] = {"token": token}
        if token_type_hint:
            body["token_type_hint"] = token_type_hint

        data = urllib.parse.urlencode(body).encode()
        req = urllib.request.Request(
            endpoint,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if bearer:
            req.add_header("Authorization", f"Bearer {bearer}")
        elif client_id and client_secret:
            creds = base64.b64encode(
                f"{client_id}:{client_secret}".encode()
            ).decode()
            req.add_header("Authorization", f"Basic {creds}")

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode(errors="replace")
            raise SystemExit(
                f"[!] Introspection HTTP {exc.code}: {body_text}"
            ) from exc
        except Exception as exc:
            raise SystemExit(f"[!] Introspection request failed: {exc}") from exc


# ──────────────────────────────────────────────
# Core JWT operations
# ──────────────────────────────────────────────

class JWTTool:
    """sign / verify / parse / resign"""

    @staticmethod
    def sign(
        payload: Dict[str, Any],
        alg: str,
        key_file: Optional[str],
        secret: Optional[str],
        headers: Optional[Dict[str, Any]],
        exp_s: Optional[int],
        nbf_s: Optional[int] = None,
        include_exp: bool = True,
    ) -> str:
        if alg not in ALGS_SIGN:
            raise SystemExit(f"[!] alg must be one of {ALGS_SIGN}")
        hdrs = headers or {}
        _guard_dangerous_headers(hdrs)
        key = KeyManager.load_sign_key(alg, key_file, secret)
        return jwt.encode(
            _with_std_claims(payload, exp_s, nbf_s, include_exp),
            key,
            algorithm=alg,
            headers=hdrs,
        )

    @staticmethod
    def verify_local(
        token: str,
        algs: Iterable[str],
        key_file: Optional[str],
        secret: Optional[str],
        opts: VerifyOpts,
    ) -> Dict[str, Any]:
        algs = list(algs)
        if not algs or any(a not in ALGS_VERIFY for a in algs):
            raise SystemExit(f"[!] Allowed verify algs: {ALGS_VERIFY}")
        _guard_dangerous_headers(jwt.get_unverified_header(token))
        key = KeyManager.load_verify_key(algs[0], key_file, secret)
        return jwt.decode(
            token,
            key=key,
            algorithms=algs,
            audience=opts.audience,
            issuer=opts.issuer,
            leeway=opts.leeway,
            options={"verify_signature": True},
        )

    @staticmethod
    def verify_jwks(
        token: str,
        jwks_url: str,
        algs: Iterable[str],
        opts: VerifyOpts,
    ) -> Dict[str, Any]:
        algs = list(algs)
        if not algs or any(a not in ALGS_VERIFY for a in algs):
            raise SystemExit(f"[!] Allowed verify algs: {ALGS_VERIFY}")
        _guard_dangerous_headers(jwt.get_unverified_header(token))
        key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key=key,
            algorithms=algs,
            audience=opts.audience,
            issuer=opts.issuer,
            leeway=opts.leeway,
            options={"verify_signature": True},
        )

    @staticmethod
    def parse_unverified(
        token: str,
        diff_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "warning": "UNVERIFIED — do not trust these claims",
            "header": jwt.get_unverified_header(token),
            "payload": jwt.decode(token, options={"verify_signature": False}),
        }
        if diff_token:
            other = jwt.decode(diff_token, options={"verify_signature": False})
            all_keys = set(result["payload"]) | set(other)
            diff: Dict[str, Any] = {}
            for k in sorted(all_keys):
                a, b = result["payload"].get(k, "<missing>"), other.get(k, "<missing>")
                if a != b:
                    diff[k] = {"token_1": a, "token_2": b}
            result["payload_diff"] = diff or "(no differences)"
        return result

    @staticmethod
    def resign(
        existing_token: str,
        new_payload: Dict[str, Any],
        alg: str,
        key_file: Optional[str],
        secret: Optional[str],
        headers: Optional[Dict[str, Any]],
        exp_s: Optional[int],
        nbf_s: Optional[int] = None,
        include_exp: bool = True,
    ) -> str:
        # Validate existing token is parseable (no signature skip)
        _ = jwt.get_unverified_header(existing_token)
        return JWTTool.sign(
            new_payload, alg, key_file, secret, headers, exp_s, nbf_s, include_exp
        )


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def _add_key_source(parser: argparse.ArgumentParser) -> None:
    """Attach --key-file / --secret as a mutually exclusive group."""
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--key-file", help="PEM key file.")
    g.add_argument("--secret", help="HMAC secret (HS* only).")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="JWT tool — sign / verify / parse / resign / DPoP / introspect",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `python jwt_tool.py examples` to print usage examples.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── sign ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("sign", help="Sign a JWT")
    sp.add_argument("--alg", required=True, choices=ALGS_SIGN)
    sp.add_argument("--key-file")
    sp.add_argument("--secret")
    sp.add_argument("--payload", required=True, help="JSON payload.")
    sp.add_argument("--headers", help='JSON extra headers, e.g. \'{"kid":"k1"}\'.')
    sp.add_argument("--exp", type=int, default=3600, help="Seconds until exp (default 3600).")
    sp.add_argument("--nbf", type=int, default=None, help="Seconds from now for nbf.")
    sp.add_argument(
        "--no-exp",
        action="store_true",
        help="Omit exp claim entirely (useful for negative testing).",
    )

    # ── verify ────────────────────────────────────────────────────────────
    vp = sub.add_parser("verify", help="Verify a JWT")
    vp.add_argument("--token", required=True)
    vp.add_argument("--alg", action="append", required=True, dest="algs",
                    help="Allowed alg(s); repeatable.")
    src = vp.add_mutually_exclusive_group(required=True)
    src.add_argument("--key-file")
    src.add_argument("--secret")
    src.add_argument("--jwks", help="JWKS endpoint URL.")
    vp.add_argument("--aud")
    vp.add_argument("--iss")
    vp.add_argument("--leeway", type=int, default=0)

    # ── parse ─────────────────────────────────────────────────────────────
    pp = sub.add_parser("parse", help="Decode header & payload (no verification)")
    pp.add_argument("--token", required=True)
    pp.add_argument("--diff", metavar="TOKEN2",
                    help="Second token to diff payload claims against.")

    # ── resign ────────────────────────────────────────────────────────────
    rp = sub.add_parser("resign", help="Re-sign a JWT with a known key")
    rp.add_argument("--existing-token", required=True)
    rp.add_argument("--alg", required=True, choices=ALGS_SIGN)
    rp.add_argument("--key-file")
    rp.add_argument("--secret")
    rp.add_argument("--new-payload", required=True, help="JSON for the new token.")
    rp.add_argument("--headers", help="JSON extra headers.")
    rp.add_argument("--exp", type=int, help="Seconds until exp.")
    rp.add_argument("--nbf", type=int, default=None, help="Seconds from now for nbf.")
    rp.add_argument("--no-exp", action="store_true", help="Omit exp claim.")

    # ── thumbprint ────────────────────────────────────────────────────────
    tp = sub.add_parser("thumbprint", help="Compute JWK Thumbprint (RFC 7638)")
    tp.add_argument(
        "--key-file", required=True,
        help="PEM public or private key (public portion is used).",
    )

    # ── dpop ──────────────────────────────────────────────────────────────
    dp = sub.add_parser("dpop", help="Create a DPoP proof JWT (RFC 9449)")
    dp.add_argument("--alg", required=True, choices=ALGS_DPOP)
    dp.add_argument("--key-file", required=True, help="PEM private key.")
    dp.add_argument("--htm", required=True, help="HTTP method (e.g. POST).")
    dp.add_argument("--htu", required=True, help="Target URI.")
    dp.add_argument("--access-token", help="Access token for ath binding.")
    dp.add_argument("--nonce", help="Server-issued nonce.")
    dp.add_argument("--extra", help="JSON extra payload claims.")

    # ── dpop-verify ───────────────────────────────────────────────────────
    dv = sub.add_parser("dpop-verify", help="Verify a DPoP proof JWT")
    dv.add_argument("--token", required=True)
    dv.add_argument("--alg", required=True, choices=ALGS_DPOP)
    dv.add_argument("--key-file", required=True, help="PEM public key.")
    dv.add_argument("--htm", required=True)
    dv.add_argument("--htu", required=True)
    dv.add_argument("--access-token", help="Access token to verify ath against.")
    dv.add_argument("--nonce")
    dv.add_argument("--leeway", type=int, default=5)

    # ── introspect ────────────────────────────────────────────────────────
    ip = sub.add_parser("introspect", help="RFC 7662 token introspection")
    ip.add_argument("--token", required=True)
    ip.add_argument("--endpoint", required=True, help="Introspection endpoint URL.")
    ip.add_argument("--client-id")
    ip.add_argument("--client-secret")
    ip.add_argument("--bearer", help="Bearer token for endpoint auth.")
    ip.add_argument("--hint", dest="token_type_hint",
                    help="token_type_hint value (e.g. access_token).")

    # ── keys ──────────────────────────────────────────────────────────────
    kg = sub.add_parser("keys", help="Keypair generation")
    ksub = kg.add_subparsers(dest="kcmd", required=True)
    kr = ksub.add_parser("gen-rsa")
    kr.add_argument("--bits", type=int, default=2048)
    kr.add_argument("--out-priv", required=True)
    kr.add_argument("--out-pub", required=True)
    ke = ksub.add_parser("gen-ec")
    ke.add_argument("--out-priv", required=True)
    ke.add_argument("--out-pub", required=True)
    kd = ksub.add_parser("gen-eddsa")
    kd.add_argument("--out-priv", required=True)
    kd.add_argument("--out-pub", required=True)

    # ── hmac ──────────────────────────────────────────────────────────────
    hs = sub.add_parser("hmac", help="HMAC helpers")
    hsub = hs.add_subparsers(dest="hcmd", required=True)
    hg = hsub.add_parser("gen-secret")
    hg.add_argument("--bytes", type=int, default=32)
    hg.add_argument("--out", required=True)

    # ── examples ──────────────────────────────────────────────────────────
    sub.add_parser("examples", help="Print usage examples")

    return p


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        # ── sign ──────────────────────────────────────────────────────────
        if args.cmd == "sign":
            token = JWTTool.sign(
                payload=_parse_json(args.payload),
                alg=args.alg,
                key_file=args.key_file,
                secret=args.secret,
                headers=_parse_json(args.headers),
                exp_s=args.exp,
                nbf_s=args.nbf,
                include_exp=not args.no_exp,
            )
            print(token)

        # ── verify ────────────────────────────────────────────────────────
        elif args.cmd == "verify":
            opts = VerifyOpts(
                audience=args.aud, issuer=args.iss, leeway=args.leeway
            )
            out = (
                JWTTool.verify_jwks(args.token, args.jwks, args.algs, opts)
                if getattr(args, "jwks", None)
                else JWTTool.verify_local(
                    args.token, args.algs, args.key_file, args.secret, opts
                )
            )
            _j({"valid": True, "claims": out})

        # ── parse ─────────────────────────────────────────────────────────
        elif args.cmd == "parse":
            _j(JWTTool.parse_unverified(args.token, diff_token=args.diff))

        # ── resign ────────────────────────────────────────────────────────
        elif args.cmd == "resign":
            token = JWTTool.resign(
                existing_token=args.existing_token,
                new_payload=_parse_json(args.new_payload),
                alg=args.alg,
                key_file=args.key_file,
                secret=args.secret,
                headers=_parse_json(args.headers),
                exp_s=args.exp,
                nbf_s=args.nbf,
                include_exp=not args.no_exp,
            )
            print(token)

        # ── thumbprint ────────────────────────────────────────────────────
        elif args.cmd == "thumbprint":
            tp = JWKThumbprint.from_pem_file(args.key_file)
            _j({"thumbprint_sha256": tp})

        # ── dpop ──────────────────────────────────────────────────────────
        elif args.cmd == "dpop":
            proof = DPoP.create_proof(
                alg=args.alg,
                key_file=args.key_file,
                htm=args.htm,
                htu=args.htu,
                access_token=args.access_token,
                nonce=args.nonce,
                extra_claims=_parse_json(args.extra),
            )
            print(proof)
            # Also show the decoded proof so the user can inspect it
            _j({
                "header": jwt.get_unverified_header(proof),
                "payload": jwt.decode(proof, options={"verify_signature": False}),
            })

        # ── dpop-verify ───────────────────────────────────────────────────
        elif args.cmd == "dpop-verify":
            claims = DPoP.verify_proof(
                token=args.token,
                alg=args.alg,
                key_file=args.key_file,
                htm=args.htm,
                htu=args.htu,
                access_token=args.access_token,
                nonce=args.nonce,
                leeway=args.leeway,
            )
            _j({"valid": True, "claims": claims})

        # ── introspect ────────────────────────────────────────────────────
        elif args.cmd == "introspect":
            result = Introspect.call(
                token=args.token,
                endpoint=args.endpoint,
                client_id=args.client_id,
                client_secret=args.client_secret,
                bearer=args.bearer,
                token_type_hint=args.token_type_hint,
            )
            _j(result)

        # ── keys ──────────────────────────────────────────────────────────
        elif args.cmd == "keys":
            if args.kcmd == "gen-rsa":
                priv, pub = KeyManager.gen_rsa(args.bits)
            elif args.kcmd == "gen-ec":
                priv, pub = KeyManager.gen_ec()
            else:
                priv, pub = KeyManager.gen_eddsa()
            _write(args.out_priv, priv)
            _write(args.out_pub, pub)
            print(f"[+] Wrote private : {args.out_priv}")
            print(f"[+] Wrote public  : {args.out_pub}")

        # ── hmac ──────────────────────────────────────────────────────────
        elif args.cmd == "hmac" and args.hcmd == "gen-secret":
            _write(args.out, secrets.token_bytes(args.bytes).hex() + "\n")
            print(f"[+] Wrote {args.bytes}-byte hex secret → {args.out}")

        # ── examples ──────────────────────────────────────────────────────
        elif args.cmd == "examples":
            doc = (__doc__ or "").split("Quick examples", 1)
            print("Quick examples" + (doc[1] if len(doc) > 1 else ""))

    except ExpiredSignatureError:
        _j({"valid": False, "error": "expired"})
        sys.exit(1)
    except InvalidSignatureError:
        _j({"valid": False, "error": "invalid_signature"})
        sys.exit(1)
    except PyJWTError as exc:
        _j({"valid": False, "error": f"jwt_error: {exc}"})
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
