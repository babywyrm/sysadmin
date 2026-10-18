#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import time
import uuid
import urllib.request
import urllib.error

# ----------------------------
# Config (match your app.yml)
# ----------------------------
HMAC_SECRET = b"super-secret-demo-key-change-me-please-123456"
URL = "http://127.0.0.1:8080/api/hello"
METHOD = "GET"

# ----------------------------
# Helpers
# ----------------------------
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64u_json(obj) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hs256_jwt(header: dict, payload: dict, secret: bytes) -> str:
    h = b64u_json(header)
    p = b64u_json(payload)
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"

# ----------------------------
# Minimal EC JWK (P-256) demo
# ----------------------------
# NOTE: We are not doing real ECDSA signing here to keep deps zero.
# For the demo filter you built, the proof signature *is* verified via jwk,
# so this client needs to sign with a real EC private key.
#
# Therefore, we generate proof using 'openssl' via subprocess (present on most boxes).
import subprocess

def openssl_gen_p256_key():
    # returns (priv_pem, pub_jwk)
    priv = subprocess.check_output(["openssl", "ecparam", "-name", "prime256v1", "-genkey"])
    pub = subprocess.check_output(["openssl", "ec", "-pubout"], input=priv)

    # Extract x/y from public key with openssl (DER -> raw coordinates)
    # This uses openssl to spit out uncompressed point in hex.
    text = subprocess.check_output(["openssl", "ec", "-pubin", "-text", "-noout"], input=pub).decode()
    # Find "pub:" section (hex bytes, colon separated, can span lines)
    lines = text.splitlines()
    pub_bytes_hex = ""
    in_pub = False
    for line in lines:
        if line.strip().startswith("pub:"):
            in_pub = True
            continue
        if in_pub:
            if line.strip().startswith("ASN1 OID") or line.strip().startswith("NIST CURVE"):
                break
            pub_bytes_hex += line.strip().replace(":", "")
    pub_bytes = bytes.fromhex(pub_bytes_hex)

    # Uncompressed point = 0x04 || X(32) || Y(32)
    if len(pub_bytes) < 65 or pub_bytes[0] != 0x04:
        raise RuntimeError("Unexpected EC public key format from openssl")
    x = pub_bytes[1:33]
    y = pub_bytes[33:65]

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(x),
        "y": b64u(y),
    }
    return priv, jwk

def jwk_thumbprint(jwk: dict) -> str:
    # RFC7638 thumbprint: hash of canonical JSON with required members
    # For EC P-256: crv, kty, x, y
    canon = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True
    ).encode()
    return b64u(sha256(canon))

def openssl_es256_sign(priv_pem: bytes, signing_input: bytes) -> bytes:
    # JWS ES256 requires signature as raw (r||s), not DER.
    # We'll ask openssl to output DER, then convert to raw.
    der = subprocess.check_output(
        ["openssl", "dgst", "-sha256", "-sign", "/dev/stdin"],
        input=priv_pem + b"\n"  # ensure PEM ends ok
    )
    # That doesn't sign the input; openssl dgst signs stdin content.
    # We need to sign signing_input. Provide signing_input as stdin to dgst, and key via file.
    # We'll write the key to a temp file.
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(priv_pem)
        key_path = f.name
    try:
        der = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input
        )
    finally:
        os.unlink(key_path)

    # Convert ASN.1 DER ECDSA signature to raw r||s
    # DER format: 30 .. 02 lenR R 02 lenS S
    from asn1crypto import core  # type: ignore
    sig = core.Sequence.load(der)
    r = int(sig[0]).to_bytes(32, "big")
    s = int(sig[1]).to_bytes(32, "big")
    return r + s

# We need asn1crypto for DER->raw. Provide fallback: install-less minimal parse.
def der_ecdsa_to_raw(der: bytes) -> bytes:
    # Very small DER parser for ECDSA sig
    if len(der) < 8 or der[0] != 0x30:
        raise RuntimeError("Bad DER signature")
    idx = 2
    if der[1] & 0x80:
        n = der[1] & 0x7F
        idx = 2 + n
    # INTEGER r
    if der[idx] != 0x02:
        raise RuntimeError("Bad DER signature (r tag)")
    rlen = der[idx+1]
    r = der[idx+2:idx+2+rlen]
    idx = idx+2+rlen
    # INTEGER s
    if der[idx] != 0x02:
        raise RuntimeError("Bad DER signature (s tag)")
    slen = der[idx+1]
    s = der[idx+2:idx+2+slen]

    # Strip leading 0x00 if present, then pad
    r = r.lstrip(b"\x00")
    s = s.lstrip(b"\x00")
    r = (b"\x00"*32 + r)[-32:]
    s = (b"\x00"*32 + s)[-32:]
    return r + s

def es256_jws(priv_pem: bytes, header: dict, payload: dict) -> str:
    h = b64u_json(header)
    p = b64u_json(payload)
    signing_input = f"{h}.{p}".encode()

    # DER signature from openssl, then convert to raw
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(priv_pem)
        key_path = f.name
    try:
        der = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input
        )
    finally:
        os.unlink(key_path)

    raw = der_ecdsa_to_raw(der)
    return f"{h}.{p}.{b64u(raw)}"

# ----------------------------
# Main flow
# ----------------------------
def main():
    priv, jwk = openssl_gen_p256_key()
    jkt = jwk_thumbprint(jwk)

    # Access token (HS256) - your server validates this as the authenticated principal
    now = int(time.time())
    access_header = {"alg": "HS256", "typ": "JWT"}
    access_payload = {
        "sub": "htb-user",
        "iat": now,
        "exp": now + 300,
        "scope": "demo",
        "cnf": {"jkt": jkt},
    }
    access_token = hs256_jwt(access_header, access_payload, HMAC_SECRET)

    # DPoP proof for resource request
    ath = b64u(sha256(access_token.encode()))
    proof_header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    proof_payload = {
        "htm": METHOD,
        "htu": URL,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "ath": ath,
    }
    proof = es256_jws(priv, proof_header, proof_payload)

    def call(proof_token: str, label: str):
        req = urllib.request.Request(URL, method=METHOD)
        req.add_header("Authorization", f"DPoP {access_token}")
        req.add_header("DPoP", proof_token)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode()
                print(f"\n[{label}] HTTP {r.status}")
                print(body)
        except urllib.error.HTTPError as e:
            print(f"\n[{label}] HTTP {e.code}")
            print(e.read().decode())

    call(proof, "FIRST CALL (should succeed)")
    call(proof, "REPLAY (should fail: jti reused)")

if __name__ == "__main__":
    main()
