#!/usr/bin/env python3
"""
aes_cipher.py—AES encrypt/decrypt utility supporting CBC and GCM modes with key loading options.

Usage:
  # Encrypt in CBC (default):
  ./aes_cipher.py encrypt \
    --key 'Your16ByteKeyHere!' \
    --data 'Secret message'

  # Encrypt in GCM:
  ./aes_cipher.py encrypt \
    --mode gcm \
    --key 'YourKeyHere16or32bytes' \
    --data 'Secret message'

  # Decrypt base64 ciphertext (auto-detects mode):
  ./aes_cipher.py decrypt \
    --key 'YourKeyHere16or32bytes' \
    --data '<base64 ciphertext>'

  # Load key from environment (AES_KEY):
  export AES_KEY='YourKeyHere16or32bytes'
  ./aes_cipher.py encrypt --data 'Message'
"""

import argparse
import base64
import os
import sys
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size  # 16 bytes


def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len


def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding bytes")
    return data[:-padding_len]


class AESCipher:
    def __init__(self, key: bytes, mode: str = "cbc"):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes")
        if mode not in ("cbc", "gcm"):
            raise ValueError("Mode must be 'cbc' or 'gcm'")
        self.key = key
        self.mode = mode

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode("utf-8")
        if self.mode == "cbc":
            iv = get_random_bytes(BLOCK_SIZE)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ct = cipher.encrypt(pad(data))
            payload = iv + ct
        else:  # GCM mode
            iv = get_random_bytes(12)  # 96-bit nonce
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            ct, tag = cipher.encrypt_and_digest(data)
            payload = iv + ct + tag
        return base64.b64encode(payload).decode("utf-8")

    def decrypt(self, b64_ciphertext: str) -> str:
        raw = base64.b64decode(b64_ciphertext)
        # Detect mode by length: GCM nonce=12, tag=16
        if len(raw) >= 12 + 16 and self.mode == "gcm":
            iv = raw[:12]
            tag = raw[-16:]
            ct = raw[12:-16]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            data = cipher.decrypt_and_verify(ct, tag)
        else:
            # assume CBC
            iv = raw[:BLOCK_SIZE]
            ct = raw[BLOCK_SIZE:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            data = unpad(cipher.decrypt(ct))
        return data.decode("utf-8")


def get_key(args_key: str) -> bytes:
    if args_key:
        return args_key.encode("utf-8")
    env_key = os.environ.get("AES_KEY")
    if env_key:
        return env_key.encode("utf-8")
    print("Error: No key provided. Use --key or set AES_KEY.")
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AES encrypt/decrypt with CBC/GCM modes")
    p.add_argument("mode", choices=("encrypt", "decrypt"), help="operation mode")
    p.add_argument(
        "--key", "-k", default="",
        help="secret key (16,24,32 bytes) or empty to use AES_KEY env var"
    )
    p.add_argument(
        "--data", "-d", required=True,
        help="plaintext to encrypt or base64 ciphertext to decrypt"
    )
    p.add_argument(
        "--cipher-mode", "-m", choices=("cbc", "gcm"), default="cbc",
        help="cipher mode for encryption (default cbc)"
    )
    return p.parse_args()


def main():
    args = parse_args()
    key = get_key(args.key)
    cipher = AESCipher(key, mode=args.cipher_mode)

    if args.mode == "encrypt":
        print(cipher.encrypt(args.data))
    else:
        try:
            print(cipher.decrypt(args.data))
        except Exception as e:
            print(f"Decryption error: {e}")


if __name__ == "__main__":
    main()

##
##
