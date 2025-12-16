#!/usr/bin/env python3
"""
ansible_vault2john.py

Modern Ansible Vault hash extractor for John the Ripper.

Based on:
  https://fossies.org/linux/john/run/ansible2john.py

Supports:
  - Ansible Vault AES256
  - Python 3 only
  - Multiple input files
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from binascii import unhexlify


VAULT_HEADER = b"$ANSIBLE_VAULT"
SUPPORTED_CIPHER = "AES256"


def parse_vault_file(path: Path) -> str | None:
    """
    Parse an Ansible Vault file and return a JtR-compatible hash line.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"[!] Failed to read {path}: {exc}", file=sys.stderr)
        return None

    if not data.startswith(VAULT_HEADER):
        return None

    try:
        lines = data.splitlines()
        header = lines[0].split(b";")

        if len(header) < 3:
            raise ValueError("Malformed vault header")

        version = header[1].decode()
        cipher = header[2].decode()

        if cipher != SUPPORTED_CIPHER:
            print(
                f"[!] {path.name}: unsupported cipher '{cipher}'",
                file=sys.stderr,
            )
            return None

        hex_blob = b"".join(lines[1:])
        salt, checksum, ciphertext = unhexlify(hex_blob).split(b"\n")

        return (
            f"{path.name}:"
            f"$ansible$0*0*"
            f"{salt.decode()}*"
            f"{ciphertext.decode()}*"
            f"{checksum.decode()}"
        )

    except Exception as exc:
        print(f"[!] Failed to parse {path}: {exc}", file=sys.stderr)
        return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract Ansible Vault hashes for John the Ripper"
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="Ansible Vault .yml files",
    )

    args = parser.parse_args()

    for vault_file in args.files:
        result = parse_vault_file(vault_file)
        if result:
            print(result)


if __name__ == "__main__":
    main()
