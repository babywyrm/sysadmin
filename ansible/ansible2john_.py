#!/usr/bin/env python3
"""
ansible_vault2john.py (2025 Edition)

Extract Ansible Vault hashes for John the Ripper and perform
basic vault hygiene checks.

Legitimate use cases:
  - Incident response
  - Red-team / purple-team audits
  - Security reviews
  - CTFs

Based on:
  https://fossies.org/linux/john/run/ansible2john.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from binascii import unhexlify
from typing import Iterator


VAULT_HEADER = b"$ANSIBLE_VAULT"
SUPPORTED_CIPHER = "AES256"


# -------------------------
# Helpers
# -------------------------

def is_vault_file(path: Path) -> bool:
    """Quick check to see if file looks like an Ansible Vault."""
    try:
        return path.is_file() and path.read_bytes().startswith(VAULT_HEADER)
    except OSError:
        return False


def iter_vault_files(paths: list[Path], recursive: bool) -> Iterator[Path]:
    """Yield vault files from input paths."""
    for path in paths:
        if path.is_file():
            if is_vault_file(path):
                yield path
        elif path.is_dir() and recursive:
            for p in path.rglob("*"):
                if is_vault_file(p):
                    yield p


def parse_vault(path: Path) -> dict | None:
    """
    Parse an Ansible Vault file and return structured metadata.
    """
    try:
        raw = path.read_bytes()
        lines = raw.splitlines()

        header = lines[0].split(b";")
        if len(header) < 3:
            raise ValueError("Malformed vault header")

        vault_version = header[1].decode()
        cipher = header[2].decode()

        if cipher != SUPPORTED_CIPHER:
            raise ValueError(f"Unsupported cipher: {cipher}")

        hex_blob = b"".join(lines[1:])
        salt, checksum, ciphertext = unhexlify(hex_blob).split(b"\n")

        return {
            "file": str(path),
            "filename": path.name,
            "vault_version": vault_version,
            "cipher": cipher,
            "salt": salt.decode(),
            "checksum": checksum.decode(),
            "ciphertext": ciphertext.decode(),
        }

    except Exception as exc:
        print(f"[!] Failed parsing {path}: {exc}", file=sys.stderr)
        return None


def to_john_format(vault: dict) -> str:
    """Convert parsed vault data into John the Ripper format."""
    return (
        f"{vault['filename']}:"
        f"$ansible$0*0*"
        f"{vault['salt']}*"
        f"{vault['ciphertext']}*"
        f"{vault['checksum']}"
    )


def audit_warning(vault: dict) -> list[str]:
    """Return audit warnings for the vault."""
    warnings = []

    if vault["vault_version"] not in {"1.1", "1.2"}:
        warnings.append(f"Unknown vault format {vault['vault_version']}")

    if len(vault["salt"]) < 16:
        warnings.append("Salt length unusually short")

    return warnings


# -------------------------
# Main
# -------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and audit Ansible Vault hashes"
    )

    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="Vault file(s) or directories",
    )

    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Recursively scan directories",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of John format",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress warnings",
    )

    args = parser.parse_args()

    results = []

    for vault_file in iter_vault_files(args.paths, args.recursive):
        parsed = parse_vault(vault_file)
        if not parsed:
            continue

        warnings = audit_warning(parsed)
        parsed["warnings"] = warnings

        if not args.quiet:
            for w in warnings:
                print(f"[!] {vault_file.name}: {w}", file=sys.stderr)

        results.append(parsed)

        if not args.json:
            print(to_john_format(parsed))

    if args.json:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
```

---

## 🔧 Example Usage

### Single file

```bash
./ansible_vault2john.py secrets.yml
```

### Recursive repo scan

```bash
./ansible_vault2john.py . --recursive
```

### JSON output (CI / tooling)

```bash
./ansible_vault2john.py . -r --json > vault_report.json
```

##
##
