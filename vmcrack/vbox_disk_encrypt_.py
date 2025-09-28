#!/usr/bin/env python3

"""
pyvboxdie-cracker.py
Tool to attempt cracking VirtualBox Disk Image (VDI/VBox) encryption passwords
via keystore extraction and PBKDF2-HMAC derivation.

EDUCATIONAL / RECOVERY USE ONLY.
"""

import argparse
import base64
import binascii
import sys
import xml.dom.minidom
from pathlib import Path
from struct import unpack
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Keystore structure mapping
KEYSTORE_STRUCT = {
    "FileHeader": None,
    "Version": None,
    "EVP_Algorithm": None,
    "PBKDF2_Hash": None,
    "Key_Length": None,
    "Final_Hash": None,
    "KL2_PBKDF2": None,
    "Salt2_PBKDF2": None,
    "Iteration2_PBKDF2": None,
    "Salt1_PBKDF2": None,
    "Iteration1_PBKDF2": None,
    "EVP_Length": None,
    "Enc_Password": None,
}

TWEAK = 16 * b"\x00"


def parse_keystore(vbox_file: Path) -> Dict[str, Any]:
    """Parse the keystore element out of a VirtualBox XML."""
    try:
        dom = xml.dom.minidom.parse(str(vbox_file))
    except Exception as e:
        sys.exit(f"[-] Cannot parse VBox XML: {e}")

    hds = dom.getElementsByTagName("HardDisk")
    if not hds:
        sys.exit("[-] No HardDisk nodes found in VBox file")

    keystore_data: Optional[str] = None
    for disk in hds:
        props = disk.getElementsByTagName("Property")
        if props:
            print(f"[*] Found encrypted disk: {disk.getAttribute('location')}")
            # The second <Property> typically holds the keystore
            keystore_data = props[1].getAttribute("value") if len(props) > 1 else None
            break

    if not keystore_data:
        sys.exit("[-] No keystore found in VBox file properties")

    raw_bytes = base64.b64decode(keystore_data)
    fields = unpack("<4sxb32s32sI32sI32sI32sII64s", raw_bytes)

    ks = {}
    for idx, key in enumerate(KEYSTORE_STRUCT.keys()):
        ks[key] = fields[idx]

    return ks


def select_hash(ks: Dict[str, Any]) -> hashes.HashAlgorithm:
    """Return the PBKDF2 hash algorithm from keystore."""
    algo_str = ks["PBKDF2_Hash"].rstrip(b"\x00").decode()
    if "SHA1" in algo_str:
        return hashes.SHA1()
    if "SHA256" in algo_str:
        return hashes.SHA256()
    if "SHA512" in algo_str:
        return hashes.SHA512()
    sys.exit(f"[-] Unsupported PBKDF2 hash in keystore: {algo_str}")


def print_keystore_info(ks: Dict[str, Any]) -> None:
    print("[*] Keystore Information")
    print(f"   Algorithm: {ks['EVP_Algorithm'].rstrip(b'\\x00').decode()}")
    print(f"   PBKDF2 Hash: {ks['PBKDF2_Hash'].rstrip(b'\\x00').decode()}")
    print(f"   Final Hash: {binascii.hexlify(ks['Final_Hash'].rstrip(b'\\x00')).decode()}")


def crack_keystore(ks: Dict[str, Any], wordlist: Path) -> None:
    """Attempt to crack VBox keystore using a password list."""
    algo = select_hash(ks)
    tried = 0

    try:
        with wordlist.open("r", encoding="utf-8", errors="ignore") as f:
            for pwd in f:
                password = pwd.strip()
                if not password:
                    continue

                # Derive AES key (KDF1)
                kdf1 = PBKDF2HMAC(
                    algorithm=algo,
                    length=ks["Key_Length"],
                    salt=ks["Salt1_PBKDF2"],
                    iterations=ks["Iteration1_PBKDF2"],
                )
                aes_key = kdf1.derive(password.encode())

                # Decrypt Enc_Password
                cipher = Cipher(algorithms.AES(aes_key), modes.XTS(TWEAK))
                dec = cipher.decryptor()
                decrypted = dec.update(ks["Enc_Password"]) + dec.finalize()

                # Derive final hash (KDF2)
                kdf2 = PBKDF2HMAC(
                    algorithm=algo,
                    length=ks["KL2_PBKDF2"],
                    salt=ks["Salt2_PBKDF2"],
                    iterations=ks["Iteration2_PBKDF2"],
                )
                check_hash = kdf2.derive(decrypted)

                if (binascii.hexlify(check_hash).decode() ==
                        binascii.hexlify(ks["Final_Hash"].rstrip(b"\x00")).decode()):
                    print(f"[+] Password found: {password}")
                    return

                tried += 1
                if tried % 1000 == 0:
                    print(f"    {tried} passwords tested...")

    except FileNotFoundError:
        sys.exit(f"[-] Wordlist not found: {wordlist}")

    print("[-] Password not found in provided wordlist.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attempt to crack VirtualBox Disk Image Encryption passwords"
    )
    parser.add_argument("-v", "--vbox", type=Path, required=True, help="Path to .vbox file")
    parser.add_argument("-d", "--dict", type=Path, required=True, help="Path to password list")

    args = parser.parse_args()
    print("[*] Starting pyvboxdie-cracker\n")

    ks = parse_keystore(args.vbox)
    print_keystore_info(ks)
    crack_keystore(ks, args.dict)


if __name__ == "__main__":
    main()

##
##
