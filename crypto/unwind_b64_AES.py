#!/usr/bin/env python3
"""
aes_cipher.py—Secure AES encrypt/decrypt utility supporting CBC and GCM modes.

Usage:
  # Encrypt in CBC (default):
  ./aes_cipher.py encrypt \
    --key 'Your16ByteKeyHere!' \
    --data 'Secret message'

  # Encrypt in GCM (recommended):
  ./aes_cipher.py encrypt \
    --mode gcm \
    --key 'YourKeyHere16or32bytes' \
    --data 'Secret message'

  # Decrypt base64 ciphertext:
  ./aes_cipher.py decrypt \
    --key 'YourKeyHere16or32bytes' \
    --data '<base64 ciphertext>'

  # Load key from environment (AES_KEY):
  export AES_KEY='YourKeyHere16or32bytes'
  ./aes_cipher.py encrypt --data 'Message'

  # Read data from file:
  ./aes_cipher.py encrypt --key-file key.bin --input-file message.txt
"""

import argparse
import base64
import os
import secrets
import sys
from pathlib import Path
from typing import Literal, Union

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Type aliases
CipherMode = Literal["cbc", "gcm"]
Operation = Literal["encrypt", "decrypt"]

# Constants
BLOCK_SIZE = AES.block_size  # 16 bytes
GCM_NONCE_SIZE = 12  # 96-bit nonce for GCM
GCM_TAG_SIZE = 16    # 128-bit tag for GCM
PBKDF2_ITERATIONS = 100_000  # OWASP recommended minimum


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class InvalidKeyError(CryptoError):
    """Raised when key format or size is invalid."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""
    pass


def secure_pad(data: bytes) -> bytes:
    """Apply PKCS7 padding to data."""
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len


def secure_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding from data with timing-safe validation."""
    if not data:
        raise DecryptionError("Cannot unpad empty data")
    
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise DecryptionError("Invalid padding length")
    
    if len(data) < padding_len:
        raise DecryptionError("Data too short for padding")
    
    # Constant-time padding validation
    padding_bytes = data[-padding_len:]
    valid = True
    for byte in padding_bytes:
        valid &= (byte == padding_len)
    
    if not valid:
        raise DecryptionError("Invalid padding bytes")
    
    return data[:-padding_len]


def derive_key_from_password(
    password: str, 
    salt: bytes, 
    key_length: int = 32
) -> bytes:
    """Derive a cryptographic key from password using PBKDF2."""
    return PBKDF2(
        password, 
        salt, 
        key_length, 
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256
    )


class AESCipher:
    """Secure AES encryption/decryption with CBC and GCM modes."""
    
    def __init__(self, key: bytes, mode: CipherMode = "gcm"):
        """
        Initialize AES cipher.
        
        Args:
            key: Encryption key (16, 24, or 32 bytes)
            mode: Cipher mode ('cbc' or 'gcm')
        """
        if len(key) not in (16, 24, 32):
            raise InvalidKeyError(
                f"Key must be 16, 24, or 32 bytes, got {len(key)}"
            )
        
        self.key = key
        self.mode = mode
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string and return base64 encoded result.
        
        Args:
            plaintext: String to encrypt
            
        Returns:
            Base64 encoded ciphertext with IV/nonce and tag (for GCM)
        """
        try:
            data = plaintext.encode("utf-8")
            
            if self.mode == "cbc":
                return self._encrypt_cbc(data)
            else:  # GCM mode
                return self._encrypt_gcm(data)
                
        except Exception as e:
            raise CryptoError(f"Encryption failed: {e}") from e
    
    def decrypt(self, b64_ciphertext: str) -> str:
        """
        Decrypt base64 encoded ciphertext.
        
        Args:
            b64_ciphertext: Base64 encoded ciphertext
            
        Returns:
            Decrypted plaintext string
        """
        try:
            raw = base64.b64decode(b64_ciphertext)
        except Exception as e:
            raise DecryptionError(f"Invalid base64 data: {e}") from e
        
        try:
            if self.mode == "gcm":
                return self._decrypt_gcm(raw)
            else:  # CBC mode
                return self._decrypt_cbc(raw)
                
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def _encrypt_cbc(self, data: bytes) -> str:
        """Encrypt using CBC mode."""
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(secure_pad(data))
        payload = iv + ciphertext
        return base64.b64encode(payload).decode("ascii")
    
    def _encrypt_gcm(self, data: bytes) -> str:
        """Encrypt using GCM mode."""
        nonce = get_random_bytes(GCM_NONCE_SIZE)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        payload = nonce + ciphertext + tag
        return base64.b64encode(payload).decode("ascii")
    
    def _decrypt_cbc(self, raw: bytes) -> str:
        """Decrypt using CBC mode."""
        if len(raw) < BLOCK_SIZE:
            raise DecryptionError("Ciphertext too short for CBC mode")
        
        iv = raw[:BLOCK_SIZE]
        ciphertext = raw[BLOCK_SIZE:]
        
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise DecryptionError("Invalid ciphertext length for CBC mode")
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        data = secure_unpad(padded_data)
        return data.decode("utf-8")
    
    def _decrypt_gcm(self, raw: bytes) -> str:
        """Decrypt using GCM mode."""
        min_length = GCM_NONCE_SIZE + GCM_TAG_SIZE
        if len(raw) < min_length:
            raise DecryptionError(f"Ciphertext too short for GCM mode")
        
        nonce = raw[:GCM_NONCE_SIZE]
        tag = raw[-GCM_TAG_SIZE:]
        ciphertext = raw[GCM_NONCE_SIZE:-GCM_TAG_SIZE]
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data.decode("utf-8")


def load_key_from_sources(
    args_key: str,
    key_file: Union[str, None] = None,
    password: Union[str, None] = None
) -> bytes:
    """
    Load encryption key from various sources with priority order.
    
    Priority: args_key > key_file > password + salt > AES_KEY env var
    """
    # Direct key argument
    if args_key:
        return args_key.encode("utf-8")
    
    # Key from file
    if key_file:
        key_path = Path(key_file)
        if not key_path.exists():
            print(f"Error: Key file '{key_file}' not found.")
            sys.exit(1)
        
        try:
            with key_path.open("rb") as f:
                key_data = f.read()
            
            if len(key_data) not in (16, 24, 32):
                print(f"Error: Key file must contain 16, 24, or 32 bytes.")
                sys.exit(1)
            
            return key_data
        except Exception as e:
            print(f"Error reading key file: {e}")
            sys.exit(1)
    
    # Derive key from password
    if password:
        # For password-based keys, we need a salt
        # In a real application, you'd store/retrieve the salt
        salt = b"static_salt_change_this"  # WARNING: Use random salt in production
        return derive_key_from_password(password, salt)
    
    # Environment variable
    env_key = os.environ.get("AES_KEY")
    if env_key:
        return env_key.encode("utf-8")
    
    print("Error: No key provided. Use --key, --key-file, --password, or set AES_KEY.")
    sys.exit(1)


def read_input_data(data_arg: str, input_file: Union[str, None] = None) -> str:
    """Read input data from argument or file."""
    if input_file:
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"Error: Input file '{input_file}' not found.")
            sys.exit(1)
        
        try:
            with input_path.open("r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            print(f"Error reading input file: {e}")
            sys.exit(1)
    
    return data_arg


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Secure AES encrypt/decrypt with CBC/GCM modes",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "operation", 
        choices=("encrypt", "decrypt"), 
        help="Operation to perform"
    )
    
    # Key sources (mutually exclusive group would be better)
    parser.add_argument(
        "--key", "-k", 
        default="",
        help="Secret key (16,24,32 bytes) as string"
    )
    
    parser.add_argument(
        "--key-file", 
        help="Path to binary key file (16,24,32 bytes)"
    )
    
    parser.add_argument(
        "--password", "-p",
        help="Password for key derivation (uses PBKDF2)"
    )
    
    # Data sources
    parser.add_argument(
        "--data", "-d", 
        default="",
        help="Data to encrypt/decrypt"
    )
    
    parser.add_argument(
        "--input-file", "-i",
        help="Read input data from file"
    )
    
    # Cipher configuration
    parser.add_argument(
        "--mode", "-m", 
        choices=("cbc", "gcm"), 
        default="gcm",
        help="Cipher mode (default: gcm - recommended)"
    )
    
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    try:
        args = parse_args()
        
        # Load key from various sources
        key = load_key_from_sources(args.key, args.key_file, args.password)
        
        # Read input data
        if not args.data and not args.input_file:
            print("Error: No data provided. Use --data or --input-file.")
            sys.exit(1)
        
        data = read_input_data(args.data, args.input_file)
        if not data:
            print("Error: Input data is empty.")
            sys.exit(1)
        
        # Initialize cipher
        cipher = AESCipher(key, mode=args.mode)
        
        # Perform operation
        if args.operation == "encrypt":
            result = cipher.encrypt(data)
            print(result)
        else:  # decrypt
            result = cipher.decrypt(data)
            print(result)
            
    except (CryptoError, InvalidKeyError, DecryptionError) as e:
        print(f"Cryptographic error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
