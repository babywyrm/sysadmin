##
##
## Sign and Verify signature using a SSL certificate. I've been wanting to play around with various RSA signing methods. Particularly around JWT RSA signed tokens and verifying a sig using the public key extracted from a website certificate. Some of the nuances of it all can be a bit tricky. As part of my effort to get my head around it I cobbled t…
##
##

import argparse
import logging
from pathlib import Path
from typing import List
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_KEY_DIR = Path("keys/")
DEFAULT_KEY_BITS = 2048
DEFAULT_FILE_DIR = Path("files/")


def generate_rsa_key_pair(name: str, bits: int, key_dir: Path) -> None:
    """
    Generate an RSA key pair and save them to files.
    
    Args:
        name (str): Base name for the key files.
        bits (int): Length of the RSA key.
        key_dir (Path): Directory to save the keys.
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Generating RSA key pair: {name} ({bits} bits)")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )

    private_key_path = key_dir / f"{name}_private.pem"
    public_key_path = key_dir / f"{name}_public.pem"

    # Save private key
    with private_key_path.open("wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with public_key_path.open("wb") as public_file:
        public_file.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    logger.info(f"Keys saved to {private_key_path} and {public_key_path}")


def sign_file(file_path: Path, private_key_path: Path, output_path: Path) -> None:
    """
    Sign a file using a private RSA key.
    
    Args:
        file_path (Path): Path to the file to be signed.
        private_key_path (Path): Path to the private key.
        output_path (Path): Path to save the signature.
    """
    logger.info(f"Signing file: {file_path} with {private_key_path}")
    with private_key_path.open("rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with file_path.open("rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        PKCS1v15(),
        SHA256()
    )

    with output_path.open("wb") as sig_file:
        sig_file.write(signature)

    logger.info(f"Signature saved to {output_path}")


def verify_signature(file_path: Path, public_key_path: Path, signature_path: Path) -> bool:
    """
    Verify a file's signature using a public RSA key.
    
    Args:
        file_path (Path): Path to the signed file.
        public_key_path (Path): Path to the public key.
        signature_path (Path): Path to the signature file.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    logger.info(f"Verifying signature for {file_path} using {public_key_path}")
    with public_key_path.open("rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    with file_path.open("rb") as f:
        data = f.read()

    with signature_path.open("rb") as sig_file:
        signature = sig_file.read()

    try:
        public_key.verify(
            signature,
            data,
            PKCS1v15(),
            SHA256()
        )
        logger.info("Signature verification succeeded")
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


def find_files(directory: Path, extension: str = "") -> List[Path]:
    """
    Find all files in a directory with a given extension.
    
    Args:
        directory (Path): Directory to search.
        extension (str): File extension to filter (optional).
    
    Returns:
        List[Path]: List of matching file paths.
    """
    logger.info(f"Searching for files in {directory} with extension '{extension}'")
    return [f for f in directory.rglob(f"*{extension}") if f.is_file()]


def main():
    parser = argparse.ArgumentParser(description="Modernized RSA Key and File Signing Script")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-command help")

    # Sub-command: Generate RSA Keys
    parser_generate = subparsers.add_parser("generate", help="Generate RSA key pair")
    parser_generate.add_argument("-n", "--name", required=True, help="Base name for key files")
    parser_generate.add_argument("-b", "--bits", type=int, default=DEFAULT_KEY_BITS, help="RSA key length")
    parser_generate.add_argument("-d", "--dir", type=Path, default=DEFAULT_KEY_DIR, help="Directory to save keys")

    # Sub-command: Sign File
    parser_sign = subparsers.add_parser("sign", help="Sign a file with a private key")
    parser_sign.add_argument("-f", "--file", required=True, type=Path, help="Path to the file to sign")
    parser_sign.add_argument("-k", "--key", required=True, type=Path, help="Path to the private key")
    parser_sign.add_argument("-o", "--output", required=True, type=Path, help="Output path for the signature")

    # Sub-command: Verify Signature
    parser_verify = subparsers.add_parser("verify", help="Verify a file's signature")
    parser_verify.add_argument("-f", "--file", required=True, type=Path, help="Path to the file")
    parser_verify.add_argument("-k", "--key", required=True, type=Path, help="Path to the public key")
    parser_verify.add_argument("-s", "--signature", required=True, type=Path, help="Path to the signature file")

    # Parse arguments
    args = parser.parse_args()

    # Dispatch sub-command
    if args.command == "generate":
        generate_rsa_key_pair(args.name, args.bits, args.dir)
    elif args.command == "sign":
        sign_file(args.file, args.key, args.output)
    elif args.command == "verify":
        is_valid = verify_signature(args.file, args.key, args.signature)
        logger.info(f"Verification result: {'Valid' if is_valid else 'Invalid'}")


if __name__ == "__main__":
    main()
