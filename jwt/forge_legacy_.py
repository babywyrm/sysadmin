import jwt
import time
import json
import base64
import secrets
from jwt import PyJWKClient
from jwt.exceptions import InvalidSignatureError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256

##
## try the GD help option lol
##

def generate_rsa_keypair():
    """
    Generate a 2048-bit RSA key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Convert keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

# Sign a JWT with HMAC
def sign_hmac_jwt(payload, secret_key):
    """
    Sign a JWT using an HMAC secret key.
    """
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

# Verify an HMAC JWT
def verify_hmac_jwt(token, secret_key):
    """
    Verify an HMAC JWT using a secret key.
    """
    try:
        decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
        return decoded
    except InvalidSignatureError:
        return "Invalid Signature"

# Forge a JWT with HMAC
def forge_hmac_jwt(existing_token, new_payload, secret_key):
    """
    Forge a new JWT with a known HMAC secret key based on an existing token's structure.
    """
    # Decode the existing token to extract its header
    try:
        header = jwt.get_unverified_header(existing_token)
        new_token = jwt.encode(new_payload, secret_key, algorithm=header.get("alg", "HS256"))
        return new_token
    except Exception as e:
        return f"Error forging token: {e}"

# Sign a JWT with RSA
def sign_rsa_jwt(payload, private_key):
    """
    Sign a JWT using an RSA private key.
    """
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token

# Verify an RSA JWT
def verify_rsa_jwt(token, public_key):
    """
    Verify an RSA JWT using a public key.
    """
    try:
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        return decoded
    except InvalidSignatureError:
        return "Invalid Signature"

# Interactive forging
def interactive_forging():
    """
    Interactive mode for forging JWTs with a known HMAC secret key.
    """
    print("\n=== Interactive JWT Forging ===")
    existing_token = input("Enter the existing JWT: ").strip()
    secret_key = input("Enter the known HMAC secret key: ").strip()

    try:
        print("Decoding existing token...")
        decoded_header = jwt.get_unverified_header(existing_token)
        print(f"Header: {decoded_header}")

        decoded_payload = jwt.decode(existing_token, secret_key, algorithms=["HS256"], options={"verify_signature": False})
        print(f"Original Payload: {decoded_payload}")

        new_payload_input = input("Enter new payload as JSON: ").strip()
        new_payload = json.loads(new_payload_input)

        forged_token = forge_hmac_jwt(existing_token, new_payload, secret_key)
        print(f"Forged Token: {forged_token}")

    except Exception as e:
        print(f"[ERROR] Failed to forge JWT: {e}")

# Help section
def show_help():
    """
    Display help for script usage.
    """
    print("\n=== JWT Tool Help ===")
    print("1. Generate and verify JWTs using HMAC or RSA.")
    print("2. Forge JWTs interactively with a known HMAC secret key.")
    print("3. Example usage:")
    print("   - Run interactively for forging: python script.py --forge")
    print("   - Generate and verify tokens: Run script without arguments.")

# Main execution
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="JWT Utility Script")
    parser.add_argument("--forge", action="store_true", help="Run interactive JWT forging mode.")

    args = parser.parse_args()

    if args.forge:
        interactive_forging()
    else:
        show_help()

        # Example payload
        payload = {
            "hello": "world",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }

        # 1. HMAC Example
        print("=== HMAC Example ===")
        hmac_secret = secrets.token_hex(32)  # Generate a random HMAC secret key
        print(f"HMAC Secret Key: {hmac_secret}")

        hmac_token = sign_hmac_jwt(payload, hmac_secret)
        print(f"HMAC Token: {hmac_token}")

        hmac_verified = verify_hmac_jwt(hmac_token, hmac_secret)
        print(f"HMAC Verification Result: {hmac_verified}")

        # Forge a JWT with the known HMAC secret
        new_payload = {
            "hello": "forged",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        forged_token = forge_hmac_jwt(hmac_token, new_payload, hmac_secret)
        print(f"Forged HMAC Token: {forged_token}")

        forged_verified = verify_hmac_jwt(forged_token, hmac_secret)
        print(f"Forged Token Verification Result: {forged_verified}")

        # 2. RSA Example
        print("\n=== RSA Example ===")
        rsa_private_key, rsa_public_key = generate_rsa_keypair()
        print(f"RSA Private Key: {rsa_private_key}")
        print(f"RSA Public Key: {rsa_public_key}")

        rsa_token = sign_rsa_jwt(payload, rsa_private_key)
        print(f"RSA Token: {rsa_token}")

        rsa_verified = verify_rsa_jwt(rsa_token, rsa_public_key)
        print(f"RSA Verification Result: {rsa_verified}")

##
##
