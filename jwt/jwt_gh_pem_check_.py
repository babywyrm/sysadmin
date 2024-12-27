import os,sys,re
import time
import jwt  # PyJWT
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

##
##

def generate_jwt_token(private_key_path: str, app_identifier: int, audience: str = None, scopes: list = None) -> str:
    """
    Generate a JWT token for GitHub API authentication.

    Args:
        private_key_path (str): Path to the GitHub App private key file (PEM format).
        app_identifier (int): GitHub App's identifier.
        audience (str, optional): The intended audience for the token.
        scopes (list, optional): List of scopes to include in the token.

    Returns:
        str: Encoded JWT token.
    """
    try:
        # Read the private key file
        with open(private_key_path, "rb") as fd:
            private_key_contents = fd.read()

        # Load the private key
        private_key = load_pem_private_key(private_key_contents, password=None, backend=default_backend())

        # Create the JWT payload
        current_time = int(time.time())
        payload = {
            'iat': current_time,  # Issued at time
            'exp': current_time + (10 * 60),  # Expiration time (10 minutes max)
            'iss': app_identifier,  # GitHub App's identifier
        }

        if audience:
            payload['aud'] = audience

        if scopes:
            payload['scopes'] = scopes

        # Generate the JWT
        token = jwt.encode(payload, private_key, algorithm='RS256')
        return token

    except FileNotFoundError:
        raise FileNotFoundError(f"Private key file not found at: {private_key_path}")
    except Exception as e:
        raise RuntimeError(f"Error generating JWT token: {e}")


def verify_jwt_token(token: str, public_key_path: str):
    """
    Verify a JWT token and print its claims.

    Args:
        token (str): The JWT token to verify.
        public_key_path (str): Path to the public key file (PEM format).

    Returns:
        dict: Decoded token payload if verification is successful.
    """
    try:
        # Read the public key file
        with open(public_key_path, "rb") as fd:
            public_key_contents = fd.read()

        # Decode and verify the JWT
        decoded = jwt.decode(token, public_key_contents, algorithms=['RS256'], options={"verify_exp": True})

        print("JWT Verified Successfully!")
        print("Claims:")
        for key, value in decoded.items():
            print(f"  {key}: {value}")

        return decoded

    except jwt.ExpiredSignatureError:
        raise RuntimeError("Error: The token has expired.")
    except jwt.InvalidTokenError as e:
        raise RuntimeError(f"Error: Invalid token. Details: {e}")


def main():
    """Main entry point for the script."""
    if len(sys.argv) < 3:
        print("Usage: genjwt.py <path_to_private_key.pem> <app_identifier> [--verify <token> <path_to_public_key.pem>] [--aud <audience>] [--scopes <scope1,scope2,...>]")
        sys.exit(1)

    private_key_path = sys.argv[1]
    try:
        app_identifier = int(sys.argv[2])
    except ValueError:
        print("Error: App identifier must be an integer.")
        sys.exit(1)

    audience = None
    scopes = None
    verify_mode = False
    token_to_verify = None
    public_key_path = None

    # Parse additional arguments
    for i in range(3, len(sys.argv)):
        if sys.argv[i] == "--aud" and i + 1 < len(sys.argv):
            audience = sys.argv[i + 1]
        elif sys.argv[i] == "--scopes" and i + 1 < len(sys.argv):
            scopes = sys.argv[i + 1].split(",")
        elif sys.argv[i] == "--verify" and i + 2 < len(sys.argv):
            verify_mode = True
            token_to_verify = sys.argv[i + 1]
            public_key_path = sys.argv[i + 2]

    if verify_mode:
        try:
            verify_jwt_token(token_to_verify, public_key_path)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        try:
            jwt_token = generate_jwt_token(private_key_path, app_identifier, audience, scopes)
            print("Generated JWT Token:")
            print(jwt_token)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()

##
##
