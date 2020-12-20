import os
import sys
import hmac
import base64
import hashlib
import argparse

##########################
## Examples:
##
## Generate a sha1 checksum
##
## python checksum.py -H sha1 -f test.txt -g
## b29d28bc5239dbc2689215811b2a73588609f301
## Generate a signature
##
## python checksum.py -f test.txt -s secret
## 3YYMCthY4hFxQj1wPF3uAg==
## Verify a checksum
##
## python -H sha1 -f test.txt -v b29d28bc5239dbc2689215811b2a73588609f301
## Verify a signature
##
## python -f test.txt -s secret -v 3YYMCthY4hFxQj1wPF3uAg==
##########################

def checksum(hash, seed=None):
    hashs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512
    }
    method = hashs.get(hash, hashlib.md5)()
    if seed is not None:
        method.update(seed.encode("utf-8"))
    else:
        method.update(os.urandom(32))
    return method.hexdigest()

def sign(hash, message, secret):
    hashs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512
    }
    method = hashs.get(hash, hashlib.md5)()
    digest = hmac.new(secret.encode("utf-8"), 
                msg=message.encode(),
                digestmod=hashs.get(hash, hashlib.md5)).digest()
    signature = base64.b64encode(digest).decode("utf-8")
    return signature

def verify(hash, input, check, secret=None):
    challenge = None
    if secret is not None:
        challenge = sign(hash, input, secret)
    else:
        challenge = checksum(hash, input)
    return "Valid! :D" if challenge == check else "Invalid :("

def main():
    description = "Checksum tool to generate, sign, and verify"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-g", "--generate", dest="generate", 
        action="store_true", help="Generates checksum")
    parser.add_argument("-s", "--sign", dest="sign", default=None, 
        help="Signs input using HMAC")
    parser.add_argument("-H", "--hash", dest="hash", default="md5",
        help="Hash method (md5, sha1, sha224, sha256, sha384, sha512)")
    parser.add_argument("-v", "--verify", dest="verify", default=None,
        help="Checksum or signature used to verify against file / stdin")
    parser.add_argument("-f", "--file", dest="file", 
        type=argparse.FileType("r"), default=sys.stdin,
        help="File / stdin to create checksum, make signature, or verify from")
    arguments = parser.parse_args()

    if arguments.verify is not None:
        if not arguments.file:
            print("Missing input to generate checksum from")
            sys.exit(1)
        if arguments.sign is not None:
            print(verify(arguments.hash, arguments.file.read(),
                         arguments.verify, arguments.sign))
            return
        else:
            print(verify(arguments.hash, arguments.file.read(),
                         arguments.verify))
            return
    elif arguments.generate:
        if not arguments.file:
            print("Missing input to generate checksum from")
            sys.exit(1)
        print(checksum(arguments.hash, arguments.file.read()))
        return
    elif arguments.sign is not None:
        if not arguments.file:
            print("Missing input to generate checksum from")
            sys.exit(1)
        print(sign(arguments.hash, arguments.file.read(), arguments.sign))
        return
    print("Missing function (-g, -s, -v)")
    sys.exit(1)

if __name__ == "__main__":
    main()
    
##################################
##
##
