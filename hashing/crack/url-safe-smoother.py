
#####
#####

import hashlib
import base64
import os
import sys

def cryptBytes(hash_type, salt, value):
    if not hash_type:
        hash_type = "SHA"
    if not salt:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    hash_obj = hashlib.new(hash_type)
    hash_obj.update(salt.encode('utf-8'))
    hash_obj.update(value)
    hashed_bytes = hash_obj.digest()
    result = f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
    return result

def getCryptedBytes(hash_type, salt, value):
    try:
        hash_obj = hashlib.new(hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')
    except hashlib.NoSuchAlgorithmException as e:
        raise Exception(f"Error while computing hash of type {hash_type}: {e}")

##
## consider padding
##

def main():
    hash_type = "SHA1"
    salt = "d"
    search = "$SHA1$xxx$xxxxxxxxxxxxxXXXXXxxx="
    ##search = "$SHA1$xxx$xxxxxxxxXXXXXXXXxxxxxxxx"
    wordlist_path = '../WriteUp/rockyou.txt'

    with open(wordlist_path, 'r', encoding='latin-1') as wordlist:
        total_passwords = sum(1 for _ in wordlist)

    with open(wordlist_path, 'r', encoding='latin-1') as wordlist:
        for index, password in enumerate(wordlist, start=1):
            value = password.strip()
            hashed_password = cryptBytes(hash_type, salt, value.encode('utf-8'))
            sys.stdout.write(f"\rChecking passwords [{index}/{total_passwords}] {{'|/-\\'[index % 4]}}")
            sys.stdout.flush()

            if hashed_password == search:
                print(f'\nFound Password: {value}, hash: {hashed_password}')
                return

    print("\nPassword not found in the wordlist.")

if __name__ == "__main__":
    main()

#####
#####
