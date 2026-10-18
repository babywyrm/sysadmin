import os
import re
import base64

##
##

def find_hashes_in_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
        # Regular expression to find hashes
        hash_pattern = re.compile(r'\b[A-Za-z0-9+/]{4,}={0,2}\b')
        hashes = hash_pattern.findall(content)
        return hashes

def decode_base64_hash(encoded_hash):
    try:
        decoded_hash = base64.b64decode(encoded_hash).decode('utf-8')
        return decoded_hash
    except:
        return None

def main(directory):
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a valid directory.")
        return
    
    print("Decoded hashes found in files:")
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            hashes = find_hashes_in_file(file_path)
            if hashes:
                print(f"\nFile: {file_name}")
                for hash_str in hashes:
                    decoded_hash = decode_base64_hash(hash_str)
                    if decoded_hash:
                        print(f"  {hash_str} -> {decoded_hash}")
                    else:
                        print(f"  {hash_str} -> Unable to decode")

if __name__ == "__main__":
    directory = input("Enter the directory path: ")
    main(directory)

##
##
