#!/usr/bin/env python3

##
##

import subprocess
import getpass
import pickle
import platform
import sys
from datetime import datetime

def get_system_info():
    return {
        'platform': platform.platform(),
        'python_version': sys.version,
    }

def encrypt_file(input_file, public_key_path, encrypted_output_path):
    encrypt_command = f'age -R {public_key_path} {input_file} > {encrypted_output_path}'
    subprocess.run(encrypt_command, shell=True)

def compress_with_7z(input_file, zip_output_path, passphrase):
    zip_command = f'7z a -p{passphrase} {zip_output_path} {input_file}'
    subprocess.run(zip_command, shell=True)

def create_memory_dump(public_key_path, input_file, passphrase, encrypted_output_file, zip_output_file):
    # Create a dictionary to hold the state you want to dump
    memory_state = {
        'timestamp': str(datetime.now()),
        'system_info': get_system_info(),
        'public_key_path': public_key_path,
        'input_file': input_file,
        'passphrase': passphrase,
        'encrypted_output_file': encrypted_output_file,
        'zip_output_file': zip_output_file,
    }

    # Dump the state to a binary file
    with open('memory_dump.pkl', 'wb') as f:
        pickle.dump(memory_state, f)

def main():
    # Prompt user for the recipient's SSH public key path
    public_key_path = input("Enter the recipient's SSH public key path: ").strip()

    # Prompt user for the file to encrypt
    input_file = input('Enter the file to encrypt: ').strip()

    # Prompt user for the passphrase for 7z compression
    passphrase = getpass.getpass('Enter the passphrase for the 7z file: ')

    # Set the output file names
    encrypted_output_file = f'{input_file}.enc'
    zip_output_file = f'{input_file}.zip'

    # Call the function to create a memory dump
    create_memory_dump(public_key_path, input_file, passphrase, encrypted_output_file, zip_output_file)

    # Encrypt the specified file
    encrypt_file(input_file, public_key_path, encrypted_output_file)

    print(f'Encryption completed. Encrypted file: {encrypted_output_file}')

    # Compress the encrypted file with 7z
    compress_with_7z(encrypted_output_file, zip_output_file, passphrase)

    print(f'Compression completed. Compressed file: {zip_output_file}')

if __name__ == '__main__':
    main()

##
##
