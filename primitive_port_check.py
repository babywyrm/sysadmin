#!/usr/bin/python
##########
############################
############################
#
#
# This script checks whether a port is open on localhost

import socket, sys

port = 443
url = '127.0.0.1'

if len(sys.argv) == 2:
        try:
                port = int(sys.argv[1])
        except ValueError:
                url = str(sys.argv[1])

elif len(sys.argv) == 3:
        try:
                port = int(sys.argv[2])
                url = str(sys.argv[1])
        except ValueError:
                port = int(sys.argv[1])
                url = str(sys.argv[2])
else:
        pass

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
        result = sock.connect_ex((url, port))
except OverflowError:
        print "Port range should be between 0 and 65535"
        sys.exit()

if result == 0:
        print "Port ", port, " is open", " :)"
else:
        print "Port ", port, " is closed", " :("
        
        
#############################
