#!/usr/bin/python3

########## test_me_plz_
#################################
#
#####################

import paramiko
import sys

if len(sys.argv) < 4:
    print()
    "args missing"
    sys.exit(1)

hostname = sys.argv[1]
password = sys.argv[2]
command = sys.argv[3]

username = "admin"
port = 22

try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)

    client.connect(hostname, port=port, username=username, password=password)

    stdin, stdout, stderr = client.exec_command(command)
    print()
    stdout.read(),

finally:
    client.close()

############################################
