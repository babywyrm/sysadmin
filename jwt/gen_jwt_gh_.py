#!/usr/bin/python3

####################
##
##
##
##
# This is an example script that generates JWT tokens for the Github API..
# Ogfi Usage: genjwt.py your_github_private_key.pem
#
# After getting a token, you can make curl requests to the API like this:
# curl -i -H "Authorization: Bearer JWT_TOKEN" -H "Accept: application/vnd.github.machine-man-preview+json" "https://api.github.com/app"
import sys
import jwt
import time

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

current_time = int(time.time())
payload = {
    # issued at time
    'iat': current_time,

    # JWT expiration time (10 minute maximum)
    'exp': current_time + (10 * 60),

    # GitHub App's identifier – you can get it from the github application dashboard
    'iss': YOUR_APP_IDENTIFIER,
}

private_key_file = sys.argv[1]
with open(private_key_file) as fd:
    private_key_contents = fd.read().encode()

cert_obj = load_pem_private_key(private_key_contents, password=None, backend=default_backend())
encoded = jwt.encode(payload, private_key_contents, algorithm='RS256')
print(encoded)

###############################
##
##
