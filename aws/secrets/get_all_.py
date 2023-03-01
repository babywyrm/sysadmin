#!/usr/bin/python3

##
##

import json
import subprocess

secrets = json.loads(subprocess.getoutput("aws secretsmanager list-secrets"))
for secret in secrets.values():
    for s in secret:
        name = s.get('Name')
        data = json.loads(subprocess.getoutput("aws secretsmanager get-secret-value --secret-id {}".format(name)))
        value = data.get('SecretString')
        print("{}: {}".format(name, value))


##
##
