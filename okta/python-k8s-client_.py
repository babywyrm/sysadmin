
##
##

import requests
import logging
from urllib.parse import urlparse
from urllib.parse import parse_qs
import json
from os import system
from kubernetes import client, config

#logging.basicConfig(level=logging.DEBUG)


def get_openunison_token_from_okta(okta_domain,username,password,openunison_host):
    s = requests.Session() 
    # initiate the request
    response = s.get("https://" + openunison_host + "/k8stoken/token/user")
    # get the url from the okta login page
    parsed_url = urlparse(response.url)
    query_string = parsed_url.query
    query = parse_qs(query_string)
    # generate a redirect
    full_redirect_url = "https://" + okta_domain + query['fromURI'][0]
    
    # login to Okta
    okta_url = "https://" + okta_domain + "/api/v1/authn"

    payload = json.dumps({
    "password": password ,
    "username": username ,
    "options": {
    "warnBeforePasswordExpired": True,
    "multiOptionalFactorEnroll": False
    }
    })
    headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
    }
    response = s.post(okta_url, headers=headers, data = payload)

    okta_token = response.json()["sessionToken"]

    # finish login, redirect to token page

    finish_login_url = "https://" + okta_domain + "/login/sessionCookieRedirect?checkAccountSetupComplete=true&token=" + okta_token + "&redirectUrl=" + full_redirect_url
    response = s.get(finish_login_url)
    return json.loads(response.content)

# Load the token from openunison
openunison_token = get_openunison_token_from_okta("xyz.okta.com","user@domain.com","password","k8sou.apps.domain.com")

# get the command that will generate a full kubectl configuration file
kubectl_cmd = openunison_token['token']['kubectl Command']

# create the kubectl configuration
system(kubectl_cmd)

# do something with the python client

config.load_kube_config()

v1 = client.CoreV1Api()
print("Listing pods with their IPs:")
ret = v1.list_pod_for_all_namespaces(watch=False)
for i in ret.items:
    print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
    
    
###
###


