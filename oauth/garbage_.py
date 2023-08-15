#!/usr/bin/env python

##
## https://gist.github.com/zaki-yama/c3407b550628e63af432
##

import cgi
import requests
import json
from simple_salesforce import Salesforce

from logging import getLogger, StreamHandler, DEBUG
logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)
logger.setLevel(DEBUG)
logger.addHandler(handler)

#login here:
#https://login.salesforce.com/services/oauth2/authorize?response_type=code&client_id=3MVG9A2kN3Bn17hsWsLDatw._IVMEUBoPKv.7ksp0tz7xLX4tWDVgyzwTCA7i_yTfP.qYuNOsSoPNcdVH6DuE&redirect_uri=http://localhost/cgi-bin/python/oauth.py

consumer_key = 'YOUR_CONSUMER_KEY'
consumer_secret = 'YOUR_CONSUMER_SECRET'
request_token_url = 'https://login.salesforce.com/services/oauth2/token'
access_token_url = 'https://login.salesforce.com/services/oauth2/token'
redirect_uri = 'http://localhost:8000/cgi-bin/force_oauth.py'
authorize_url = 'https://login.salesforce.com/services/oauth2/authorize' #?response_type=token&client_id='+consumer_key+'&redirect_uri='+redirect_uri

query = cgi.FieldStorage()
req = None


records = []
if 'code' in query:
    code = query.getvalue('code')

    data = {
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'code': code,
            'client_id' : consumer_key,
            'client_secret' : consumer_secret
            }
    headers = {
            'content-type': 'application/x-www-form-urlencoded'
            }
    req = requests.post(access_token_url,data=data,headers=headers)
    response = req.json()
    logger.debug(response)
    sf = Salesforce(instance_url=response['instance_url'], session_id=response['access_token'])
    records = sf.query("SELECT Id, Name, Email FROM Contact")
    records = records['records']
    for record in records:
        logger.debug(record)

#print(web page
print("Content-type: text/html")
print()

print("<html><body>")
print("<h1>SELECT Id, Name, Email FROM Contact</h1>")

if 'login' in query:
    auth_url = "https://login.salesforce.com/services/oauth2/authorize?response_type=code&client_id="+consumer_key+"&redirect_uri="+redirect_uri
    print("Location: <a href=\"" + auth_url + "\">" + auth_url + "</a>")
    print()

print("<table>")
print("<tr><td><b>Name</b></td><td><b>Email</b></td></tr>")
for record in records:
    print("<tr><td>{0}</td><td>{1}</td></tr>".format(record['Name'], record['Email']))

print("</table>")

print("</body></html>")

##
##
##
