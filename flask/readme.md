<br>
<br>
https://wesselhuising.medium.com/adding-ssl-to-a-flask-application-running-inside-a-docker-container-856166bf3a86
<br>

https://www.digitalocean.com/community/tutorials/how-to-build-and-deploy-a-flask-application-using-docker-on-ubuntu-20-04
<br>

https://forums.docker.com/t/docker-is-running-but-i-cannot-access-localhost-flask-application/82193
<br>

############################

'''
When passing variables via Shotgun's custom URL handler &
action menu items, sometimes you just need a server to test 
whether the field data you want is correctly getting through.
-----
If you're creating a custom URL handler or using modals, you'll need 
to generate a self-signed certificate in the same directory as you place 
this file. 
To generate a security certificate for testing, follow steps 1-4 of 
  http://www.akadia.com/services/ssh_test_certificate.html
Once you've finished testing and want to deploy your code to production, 
you can get a real security certificate for free here:
  https://letsencrypt.org/
Notes: 
(1) If you're just using this for action menu items that open into
a new browser tab, you do not need a security certificate.
(2) If you're testing loading an action menu item into a modal window using a
self-generated certificate, you'll likely need to open the URL in a
new browser window first to bypass the browser's security warning, before
it will load properly into Shotgun.
-----
For more information and install instructions for Flask,
see : http://flask.pocoo.org/
'''

from OpenSSL import SSL
from flask import Flask, request
app = Flask(__name__)

@app.route("/", methods=['POST', 'GET'])
def index():

    html = "GET DATA:<br />"
    html += "{0}<br />".format(request.args)
    html += "<hr />"
    html +=  "POST DATA:<br />"
    html += "{0}<br />".format(request.form)

    return html

if __name__ == "__main__":
    context = ('server.crt', 'server.key')
    app.run(host='127.0.0.1', port=5000, ssl_context=context, threaded=True, debug=True)
    
    
############################
############################    
