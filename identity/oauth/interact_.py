# an interactive python script to assist in getting access tokens for OAuth v1
# APIs. requires python's OAuth2 library (pip install oauth2)
#
# run from the command line like so:
#
# $ python three_legged_oauth_helper.py --consumer_key=<ckey> \
#   --consumer_secret=<csecret> \
#   --request_token_url=<request_token_url> \
#   --authorize_url=<authorize_url> \
#   --access_token_url=<access_token_url>
#
# ... where <ckey> is your consumer key, <csecret> is your consumer secret,
# and <request_token_url>, <authorize_url>, <access_token_url> are the
# request token URL, authorize URL, and access_token URL of the service you're
# targeting (respectively). Default URLs are supplied for the Tumblr API.

import oauth2 as oauth
import urlparse

from optparse import OptionParser
parser = OptionParser()
parser.add_option("--consumer_key", dest="consumer_key")
parser.add_option("--consumer_secret", dest="consumer_secret")
parser.add_option("--request_token_url", dest="request_token_url",
  	default="http://www.tumblr.com/oauth/request_token")
parser.add_option("--authorize_url", dest="authorize_url",
		default="http://www.tumblr.com/oauth/authorize")
parser.add_option("--access_token_url", dest="access_token_url",
		default="http://www.tumblr.com/oauth/access_token")
(options, args) = parser.parse_args()

consumer = oauth.Consumer(options.consumer_key, options.consumer_secret)
client = oauth.Client(consumer)

resp, content = client.request(options.request_token_url, "POST")

request_token = dict(urlparse.parse_qsl(content))

print "Paste this URL into your browser and authorize the application."
print "  %s?%s" % (options.authorize_url, content)
print """
After authorizing this application, you'll be redirected either to your OAuth
callback URL, or to a page showing a PIN. If you're redirected to the callback
page, copy the 'oauth_verifier' value from the query string in your browser's
URL display and paste it here. If you see a PIN, copy it and paste it below.
"""

verifier = raw_input("> ")

token = oauth.Token(request_token['oauth_token'],
		request_token['oauth_token_secret'])
token.set_verifier(verifier)
token_client = oauth.Client(consumer, token)
resp, content = token_client.request(options.access_token_url, "POST")

access_token = dict(urlparse.parse_qsl(content))

print "Your access token: %s" % access_token['oauth_token']
print "Your access token secret: %s" % access_token['oauth_token_secret']


##
##
