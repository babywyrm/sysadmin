"""
Requirements
- Python 2.7 (Jython requirement)
- BeautifulSoup4 (Installed from Python2.7)
- http-parser
"""


from burp import IBurpExtender
from burp import IProxyListener
from bs4 import BeautifulSoup
from http_parser.http import HttpStream
from io import BytesIO

from org.python.core.util import StringUtil


TARGETS = [
    "www.test.com",
]


class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerProxyListener(self)
        callbacks.setExtensionName("Fake News Proxy Listener")
        return

    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            host = message.getMessageInfo().getHttpService().getHost()
            if host not in TARGETS:
                # print("%s not in targets" % (host,))
                return
            msg = message.getMessageInfo().getResponse()

            # There must be a better way to do this, instead of streaming it into a string and back again!
            # Cant find anything in the Jython docs?
            stream = HttpStream(BytesIO(msg.tostring()))

            if stream.status_code() != 200:  # Ignore redirects and other garbage
                return

            type_ = stream.headers().get("Content-Type")
            # Only proceed if this is HTML
            if not type_.startswith('text/html'):
                return

            html = stream.body_string()
            soup = BeautifulSoup(html)

            # ... Do stuff with soup to modify the HTML

            # Write the headers back again, replace/swap any if needed now.
            old_headers = "\r\n".join(["%s: %s" % (key, value) for key, value in stream.headers().iteritems()])

            # Write the HTTP response
            new_response = "HTTP/1.1 200 OK\r\n" + old_headers + "\r\n\r\n" + str(soup)

            # Send back to the message
            message.getMessageInfo().setResponse(StringUtil.toBytes(new_response))
        return

##################
##################
##
##
