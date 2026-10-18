"""
A simple proxy server, based on original by gear11:
https://gist.github.com/gear11/8006132

Modified from original to support both GET and POST, status code passthrough, header and form data passthrough.

Usage: http://hostname:port/p/(URL to be proxied, minus protocol)
For example: http://localhost:5000/p/www.google.com
"""
import re
from urllib.parse import urlparse, urlunparse
from flask import Flask, render_template, request, abort, Response, redirect
import requests
import logging

app = Flask(__name__.split('.')[0])
logging.basicConfig(level=logging.INFO)
APPROVED_HOSTS = set(["google.com", "www.google.com", "yahoo.com"])
CHUNK_SIZE = 1024
LOG = logging.getLogger("app.py")


@app.route('/<path:url>', methods=["GET", "POST"])
def root(url):
    # If referred from a proxy request, then redirect to a URL with the proxy prefix.
    # This allows server-relative and protocol-relative URLs to work.
    referer = request.headers.get('referer')
    if not referer:
        return Response("Relative URL sent without a a proxying request referal. Please specify a valid proxy host (/p/url)", 400)
    proxy_ref = proxied_request_info(referer)
    host = proxy_ref[0]
    redirect_url = "/p/%s/%s%s" % (host, url, ("?" + request.query_string.decode('utf-8') if request.query_string else ""))
    LOG.debug("Redirecting relative path to one under proxy: %s", redirect_url)
    return redirect(redirect_url)


@app.route('/p/<path:url>', methods=["GET", "POST"])
def proxy(url):
    """Fetches the specified URL and streams it out to the client.

    If the request was referred by the proxy itself (e.g. this is an image fetch
    for a previously proxied HTML page), then the original Referer is passed."""
    # Check if url to proxy has host only, and redirect with trailing slash
    # (path component) to avoid breakage for downstream apps attempting base
    # path detection
    url_parts = urlparse('%s://%s' % (request.scheme, url))
    if url_parts.path == "":
        parts = urlparse(request.url)
        LOG.warning("Proxy request without a path was sent, redirecting assuming '/': %s -> %s/" % (url, url))
        return redirect(urlunparse(parts._replace(path=parts.path+'/')))

    LOG.debug("%s %s with headers: %s", request.method, url, request.headers)
    r = make_request(url, request.method, dict(request.headers), request.form)
    LOG.debug("Got %s response from %s",r.status_code, url)
    headers = dict(r.raw.headers)
    def generate():
        for chunk in r.raw.stream(decode_content=False):
            yield chunk
    out = Response(generate(), headers=headers)
    out.status_code = r.status_code
    return out


def make_request(url, method, headers={}, data=None):
    url = 'http://%s' % url
    # Ensure the URL is approved, else abort
    if not is_approved(url):
        LOG.warn("URL is not approved: %s", url)
        abort(403)

    # Pass original Referer for subsequent resource requests
    referer = request.headers.get('referer')
    if referer:
        proxy_ref = proxied_request_info(referer)
        headers.update({ "referer" : "http://%s/%s" % (proxy_ref[0], proxy_ref[1])})

    # Fetch the URL, and stream it back
    LOG.debug("Sending %s %s with headers: %s and data %s", method, url, headers, data)
    return requests.request(method, url, params=request.args, stream=True, headers=headers, allow_redirects=False, data=data)

def is_approved(url):
    """Indicates whether the given URL is allowed to be fetched.  This
    prevents the server from becoming an open proxy"""
    parts = urlparse(url)
    return parts.netloc in APPROVED_HOSTS

def proxied_request_info(proxy_url):
    """Returns information about the target (proxied) URL given a URL sent to
    the proxy itself. For example, if given:
        http://localhost:5000/p/google.com/search?q=foo
    then the result is:
        ("google.com", "search?q=foo")"""
    parts = urlparse(proxy_url)
    if not parts.path:
        return None
    elif not parts.path.startswith('/p/'):
        return None
    matches = re.match('^/p/([^/]+)/?(.*)', parts.path)
    proxied_host = matches.group(1)
    proxied_path = matches.group(2) or '/'
    proxied_tail = urlunparse(parts._replace(scheme="", netloc="", path=proxied_path))
    LOG.debug("Referred by proxy host, uri: %s, %s", proxied_host, proxied_tail)
    return [proxied_host, proxied_tail]
  
#################
##
