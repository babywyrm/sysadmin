#!/usr/bin/env python3
"""This is a sample Python 3 app that hosts an OIDC app with Flask to
authenticate against Okta and run example calls against the new Okta OAuth-scoped APIs.
This example can also be used to host authentication for an OIDC webapp that does not use
the OAuth API scopes.
This was created with an MVP in mind as an example to demonstrate the ease of interacting
with Okta's Authroization Code flow and should not be used in production without
additions to error/state-handling and strong scrutiny."""

###
###

import secrets
import base64
import hashlib
import os
import urllib

import requests
from flask import Flask, redirect, url_for, request, session

APP = Flask(__name__)
HASH = secrets.token_hex(nbytes=16)

def code_verifier(n_bytes=64):
    """Python-compatible PKCE code verifier shamelessly borrowed from
    https://github.com/openstack/deb-python-oauth2client/blob/master/oauth2client/_pkce.py."""
    verifier = base64.urlsafe_b64encode(os.urandom(n_bytes)).rstrip(b'=')
    # https://tools.ietf.org/html/rfc7636#section-4.1
    # minimum length of 43 characters and a maximum length of 128 characters.
    if len(verifier) < 43:
        raise ValueError("Verifier too short. n_bytes must be > 30.")
    elif len(verifier) > 128:
        raise ValueError("Verifier too long. n_bytes must be < 97.")
    else:
        return verifier

def code_challenge(verifier):
    """Generate a code challenge based on the code verifier"""
    digest = hashlib.sha256(verifier).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=')

CODE_VERIFIER = code_verifier()
CODE_CHALLENGE = code_challenge(CODE_VERIFIER)

APP.config['SECRET_KEY'] = HASH

# Your org's Okta domain (prod or preview, preview only for OAuth API scopes)
OKTA_URL = "https://{{orgname}}.okta{{preview}}.com/"
OAUTH_URL = "oauth2/v1/authorize"

# Your app's OIDC client ID
CLIENT_ID = "000123456789abc"
# A redirect URI, also explicitly defined in the Okta OIDC app
REDIRECT_URI = "http://localhost:5000/callback"
TOKEN_URL = "https://{{orgname}}.okta{{preview}}.com/oauth2/v1/token"
AUTHORIZE_URL = OKTA_URL + OAUTH_URL

@APP.route("/")
def login_page():
    """Basic login page with an Authenticate with Okta button. Clicking the
    button creates an auth URL using the create_auth_url function"""
    text = '<a href="%s">Authenticate with Okta</a>'
    return text % create_auth_url()

def create_auth_url():
    """This builds an auth url that Okta will accept for the Authorization Code
    Flow w/ PKCE Verification, the most secure method of auth Okta currently supports."""
    state = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    credentials = {
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        # Define your app scopes here. If you're building an OIDC app you'll
        # want to stick to the scopes defined in Okta's OIDC spec:
        # https://developer.okta.com/docs/reference/api/oidc/#scopes
        # If you're building an app to interact with your Okta OAuth APIs
        # You'll want to state each API scope you need here.
        'scope': "openid okta.groups.read okta.users.read",
        'state': state,
        'nonce': nonce,
        'code_challenge_method': 'S256',
        'code_challenge': CODE_CHALLENGE
    }
    url = (AUTHORIZE_URL + "?" + urllib.parse.urlencode(credentials))
    return url

@APP.route('/callback', methods=['GET'])
def callback():
    """Callback URI provided to Okta to ingest the authorization code,
    code verifier, or any error condition """
    # state variable is not used yet but should be used to invalidate the
    # session on incorrect match per client.
    state = request.args.get('state')
    code = request.args.get('code')
    error = request.args.get('error')
    if error:
        return "Error: " + error
    headers = {
        'accept': 'application/json',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'code': code,
        'code_verifier': CODE_VERIFIER
    }
    client_auth = requests.post(TOKEN_URL, headers=headers, data=data)
    client_json = client_auth.json()
    session['access_token'] = client_json["access_token"]
    return redirect(url_for('.methods'))

@APP.route("/groups")
def groups():
    """Example page with a function that will list all groups in the Okta instance"""
    access_token = session['access_token']
    return "%s" % list_groups(access_token)

def list_groups(access_token):
    """Okta API call to get all groups in the Okta instance"""
    request_url = OKTA_URL + "api/v1/groups"
    headers = {"Authorization": "Bearer " + access_token}
    group_request = requests.get(request_url, headers=headers).json()
    return group_request

@APP.route("/users")
def users():
    """Example page with a function that will list all users in the Okta instance"""
    access_token = session['access_token']
    return "%s" % list_users(access_token)

def list_users(access_token):
    """Okta API call to get all users in the Okta instance"""
    request_url = OKTA_URL + "api/v1/users"
    headers = {"Authorization": "Bearer " + access_token}
    group_request = requests.get(request_url, headers=headers).json()
    return group_request

@APP.route('/methods')
def methods():
    """'Index' Page of available sample API calls to Okta. Clicking either will execute
    that page's related API function."""
    list_groups_text = '<a href="/groups">List Groups</a>'
    list_users_text = '<a href="/users">List Users</a>'
    page_links = list_groups_text + "<br>" + list_users_text
    return page_links

if __name__ == "__main__":
    APP.run()
    
    
###########
###
###
