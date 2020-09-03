#!/usr/bin/env python

########################
##
##
##

__author__ = "Anand Tiwari (http://twitter.com/anandtiwarics)"
__contributors__ = ["Anand Tiwari"]
__status__ = "Production"
__license__ = "MIT"

import requests
import json
from . import __version__ as version


class BurpApi(object):
    def __init__(self, host, key, timeout=60, user_agent=None, client_version=version):

        self.host = host
        self.key = key
        self.timeout = timeout
        self.client_version = client_version

        if not user_agent:
            self.user_agent = 'PyBurprestapi/' + version
        else:
            self.user_agent = user_agent

    '''
    Burp Professional V2.0.x new API 
    
    '''

    def issue_definitions(self):
        """
        /knowledge_base/issue_definitions
        :return:
        """
        return self._request('GET', '/v0.1/knowledge_base/issue_definitions')

    def scan(self, data):
        """
        :return:
        """

        return self._request('POST', '/v0.1/scan', data=data)

    def scan_info(self, scan_id):
        """
        :param scan_id:
        :return:
        """

        return self._request('GET', '/v0.1/scan/%s' % scan_id)

    def _request(self, method, url, params=None, headers=None, data=None):
        """Common handler for all the HTTP requests."""
        if not params:
            params = {}

        # set default headers
        if not headers:
            headers = {
                'accept': '*/*'
            }
            if method == 'POST' or method == 'PUT':
                headers.update({'Content-Type': 'application/json'})
        try:
            response = requests.request(method=method, url=self.host + self.key + url, params=params,
                                        headers=headers, data=data)

            try:
                response.raise_for_status()

                response_code = response.status_code
                success = True if response_code // 100 == 2 else False
                if response.text:
                    try:
                        data = response.json()
                    except ValueError:
                        data = response.content
                else:
                    data = ''

                response_headers = response.headers

                return BurpResponse(success=success, response_code=response_code, data=data,
                                    response_headers=response_headers)
            except ValueError as e:
                return BurpResponse(success=False, message="JSON response could not be decoded {}.".format(e))
            except requests.exceptions.HTTPError as e:
                if response.status_code == 400:
                    return BurpResponse(success=False, response_code=400, message='Bad Request')
                else:
                    return BurpResponse(
                        message='There was an error while handling the request. {}'.format(response.content),
                        success=False)
        except Exception as e:
            return BurpResponse(success=False, message='Eerror is %s' % e)


class BurpResponse(object):
    """Container for all Burp REST API response, even errors."""

    def __init__(self, success, message='OK', response_code=-1, data=None, response_headers=None):
        self.message = message
        self.success = success
        self.response_code = response_code
        self.data = data
        self.response_headers = response_headers

    def __str__(self):
        if self.data:
            return str(self.data)
        else:
            return self.message

    def data_json(self, pintu=False):
        """Returns the data as a valid JSON String."""
        if pintu:
            return json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(self.data)

#####################
##
##
