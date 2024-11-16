##
##

import requests
import os,sys,re
from concurrent.futures import ThreadPoolExecutor

##
##

def parse_cookies(cookie_string):
    """Parse cookie string into a dictionary."""
    cookies = {}
    cookie_pairs = cookie_string.split(';')
    for pair in cookie_pairs:
        name, value = pair.strip().split('=', 1)
        cookies[name] = value
    return cookies

def check_cors(url, headers, cookies):
    """Check CORS configuration for a given URL."""
    try:
        # Send OPTIONS request to check CORS headers
        response_options = requests.options(url, headers=headers, cookies=cookies)
        print(f"OPTIONS {url}:")
        print(response_options.headers)
        print()

        # Send GET request to fetch resource and inspect headers
        response_get = requests.get(url, headers=headers, cookies=cookies)
        print(f"GET {url}:")
        print(f"Status Code: {response_get.status_code}")
        print(f"Headers: {response_get.headers}")
        print("Response Body (truncated):")
        print(response_get.text[:200])  # Print first 200 chars of body
        print()

        # Check if Access-Control-Allow-Origin is set correctly
        if "Access-Control-Allow-Origin" in response_get.headers:
            allowed_origin = response_get.headers["Access-Control-Allow-Origin"]
            print(f"Access-Control-Allow-Origin: {allowed_origin}")
            if allowed_origin == "*":
                print(f"[VULNERABLE] {url} allows requests from any origin!")
            elif allowed_origin == headers["Origin"]:
                print(f"[POTENTIAL ISSUE] {url} reflects the Origin header.")
            else:
                print(f"[OK] {url} restricts the origin.")
        else:
            print(f"[INFO] No Access-Control-Allow-Origin header found for {url}.")

        # Check if Access-Control-Allow-Credentials is set to true
        if "Access-Control-Allow-Credentials" in response_get.headers:
            allow_credentials = response_get.headers["Access-Control-Allow-Credentials"]
            if allow_credentials.lower() == "true":
                print(f"[WARNING] {url} allows credentials (cookies).")
    except Exception as e:
        print(f"[ERROR] Failed to check {url}: {str(e)}")

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 cors_tester.py <cookies> <base_url> <namespaces_file>")
        print("Example: python3 cors_tester.py \"sessionid=abcd1234; csrftoken=efgh5678\" https://example.com/api namespaces.txt")
        sys.exit(1)

    cookie_string = sys.argv[1]
    base_url = sys.argv[2]
    namespaces_file = sys.argv[3]

    # Parse cookies
    cookies = parse_cookies(cookie_string)

    # Define malicious headers
    headers = {
        "Origin": "https://attacker.com",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Referer": "https://attacker.com",
    }

    # Read namespaces
    if not os.path.exists(namespaces_file):
        print(f"[ERROR] File not found: {namespaces_file}")
        sys.exit(1)

    with open(namespaces_file, 'r') as f:
        namespaces = [line.strip() for line in f if line.strip()]

    # Prepare URLs for each namespace
    urls = [f"{base_url}/{namespace}" for namespace in namespaces]

    # Create a ThreadPoolExecutor to handle concurrency with threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda url: check_cors(url, headers, cookies), urls)

if __name__ == "__main__":
    main()

##
##

import asyncio
import aiohttp
import sys
import os

def parse_cookies(cookie_string):
    """Parse cookie string into a dictionary."""
    cookies = {}
    cookie_pairs = cookie_string.split(';')
    for pair in cookie_pairs:
        name, value = pair.strip().split('=', 1)
        cookies[name] = value
    return cookies

async def check_cors(session, url, headers, cookies):
    """Check CORS configuration for a given URL asynchronously."""
    try:
        # Send OPTIONS request and await the response
        async with session.options(url, headers=headers, cookies=cookies) as response_options:
            print(f"OPTIONS {url}:")
            print(dict(response_options.headers))
            print()

        # Send GET request and await the response
        async with session.get(url, headers=headers, cookies=cookies) as response_get:
            print(f"GET {url}:")
            print(f"Status Code: {response_get.status}")
            print(f"Headers: {dict(response_get.headers)}")
            print("Response Body (truncated):")
            body = await response_get.text()  # Properly await response text
            print(body[:200])  # Print first 200 chars of body
            print()

            # Analyze CORS headers
            if "Access-Control-Allow-Origin" in response_get.headers:
                allowed_origin = response_get.headers["Access-Control-Allow-Origin"]
                print(f"Access-Control-Allow-Origin: {allowed_origin}")
                if allowed_origin == "*":
                    print(f"[VULNERABLE] {url} allows requests from any origin!")
                elif allowed_origin == headers["Origin"]:
                    print(f"[POTENTIAL ISSUE] {url} reflects the Origin header.")
                else:
                    print(f"[OK] {url} restricts the origin.")
            else:
                print(f"[INFO] No Access-Control-Allow-Origin header found for {url}.")

            if "Access-Control-Allow-Credentials" in response_get.headers:
                allow_credentials = response_get.headers["Access-Control-Allow-Credentials"]
                if allow_credentials.lower() == "true":
                    print(f"[WARNING] {url} allows credentials (cookies).")

            # Check for Access-Control-Allow-Methods
            if "Access-Control-Allow-Methods" in response_get.headers:
                allowed_methods = response_get.headers["Access-Control-Allow-Methods"]
                print(f"Access-Control-Allow-Methods: {allowed_methods}")
                # Check for overly permissive methods
                unsafe_methods = ["PUT", "DELETE", "PATCH"]
                for method in unsafe_methods:
                    if method in allowed_methods:
                        print(f"[WARNING] {url} allows {method}, which could be risky.")

            # Check for Access-Control-Allow-Headers
            if "Access-Control-Allow-Headers" in response_get.headers:
                allowed_headers = response_get.headers["Access-Control-Allow-Headers"]
                print(f"Access-Control-Allow-Headers: {allowed_headers}")
                # Check for sensitive headers like Authorization
                sensitive_headers = ["Authorization", "X-API-KEY"]
                for header in sensitive_headers:
                    if header in allowed_headers:
                        print(f"[WARNING] {url} allows sensitive header: {header}.")

            # Check for Access-Control-Expose-Headers
            if "Access-Control-Expose-Headers" in response_get.headers:
                exposed_headers = response_get.headers["Access-Control-Expose-Headers"]
                print(f"Access-Control-Expose-Headers: {exposed_headers}")
                # Exposing too many headers can leak sensitive information
                if exposed_headers != "Content-Type":  # Adjust based on expected headers
                    print(f"[WARNING] {url} exposes unnecessary headers.")

            # Check for Vary: Origin
            if "Vary" in response_get.headers:
                vary_header = response_get.headers["Vary"]
                if "Origin" in vary_header:
                    print(f"[INFO] Vary header correctly set to {vary_header}")
                else:
                    print(f"[WARNING] Missing or incorrectly configured Vary header for {url}")

            # Check for Access-Control-Max-Age
            if "Access-Control-Max-Age" in response_get.headers:
                max_age = response_get.headers["Access-Control-Max-Age"]
                print(f"Access-Control-Max-Age: {max_age}")

            # Ensure credentials are not sent with wildcard origins
            if "Access-Control-Allow-Credentials" in response_get.headers and response_get.headers["Access-Control-Allow-Credentials"] == "true":
                if allowed_origin == "*":
                    print(f"[VULNERABLE] {url} allows credentials with wildcard origin!")

    except Exception as e:
        print(f"[ERROR] Failed to check {url}: {str(e)}")

async def process_urls(urls, headers, cookies):
    """Process multiple URLs asynchronously using a thread pool."""
    async with aiohttp.ClientSession() as session:
        tasks = [check_cors(session, url, headers, cookies) for url in urls]
        await asyncio.gather(*tasks)

def read_namespaces(namespaces_file):
    """Read namespaces from a file."""
    if not os.path.exists(namespaces_file):
        print(f"[ERROR] File not found: {namespaces_file}")
        sys.exit(1)

    with open(namespaces_file, 'r') as f:
        return [line.strip() for line in f if line.strip()]

async def main():
    if len(sys.argv) < 4:
        print("Usage: python3 cors_tester.py <cookies> <base_url> <namespaces_file>")
        print("Example: python3 cors_tester.py \"sessionid=abcd1234; csrftoken=efgh5678\" https://example.com/api namespaces.txt")
        sys.exit(1)

    cookie_string = sys.argv[1]
    base_url = sys.argv[2]
    namespaces_file = sys.argv[3]

    # Parse cookies
    cookies = parse_cookies(cookie_string)

    # Define malicious headers
    headers = {
        "Origin": "https://attacker.com",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Referer": "https://attacker.com",
    }

    # Read namespaces
    namespaces = read_namespaces(namespaces_file)

    # Prepare URLs
    urls = [f"{base_url}/{namespace}" for namespace in namespaces]

    # Process URLs concurrently
    await process_urls(urls, headers, cookies)

if __name__ == "__main__":
    asyncio.run(main())

##
##
