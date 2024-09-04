import requests
import os,sys,re

##
## this needs some TLC alright
##

def parse_cookies(cookie_string):
    cookies = {}
    cookie_pairs = cookie_string.split(';')
    for pair in cookie_pairs:
        name, value = pair.strip().split('=', 1)
        cookies[name] = value
    return cookies

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 cors_tester.py <cookies> <target_url>")
        print("Example: python3 cors_tester.py \"sessionid=abcd1234; csrftoken=efgh5678\" https://example.com/api")
        sys.exit(1)

    # ok so, cookies are the first argument and the URL is the last argument
    cookie_string = sys.argv[1]
    url = sys.argv[-1]

    # Parse the cookies
    cookies = parse_cookies(cookie_string)

    # define gross headers to simulate a cross-origin request
    headers = {
        "Origin": "https://attacker.com",  # Simulated malicious origin
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Referer": "https://attacker.com",
    }

    # send the OPTIONS request to see what methods are allowed
    response_options = requests.options(url, headers=headers, cookies=cookies)
    print("OPTIONS Request Headers:")
    print(response_options.headers)
    print("\n")

    # send the actual GET request to test CORS
    response_get = requests.get(url, headers=headers, cookies=cookies)
    print("GET Request Status Code:", response_get.status_code)
    print("GET Request Headers:")
    print(response_get.headers)
    print("Response Body:")
    print(response_get.text)
    print("\n")

    # check for terrible ideas
    if "Access-Control-Allow-Origin" in response_get.headers:
        allowed_origin = response_get.headers["Access-Control-Allow-Origin"]
        print(f"Access-Control-Allow-Origin header is present: {allowed_origin}")
        if allowed_origin == "*":
            print("Vulnerability Detected: The server allows requests from any origin!")
        elif allowed_origin == headers["Origin"]:
            print("Potential Vulnerability Detected: The server reflects the Origin header.")
        else:
            print("The server restricts the origin. This might be safe depending on the context.")
    else:
        print("No Access-Control-Allow-Origin header found. CORS might not be implemented.")

    # and, check if credentials are allowed
    if "Access-Control-Allow-Credentials" in response_get.headers:
        allow_credentials = response_get.headers["Access-Control-Allow-Credentials"]
        if allow_credentials.lower() == "true":
            print("Warning: Access-Control-Allow-Credentials is set to true. Cookies and credentials are allowed from the specified origin.")
    else:
        print("Access-Control-Allow-Credentials header not present. Cookies and credentials are not allowed.")

if __name__ == "__main__":
    main()


