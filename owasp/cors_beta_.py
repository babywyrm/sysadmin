import requests
import os,sys,re

##
##

# Parse cookies from a cookie string
def parse_cookies(cookie_string):
    cookies = {}
    cookie_pairs = cookie_string.split(';')
    for pair in cookie_pairs:
        if '=' in pair:
            name, value = pair.strip().split('=', 1)
            cookies[name] = value
    return cookies

# Check and analyze CORS headers
def analyze_cors_headers(response, origin):
    print(f"\nAnalyzing CORS headers for {response.request.method} request:")

    if "Access-Control-Allow-Origin" in response.headers:
        allowed_origin = response.headers["Access-Control-Allow-Origin"]
        print(f"Access-Control-Allow-Origin: {allowed_origin}")
        if allowed_origin == "*":
            print("Vulnerability Detected: Server allows requests from any origin (wildcard).")
        elif allowed_origin == origin:
            print("Potential Vulnerability: Server reflects the Origin header.")
        else:
            print("CORS policy restricts origins. This might be safe depending on the context.")
    else:
        print("No Access-Control-Allow-Origin header found. CORS might not be implemented.")

    if "Access-Control-Allow-Credentials" in response.headers:
        allow_credentials = response.headers["Access-Control-Allow-Credentials"]
        if allow_credentials.lower() == "true":
            print("Warning: Access-Control-Allow-Credentials is set to true. Cookies and credentials are allowed from the specified origin.")
    else:
        print("Access-Control-Allow-Credentials header not present. Cookies and credentials are not allowed.")

    if "Access-Control-Allow-Methods" in response.headers:
        allowed_methods = response.headers["Access-Control-Allow-Methods"]
        print(f"Access-Control-Allow-Methods: {allowed_methods}")

    if "Access-Control-Allow-Headers" in response.headers:
        allowed_headers = response.headers["Access-Control-Allow-Headers"]
        print(f"Access-Control-Allow-Headers: {allowed_headers}")

# Main function for CORS testing
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cors_tester.py <target_url> [cookies]")
        print("Example (unauthorized): python3 cors_tester.py https://example.com/api")
        print("Example (authorized): python3 cors_tester.py https://example.com/api \"sessionid=abcd1234; csrftoken=efgh5678\"")
        sys.exit(1)

    # Extract arguments
    url = sys.argv[1]
    cookie_string = sys.argv[2] if len(sys.argv) > 2 else None
    cookies = parse_cookies(cookie_string) if cookie_string else {}

    # Define headers simulating a cross-origin request
    malicious_origin = "https://attacker.com"
    headers = {
        "Origin": malicious_origin,
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Referer": malicious_origin,
    }

    # HTTP methods to test
    http_methods = ["OPTIONS", "GET", "POST", "PUT", "DELETE"]

    for method in http_methods:
        print(f"\nTesting {method} request to {url}:")

        try:
            # Make the request
            if method == "OPTIONS":
                response = requests.options(url, headers=headers, cookies=cookies, timeout=10)
            elif method == "GET":
                response = requests.get(url, headers=headers, cookies=cookies, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=headers, cookies=cookies, timeout=10)
            elif method == "PUT":
                response = requests.put(url, headers=headers, cookies=cookies, timeout=10)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, cookies=cookies, timeout=10)
            else:
                print(f"Unsupported method: {method}")
                continue

            # Print status and headers
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {response.headers}")

            # Analyze CORS headers
            analyze_cors_headers(response, malicious_origin)

            # Print response body for debugging (optional)
            if method == "GET" or method == "POST":
                print(f"Response Body:\n{response.text[:500]}...")  # Print first 500 characters

        except requests.RequestException as e:
            print(f"Error making {method} request: {e}")

if __name__ == "__main__":
    main()

##
##
