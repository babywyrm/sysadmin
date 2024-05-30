
##
##

Example..

 --cookies "sessionid=abc123; othercookie=value" --header "Authorization: Bearer token" --header "X-Custom-Header: value"

# Enhanced Analysis Explanation
The script focuses on making OPTIONS requests to check CORS headers.
The analyze_results function provides detailed feedback about the presence and values of CORS headers.
It warns if Access-Control-Allow-Origin is set to *, which can be risky.
It warns if Access-Control-Allow-Credentials is set to true, which can also be risky.
It notes when no CORS headers are found, which can be either a good or bad sign depending on the context.
This version of the script will help you understand the CORS configuration of your target server and identify potential security issues.


##
##
                                                    
import requests
import argparse
import os,sys,re

##
##

def parse_cookies(cookie_string):
    cookies = {}
    for cookie in cookie_string.split(';'):
        key, value = cookie.strip().split('=', 1)
        cookies[key] = value
    return cookies

def parse_headers(header_strings):
    headers = {}
    for header in header_strings:
        key, value = header.split(':', 1)
        headers[key.strip()] = value.strip()
    return headers

def check_cors(target_url, headers=None, cookies=None):
    test_origins = [
        "https://evil.com",
        "http://example.com",
        "null"
    ]

    results = []

    for origin in test_origins:
        try:
            response = requests.options(
                target_url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    **(headers or {})
                },
                cookies=cookies
            )
            cors_headers = {
                header: value for header, value in response.headers.items()
                if header.lower().startswith('access-control-')
            }

            results.append({
                "origin": origin,
                "status_code": response.status_code,
                "cors_headers": cors_headers
            })
        except requests.RequestException as e:
            results.append({
                "origin": origin,
                "error": str(e)
            })

    return results

def analyze_results(results):
    for result in results:
        if 'error' in result:
            print(f"Origin: {result['origin']}, Error: {result['error']}")
        else:
            print(f"Origin: {result['origin']}, Status Code: {result['status_code']}")
            if result['cors_headers']:
                for header, value in result['cors_headers'].items():
                    print(f"  {header}: {value}")
            else:
                print("  No CORS headers found.")
                
            # Security analysis
            if result['cors_headers']:
                if "access-control-allow-origin" in result['cors_headers']:
                    allowed_origin = result['cors_headers']["access-control-allow-origin"]
                    if allowed_origin == "*":
                        print("  Warning: Access-Control-Allow-Origin is set to '*', which is risky.")
                    else:
                        print(f"  Access-Control-Allow-Origin is set to '{allowed_origin}'")
                else:
                    print("  Warning: No Access-Control-Allow-Origin header found.")

                if "access-control-allow-credentials" in result['cors_headers']:
                    allow_credentials = result['cors_headers']["access-control-allow-credentials"]
                    if allow_credentials.lower() == "true":
                        print("  Warning: Access-Control-Allow-Credentials is 'true', which can be risky.")
            else:
                print("  No CORS headers found. This may be secure if no cross-origin access is needed.")
            print()

def main():
    parser = argparse.ArgumentParser(description="CORS Security Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--cookies", help="Cookies to include in the requests, separated by ';'")
    parser.add_argument("--header", action='append', help="Additional headers to include in the requests")

    args = parser.parse_args()

    headers = {}
    if args.header:
        headers = parse_headers(args.header)

    cookies = {}
    if args.cookies:
        cookies = parse_cookies(args.cookies)

    results = check_cors(args.url, headers, cookies)
    analyze_results(results)

if __name__ == "__main__":
    main()

##
##
