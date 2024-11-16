import asyncio
import aiohttp
import os,sys,re

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

async def check_cors(session, url, headers, cookies):
    """Check CORS configuration for a given URL asynchronously."""
    try:
        # Send OPTIONS request
        async with session.options(url, headers=headers, cookies=cookies) as response_options:
            print(f"OPTIONS {url}:")
            print(dict(response_options.headers))
            print()

        # Send GET request
        async with session.get(url, headers=headers, cookies=cookies) as response_get:
            print(f"GET {url}:")
            print(f"Status Code: {response_get.status}")
            print(f"Headers: {dict(response_get.headers)}")
            print("Response Body (truncated):")
            print(await response_get.text()[:200])
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
    except Exception as e:
        print(f"[ERROR] Failed to check {url}: {str(e)}")

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
    if not os.path.exists(namespaces_file):
        print(f"[ERROR] File not found: {namespaces_file}")
        sys.exit(1)

    with open(namespaces_file, 'r') as f:
        namespaces = [line.strip() for line in f if line.strip()]

    # Prepare URLs
    urls = [f"{base_url}/{namespace}" for namespace in namespaces]

    # Create an aiohttp session and process all URLs concurrently
    async with aiohttp.ClientSession() as session:
        tasks = [check_cors(session, url, headers, cookies) for url in urls]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
