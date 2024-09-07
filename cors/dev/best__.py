import requests
import os,sys,re
import logging

##
##

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_cookies(cookie_string):
    """Parse a cookie string into a dictionary."""
    cookies = {}
    try:
        cookie_pairs = cookie_string.split(';')
        for pair in cookie_pairs:
            name, value = pair.strip().split('=', 1)
            cookies[name] = value
    except ValueError as e:
        logging.error(f"Error parsing cookies: {e}")
    return cookies

def send_request(url, headers, cookies):
    """Send OPTIONS and GET requests to the target URL and return responses."""
    try:
        response_options = requests.options(url, headers=headers, cookies=cookies)
        response_get = requests.get(url, headers=headers, cookies=cookies)
        return response_options, response_get
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        sys.exit(1)

def analyze_response(response_get, headers):
    """Analyze the CORS response and print relevant information."""
    cors_header = response_get.headers.get("Access-Control-Allow-Origin")
    credentials_header = response_get.headers.get("Access-Control-Allow-Credentials")

    logging.info("GET Request Status Code: %d", response_get.status_code)
    logging.info("GET Request Headers: %s", response_get.headers)
    logging.info("Response Body: %s", response_get.text)

    if cors_header:
        logging.info(f"Access-Control-Allow-Origin header is present: {cors_header}")
        if cors_header == "*":
            logging.warning("Vulnerability Detected: The server allows requests from any origin!")
        elif cors_header == headers["Origin"]:
            logging.warning("Potential Vulnerability Detected: The server reflects the Origin header.")
        else:
            logging.info("The server restricts the origin. This might be safe depending on the context.")
    else:
        logging.info("No Access-Control-Allow-Origin header found. CORS might not be implemented.")

    if credentials_header:
        if credentials_header.lower() == "true":
            logging.warning("Warning: Access-Control-Allow-Credentials is set to true. Cookies and credentials are allowed from the specified origin.")
    else:
        logging.info("Access-Control-Allow-Credentials header not present. Cookies and credentials are not allowed.")

def process_urls(urls, headers, cookies):
    """Process each URL and perform CORS testing."""
    for url in urls:
        logging.info(f"Processing URL: {url}")
        response_options, response_get = send_request(url, headers, cookies)
        logging.info("OPTIONS Request Headers: %s", response_options.headers)
        analyze_response(response_get, headers)

def main():
    if len(sys.argv) < 3:
        logging.error("Usage: python3 cors_tester.py <cookies> <target_url|target_url_list>")
        logging.error("Example (single URL): python3 cors_tester.py \"sessionid=abcd1234; csrftoken=efgh5678\" https://example.com/api")
        logging.error("Example (URL list): python3 cors_tester.py \"sessionid=abcd1234; csrftoken=efgh5678\" https://example.com/api,https://example2.com/api")
        sys.exit(1)

    cookie_string = sys.argv[1]
    url_input = sys.argv[-1]

    # Parse the cookies
    cookies = parse_cookies(cookie_string)

    # Define headers to simulate a cross-origin request
    headers = {
        "Origin": "https://attacker.com",  # Simulated malicious origin
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Referer": "https://attacker.com",
    }

    # Handle URL input
    urls = [url.strip() for url in url_input.split(',')]
    
    # Validate URLs
    for url in urls:
        if not re.match(r'^https?:\/\/', url):
            logging.error(f"Invalid URL format: {url}")
            sys.exit(1)

    # Process URLs
    process_urls(urls, headers, cookies)

if __name__ == "__main__":
    main()

##
##
