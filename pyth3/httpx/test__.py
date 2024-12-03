import httpx
import argparse
import logging

##
##

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def test_http(
    url: str,
    method: str = "GET",
    headers: dict = None,
    data: str = None,
    params: dict = None,
    use_http2: bool = False,
    timeout: int = 10,
):
    """
    Test HTTP/1.1 or HTTP/2 request against a target URL with custom options.
    """
    try:
        # Configure the client
        transport = httpx.HTTPTransport(http2=use_http2)
        with httpx.Client(transport=transport, timeout=timeout) as client:
            logging.info(f"Testing {method.upper()} request to {url} using HTTP/{'2' if use_http2 else '1.1'}")
            response = client.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                params=params,
            )

            # Log the request and response details
            logging.info(f"Request Headers: {response.request.headers}")
            logging.info(f"Response Status Code: {response.status_code}")
            logging.info(f"Response Headers: {response.headers}")
            logging.info(f"Response Text: {response.text[:500]}")  # Truncate for readability
            return response
    except httpx.RequestError as e:
        logging.error(f"An error occurred while making the request: {e}")

def main():
    parser = argparse.ArgumentParser(description="HTTP client for testing HTTP/1.1 and HTTP/2.")
    parser.add_argument("url", help="Target URL to test.")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET).")
    parser.add_argument("--headers", type=str, help="Custom headers as a JSON string (e.g., '{\"User-Agent\": \"httpx-client\"}').")
    parser.add_argument("--data", type=str, help="Request body data for POST/PUT requests.")
    parser.add_argument("--params", type=str, help="Query parameters as a JSON string (e.g., '{\"key\": \"value\"}').")
    parser.add_argument("--http2", action="store_true", help="Use HTTP/2 instead of HTTP/1.1.")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10).")
    args = parser.parse_args()

    # Convert JSON strings to dictionaries if provided
    headers = eval(args.headers) if args.headers else None
    params = eval(args.params) if args.params else None

    # Perform the test
    test_http(
        url=args.url,
        method=args.method.upper(),
        headers=headers,
        data=args.data,
        params=params,
        use_http2=args.http2,
        timeout=args.timeout,
    )

if __name__ == "__main__":
    main()

