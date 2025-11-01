#!/usr/bin/env python3
"""
Hop-by-Hop Header Abuse Detection Tool __new__
Tests for potential HTTP request smuggling and cache poisoning vulnerabilities
by manipulating Connection header hop-by-hop directives.
"""

import requests
import random
import string
import sys
from argparse import ArgumentParser
from typing import Dict, Any
from urllib.parse import urljoin


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


class HopByHopTester:
    def __init__(self, url: str, headers: str, cache_test: bool, 
                 disable_size_check: bool, verbose: bool):
        self.url = url
        self.headers_list = [h.strip() for h in headers.split(',')]
        self.cache_test = cache_test
        self.disable_size_check = disable_size_check
        self.verbose = verbose
        self.session = requests.Session()
        
    def generate_cache_buster(self) -> str:
        """Generate a random cache buster string"""
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    
    def log_verbose(self, message: str):
        """Print verbose output"""
        if self.verbose:
            print(f"{Colors.CYAN}[VERBOSE]{Colors.END} {message}")
    
    def log_info(self, message: str):
        """Print info message"""
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    def log_warning(self, message: str):
        """Print warning message"""
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    def log_success(self, message: str):
        """Print success message"""
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    def log_error(self, message: str):
        """Print error message"""
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    def make_request(self, params: Dict[str, str], headers: Dict[str, str] = None) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            return self.session.get(
                self.url, 
                params=params, 
                headers=headers or {}, 
                allow_redirects=False,
                timeout=10
            )
        except requests.exceptions.Timeout:
            self.log_error("Request timed out")
            sys.exit(1)
        except requests.exceptions.ConnectionError as e:
            self.log_error(f"Connection error: {e}")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            self.log_error(f"Request failed: {e}")
            sys.exit(1)
    
    def compare_responses(self, res1: requests.Response, res2: requests.Response) -> Dict[str, Any]:
        """Compare two HTTP responses and return differences"""
        differences = {
            'status_code_changed': res1.status_code != res2.status_code,
            'size_changed': len(res1.content) != len(res2.content),
            'headers_changed': res1.headers != res2.headers
        }
        
        return {
            'has_changes': any(differences.values()),
            'details': differences,
            'res1_status': res1.status_code,
            'res2_status': res2.status_code,
            'res1_size': len(res1.content),
            'res2_size': len(res2.content)
        }
    
    def test_cache_poisoning(self, cache_buster: str, expected_status: int):
        """Test for cache poisoning by requesting without hop-by-hop headers"""
        self.log_info("Testing for cache poisoning...")
        params = {'cb': cache_buster}
        
        poison_test_response = self.make_request(params)
        
        if poison_test_response.status_code == expected_status:
            self.log_warning(f"Possible cache poisoning detected at {self.url}?cb={cache_buster}")
            return True
        else:
            self.log_info("No cache poisoning detected")
            return False
    
    def run_test(self):
        """Run the hop-by-hop header abuse test"""
        self.log_info(f"Testing {self.url} for hop-by-hop header abuse")
        self.log_info(f"Target headers: {', '.join(self.headers_list)}")
        
        # Generate cache busters
        cache_buster1 = self.generate_cache_buster()
        cache_buster2 = self.generate_cache_buster()
        
        # Prepare parameters
        params1 = {'cb': cache_buster1}
        params2 = {'cb': cache_buster2}
        
        # Prepare hop-by-hop headers
        hop_by_hop_headers = {
            'Connection': f"keep-alive, {', '.join(self.headers_list)}"
        }
        
        # Add the actual headers being tested
        for header in self.headers_list:
            hop_by_hop_headers[header] = f"test-{self.generate_cache_buster()}"
        
        # Make baseline request
        self.log_verbose(f"Making baseline request to {self.url}?cb={cache_buster1}")
        baseline_response = self.make_request(params1)
        
        # Make hop-by-hop request
        self.log_verbose(f"Making hop-by-hop request to {self.url}?cb={cache_buster2}")
        hop_by_hop_response = self.make_request(params2, hop_by_hop_headers)
        
        # Compare responses
        comparison = self.compare_responses(baseline_response, hop_by_hop_response)
        
        if comparison['has_changes']:
            self.log_success("Hop-by-hop header abuse detected!")
            
            if comparison['details']['status_code_changed']:
                self.log_warning(
                    f"Status code changed: {comparison['res1_status']} → "
                    f"{comparison['res2_status']}"
                )
            
            if not self.disable_size_check and comparison['details']['size_changed']:
                self.log_warning(
                    f"Response size changed: {comparison['res1_size']} → "
                    f"{comparison['res2_size']} bytes"
                )
            
            # Test for cache poisoning if enabled
            if self.cache_test:
                self.test_cache_poisoning(cache_buster2, comparison['res2_status'])
                
        else:
            self.log_verbose(
                f"No differences detected with hop-by-hop headers: "
                f"{', '.join(self.headers_list)}"
            )


def main():
    parser = ArgumentParser(
        description="Test for hop-by-hop header abuse vulnerabilities",
        formatter_class=ArgumentParser.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com/api
  %(prog)s -u https://example.com -x "X-Forwarded-For,X-Real-IP" -c -v
  %(prog)s -u https://example.com/endpoint -x "Authorization" --cache-test
        """
    )
    
    parser.add_argument(
        "-u", "--url", 
        required=True,
        help="Target URL (without query parameters)"
    )
    parser.add_argument(
        "-x", "--headers", 
        default="X-Forwarded-For",
        help="Comma-separated list of headers to test as hop-by-hop (default: X-Forwarded-For)"
    )
    parser.add_argument(
        "-c", "--cache-test", 
        action="store_true",
        help="Test for cache poisoning vulnerabilities"
    )
    parser.add_argument(
        "-d", "--disable-size-check", 
        action="store_true",
        help="Skip response size comparison"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}Error:{Colors.END} URL must start with http:// or https://")
        sys.exit(1)
    
    # Initialize and run tester
    tester = HopByHopTester(
        url=args.url,
        headers=args.headers,
        cache_test=args.cache_test,
        disable_size_check=args.disable_size_check,
        verbose=args.verbose
    )
    
    tester.run_test()


if __name__ == "__main__":
    main()
