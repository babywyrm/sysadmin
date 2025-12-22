#!/usr/bin/env python3
"""
Advanced WebSocket Fuzzer & SSRF Tester

A robust utility for security testing WebSocket endpoints. Supports concurrent fuzzing,
authentication headers, response analysis, and interactive modes.

Features:
- Asyncio-based concurrent fuzzing
- Custom headers/Authentication support
- Regex matching on responses
- Interactive shell mode
- Rate limiting and timeouts
- Payload manipulation (JSON wrapping, base64, etc.)
- Detailed reporting (JSON/CSV)
"""

import asyncio
import websockets
import argparse
import json
import csv
import sys
import re
import ssl
import time
import base64
import random
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Optional

# ──────────────────────────────────────────────────────────────── #
# Configuration & Colors
# ──────────────────────────────────────────────────────────────── #

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

BANNER = f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════╗
║    WebSocket Advanced Fuzzer & SSRF Tool   ║
╚════════════════════════════════════════════╝
{Colors.RESET}"""

# ──────────────────────────────────────────────────────────────── #
# Core Fuzzer Logic
# ──────────────────────────────────────────────────────────────── #

class WebSocketFuzzer:
    def __init__(self, args):
        self.target = args.target
        self.headers = self._parse_headers(args.headers)
        self.timeout = args.timeout
        self.delay = args.delay
        self.verbose = args.verbose
        self.match_pattern = re.compile(args.match) if args.match else None
        self.filter_pattern = re.compile(args.filter) if args.filter else None
        self.json_wrap = args.json_key
        self.results = []
        self.insecure = args.insecure
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(args.concurrency)

    def _parse_headers(self, headers_list: Optional[List[str]]) -> Dict[str, str]:
        """Convert list of 'Key: Value' strings to a dictionary."""
        headers_dict = {}
        if headers_list:
            for h in headers_list:
                try:
                    k, v = h.split(':', 1)
                    headers_dict[k.strip()] = v.strip()
                except ValueError:
                    print(f"{Colors.YELLOW}[!] Invalid header format ignored: {h}{Colors.RESET}")
        return headers_dict

    def _prepare_payload(self, raw_payload: str) -> str:
        """Modify payload based on configuration (JSON wrap, encoding, etc.)."""
        payload = raw_payload
        
        # If user wants to wrap in JSON: {"key": "payload"}
        if self.json_wrap:
            try:
                # Try to see if payload is already JSON to avoid double escaping if desired
                # But usually fuzzing involves injecting into a value
                wrapper = {self.json_wrap: payload}
                payload = json.dumps(wrapper)
            except Exception:
                pass
        
        return payload

    async def _handle_connection(self, websocket, payload: str):
        """Send a single payload and handle the response."""
        start_time = time.time()
        final_payload = self._prepare_payload(payload)

        try:
            if self.verbose:
                print(f"{Colors.DIM}[->] Sending: {final_payload[:100]}...{Colors.RESET}")
            
            await websocket.send(final_payload)
            
            # Wait for response with timeout
            response = await asyncio.wait_for(websocket.recv(), timeout=self.timeout)
            
            duration = round((time.time() - start_time) * 1000, 2)
            result_len = len(response)
            
            # Analysis Logic
            is_interesting = False
            status_symbol = f"{Colors.BLUE}[*]{Colors.RESET}"
            
            if self.match_pattern and self.match_pattern.search(response):
                is_interesting = True
                status_symbol = f"{Colors.GREEN}[+]{Colors.RESET}"
            elif self.match_pattern:
                status_symbol = f"{Colors.DIM}[.]{Colors.RESET}" # Matched nothing, dim it

            if self.filter_pattern and self.filter_pattern.search(response):
                return # Skip logging this result
            
            # Print output
            if not self.match_pattern or is_interesting:
                print(f"{status_symbol} Payload: {Colors.BOLD}{payload[:50].strip()}{Colors.RESET} | "
                      f"Size: {result_len}b | Time: {duration}ms")
                
                if is_interesting or self.verbose:
                    preview = response[:200].replace('\n', ' ') + "..." if len(response) > 200 else response
                    print(f"    {Colors.CYAN}Response: {preview}{Colors.RESET}")

            # Store Result
            self.results.append({
                "payload": payload,
                "sent_payload": final_payload,
                "response": response,
                "length": result_len,
                "duration": duration,
                "timestamp": datetime.now().isoformat()
            })

        except asyncio.TimeoutError:
            print(f"{Colors.RED}[!] Timeout waiting for response to: {payload[:30]}{Colors.RESET}")
        except websockets.exceptions.ConnectionClosed:
            print(f"{Colors.RED}[!] Connection closed unexpectedly on payload: {payload[:30]}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

    async def fuzz(self, payloads: List[str]):
        """Main fuzzing loop with concurrency support."""
        
        # Setup SSL context if needed
        ssl_context = None
        if self.target.startswith('wss://') and self.insecure:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        print(f"{Colors.BLUE}[INFO] Starting fuzzing on {self.target}{Colors.RESET}")
        print(f"{Colors.BLUE}[INFO] Payloads: {len(payloads)} | Concurrency: {self.semaphore._value}{Colors.RESET}")
        
        if self.headers:
            print(f"{Colors.DIM}[INFO] Custom Headers: {self.headers.keys()}{Colors.RESET}")

        try:
            # We connect once per batch or persistent connection? 
            # For fuzzing stateful sockets, persistent is better.
            # However, if a payload crashes the socket, we lose the pipe.
            # Robust strategy: Reconnect on loop.
            
            async with websockets.connect(
                self.target, 
                extra_headers=self.headers, 
                ssl=ssl_context,
                ping_interval=None # Disable auto-ping to avoid noise
            ) as websocket:
                
                print(f"{Colors.GREEN}[SUCCESS] Connected to server.{Colors.RESET}\n")

                for payload in payloads:
                    async with self.semaphore:
                        if self.delay > 0:
                            await asyncio.sleep(self.delay)
                        
                        try:
                            # Check if connection is still alive, if not, reconnect (simplified logic)
                            if websocket.closed:
                                print(f"{Colors.YELLOW}[!] Connection lost. Reconnecting...{Colors.RESET}")
                                websocket = await websockets.connect(self.target, extra_headers=self.headers, ssl=ssl_context)

                            await self._handle_connection(websocket, payload)
                            
                        except Exception as e:
                            print(f"{Colors.RED}[CRITICAL] Connection loop error: {e}{Colors.RESET}")
                            # Try to recover session
                            try:
                                websocket = await websockets.connect(self.target, extra_headers=self.headers, ssl=ssl_context)
                            except:
                                print(f"{Colors.RED}[FATAL] Could not reconnect.{Colors.RESET}")
                                break

        except Exception as e:
            print(f"{Colors.RED}[FATAL] Initial connection failed: {e}{Colors.RESET}")

# ──────────────────────────────────────────────────────────────── #
# Interactive Shell
# ──────────────────────────────────────────────────────────────── #

async def interactive_mode(target, headers, insecure):
    """Launch an interactive shell to talk to the websocket manually."""
    ssl_context = None
    if target.startswith('wss://') and insecure:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    print(f"\n{Colors.CYAN}>>> Interactive Mode Enabled (Type 'exit' to quit){Colors.RESET}")
    
    try:
        async with websockets.connect(target, extra_headers=headers, ssl=ssl_context) as websocket:
            print(f"{Colors.GREEN}[Connected]{Colors.RESET}")
            
            while True:
                try:
                    msg = await asyncio.to_thread(input, f"{Colors.BOLD}ws > {Colors.RESET}")
                    if msg.lower() in ['exit', 'quit']:
                        break
                    
                    await websocket.send(msg)
                    response = await websocket.recv()
                    print(f"{Colors.MAGENTA}< {response}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                    break
    except Exception as e:
        print(f"{Colors.RED}Connection failed: {e}{Colors.RESET}")

# ──────────────────────────────────────────────────────────────── #
# Utilities
# ──────────────────────────────────────────────────────────────── #

def load_payloads(file_path: str) -> List[str]:
    """Load payloads from file, handling encoding issues."""
    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Payloads file not found: {file_path}{Colors.RESET}")
        sys.exit(1)

def generate_default_payloads() -> List[str]:
    """Expanded list of SSRF and Injection payloads."""
    return [
        # HTTP Methods
        "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "POST /api/admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        
        # Path Traversal / LFI
        "../../../../etc/passwd",
        "file:///etc/passwd",
        
        # Command Injection candidates
        "; id",
        "$(id)",
        "`id`",
        "| id",
        
        # JSON specific (if target parses JSON)
        '{"action": "admin", "cmd": "whoami"}',
        '{"debug": true}',
        
        # Common Endpoints
        "GET /api/v1/users HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "GET /server-status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    ]

def save_report(results, filename):
    """Save results to JSON or CSV."""
    if not results:
        return

    print(f"\n{Colors.BLUE}[INFO] Saving report to {filename}...{Colors.RESET}")
    
    try:
        if filename.endswith('.json'):
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
        elif filename.endswith('.csv'):
            keys = results[0].keys()
            with open(filename, 'w', newline='') as f:
                dict_writer = csv.DictWriter(f, keys)
                dict_writer.writeheader()
                dict_writer.writerows(results)
        print(f"{Colors.GREEN}[SUCCESS] Report saved.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to save report: {e}{Colors.RESET}")

# ──────────────────────────────────────────────────────────────── #
# Main
# ──────────────────────────────────────────────────────────────── #

if __name__ == "__main__":
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Advanced WebSocket Fuzzer")
    
    # Target Group
    target_group = parser.add_argument_group('Target')
    target_group.add_argument("-t", "--target", help="Target URL (e.g., ws://127.0.0.1:8080)", required=True)
    target_group.add_argument("-H", "--headers", action='append', help="Custom header 'Key: Value' (can be used multiple times)")
    target_group.add_argument("-k", "--insecure", action='store_true', help="Ignore SSL certificate errors")

    # Payloads Group
    payload_group = parser.add_argument_group('Payloads')
    payload_group.add_argument("-p", "--payloads", help="Path to payloads file")
    payload_group.add_argument("-d", "--default", action='store_true', help="Use built-in default payloads")
    payload_group.add_argument("--json-key", help="Wrap payload in a JSON object with this key (e.g., --json-key 'command' becomes {'command': 'payload'})")

    # Tuning Group
    tune_group = parser.add_argument_group('Performance & Control')
    tune_group.add_argument("-c", "--concurrency", type=int, default=1, help="Number of concurrent requests (default: 1)")
    tune_group.add_argument("--timeout", type=float, default=3.0, help="Response timeout in seconds (default: 3.0)")
    tune_group.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds")
    tune_group.add_argument("-i", "--interactive", action='store_true', help="Enter interactive shell mode after scanning")

    # Analysis & Output
    out_group = parser.add_argument_group('Analysis & Output')
    out_group.add_argument("-m", "--match", help="Regex pattern to highlight in response (e.g., 'root|admin|200 OK')")
    out_group.add_argument("-f", "--filter", help="Regex pattern to hide response (e.g., 'Error|Invalid')")
    out_group.add_argument("-o", "--output", help="Save results to file (.json or .csv)")
    out_group.add_argument("-v", "--verbose", action='store_true', help="Show full request/response details")

    args = parser.parse_args()

    # Load Payloads
    payload_list = []
    if args.default:
        payload_list = generate_default_payloads()
    elif args.payloads:
        payload_list = load_payloads(args.payloads)
    elif not args.interactive:
        print(f"{Colors.RED}[!] No payloads provided. Use -d, -p, or -i for interactive mode.{Colors.RESET}")
        exit(1)

    # Initialize Fuzzer
    fuzzer = WebSocketFuzzer(args)

    # Run Fuzzing
    if payload_list:
        try:
            asyncio.run(fuzzer.fuzz(payload_list))
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Fuzzing interrupted by user.{Colors.RESET}")

    # Save Report
    if args.output:
        save_report(fuzzer.results, args.output)

    # Run Interactive Mode
    if args.interactive:
        headers_dict = fuzzer._parse_headers(args.headers)
        try:
            asyncio.run(interactive_mode(args.target, headers_dict, args.insecure))
        except KeyboardInterrupt:
            print("\nBye!")
