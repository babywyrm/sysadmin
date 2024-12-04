import httpx
import logging
import json
import shlex
import readline
import os,sys,re,h2
from time import time

##
##

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class HTTPInteractiveShell:
    def __init__(self):
        self.history_file = ".httpx_shell_history"  # File to store command history
        self.load_history()
        self.client = None
        self.init_shell()

    def load_history(self):
        """Load command history from a file."""
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass  # No history file found, starting fresh

    def save_history(self):
        """Save command history to a file."""
        readline.write_history_file(self.history_file)

    def init_shell(self):
        """Initialize the HTTP client shell."""
        print("\n=== HTTP Interactive Shell ===")
        print("Type 'help' for a list of commands or 'exit' to quit.\n")
        self.run_shell()

    def run_shell(self):
        """Run the shell loop."""
        while True:
            try:
                cmd = input("httpx> ").strip()
                if not cmd:
                    continue

                if cmd.lower() in {"exit", "quit"}:
                    self.save_history()
                    print("Exiting shell. Goodbye!")
                    break
                elif cmd.lower() in {"help", "?"}:
                    self.print_help()
                else:
                    self.parse_and_execute(cmd)
            except KeyboardInterrupt:
                print("\nExiting shell. Goodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")

    def print_help(self):
        """Print available commands."""
        help_text = """
Available commands:
- set url <URL>                  : Set the target URL.
- set method <METHOD>            : Set the HTTP method (e.g., GET, POST).
- set headers <JSON>             : Set custom headers (JSON format).
- set params <JSON>              : Set query parameters (JSON format).
- set data <STRING>              : Set request body data for POST/PUT.
- set protocol <http1|http2|auto>: Set the HTTP protocol (default: auto).
- set timeout <SECONDS>          : Set timeout (default: 10).
- run                            : Execute the HTTP request with current settings.
- show                           : Show current configuration.
- clear                          : Clear all settings.
- help                           : Display this help text.
- exit                           : Exit the shell.
        """
        print(help_text)

    def parse_and_execute(self, cmd):
        """Parse and execute a shell command."""
        args = shlex.split(cmd)
        if args[0] == "set":
            self.handle_set_command(args[1:])
        elif args[0] == "run":
            self.execute_request()
        elif args[0] == "show":
            self.show_config()
        elif args[0] == "clear":
            self.clear_config()
        else:
            print(f"Unknown command: {args[0]}")

    def handle_set_command(self, args):
        """Handle the 'set' command to update configuration."""
        if len(args) < 2:
            print("Invalid 'set' command. Type 'help' for usage.")
            return

        key, value = args[0], " ".join(args[1:])
        try:
            if key == "url":
                self.url = value
            elif key == "method":
                self.method = value.upper()
            elif key == "headers":
                self.headers = json.loads(value)
            elif key == "params":
                self.params = json.loads(value)
            elif key == "data":
                self.data = value
            elif key == "protocol":
                if value.lower() not in {"http1", "http2", "auto"}:
                    raise ValueError("Invalid protocol. Choose 'http1', 'http2', or 'auto'.")
                self.protocol = value.lower()
            elif key == "timeout":
                self.timeout = int(value)
            else:
                print(f"Unknown configuration key: {key}")
        except Exception as e:
            print(f"Error setting value: {e}")

    def execute_request(self):
        """Execute the HTTP request with the current configuration."""
        try:
            protocol = getattr(self, "protocol", "auto")
            transport = None

            if protocol == "http1":
                transport = httpx.HTTPTransport(http1=True, http2=False)
            elif protocol == "http2":
                transport = httpx.HTTPTransport(http1=False, http2=True)
            elif protocol == "auto":
                transport = httpx.HTTPTransport()

            with httpx.Client(transport=transport, timeout=getattr(self, "timeout", 10)) as client:
                logging.info(f"Sending {getattr(self, 'method', 'GET')} request to {self.url}")

                start_time = time()
                response = client.request(
                    method=getattr(self, "method", "GET"),
                    url=self.url,
                    headers=getattr(self, "headers", {}),
                    params=getattr(self, "params", {}),
                    data=getattr(self, "data", None),
                )
                elapsed_time = time() - start_time

                # Print response details
                print("\n--- Response ---")
                print(f"Status Code: {response.status_code}")
                print(f"Protocol Used: {response.http_version}")
                print(f"Headers: {response.headers}")
                print(f"Body:\n{response.text[:1000]}")  # Truncate body for readability
                print(f"Time Taken: {elapsed_time:.2f} seconds")
                print("\n----------------\n")
        except AttributeError as e:
            print("Error: Missing required configuration (e.g., URL). Use 'show' to check settings.")
        except httpx.RequestError as e:
            print(f"Request failed: {e}")

    def show_config(self):
        """Display the current configuration."""
        config = {
            "url": getattr(self, "url", None),
            "method": getattr(self, "method", "GET"),
            "headers": getattr(self, "headers", {}),
            "params": getattr(self, "params", {}),
            "data": getattr(self, "data", None),
            "protocol": getattr(self, "protocol", "auto"),
            "timeout": getattr(self, "timeout", 10),
        }
        print("\n--- Current Configuration ---")
        for key, value in config.items():
            print(f"{key}: {value}")
        print("-----------------------------\n")

    def clear_config(self):
        """Clear all settings."""
        self.url = None
        self.method = "GET"
        self.headers = {}
        self.params = {}
        self.data = None
        self.protocol = "auto"
        self.timeout = 10
        print("All settings cleared.")


if __name__ == "__main__":
    HTTPInteractiveShell()

##
##
