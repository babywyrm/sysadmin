#!/usr/bin/env python3
"""
check_python_env_and_more.py

A modern Python script to check the environment:
  - Python version and platform.
  - Command-line arguments.
  - Module search path and loaded modules.

Usage:
  ./check_python_env_and_more.py [optional arguments...]
  
Exits with an error if more than 9 arguments are provided (script name + >9 additional).
"""

import sys
import logging
from sys import argv

def main() -> int:
    # Configure logging to output to stderr.
    logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")

    # Print Python version and platform.
    print(f"Python version installed: {sys.version}")
    print(f"Python running on platform: {sys.platform}")

    # Check number of arguments. Exits if more than 10 items in argv (script + >9 arguments).
    if len(argv) > 10:
        logging.error("error: too many arguments")
        return 1

    # Print out the arguments and their count.
    print(f"argv = {argv}")
    print(f"len(argv) = {len(argv)}")

    # Demonstrate printing to stdout and stderr.
    print("Printing to stdout")
    logging.error("Printing to stderr")

    # Print module search path and loaded modules information.
    print(f"Total modules search path: {len(sys.path)}")
    print(f"Total modules loaded: {len(sys.modules)}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
