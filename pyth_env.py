#!/usr/bin/env python3
"""
check_env_secure.py (..revised..)

A robust and secure Python script to check the execution environment.

Features:
  - Uses `argparse` for structured, self-documenting argument handling.
  - Configurable logging verbosity (-v, -vv).
  - Validates user-provided arguments for potentially unsafe characters.
  - Conditionally displays sensitive path information.
  - Graceful top-level exception handling.

Usage:
  ./check_env_secure.py [OPTIONS] [ARGUMENTS...]
"""

import os, sys, re
import logging
import argparse

# --- Constants ---
# Use constants for configuration to make them easy to find and change.
MAX_USER_ARGS = 9
# A simple regex to detect common shell metacharacters.
# This is a basic security check to demonstrate input validation.
UNSAFE_CHAR_PATTERN = re.compile(r"[;\"'&|`$()]")

# --- Main Application Logic ---


def setup_logging(verbosity: int) -> None:
    """Configures logging based on the verbosity level."""
    if verbosity >= 2:
        log_level = logging.DEBUG
    elif verbosity == 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    # Log to stderr, which is standard practice for diagnostics.
    logging.basicConfig(
        level=log_level,
        stream=sys.stderr,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.debug("Debug logging enabled.")


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="A robust script to check the Python environment.",
        epilog="Example: ./check_env_secure.py -v --show-system-paths my-arg",
    )
    parser.add_argument(
        "user_args",
        nargs="*",  # 0 or more positional arguments
        help="Optional user-provided arguments to inspect.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity. -v for INFO, -vv for DEBUG.",
    )
    parser.add_argument(
        "--show-system-paths",
        action="store_true",
        help="""Display potentially sensitive system and module path info.
             (Not recommended in production environments).""",
    )
    return parser.parse_args()


def print_system_info() -> None:
    """Prints basic, non-sensitive system information."""
    logging.info(f"Python version: {sys.version.split()[0]}")
    logging.info(f"Platform: {sys.platform}")


def process_and_validate_arguments(args: list[str]) -> bool:
    """Processes, validates, and reports on user-provided arguments."""
    logging.info(f"Received {len(args)} user arguments.")
    print(f"Arguments provided: {args}")

    if len(args) > MAX_USER_ARGS:
        logging.error(
            f"Too many arguments. Received {len(args)}, maximum is {MAX_USER_ARGS}."
        )
        return False

    for i, arg in enumerate(args):
        if UNSAFE_CHAR_PATTERN.search(arg):
            # Log a security warning but don't expose the potentially malicious
            # content in the log, just its position.
            logging.warning(
                f"Security check: Argument {i+1} contains potentially unsafe characters."
            )
    return True


def print_sensitive_info() -> None:
    """Prints potentially sensitive module and path information."""
    logging.debug("Displaying sensitive system path information as requested.")
    print(f"Module search path (sys.path) contains {len(sys.path)} entries.")
    print(f"There are currently {len(sys.modules)} modules loaded.")


def main() -> int:
    """Main entry point for the script."""
    args = parse_arguments()
    setup_logging(args.verbose)

    logging.info("Starting environment check...")

    print_system_info()

    if not process_and_validate_arguments(args.user_args):
        return 1  # Exit with an error code

    if args.show_system_paths:
        print_sensitive_info()
    else:
        logging.info(
            "Sensitive path info hidden. Use --show-system-paths to display."
        )

    logging.info("Environment check finished successfully.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Catch any unexpected errors, log them, and exit gracefully.
        logging.critical(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)
