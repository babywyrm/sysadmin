#!/usr/bin/env python3
"""
check_env_secure.py (..revised with Poetry and uv support..)

A robust and secure Python script to check the execution environment, including
support for modern Python tooling like Poetry and uv.

Features:
  - Uses `argparse` for structured, self-documenting argument handling.
  - Configurable logging verbosity (-v, -vv).
  - Validates user-provided arguments for potentially unsafe characters.
  - Conditionally displays sensitive path information.
  - Checks for the presence and context of Poetry and uv environments.
  - Graceful top-level exception handling.

Usage:
  ./check_env_secure.py [OPTIONS] [ARGUMENTS...]
"""

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# For Python < 3.11, tomli is needed to parse pyproject.toml
try:
    import tomllib
except ImportError:
    import tomli as tomllib

# --- Constants ---
MAX_USER_ARGS = 10
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
        epilog="Example: ./check_env_secure.py -v --check-poetry --check-uv",
    )
    parser.add_argument(
        "user_args",
        nargs="*",
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
        help="Display potentially sensitive system and module path info.",
    )
    parser.add_argument(
        "--check-poetry",
        action="store_true",
        help="Check for and report on the Poetry environment.",
    )
    parser.add_argument(
        "--check-uv",
        action="store_true",
        help="Check for and report on the uv environment.",
    )
    return parser.parse_args()


def is_tool_installed(name: str) -> bool:
    """Checks if a command-line tool is available in the system's PATH."""
    return shutil.which(name) is not None


def find_project_root(marker: str = "pyproject.toml") -> Path | None:
    """Finds the project root by searching upwards for a marker file."""
    current_dir = Path.cwd().resolve()
    while current_dir != current_dir.parent:
        if (current_dir / marker).exists():
            return current_dir
        current_dir = current_dir.parent
    return None


def print_system_info() -> None:
    """Prints basic, non-sensitive system information."""
    print("\n--- System Information ---")
    logging.info(f"Python version: {sys.version.split()[0]}")
    logging.info(f"Python executable: {sys.executable}")
    logging.info(f"Platform: {sys.platform}")
    # Check for an active virtual environment, which is standard for both tools
    virtual_env = os.getenv("VIRTUAL_ENV")
    if virtual_env:
        logging.info(f"Active virtual environment: {virtual_env}")
    else:
        logging.info("No active virtual environment detected.")


def process_and_validate_arguments(args: list[str]) -> bool:
    """Processes, validates, and reports on user-provided arguments."""
    print("\n--- User Arguments ---")
    logging.info(f"Received {len(args)} user arguments.")
    print(f"Arguments provided: {args}")

    if len(args) > MAX_USER_ARGS:
        logging.error(
            f"Too many arguments. Received {len(args)}, maximum is {MAX_USER_ARGS}."
        )
        return False

    for i, arg in enumerate(args):
        if UNSAFE_CHAR_PATTERN.search(arg):
            logging.warning(
                f"Security check: Argument {i+1} contains potentially unsafe characters."
            )
    return True


def check_poetry_environment() -> None:
    """Checks for and reports on the Poetry environment."""
    print("\n--- Poetry Environment Check ---")
    if not is_tool_installed("poetry"):
        logging.warning("Poetry is not installed or not in PATH.")
        return

    logging.info("Poetry executable found.")
    project_root = find_project_root("pyproject.toml")
    if not project_root:
        logging.info("No pyproject.toml found in current or parent directories.")
        return

    logging.info(f"Found project root at: {project_root}")
    try:
        with open(project_root / "pyproject.toml", "rb") as f:
            pyproject_data = tomllib.load(f)
        
        poetry_config = pyproject_data.get("tool", {}).get("poetry", {})
        project_name = poetry_config.get("name", "N/A")
        project_version = poetry_config.get("version", "N/A")
        dependencies = poetry_config.get("dependencies", {})

        print(f"  Project Name: {project_name}")
        print(f"  Project Version: {project_version}")
        print(f"  Main Dependencies: {list(dependencies.keys())}")

        if (project_root / "poetry.lock").exists():
            logging.info("Found poetry.lock file.")

    except (IOError, tomllib.TOMLDecodeError) as e:
        logging.error(f"Could not read or parse pyproject.toml: {e}")


def check_uv_environment() -> None:
    """Checks for and reports on the uv environment."""
    print("\n--- uv Environment Check ---")
    if not is_tool_installed("uv"):
        logging.warning("uv is not installed or not in PATH.")
        return

    try:
        result = subprocess.run(
            ["uv", "--version"], capture_output=True, text=True, check=True
        )
        uv_version = result.stdout.strip()
        logging.info(f"Found uv version: {uv_version}")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Could not execute 'uv --version': {e}")

    project_root = find_project_root()
    if project_root:
        if (project_root / "uv.lock").exists():
            logging.info("Found uv.lock file in project root.")
        elif (project_root / "requirements.lock").exists():
            logging.info("Found requirements.lock file in project root.")
        else:
            logging.info("No uv.lock or requirements.lock file found.")


def print_sensitive_info() -> None:
    """Prints potentially sensitive module and path information."""
    print("\n--- System Path Details (Sensitive) ---")
    logging.debug("Displaying sensitive system path information as requested.")
    print(f"Module search path (sys.path) contains {len(sys.path)} entries:")
    for path in sys.path:
        print(f"  - {path}")
    print(f"There are currently {len(sys.modules)} modules loaded.")


def main() -> int:
    """Main entry point for the script."""
    args = parse_arguments()
    setup_logging(args.verbose)

    logging.info("Starting environment check...")

    print_system_info()

    if not process_and_validate_arguments(args.user_args):
        return 1  # Exit with an error code

    if args.check_poetry:
        check_poetry_environment()

    if args.check_uv:
        check_uv_environment()

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
        logging.critical(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)
##
##
