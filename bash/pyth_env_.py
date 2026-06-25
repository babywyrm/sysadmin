#!/usr/bin/env python3
"""
check_env_secure.py

Secure, deterministic environment inspection tool with Poetry and uv support, ..beta

Design goals:
- No implicit trust in user input
- No command execution beyond version checks
- Explicit disclosure of sensitive data
- CI-safe exit codes
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib

# ---------------------------------------------------------------------------
# Constants & Policy
# ---------------------------------------------------------------------------

MAX_USER_ARGS = 10

# Allowlist-based validation (safer than denylist)
SAFE_ARG_PATTERN = re.compile(r"^[a-zA-Z0-9._\-:/]+$")

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_RUNTIME_ERROR = 1


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolStatus:
    name: str
    installed: bool
    version: Optional[str] = None
    lockfile_present: bool = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(verbosity: int) -> None:
    level = (
        logging.DEBUG if verbosity >= 2
        else logging.INFO if verbosity == 1
        else logging.WARNING
    )

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Secure Python environment inspection utility",
        epilog="Example: check_env_secure.py -v --check-poetry --check-uv",
    )

    parser.add_argument("user_args", nargs="*", help="User-provided arguments to inspect")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--show-system-paths", action="store_true")
    parser.add_argument("--check-poetry", action="store_true")
    parser.add_argument("--check-uv", action="store_true")

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_run(cmd: list[str]) -> Optional[str]:
    """Run a safe, fixed command and return stdout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        logging.debug(f"Command failed: {cmd} ({exc})")
        return None


def find_project_root(marker: str = "pyproject.toml") -> Optional[Path]:
    current = Path.cwd().resolve()
    while current != current.parent:
        if (current / marker).exists():
            return current
        current = current.parent
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_user_args(args: Iterable[str]) -> None:
    args = list(args)

    if len(args) > MAX_USER_ARGS:
        raise ValueError(f"Too many arguments (max {MAX_USER_ARGS})")

    for arg in args:
        if not SAFE_ARG_PATTERN.match(arg):
            raise ValueError(f"Unsafe characters detected in argument: {arg!r}")


# ---------------------------------------------------------------------------
# Environment Inspection
# ---------------------------------------------------------------------------

def inspect_system() -> None:
    print("\n--- System Information ---")
    print(f"Python version: {sys.version.split()[0]}")
    print(f"Python executable: {sys.executable}")
    print(f"Platform: {sys.platform}")

    venv = os.getenv("VIRTUAL_ENV")
    print(f"Virtual environment: {venv if venv else 'None'}")


def inspect_poetry() -> ToolStatus:
    if not tool_exists("poetry"):
        return ToolStatus("poetry", installed=False)

    version = safe_run(["poetry", "--version"])
    root = find_project_root("pyproject.toml")

    lock_present = bool(root and (root / "poetry.lock").exists())
    return ToolStatus("poetry", True, version, lock_present)


def inspect_uv() -> ToolStatus:
    if not tool_exists("uv"):
        return ToolStatus("uv", installed=False)

    version = safe_run(["uv", "--version"])
    root = find_project_root()

    lock_present = bool(
        root and (
            (root / "uv.lock").exists()
            or (root / "requirements.lock").exists()
        )
    )

    return ToolStatus("uv", True, version, lock_present)


def inspect_pyproject() -> None:
    root = find_project_root("pyproject.toml")
    if not root:
        logging.info("No pyproject.toml found")
        return

    try:
        with open(root / "pyproject.toml", "rb") as f:
            data = tomllib.load(f)

        poetry = data.get("tool", {}).get("poetry", {})
        print("\n--- pyproject.toml ---")
        print(f"Project: {poetry.get('name', 'N/A')}")
        print(f"Version: {poetry.get('version', 'N/A')}")

    except Exception as exc:
        logging.warning(f"Failed to parse pyproject.toml: {exc}")


def show_sensitive_paths() -> None:
    print("\n--- Sensitive System Paths ---")
    for path in sys.path:
        print(f"  {path}")
    print(f"Loaded modules: {len(sys.modules)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_arguments()
    setup_logging(args.verbose)

    logging.info("Starting environment inspection")

    try:
        validate_user_args(args.user_args)
    except ValueError as exc:
        logging.error(exc)
        return EXIT_INVALID_INPUT

    inspect_system()

    if args.check_poetry:
        poetry = inspect_poetry()
        print(f"\nPoetry installed: {poetry.installed}")
        if poetry.version:
            print(f"Poetry version: {poetry.version}")
        print(f"poetry.lock present: {poetry.lockfile_present}")
        inspect_pyproject()

    if args.check_uv:
        uv = inspect_uv()
        print(f"\nuv installed: {uv.installed}")
        if uv.version:
            print(f"uv version: {uv.version}")
        print(f"Lockfile present: {uv.lockfile_present}")

    if args.show_system_paths:
        show_sensitive_paths()
    else:
        logging.info("Sensitive paths hidden (use --show-system-paths)")

    logging.info("Inspection completed successfully")
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        logging.critical("Unhandled exception", exc_info=exc)
        sys.exit(EXIT_RUNTIME_ERROR)
      
##
##
