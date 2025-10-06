#!/usr/bin/env python3
"""
salt_pepper_demo.py (..beta..)
===================

Educational command-line tool demonstrating salted and peppered password hashing.

Supports both SHA-256 (simple) and Argon2 (modern) hashing modes.
This tool is for teaching and experimentation only — not for production use.

Example usage:
    python3 salt_pepper_demo.py init
    python3 salt_pepper_demo.py add --user alice --password Secret123 --argon2
    python3 salt_pepper_demo.py verify --user alice --password Secret123
    python3 salt_pepper_demo.py list
"""

import argparse
import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
from dataclasses import dataclass
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# ==========================================================
# Configuration
# ==========================================================

DB_PATH = "demo_users.db"
SECRET_PEPPER = os.getenv("DEMO_PEPPER", "SuperSecretPepperValue")

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


# ==========================================================
# Utilities
# ==========================================================

def generate_salt(length: int = 16) -> str:
    return secrets.token_hex(length)


def apply_pepper(password: str, secret_pepper: str) -> str:
    """
    Combine a hidden server-side pepper with the password.
    Here we reverse the password and append the pepper.
    """
    return password[::-1] + secret_pepper


def hash_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_argon2(value: str) -> str:
    return ph.hash(value)


def verify_argon2(hashed_value: str, plain_value: str) -> bool:
    try:
        ph.verify(hashed_value, plain_value)
        return True
    except VerifyMismatchError:
        return False


# ==========================================================
# Database
# ==========================================================

@dataclass
class User:
    username: str
    password_hash: str
    salt: str
    algorithm: str


def init_db() -> None:
    """Initialize or verify the demo SQLite database."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                algorithm TEXT NOT NULL
            );
        """)
        conn.commit()
    print(f"Database initialized at {DB_PATH}")


def add_user(username: str, password: str, use_argon2: bool = False) -> None:
    """Add a user to the database with salted + peppered hash."""
    salt = generate_salt()
    peppered = apply_pepper(password, SECRET_PEPPER)
    combined = peppered + salt

    if use_argon2:
        password_hash = hash_argon2(combined)
        algorithm = "argon2"
    else:
        password_hash = hash_sha256(combined)
        algorithm = "sha256"

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password_hash, salt, algorithm) VALUES (?, ?, ?, ?);",
            (username, password_hash, salt, algorithm)
        )
        conn.commit()
    print(f"User '{username}' added using {algorithm.upper()} hashing.")


def verify_user(username: str, password: str) -> bool:
    """Verify a password for an existing user."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT password_hash, salt, algorithm FROM users WHERE username = ?;",
            (username,)
        )
        row = cur.fetchone()
        if not row:
            print(f"User '{username}' not found.")
            return False

    stored_hash, stored_salt, algorithm = row
    peppered = apply_pepper(password, SECRET_PEPPER)
    combined = peppered + stored_salt

    if algorithm == "argon2":
        match = verify_argon2(stored_hash, combined)
    else:
        test_hash = hash_sha256(combined)
        match = hmac.compare_digest(test_hash, stored_hash)

    if match:
        print("Password verification succeeded.")
    else:
        print("Password verification failed.")

    return match


def list_users() -> None:
    """List all users and their hashing algorithm."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT username, algorithm FROM users;").fetchall()
        if not rows:
            print("No users found.")
            return
        print(f"{'Username':<20} Algorithm")
        print("-" * 32)
        for username, algorithm in rows:
            print(f"{username:<20} {algorithm}")


# ==========================================================
# CLI Layer
# ==========================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Salt & Pepper educational password hashing demo.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    init_parser = subparsers.add_parser("init", help="Initialize the database.")

    # add
    add_parser = subparsers.add_parser("add", help="Add a new user.")
    add_parser.add_argument("--user", required=True, help="Username.")
    add_parser.add_argument("--password", required=True, help="Plaintext password.")
    add_parser.add_argument(
        "--argon2", action="store_true", help="Use Argon2 instead of SHA-256."
    )

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a user's password.")
    verify_parser.add_argument("--user", required=True, help="Username.")
    verify_parser.add_argument("--password", required=True, help="Password to verify.")

    # list
    list_parser = subparsers.add_parser("list", help="List all users and algorithms.")

    return parser.parse_args()


# ==========================================================
# Main Entrypoint
# ==========================================================

def main() -> None:
    args = parse_args()

    if args.command == "init":
        init_db()

    elif args.command == "add":
        add_user(args.user, args.password, use_argon2=args.argon2)

    elif args.command == "verify":
        verify_user(args.user, args.password)

    elif args.command == "list":
        list_users()

    else:
        print("Unknown command. Use --help for usage details.")
        sys.exit(1)


if __name__ == "__main__":
    main()
