#!/usr/bin/env python3
"""
salt_pepper_demo.py
===================

A modernized educational demo showing how salts and peppers add randomness
and resilience to password hashing.

For educational and demonstration purposes only — not for production use.

This version integrates both SHA-256 (simple demo) and Argon2 (modern best practice)
to illustrate the conceptual and practical differences.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# ==========================================================
# Configuration
# ==========================================================

DB_PATH = "demo_users.db"
SECRET_PEPPER = os.getenv("DEMO_PEPPER", "SuperSecretPepperValue")


# Argon2 configuration (tuned for demo purposes)
ph = PasswordHasher(
    time_cost=3,      # Number of iterations
    memory_cost=65536,  # 64 MiB memory
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


# ==========================================================
# Salt, Pepper, and Hash Utilities
# ==========================================================

def generate_salt(length: int = 16) -> str:
    """Generate a cryptographically secure salt string (hex encoded)."""
    return secrets.token_hex(length)


def apply_pepper(password: str, secret_pepper: str) -> str:
    """
    Apply a pepper transformation to the password.

    Peppering involves mixing a hidden, server-side secret with the password.
    This should never be stored in the database.
    """
    # Simple educational transformation:
    # Reverse + append hidden pepper
    return password[::-1] + secret_pepper


def hash_sha256(value: str) -> str:
    """Compute a SHA-256 hash of the given string (for demonstration)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_argon2(value: str) -> str:
    """Generate an Argon2 hash."""
    return ph.hash(value)


def verify_argon2(hashed_value: str, plain_value: str) -> bool:
    """Verify Argon2 hash."""
    try:
        ph.verify(hashed_value, plain_value)
        return True
    except VerifyMismatchError:
        return False


# ==========================================================
# Database Setup
# ==========================================================

@dataclass
class User:
    username: str
    password_hash: str
    salt: str
    algorithm: str  # "sha256" or "argon2"


def init_db() -> None:
    """Initialize a SQLite database with a user table."""
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


# ==========================================================
# Database Operations
# ==========================================================

def add_user(username: str, password: str, use_argon2: bool = False) -> None:
    """
    Add a user to the database with salted and peppered hash.

    Args:
        username: User's name.
        password: Plaintext password.
        use_argon2: Whether to use Argon2 or SHA-256 for hashing.
    """
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


def verify_user(username: str, password: str) -> bool:
    """Verify a user's password against the stored salted and peppered hash."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT password_hash, salt, algorithm FROM users WHERE username = ?;",
            (username,)
        )
        row = cur.fetchone()
        if not row:
            return False

    stored_hash, stored_salt, algorithm = row
    peppered = apply_pepper(password, SECRET_PEPPER)
    combined = peppered + stored_salt

    if algorithm == "argon2":
        return verify_argon2(stored_hash, combined)

    test_hash = hash_sha256(combined)
    return hmac.compare_digest(test_hash, stored_hash)


# ==========================================================
# Demonstration Runner
# ==========================================================

def demo() -> None:
    """Demonstrate adding and verifying users with and without Argon2."""
    init_db()

    print("Initializing demo database and adding sample users...")

    add_user("andrew", "Password123", use_argon2=False)
    add_user("maria", "Password123", use_argon2=True)

    print("\nStored users:")
    with sqlite3.connect(DB_PATH) as conn:
        for row in conn.execute("SELECT username, algorithm FROM users;"):
            print(f"  {row[0]} (algorithm={row[1]})")

    print("\nVerification tests:")
    for user in ("andrew", "maria"):
        correct = verify_user(user, "Password123")
        wrong = verify_user(user, "WrongPass")
        print(f"  {user} -> correct={correct}, wrong={wrong}")


if __name__ == "__main__":
    demo()
