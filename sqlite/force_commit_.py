import sqlite3
from contextlib import contextmanager

DB_PATH = "mydb.sqlite"

@contextmanager
def get_conn(db_path=DB_PATH):
    """Context manager to auto-commit and close properly."""
    conn = sqlite3.connect(db_path, isolation_level=None)  # autocommit mode
    conn.execute("PRAGMA journal_mode=WAL;")               # ensure WAL is on
    conn.execute("PRAGMA synchronous=NORMAL;")             # safe + fast
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")

def insert_user(name, email):
    with get_conn() as conn:
        conn.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))

def fetch_users():
    with get_conn() as conn:
        return conn.execute("SELECT id, name, email, created_at FROM users").fetchall()

def checkpoint():
    """Force WAL checkpoint (flush WAL into main db)."""
    with get_conn() as conn:
        conn.execute("PRAGMA wal_checkpoint(FULL);")
