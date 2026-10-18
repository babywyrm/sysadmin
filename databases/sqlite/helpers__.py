"""
robust_sqlite.py

Robust SQLite helper:
 - connection pool (thread-safe)
 - WAL + PRAGMA tuning
 - transaction context manager with automatic retries
 - bulk insert helper
 - background WAL checkpointing
 - safe online backup
"""

import sqlite3
import threading
import queue
import time
import random
from contextlib import contextmanager
from typing import Iterable, Sequence, Tuple, Optional, Any


class SQLiteLockedError(Exception):
    pass


def _is_locked_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "database is locked" in msg or "database is busy" in msg


class RobustSQLite:
    def __init__(
        self,
        db_path: str,
        pool_size: int = 4,
        connect_timeout: float = 5.0,
        busy_timeout_ms: int = 5000,
        journal_mode: str = "WAL",
        synchronous: str = "NORMAL",
        foreign_keys: bool = True,
    ):
        """
        db_path: path to sqlite DB file
        pool_size: number of connections kept in the pool (per-process)
        connect_timeout: sqlite3.connect timeout (seconds)
        busy_timeout_ms: PRAGMA busy_timeout (ms)
        journal_mode: 'WAL' recommended for concurrency
        synchronous: 'FULL' or 'NORMAL' (FULL safer)
        """
        self.db_path = db_path
        self.pool_size = max(1, pool_size)
        self.connect_timeout = connect_timeout
        self.busy_timeout_ms = busy_timeout_ms
        self.journal_mode = journal_mode
        self.synchronous = synchronous
        self.foreign_keys = foreign_keys

        self._pool = queue.Queue(maxsize=self.pool_size)
        self._conns = []  # keep references for closing
        self._pool_lock = threading.Lock()
        self._closed = False

        # create initial connections
        for _ in range(self.pool_size):
            conn = self._make_connection()
            self._pool.put(conn)
            self._conns.append(conn)

        # checkpointer thread handle
        self._checkpointer_thread: Optional[threading.Thread] = None
        self._checkpointer_stop = threading.Event()

    def _make_connection(self) -> sqlite3.Connection:
        # check_same_thread=False so connections can be used across threads that borrow them
        conn = sqlite3.connect(
            self.db_path,
            timeout=self.connect_timeout,
            check_same_thread=False,
            isolation_level=None,  # we manage transactions explicitly
        )
        # convenience: return rows as dict-like objects
        conn.row_factory = sqlite3.Row

        # apply pragmas
        cur = conn.cursor()
        # busy timeout helps reduce 'database is locked' exceptions
        cur.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)};")
        if self.journal_mode:
            # journal_mode returns the new mode; read it to apply
            cur.execute(f"PRAGMA journal_mode = {self.journal_mode};")
            _ = cur.fetchone()
        if self.synchronous:
            cur.execute(f"PRAGMA synchronous = {self.synchronous};")
        if self.foreign_keys:
            cur.execute("PRAGMA foreign_keys = ON;")
        cur.close()
        return conn

    @contextmanager
    def _borrow_conn(self):
        if self._closed:
            raise RuntimeError("SQLite helper is closed")
        conn = self._pool.get()
        try:
            yield conn
        finally:
            # return connection to pool
            self._pool.put(conn)

    @contextmanager
    def transaction(
        self,
        retry_attempts: int = 5,
        base_backoff: float = 0.05,
        max_backoff: float = 1.0,
        immediate: bool = True,
    ):
        """
        Transaction context manager.

        Usage:
            with db.transaction() as cur:
                cur.execute(...)
                cur.execute(...)

        It yields a cursor bound to a connection and commits automatically on exit.
        Retries on 'database is locked' errors with exponential backoff.
        immediate: if True uses BEGIN IMMEDIATE to reserve a write lock early (useful if you intend to write)
        """
        attempts = 0
        while True:
            attempts += 1
            with self._borrow_conn() as conn:
                cur = conn.cursor()
                try:
                    if immediate:
                        cur.execute("BEGIN IMMEDIATE;")
                    else:
                        cur.execute("BEGIN;")
                    yield cur
                    conn.commit()
                    cur.close()
                    return
                except sqlite3.OperationalError as exc:
                    conn.rollback()
                    cur.close()
                    if _is_locked_error(exc) and attempts <= retry_attempts:
                        backoff = min(max_backoff, base_backoff * (2 ** (attempts - 1)))
                        # jitter a bit
                        backoff = backoff * (0.75 + random.random() * 0.5)
                        time.sleep(backoff)
                        continue
                    # turn into a clearer error
                    raise SQLiteLockedError(str(exc)) from exc
                except Exception:
                    conn.rollback()
                    cur.close()
                    raise

    def execute(
        self,
        sql: str,
        params: Optional[Sequence[Any]] = None,
        retry_attempts: int = 5,
    ):
        """Simple execute wrapper (auto transaction)."""
        with self.transaction(retry_attempts=retry_attempts) as cur:
            if params:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
            # return lastrowid / rowcount etc as needed
            return cur

    def fetchall(self, sql: str, params: Optional[Sequence[Any]] = None):
        with self._borrow_conn() as conn:
            cur = conn.cursor()
            try:
                if params:
                    cur.execute(sql, params)
                else:
                    cur.execute(sql)
                rows = cur.fetchall()
                cur.close()
                return rows
            except Exception:
                cur.close()
                raise

    def bulk_insert(
        self,
        table: str,
        columns: Sequence[str],
        rows: Iterable[Sequence[Any]],
        batch_size: int = 1000,
        retry_attempts: int = 5,
    ):
        """
        Efficient, batched bulk insert.

        table: table name
        columns: sequence of column names
        rows: iterable of row tuples
        """
        cols = ", ".join(f'"{c}"' for c in columns)
        placeholders = ", ".join("?" for _ in columns)
        sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders});"

        batch = []
        count = 0
        for r in rows:
            batch.append(tuple(r))
            if len(batch) >= batch_size:
                with self.transaction(retry_attempts=retry_attempts) as cur:
                    cur.executemany(sql, batch)
                count += len(batch)
                batch.clear()

        if batch:
            with self.transaction(retry_attempts=retry_attempts) as cur:
                cur.executemany(sql, batch)
            count += len(batch)
        return count

    def start_checkpointer(self, interval_seconds: int = 60):
        """
        Start background thread to checkpoint WAL periodically.
        interval_seconds: how often to attempt a checkpoint
        """
        if self._checkpointer_thread and self._checkpointer_thread.is_alive():
            return  # already running
        self._checkpointer_stop.clear()

        def _checkpoint_loop():
            while not self._checkpointer_stop.is_set():
                try:
                    with self._borrow_conn() as conn:
                        cur = conn.cursor()
                        # FULL ensures WAL flushed to main; PASSIVE less aggressive
                        cur.execute("PRAGMA wal_checkpoint(FULL);")
                        _ = cur.fetchone()
                        cur.close()
                except Exception:
                    # do not crash thread on a transient error
                    pass
                # sleep interruptibly
                self._checkpointer_stop.wait(interval_seconds)

        t = threading.Thread(target=_checkpoint_loop, daemon=True, name="sqlite-checkpointer")
        self._checkpointer_thread = t
        t.start()

    def stop_checkpointer(self):
        if self._checkpointer_thread:
            self._checkpointer_stop.set()
            self._checkpointer_thread.join(timeout=5)
            self._checkpointer_thread = None

    def backup(self, dest_path: str, pages: int = 0, sleep: float = 0.1):
        """
        Perform a safe online backup to dest_path using the SQLite backup API.
        pages=0 => copy all in a single call (fast but may lock); use small pages for long-running DB
        """
        # borrow a connection; create a new connection to dest_path and run backup
        with self._borrow_conn() as src_conn:
            dest_conn = sqlite3.connect(dest_path, timeout=self.connect_timeout, check_same_thread=False)
            try:
                src_conn.backup(dest_conn, pages=pages, sleep=sleep)
            finally:
                dest_conn.close()

    def integrity_check(self) -> Tuple[bool, str]:
        """Run PRAGMA integrity_check; returns (ok, message)."""
        with self._borrow_conn() as conn:
            cur = conn.cursor()
            cur.execute("PRAGMA integrity_check(1);")
            rows = cur.fetchall()
            cur.close()
            if len(rows) == 1 and rows[0][0] == "ok":
                return True, "ok"
            return False, "; ".join(str(r[0]) for r in rows)

    def vacuum(self):
        """Run VACUUM safely (this will obtain exclusive lock briefly)."""
        with self.transaction(immediate=True) as cur:
            cur.execute("VACUUM;")

    def close(self):
        """Gracefully stop background threads and close connections."""
        self.stop_checkpointer()
        self._closed = True
        # empty the pool so connections are not returned again
        while not self._pool.empty():
            conn = self._pool.get_nowait()
            try:
                conn.close()
            except Exception:
                pass
        # close any others
        for c in self._conns:
            try:
                c.close()
            except Exception:
                pass
        self._conns.clear()

    # small helper for convenience
    def ensure_tables(self, ddl_statements: Iterable[str]):
        """Accepts an iterable of CREATE TABLE IF NOT EXISTS ... statements and runs them."""
        for ddl in ddl_statements:
            with self.transaction() as cur:
                cur.execute(ddl)

##
##
