"""Postgres storage for Vercel; local development continues to use SQLite.

The adapter covers the application's fixed SQL statements only. Parameters are
always passed separately to psycopg; user input never becomes SQL text.
"""
import re
import sqlite3
from contextlib import contextmanager

from .storage import Store
from .intelligence import Intelligence


class Row(dict):
    """Preserve sqlite3.Row's named and positional access at API boundaries."""

    def __getitem__(self, key):
        return tuple(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


def row_factory(cursor):
    names = [column.name for column in cursor.description] if cursor.description else []
    return lambda values: Row(zip(names, values))


def translate(statement):
    statement = statement.replace("?", "%s").strip().rstrip(";")
    if statement.startswith("INSERT OR IGNORE INTO"):
        statement = statement.replace("INSERT OR IGNORE INTO", "INSERT INTO", 1) + " ON CONFLICT DO NOTHING"
    elif statement.startswith("INSERT OR REPLACE INTO metadata"):
        statement = statement.replace("INSERT OR REPLACE INTO", "INSERT INTO", 1) + " ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value"
    return statement


class Connection:
    def __init__(self, db):
        self.db = db

    def execute(self, statement, parameters=()):
        import psycopg
        statement = translate(statement)
        returns_id = bool(re.match(r"INSERT INTO (users|scans)\(", statement))
        if returns_id:
            statement += " RETURNING id"
        try:
            cursor = self.db.execute(statement, parameters)
        except psycopg.errors.UniqueViolation as error:
            # The registration handler already handles duplicate usernames.
            raise sqlite3.IntegrityError("Duplicate entry") from error
        if returns_id:
            return InsertResult(cursor.fetchone()[0])
        return cursor

    def executemany(self, statement, rows):
        with self.db.cursor() as cursor:
            cursor.executemany(translate(statement), rows)

    def executescript(self, statements):
        for statement in statements.split(";"):
            if statement.strip():
                self.db.execute(statement)


class InsertResult:
    def __init__(self, lastrowid):
        self.lastrowid = lastrowid


@contextmanager
def connect(dsn):
    import psycopg
    # A short-lived connection works with Neon's transaction pooler and avoids
    # leaving a separate pool alive in every serverless function instance.
    with psycopg.connect(dsn, row_factory=row_factory, connect_timeout=10,
                         prepare_threshold=None) as db:
        db.execute("SET LOCAL statement_timeout = '20s'")
        yield Connection(db)


class PostgresStore(Store):
    def __init__(self, dsn):
        self.dsn = dsn

    def connection(self):
        return connect(self.dsn)

    def initialize(self):
        with self.connection() as db:
            db.execute("SELECT pg_advisory_xact_lock(194205718)")
            db.executescript(SCHEMA)

    def allow_attempt(self, key, current, limit):
        with self.connection() as db:
            # Serialize each category/client window across function instances.
            db.execute("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", (key,))
            db.execute("DELETE FROM rate_limits WHERE bucket=? AND created_at<?", (key, current - 60))
            count = db.execute("SELECT COUNT(*) FROM rate_limits WHERE bucket=?", (key,)).fetchone()[0]
            if count >= limit:
                return False
            db.execute("INSERT INTO rate_limits(bucket,created_at) VALUES (?,?)", (key, current))
            # Bound old windows from inactive clients as well.
            db.execute("DELETE FROM rate_limits WHERE created_at<?", (current - 120,))
            return True


class PostgresIntelligence(Intelligence):
    def __init__(self, dsn):
        import threading
        self.dsn = dsn
        self.lock = threading.Lock()
        self.cache = {}
        self.last_vt = self.last_refresh = 0
        # Feed and metadata tables are created by the deployment migration.

    def connection(self):
        return connect(self.dsn)

    def status(self):
        with self.connection() as db:
            # dict(cursor) expects pairs; psycopg returns mapping-compatible rows.
            metadata = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM metadata")}
            count = int(metadata.get("entries", "0"))
        import os
        import time
        from datetime import datetime, timezone
        updated = float(metadata.get("updated", 0))
        return {"source": metadata.get("source", "PhishTank"), "entries": count,
                "updated_at": datetime.fromtimestamp(updated, timezone.utc).isoformat() if updated else None,
                "status": "fresh" if updated and time.time() - updated < 86400 else "stale" if updated else "not_loaded",
                "virustotal_configured": bool(os.getenv("VIRUSTOTAL_API_KEY")), "last_refresh_error": metadata.get("error") or None}

    def import_feed(self, rows, source="PhishTank", updated=None):
        result = super().import_feed(rows, source, updated)
        with self.connection() as db:
            count = db.execute("SELECT COUNT(*) FROM feed").fetchone()[0]
            db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", ("entries", str(count)))
        return {**result, "entries": count}


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    username TEXT UNIQUE NOT NULL, email TEXT, password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', settings TEXT NOT NULL
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);
CREATE TABLE IF NOT EXISTS pending_registrations (
    username TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    code_hash TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL,
    sent_at DOUBLE PRECISION NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    expires DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, created_at TEXT NOT NULL, report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocklist (
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, host TEXT NOT NULL,
    created_at TEXT NOT NULL, PRIMARY KEY(user_id,host)
);
CREATE TABLE IF NOT EXISTS logs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS extension_tokens (
    token TEXT PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    expires DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS evaluations (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feed (hash TEXT PRIMARY KEY, host TEXT, phish_id TEXT);
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS rate_limits (bucket TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS scans_owner_recent ON scans(user_id,id DESC);
CREATE INDEX IF NOT EXISTS evaluations_owner_recent ON evaluations(user_id,id DESC);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);
CREATE INDEX IF NOT EXISTS rate_limits_bucket_time ON rate_limits(bucket,created_at);
"""
