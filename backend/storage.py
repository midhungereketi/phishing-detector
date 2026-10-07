import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DEFAULT_SETTINGS = {"high_threshold": 70, "auto_block": False, "show_alerts": True}


def now():
    return datetime.now(timezone.utc).isoformat()


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 300000).hex()
    return salt + ":" + digest


def password_matches(password, stored):
    salt, digest = stored.split(":")
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 300000).hex()
    return hmac.compare_digest(actual, digest)


class Store:
    def __init__(self, path):
        self.path = str(path)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def initialize(self):
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', settings TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL, created_at TEXT NOT NULL, report TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS blocklist (
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, host TEXT NOT NULL,
                    created_at TEXT NOT NULL, PRIMARY KEY(user_id, host)
                );
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS extension_tokens (
                    token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evaluations (
                    id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL, report TEXT NOT NULL
                );
            """)

    def create_user(self, username, password, role="user"):
        with self.connection() as db:
            cursor = db.execute("INSERT INTO users(username,password,role,settings) VALUES (?,?,?,?)", (username, password_hash(password), role, json.dumps(DEFAULT_SETTINGS)))
            return cursor.lastrowid

    def log(self, username, action):
        with self.connection() as db:
            db.execute("INSERT INTO logs(username,action,created_at) VALUES (?,?,?)", (username, action, now()))

    def settings(self, user_id):
        with self.connection() as db:
            return json.loads(db.execute("SELECT settings FROM users WHERE id=?", (user_id,)).fetchone()[0])

    def blocked(self, user_id):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT host,created_at FROM blocklist WHERE user_id=? ORDER BY created_at DESC", (user_id,))]

    def block(self, user_id, host):
        with self.connection() as db:
            db.execute("INSERT OR IGNORE INTO blocklist(user_id,host,created_at) VALUES (?,?,?)", (user_id, host, now()))

    def save_report(self, user_id, report):
        report["created_at"] = now()
        with self.connection() as db:
            cursor = db.execute("INSERT INTO scans(user_id,kind,created_at,report) VALUES (?,?,?,?)", (user_id, report["kind"], report["created_at"], json.dumps(report)))
            report["id"] = cursor.lastrowid
            db.execute("UPDATE scans SET report=? WHERE id=?", (json.dumps(report), report["id"]))
        return report

    def history(self, user_id):
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT report FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 200", (user_id,))]
