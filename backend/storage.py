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
                CREATE TABLE IF NOT EXISTS pending_registrations (
                    username TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
                    code_hash TEXT NOT NULL, expires REAL NOT NULL, sent_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0
                );
            """)
            if "email" not in {row[1] for row in db.execute("PRAGMA table_info(users)")}:
                db.execute("ALTER TABLE users ADD COLUMN email TEXT")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email)")

    def prepare_registration(self, username, email, password, code_hash, current):
        from .otp import CODE_LIFETIME, RESEND_COOLDOWN

        with self.connection() as db:
            if db.execute("SELECT 1 FROM users WHERE username=? OR email=?", (username, email)).fetchone():
                return "taken"
            pending = db.execute("SELECT username,email,sent_at FROM pending_registrations WHERE username=? OR email=?", (username, email)).fetchone()
            if pending:
                if pending["username"] != username or pending["email"] != email:
                    return "taken"
                if current - pending["sent_at"] < RESEND_COOLDOWN:
                    return "cooldown"
            # Username is the conflict target; an email reserved by another
            # pending signup is rejected above (and by the unique constraint).
            db.execute("INSERT INTO pending_registrations(username,email,password,code_hash,expires,sent_at,attempts) VALUES (?,?,?,?,?,?,0) ON CONFLICT(username) DO UPDATE SET email=excluded.email,password=excluded.password,code_hash=excluded.code_hash,expires=excluded.expires,sent_at=excluded.sent_at,attempts=0",
                       (username, email, password_hash(password), code_hash, current + CODE_LIFETIME, current))
        return "ready"

    def cancel_registration(self, username, code_hash):
        with self.connection() as db:
            db.execute("DELETE FROM pending_registrations WHERE username=? AND code_hash=?", (username, code_hash))

    def complete_registration(self, username, email, code, current):
        from .otp import MAX_ATTEMPTS, matches

        with self.connection() as db:
            pending = db.execute("SELECT * FROM pending_registrations WHERE username=? AND email=?", (username, email)).fetchone()
            if not pending:
                return "invalid", None
            if pending["expires"] <= current or pending["attempts"] >= MAX_ATTEMPTS:
                db.execute("DELETE FROM pending_registrations WHERE username=?", (username,))
                return "expired", None
            if not matches(code, pending["code_hash"]):
                db.execute("UPDATE pending_registrations SET attempts=attempts+1 WHERE username=?", (username,))
                return "invalid", None
            removed = db.execute("DELETE FROM pending_registrations WHERE username=? AND email=? AND code_hash=? AND attempts=? AND expires>?",
                                 (username, email, pending["code_hash"], pending["attempts"], current))
            if removed.rowcount != 1:
                return "invalid", None
            cursor = db.execute("INSERT INTO users(username,email,password,role,settings) VALUES (?,?,?,?,?)",
                                (username, email, pending["password"], "user", json.dumps(DEFAULT_SETTINGS)))
            return "created", cursor.lastrowid

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
