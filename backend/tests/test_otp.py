import sqlite3
import time
from unittest.mock import MagicMock, Mock

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.otp import send_code
from backend.storage import Store


HEADERS = {"X-PhishGuard": "1"}
ACCOUNT = {"username": "newstudent", "email": "newstudent@example.test", "password": "StrongPassword!123"}


def test_registration_requires_delivered_code_and_cannot_replay(tmp_path):
    codes = []
    database = tmp_path / "users.sqlite3"
    with TestClient(create_app(database, mailer=lambda email, code: codes.append((email, code))), headers=HEADERS) as client:
        assert client.post("/api/auth/register", json=ACCOUNT).status_code == 202
        assert codes[0][0] == ACCOUNT["email"]
        assert client.get("/api/auth/me").status_code == 401
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
            pending = db.execute("SELECT password,code_hash FROM pending_registrations").fetchone()
            assert ACCOUNT["password"] not in pending and codes[0][1] not in pending
        request = {"username": ACCOUNT["username"], "email": ACCOUNT["email"], "code": "000000" if codes[0][1] != "000000" else "111111"}
        assert client.post("/api/auth/register/verify", json=request).status_code == 400
        request["code"] = codes[0][1]
        verified = client.post("/api/auth/register/verify", json=request)
        assert verified.status_code == 201
        assert client.get("/api/auth/me").json()["username"] == ACCOUNT["username"]
        assert client.post("/api/auth/register/verify", json=request).status_code == 400
        assert client.post("/api/auth/register", json={**ACCOUNT, "username": "different"}).status_code == 409


def test_cooldown_expiry_and_attempt_limit(tmp_path):
    codes = []
    database = tmp_path / "users.sqlite3"
    with TestClient(create_app(database, mailer=lambda email, code: codes.append(code)), headers=HEADERS) as client:
        assert client.post("/api/auth/register", json=ACCOUNT).status_code == 202
        assert client.post("/api/auth/register", json=ACCOUNT).status_code == 429
        wrong = "000000" if codes[0] != "000000" else "111111"
        body = {"username": ACCOUNT["username"], "email": ACCOUNT["email"], "code": wrong}
        for _ in range(5):
            assert client.post("/api/auth/register/verify", json=body).status_code == 400
        body["code"] = codes[0]
        assert client.post("/api/auth/register/verify", json=body).status_code == 400
        with sqlite3.connect(database) as db:
            db.execute("UPDATE pending_registrations SET sent_at=? WHERE username=?", (time.time() - 61, ACCOUNT["username"]))
        assert client.post("/api/auth/register", json=ACCOUNT).status_code == 202
        assert len(codes) == 2
        if codes[1] != codes[0]:
            body["code"] = codes[0]
            assert client.post("/api/auth/register/verify", json=body).status_code == 400
        with sqlite3.connect(database) as db:
            db.execute("UPDATE pending_registrations SET expires=? WHERE username=?", (time.time() - 1, ACCOUNT["username"]))
        body["code"] = codes[1]
        assert client.post("/api/auth/register/verify", json=body).status_code == 400
        assert client.get("/api/auth/me").status_code == 401


def test_delivery_failure_leaves_no_pending_account(tmp_path):
    database = tmp_path / "users.sqlite3"
    def fail(_email, _code):
        raise RuntimeError("provider unavailable")

    with TestClient(create_app(database, mailer=fail), headers=HEADERS) as client:
        assert client.post("/api/auth/register", json=ACCOUNT).status_code == 503
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT COUNT(*) FROM pending_registrations").fetchone()[0] == 0
            assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_existing_username_password_accounts_survive_schema_upgrade(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', settings TEXT NOT NULL)")
    store = Store(database)
    store.initialize()
    store.create_user("legacy", "LegacyPassword!123")
    with TestClient(create_app(database), headers=HEADERS) as client:
        assert client.post("/api/auth/login", json={"username": "legacy", "password": "LegacyPassword!123"}).status_code == 200


def test_resend_and_smtp_delivery_keep_code_server_side(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_EMAIL_FROM", "PhishGuard <verify@example.com>")
    monkeypatch.setenv("RESEND_API_KEY", "test-server-key")
    post = Mock(return_value=Mock())
    monkeypatch.setattr("backend.otp.httpx.post", post)
    send_code("student@example.com", "123456")
    assert post.call_args.args[0] == "https://api.resend.com/emails"
    assert post.call_args.kwargs["json"]["to"] == ["student@example.com"]
    assert "123456" in post.call_args.kwargs["json"]["text"]

    monkeypatch.delenv("RESEND_API_KEY")
    monkeypatch.setenv("PHISHGUARD_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("PHISHGUARD_SMTP_USERNAME", "verify@example.com")
    monkeypatch.setenv("PHISHGUARD_SMTP_PASSWORD", "app-password")
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    factory = Mock(return_value=smtp)
    monkeypatch.setattr("backend.otp.smtplib.SMTP", factory)
    send_code("student@example.com", "654321")
    factory.assert_called_once_with("smtp.example.com", 587, timeout=10)
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("verify@example.com", "app-password")
    assert "654321" in smtp.send_message.call_args.args[0].get_content()
