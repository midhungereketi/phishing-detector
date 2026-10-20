"""Cloud boundaries: persistent storage, host validation and deployed extension."""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.postgres import Row, translate


def test_cloud_requires_persistent_database(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="persistent Postgres"):
        create_app()


def test_postgres_rows_and_sql_bindings():
    row = Row(id=7, username="student")
    assert row[0] == row["id"] == 7
    assert dict(row) == {"id": 7, "username": "student"}
    assert translate("SELECT * FROM users WHERE username=?") == "SELECT * FROM users WHERE username=%s"
    assert translate("INSERT OR IGNORE INTO blocklist VALUES (?,?,?)").endswith("ON CONFLICT DO NOTHING")
    assert translate("INSERT OR REPLACE INTO metadata VALUES (?,?)").endswith("ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value")


def test_deployed_host_cookie_and_extension(tmp_path, monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_URL", "preview.example.test")
    monkeypatch.setenv("PHISHGUARD_ALLOWED_HOSTS", "phishguard.example.test")
    monkeypatch.setenv("PHISHGUARD_PUBLIC_ORIGIN", "https://phishguard.example.test")
    codes = {}
    app = create_app(tmp_path / "users.sqlite3", tmp_path / "intelligence.sqlite3", mailer=lambda email, code: codes.__setitem__(email, code))
    with TestClient(app, base_url="https://phishguard.example.test", headers={"X-PhishGuard": "1"}) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/health", headers={"host": "attacker.example.test"}).status_code == 400
        email = "cloudtester@example.test"
        assert client.post("/api/auth/register", json={"username": "cloudtester", "email": email, "password": "DisposableCloud!123"}).status_code == 202
        response = client.post("/api/auth/register/verify", json={"username": "cloudtester", "email": email, "code": codes[email]})
        assert response.status_code == 201
        assert "Secure" in response.headers["set-cookie"]
        assert client.get("/api/auth/me").status_code == 200
        response = client.get("/api/extension/download")
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            manifest = json.loads(archive.read("phishguard-extension/manifest.json"))
            assert manifest["host_permissions"] == ["https://phishguard.example.test/*"]
            background = archive.read("phishguard-extension/background.js").decode()
            assert "https://phishguard.example.test/api" in background
            assert "http://127.0.0.1:8000/api" not in background
