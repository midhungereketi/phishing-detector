"""Verify the real Postgres-backed API and clean up only this run's test user.

Run after migrate-cloud.py with DATABASE_URL supplied via env or .env.cloud.
No secrets are printed. This uses the real model and a dedicated disposable user.
"""
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.postgres import PostgresStore

load_dotenv(".env.cloud")
if not os.getenv("DATABASE_URL"):
    raise SystemExit("DATABASE_URL is required. No check was run.")
username = "cloud_check_" + secrets.token_hex(6)
password = secrets.token_urlsafe(24)
store = PostgresStore(os.environ["DATABASE_URL"])
headers = {"X-PhishGuard": "1"}
try:
    app = create_app()
    with TestClient(app, headers=headers) as first:
        assert first.get("/api/health").json()["models_ready"]
        assert first.post("/api/auth/register", json={"username": username, "password": password}).status_code == 201
        assert first.post("/api/auth/register", json={"username": username, "password": password}).status_code == 409
        report = first.post("/api/scan/url", json={"url": "https://www.wikipedia.org/"})
        assert report.status_code == 200, report.text
        report_id = report.json()["id"]
        assert first.post("/api/blocklist", json={"host": "blocked.example.test"}).status_code == 200
        assert first.put("/api/settings", json={"high_threshold": 65, "auto_block": False, "show_alerts": True}).status_code == 200
    # Separate application instance and new login: persistence cannot depend on
    # a serverless process's memory or filesystem.
    with TestClient(create_app(), headers=headers) as second:
        assert second.post("/api/auth/login", json={"username": username, "password": password}).status_code == 200
        assert second.get("/api/history").json()[0]["id"] == report_id
        assert second.get("/api/settings").json()["high_threshold"] == 65
        assert second.get("/api/blocklist").json()[0]["host"] == "blocked.example.test"
        assert second.get("/api/intelligence").status_code == 200
        assert second.get("/api/evaluation").json() == []
        assert second.post("/api/extension/pair").status_code == 200
    print("PASS: real Postgres registration, duplicate handling, model scan, history, settings, blocklist, feed status and extension pairing across two app instances.")
finally:
    with store.connection() as db:
        db.execute("DELETE FROM users WHERE username=?", (username,))
        db.execute("DELETE FROM logs WHERE username=?", (username,))
    print("Disposable cloud verification account removed.")
