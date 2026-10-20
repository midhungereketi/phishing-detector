"""Exercise the public deployment with disposable data and no database secrets.

Usage: python scripts/verify-deployment.py https://your-production-domain
Only generated test credentials and reserved example email/host data are sent.
The test leaves one random-password test account, clears its history/blocklist,
and revokes its sessions. It never modifies another user's data.
"""
import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx

origin = sys.argv[1].rstrip("/")
if urlsplit(origin).scheme != "https":
    raise SystemExit("Use the canonical HTTPS deployment origin.")
username = "deploy_test_" + secrets.token_hex(5)
password = secrets.token_urlsafe(24)
credentials = {"username": username, "password": password}
passed = []
headers = {"X-PhishGuard": "1"}


def check(response, code=200):
    assert response.status_code == code, f"{response.request.method} {response.request.url.path}: HTTP {response.status_code}: {response.text[:300]}"
    return response.json()


with httpx.Client(base_url=origin, headers=headers, timeout=90) as client:
    assert check(client.get("/api/health"))["models_ready"]
    passed.append("Hosted API and trained models ready")
    registered = client.post("/api/auth/register", json=credentials)
    check(registered, 201)
    assert "Secure" in registered.headers["set-cookie"]
    passed.append("Registration and secure server session")
    try:
        check(client.post("/api/auth/register", json=credentials), 409)
        report = check(client.post("/api/scan/url", json={"url": "https://www.wikipedia.org/"}))
        assert report["risk_level"] == "Low"
        report_id = report["id"]
        email = check(client.post("/api/scan/email", json={"raw": "From: Security <security@account-check.example>\nReply-To: recovery@support-verification.example\nSubject: Urgent verify your password\n\nYour account will be suspended. Confirm your password immediately. http://192.0.2.15/verify/account"}))
        assert email["features"]["reply_mismatch"] == 1
        passed.append("Real URL and email model inference with stored reports")
        check(client.post("/api/blocklist", json={"host": "www.wikipedia.org"}))
        assert not check(client.post("/api/link-access", json={"url": report["url"]}))["allowed"]
        check(client.put("/api/settings", json={"high_threshold": 65, "auto_block": False, "show_alerts": True}))
        # New session/cookies, proving records are in the persistent database.
        with httpx.Client(base_url=origin, headers=headers, timeout=90) as second:
            check(second.post("/api/auth/login", json=credentials))
            assert report_id in [r["id"] for r in check(second.get("/api/history"))]
            assert check(second.get("/api/settings"))["high_threshold"] == 65
            assert check(second.get("/api/blocklist"))[0]["host"] == "www.wikipedia.org"
            check(second.post("/api/auth/logout"))
        passed.append("History, preferences and blocklist persist across separate logins")
        token = check(client.post("/api/extension/pair"))["token"]
        response = client.get("/api/extension/blocklist", headers={"Authorization": "Bearer " + token}, cookies={})
        assert "www.wikipedia.org" in check(response)["hosts"]
        check(client.delete("/api/extension/pair"))
        passed.append("Scoped browser extension pairing and synced hosts")
        status = check(client.get("/api/intelligence"))
        assert status["status"] in ("fresh", "stale", "not_loaded")
        assert check(client.get("/api/evaluation")) == []
        passed.append("Feed status and evaluation history")
    finally:
        check(client.delete("/api/history"))
        check(client.delete("/api/blocklist/www.wikipedia.org"))
        check(client.post("/api/auth/logout"))
    assert client.get("/api/history").status_code == 401
    passed.append("Test history cleared, test block removed, session revoked")

output = {"origin": origin, "username": username, "passed": passed}
Path("artifacts").mkdir(exist_ok=True)
Path("artifacts/deployment-verification.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
print(json.dumps(output, indent=2))
