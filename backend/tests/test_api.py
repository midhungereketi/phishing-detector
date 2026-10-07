import json
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.detector import MODEL_DIR
from backend.storage import Store

HEADERS = {"X-PhishGuard": "1"}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "test.sqlite3"), headers=HEADERS) as client:
        yield client


def register(client, username="student"):
    response = client.post("/api/auth/register", json={"username": username, "password": "TestPassword!123"})
    assert response.status_code == 201
    return response


def test_authentication_session_and_no_client_role_escalation(client):
    assert client.post("/api/scan/url", json={"url": "https://example.com"}).status_code == 401
    response = register(client)
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    assert client.get("/api/auth/me").json()["role"] == "user"
    assert client.get("/api/admin/logs").status_code == 403
    assert client.post("/api/auth/register", json={"username": "attacker", "password": "TestPassword!123", "role": "admin"}).status_code == 422
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json={"username": "student", "password": "wrong-password"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "student", "password": "TestPassword!123"}).status_code == 200


def test_invalid_input_no_fake_low_risk_result(client):
    register(client)
    assert client.post("/api/scan/url", json={"url": "https://"}).status_code == 422
    assert client.get("/api/history").json() == []


def test_real_model_predictions_and_history_are_user_scoped(client):
    register(client)
    response = client.post("/api/scan/url", json={"url": "http://192.0.2.15/verify/account?login=confirm"})
    assert response.status_code == 200
    report = response.json()
    assert report["risk_level"] == "High"
    assert 0 <= report["model_score"] <= 100
    assert report["signals"] and report["features"]["ip_host"] == 1
    assert len(client.get("/api/history").json()) == 1
    client.post("/api/auth/logout")
    register(client, "another_student")
    assert client.get("/api/history").json() == []
    client.delete("/api/history")
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "student", "password": "TestPassword!123"})
    assert len(client.get("/api/history").json()) == 1


def test_current_blocklist_denies_previously_low_risk_link_and_is_user_scoped(client):
    register(client)
    url = "https://www.wikipedia.org/"
    assert client.post("/api/link-access", json={"url": url}).json()["allowed"] is True
    assert client.post("/api/blocklist", json={"host": "www.wikipedia.org"}).status_code == 200
    assert client.post("/api/link-access", json={"url": url}).json()["allowed"] is False
    report = client.post("/api/scan/url", json={"url": url}).json()
    assert report["score"] == 100 and report["model_score"] < 30
    client.post("/api/auth/logout")
    register(client, "independent_student")
    assert client.get("/api/blocklist").json() == []
    assert client.post("/api/link-access", json={"url": url}).json()["allowed"] is True


def test_risky_url_cannot_be_opened(client):
    register(client)
    assert client.post("/api/link-access", json={"url": "http://192.0.2.15/verify/account"}).json()["allowed"] is False


def test_settings_persist_and_autoblock_can_be_removed(client):
    register(client)
    settings = {"high_threshold": 60, "auto_block": True, "show_alerts": False}
    assert client.put("/api/settings", json=settings).json() == settings
    assert client.get("/api/settings").json() == settings
    assert client.put("/api/settings", json={**settings, "high_threshold": 5}).status_code == 422
    report = client.post("/api/scan/url", json={"url": "http://192.0.2.15/verify/account"}).json()
    assert "192.0.2.15" in report["blocked_hosts"]
    assert len(client.get("/api/blocklist").json()) == 1
    assert client.delete("/api/blocklist/192.0.2.15").status_code == 200
    assert client.get("/api/blocklist").json() == []


def test_email_report_contains_headers_links_and_no_raw_message_body(client):
    register(client)
    raw = '''From: Help <help@bank.example>
Reply-To: recovery@evil.test
Subject: Action required: verify your password
Content-Type: text/html; charset=utf-8
Authentication-Results: test.local; dmarc=fail

<p>Private message content marker. Your account is suspended. Confirm your password immediately.</p>
<a href="http://192.0.2.15/verify">https://bank.example/</a>'''
    response = client.post("/api/scan/email", json={"raw": raw})
    assert response.status_code == 200
    report = response.json()
    assert report["kind"] == "email" and report["risk_level"] == "High"
    assert report["features"]["reply_mismatch"] == 1
    assert report["features"]["link_label_mismatch"] == 1
    assert len(report["links"]) >= 1
    assert "unverified" in report["signals"][-1].lower() or "not been independently verified" in report["signals"][-1].lower()
    history = json.dumps(client.get("/api/history").json())
    assert "Private message content marker" not in history
    assert "model_text" not in history


def test_email_links_are_capped_and_flagged(client):
    register(client)
    raw = "Subject: Many links\n\n" + " ".join(f"https://example.com/path{i}" for i in range(25))
    report = client.post("/api/scan/email", json={"raw": raw}).json()
    assert len(report["links"]) == 20
    assert report["links_truncated"] is True


def test_csrf_header_required(client):
    register(client)
    response = client.post("/api/scan/url", json={"url": "https://example.com"}, headers={"X-PhishGuard": ""})
    assert response.status_code == 403


def test_admin_access_uses_database_role_and_activity_is_recorded(tmp_path):
    database = tmp_path / "admin.sqlite3"
    store = Store(database)
    store.initialize()
    store.create_user("professor", "AdminTestPassword!", "admin")
    with TestClient(create_app(database), headers=HEADERS) as client:
        client.post("/api/auth/login", json={"username": "professor", "password": "AdminTestPassword!"})
        logs = client.get("/api/admin/logs")
        assert logs.status_code == 200
        assert logs.json()[0]["action"] == "Signed in"


def test_training_metadata_matches_artifacts_and_real_holdout(client):
    evaluation = client.get("/api/models").json()["evaluation"]
    assert evaluation["url"]["domain_overlap"] == 0
    assert evaluation["url"]["source_counts"]["UCI PhiUSIIL"] == 30000
    for kind in ("url", "email"):
        m = evaluation[kind]["metrics"]
        assert sum(sum(row) for row in m["confusion_matrix"]) == m["test_samples"]
        assert 0 <= m["accuracy"] <= 1
    assert (MODEL_DIR / "url_model.joblib").exists()
