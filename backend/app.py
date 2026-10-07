import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .detector import Detector, finalize
from .features import normalize_url
from .storage import Store, password_matches
from .intelligence import Intelligence, evidence_score
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env", override=False)


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)


class URLInput(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    network_checks: bool = False
    reputation_check: bool = False


class EmailInput(BaseModel):
    raw: str = Field(min_length=10, max_length=300000)


class EvaluationInput(BaseModel):
    csv: str = Field(min_length=10, max_length=500000)
    source: str = Field(min_length=3, max_length=200)


class SettingsInput(BaseModel):
    high_threshold: int = Field(ge=50, le=95)
    auto_block: bool
    show_alerts: bool


class HostInput(BaseModel):
    host: str = Field(min_length=1, max_length=253)


def create_app(database=None, intelligence_path=None):
    store = Store(database or ROOT / "backend" / "phishguard.sqlite3")

    @asynccontextmanager
    async def lifespan(app):
        store.initialize()
        app.state.detector = Detector()
        app.state.intelligence = Intelligence(intelligence_path)
        yield

    app = FastAPI(title="Phishing Attack Detection and Prevention Using Machine Learning", version="2.0.0", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])
    extension_origins = [origin.strip() for origin in os.getenv("PHISHGUARD_EXTENSION_ORIGINS", "").split(",") if re.fullmatch(r"chrome-extension://[a-p]{32}", origin.strip())]
    if extension_origins:
        app.add_middleware(CORSMiddleware, allow_origins=extension_origins, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type", "X-PhishGuard"])
    attempts = defaultdict(deque)

    @app.middleware("http")
    async def security_headers(request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-phishguard") != "1":
            return Response("Missing request protection header", status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def rate_limit(request, category, limit):
        key = (category, request.client.host)
        bucket = attempts[key]
        current = time.time()
        while bucket and bucket[0] < current - 60:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(429, "Too many requests. Wait one minute and try again.")
        bucket.append(current)

    def user(request: Request):
        token = request.cookies.get("phishguard_session", "")
        digest = hashlib.sha256(token.encode()).hexdigest()
        with store.connection() as db:
            row = db.execute("SELECT users.id,users.username,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?", (digest, time.time())).fetchone()
        if not row:
            raise HTTPException(401, "Sign in to continue.")
        return dict(row)

    def admin(current=Depends(user)):
        if current["role"] != "admin":
            raise HTTPException(403, "Administrator access required.")
        return current

    def require_model(request):
        detector = request.app.state.detector
        if not detector.ready:
            raise HTTPException(503, "Models are not trained. Run python -m backend.train --download, then restart the API.")
        return detector

    def session(response, user_id):
        token = secrets.token_urlsafe(32)
        with store.connection() as db:
            db.execute("DELETE FROM sessions WHERE expires<=?", (time.time(),))
            db.execute("INSERT INTO sessions(token,user_id,expires) VALUES (?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user_id, time.time() + 86400))
        response.set_cookie("phishguard_session", token, max_age=86400, httponly=True, samesite="strict", secure=os.environ.get("PHISHGUARD_SECURE_COOKIE") == "1")

    @app.get("/api/health")
    def health(request: Request):
        return {"status": "online", "models_ready": request.app.state.detector.ready}

    @app.post("/api/auth/register", status_code=201)
    def register(data: Credentials, request: Request, response: Response):
        rate_limit(request, "auth", 20)
        username = data.username.lower()
        try:
            user_id = store.create_user(username, data.password)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "That username is already registered.") from None
        session(response, user_id)
        store.log(username, "Account registered")
        return {"id": user_id, "username": username, "role": "user"}

    @app.post("/api/auth/login")
    def login(data: Credentials, request: Request, response: Response):
        rate_limit(request, "auth", 20)
        with store.connection() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (data.username.lower(),)).fetchone()
        if not row or not password_matches(data.password, row["password"]):
            raise HTTPException(401, "Invalid username or password.")
        session(response, row["id"])
        store.log(row["username"], "Signed in")
        return {key: row[key] for key in ("id", "username", "role")}

    @app.get("/api/auth/me")
    def me(current=Depends(user)):
        return current

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response, current=Depends(user)):
        with store.connection() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (hashlib.sha256(request.cookies.get("phishguard_session", "").encode()).hexdigest(),))
        response.delete_cookie("phishguard_session")
        store.log(current["username"], "Signed out")
        return {"ok": True}

    def save(report, current):
        settings = store.settings(current["id"])
        hosts = {row["host"] for row in store.blocked(current["id"])}
        report = finalize(report, settings, hosts)
        initial = [report] if report["kind"] == "url" else report["links"]
        candidates = [item for candidate in initial for item in [candidate, *candidate.get("redirects", [])]]
        if settings["auto_block"]:
            for candidate in candidates:
                if max(candidate["model_score"], evidence_score(candidate)[0]) >= settings["high_threshold"]:
                    store.block(current["id"], candidate["host"])
                    hosts.add(candidate["host"])
            report = finalize(report, settings, hosts)
        store.log(current["username"], f"{report['kind'].upper()} scan: {report['risk_level']} risk")
        return store.save_report(current["id"], report)

    @app.post("/api/scan/url")
    def scan_url(data: URLInput, request: Request, current=Depends(user)):
        rate_limit(request, "scan", 60)
        detector = require_model(request)
        try:
            report = {"kind": "url", **detector.analyze_url(data.url)}
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        if data.network_checks or data.reputation_check:
            rate_limit(request, "live", 10)
        request.app.state.intelligence.enrich(report, detector, data.network_checks, data.reputation_check)
        return save(report, current)

    @app.post("/api/scan/email")
    def scan_email(data: EmailInput, request: Request, current=Depends(user)):
        rate_limit(request, "scan", 60)
        detector = require_model(request)
        try:
            report = {"kind": "email", **detector.analyze_email(data.raw)}
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        for link in report["links"]:
            request.app.state.intelligence.enrich(link, detector)
        return save(report, current)

    @app.post("/api/scan/email-file")
    async def scan_email_file(request: Request, current=Depends(user)):
        rate_limit(request, "scan", 60)
        if request.headers.get("content-type", "").split(";")[0] not in ("message/rfc822", "application/octet-stream", "text/plain"):
            raise HTTPException(415, "Upload an .eml file as message/rfc822.")
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 300000:
                raise HTTPException(413, "Email files must be no larger than 300 KB.")
            chunks.append(chunk)
        try:
            detector = require_model(request)
            analyzed = await run_in_threadpool(detector.analyze_email, b"".join(chunks))
            report = {"kind": "email", **analyzed, "input_method": "eml_file"}
            for link in report["links"]:
                request.app.state.intelligence.enrich(link, detector)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return save(report, current)

    @app.get("/api/history")
    def history(current=Depends(user)):
        return store.history(current["id"])

    def saved_redirect_warning(url, current):
        with store.connection() as db:
            recent = db.execute("SELECT report FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 200", (current["id"],)).fetchall()
        for row in recent:
            saved = json.loads(row[0])
            if saved.get('kind') == 'url' and saved.get('url') == url and saved.get('network', {}).get('status') == 'observed':
                # A newer successful live scan replaces the earlier observation.
                return bool(saved.get('redirects') and saved.get('risk_level') != 'Low')
        return False

    @app.post("/api/link-access")
    def link_access(data: URLInput, request: Request, current=Depends(user)):
        rate_limit(request, "scan", 60)
        try:
            report = {"kind": "url", **require_model(request).analyze_url(data.url)}
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        request.app.state.intelligence.enrich(report, require_model(request))
        hosts = {row["host"] for row in store.blocked(current["id"])}
        report = finalize(report, store.settings(current["id"]), hosts)
        # A recent saved live report may contain risky redirect evidence. Offline
        # reclassification of the original URL must not silently bypass that warning.
        saved_warning = saved_redirect_warning(report['url'], current)
        allowed = report["risk_level"] == "Low" and not report["blocked_hosts"] and not saved_warning
        store.log(current["username"], "Link access allowed" if allowed else "Link access denied")
        return {"allowed": allowed, "url": report["url"], "reason": "No strong signal detected; safety is not guaranteed." if allowed else "A saved report found a risky redirect. Rescan with live checks before opening." if saved_warning else report["action"]}

    @app.delete("/api/history")
    def clear_history(current=Depends(user)):
        with store.connection() as db:
            db.execute("DELETE FROM scans WHERE user_id=?", (current["id"],))
        store.log(current["username"], "Cleared own scan history")
        return {"ok": True}

    @app.get("/api/models")
    def models(request: Request):
        return {"ready": request.app.state.detector.ready, "evaluation": request.app.state.detector.metadata}

    @app.get("/api/intelligence")
    def intelligence_status(request: Request, current=Depends(user)):
        return request.app.state.intelligence.status()

    @app.post("/api/intelligence/refresh")
    def refresh_intelligence(request: Request, current=Depends(user)):
        rate_limit(request, "feed", 2)
        try:
            status = request.app.state.intelligence.refresh()
        except ValueError as error:
            raise HTTPException(503, str(error)) from None
        store.log(current["username"], "Refreshed phishing intelligence feed")
        return status

    @app.post("/api/evaluation/urls")
    def evaluate_urls(data: EvaluationInput, request: Request, current=Depends(user)):
        from .evaluate import evaluate_csv
        rate_limit(request, "evaluate", 3)
        try:
            result = evaluate_csv(data.csv, require_model(request), data.source, max_rows=1000)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        with store.connection() as db:
            db.execute("INSERT INTO evaluations(user_id,created_at,report) VALUES (?,?,?)", (current["id"], result["evaluated_at"], json.dumps(result)))
        return result

    @app.get("/api/evaluation")
    def evaluation_history(current=Depends(user)):
        with store.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT report FROM evaluations WHERE user_id=? ORDER BY id DESC LIMIT 10", (current["id"],))]

    @app.post("/api/extension/pair")
    def pair_extension(request: Request, current=Depends(user)):
        rate_limit(request, "pair", 5)
        token = secrets.token_urlsafe(32)
        with store.connection() as db:
            db.execute("INSERT INTO extension_tokens(token,user_id,expires) VALUES (?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), current["id"], time.time() + 30 * 86400))
        return {"token": token, "expires_in_days": 30}

    @app.get("/api/extension/download")
    def download_extension(current=Depends(user)):
        import io
        import zipfile
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in (ROOT / "extension").iterdir():
                if path.is_file() and path.suffix in (".js", ".json", ".html", ".css", ".md"):
                    archive.write(path, "phishguard-extension/" + path.name)
        output.seek(0)
        return StreamingResponse(output, media_type="application/zip", headers={"Content-Disposition": "attachment; filename=phishguard-extension.zip"})

    @app.delete("/api/extension/pair")
    def revoke_extensions(current=Depends(user)):
        with store.connection() as db:
            db.execute("DELETE FROM extension_tokens WHERE user_id=?", (current["id"],))
        return {"ok": True}

    def extension_user(request: Request):
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        with store.connection() as db:
            row = db.execute("SELECT users.id,users.username FROM extension_tokens JOIN users ON users.id=extension_tokens.user_id WHERE token=? AND expires>?", (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
        if not row:
            raise HTTPException(401, "Extension pairing expired or invalid. Generate a new token in Protection.")
        return dict(row)

    @app.get("/api/extension/blocklist")
    def extension_blocklist(current=Depends(extension_user)):
        return {"hosts": [row["host"] for row in store.blocked(current["id"])], "username": current["username"]}

    @app.post("/api/extension/check")
    def extension_check(data: URLInput, request: Request, current=Depends(extension_user)):
        rate_limit(request, "extension", 120)
        try:
            detector = require_model(request)
            report = {"kind": "url", **detector.analyze_url(data.url)}
            request.app.state.intelligence.enrich(report, detector)
            report = finalize(report, store.settings(current["id"]), {row["host"] for row in store.blocked(current["id"])})
            if report['score'] < 30 and saved_redirect_warning(report['url'], current):
                report.update(score=30, risk_level='Medium', action='A saved scan found a risky redirect. Rescan with live checks in PhishGuard.')
            return {key: report[key] for key in ("url", "host", "score", "risk_level", "action", "model_score", "intelligence", "blocked_hosts")}
        except ValueError as error:
            raise HTTPException(422, str(error)) from None

    @app.get("/api/settings")
    def settings(current=Depends(user)):
        return store.settings(current["id"])

    @app.put("/api/settings")
    def update_settings(data: SettingsInput, current=Depends(user)):
        with store.connection() as db:
            db.execute("UPDATE users SET settings=? WHERE id=?", (json.dumps(data.model_dump()), current["id"]))
        store.log(current["username"], "Updated protection settings")
        return data.model_dump()

    @app.get("/api/blocklist")
    def blocklist(current=Depends(user)):
        return store.blocked(current["id"])

    @app.post("/api/blocklist")
    def add_block(data: HostInput, current=Depends(user)):
        try:
            normalized = normalize_url(data.host)
            host = urlsplit(normalized).hostname
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        store.block(current["id"], host)
        store.log(current["username"], "Added host to personal blocklist")
        return {"host": host}

    @app.delete("/api/blocklist/{host}")
    def remove_block(host: str, current=Depends(user)):
        with store.connection() as db:
            db.execute("DELETE FROM blocklist WHERE user_id=? AND host=?", (current["id"], host))
        return {"ok": True}

    @app.get("/api/admin/logs")
    def logs(current=Depends(admin)):
        with store.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200")]

    # A production build is served from the same origin as the API.
    if (ROOT / "dist" / "assets").exists():
        app.mount("/assets", StaticFiles(directory=ROOT / "dist" / "assets"), name="assets")

    @app.get("/")
    def frontend():
        if (ROOT / "dist" / "index.html").exists():
            return FileResponse(ROOT / "dist" / "index.html")
        return {"message": "Run npm run dev for the UI, or npm run build to serve it here."}

    return app


app = create_app()
