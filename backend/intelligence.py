"""Shared cached phishing feed, optional read-only VirusTotal lookup and enrichment."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .features import normalize_url
from .network import observe, public_request, registration

DATA = Path(__file__).parent / "data"


def identity(value):
    parsed = urlsplit(normalize_url(value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def digest(value):
    return hashlib.sha256(identity(value).encode()).hexdigest()


class Intelligence:
    def __init__(self, path=None):
        self.path = Path(path or DATA / "intelligence.sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.cache = {}
        self.last_vt = 0
        self.last_refresh = 0
        with self.connection() as db:
            db.executescript("CREATE TABLE IF NOT EXISTS feed (hash TEXT PRIMARY KEY, host TEXT, phish_id TEXT); CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def status(self):
        with self.connection() as db:
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
            count = db.execute("SELECT COUNT(*) FROM feed").fetchone()[0]
        updated = float(metadata.get("updated", 0))
        return {"source": metadata.get("source", "PhishTank"), "entries": count, "updated_at": datetime.fromtimestamp(updated, timezone.utc).isoformat() if updated else None,
                "status": "fresh" if updated and time.time() - updated < 86400 else "stale" if updated else "not_loaded", "virustotal_configured": bool(os.getenv("VIRUSTOTAL_API_KEY")), "last_refresh_error": metadata.get("error") or None}

    def import_feed(self, rows, source="PhishTank", updated=None):
        entries = []
        for row in rows:
            if row.get("verified") != "yes" or row.get("online") != "yes":
                continue
            try:
                value = identity(row["url"])
                entries.append((digest(value), urlsplit(value).hostname, str(row.get("phish_id", ""))[:30]))
            except (KeyError, ValueError):
                continue
        if not entries:
            raise ValueError("No verified, online URLs found; the existing feed was preserved.")
        with self.connection() as db:
            db.execute("DELETE FROM feed")
            db.executemany("INSERT OR IGNORE INTO feed VALUES (?,?,?)", entries)
            db.executemany("INSERT OR REPLACE INTO metadata VALUES (?,?)", [("source", source), ("updated", str(updated or time.time())), ("error", "")])
        return self.status()

    def refresh(self):
        with self.lock:
            if time.time() - self.last_refresh < 3600:
                raise ValueError("Feed refresh is limited to once per hour. The existing cache remains available.")
            self.last_refresh = time.time()
        key = os.getenv("PHISHTANK_APP_KEY", "")
        if key and not key.isalnum():
            raise ValueError("Invalid PhishTank key format")
        url = f"https://data.phishtank.com/data/{key + '/' if key else ''}online-valid.json.gz"
        try:
            result = public_request(url, "GET", max_bytes=12000000, timeout=6)
            if result["status"] != 200:
                raise ValueError(f"PhishTank returned HTTP {result['status']}. A provider key or manual feed import may be required.")
            with gzip.GzipFile(fileobj=io.BytesIO(result["body"])) as stream:
                data = stream.read(50000001)
            if len(data) > 50000000:
                raise ValueError("Feed exceeds the decompressed size limit")
            rows = json.loads(data)
            if not isinstance(rows, list):
                raise ValueError("Unexpected feed format")
            return self.import_feed(rows)
        except Exception as error:
            message = str(error) if isinstance(error, ValueError) else "Feed provider unavailable; cached entries were preserved."
            with self.connection() as db:
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('error',?)", (message,))
            raise ValueError(message) from None

    def lookup(self, value):
        status = self.status()
        with self.connection() as db:
            row = db.execute("SELECT phish_id FROM feed WHERE hash=?", (digest(value),)).fetchone()
        return {"source": status["source"], "status": "match" if row else "no_match" if status["entries"] else "unavailable", "cache_status": status["status"], "updated_at": status["updated_at"],
                "phish_id": row[0] if row else None, "message": "Exact URL matched a verified-online feed entry." if row else "No exact URL match; absence from a feed is not proof of safety." if status["entries"] else "No phishing feed loaded. This check is unavailable."}

    def virustotal(self, value):
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if not key:
            return {"status": "not_configured", "message": "Optional VirusTotal API key is not configured on the server."}
        cache_key = digest(value)
        with self.lock:
            cached = self.cache.get(cache_key)
            if cached and time.time() - cached[0] < 3600:
                return {**cached[1], "cached": True}
            if time.time() - self.last_vt < 16:
                return {"status": "rate_limited", "message": "Local provider budget exceeded; try again later."}
            self.last_vt = time.time()
        identifier = base64.urlsafe_b64encode(identity(value).encode()).decode().rstrip("=")
        try:
            response = public_request("https://www.virustotal.com/api/v3/urls/" + identifier, "GET", redirects=0, headers={"x-apikey": key})
            if response["status"] != 200:
                result = {"status": "unknown" if response["status"] == 404 else "unavailable", "message": f"VirusTotal returned HTTP {response['status']}; no fresh scan was submitted."}
            else:
                attributes = json.loads(response["body"])["data"]["attributes"]
                stats = attributes.get("last_analysis_stats", {})
                date = attributes.get("last_analysis_date")
                fresh = bool(date and time.time() - date < 7 * 86400)
                result = {"status": "observed", "source": "VirusTotal", "counts": stats, "analyzed_at": datetime.fromtimestamp(date, timezone.utc).isoformat() if date else None, "fresh": fresh,
                          "message": "Existing multi-engine report; no target was submitted for a new scan."}
        except Exception:
            result = {"status": "unavailable", "message": "VirusTotal lookup failed or timed out."}
        with self.lock:
            if len(self.cache) >= 512:
                self.cache.pop(next(iter(self.cache)))
            self.cache[cache_key] = (time.time(), result)
        return result

    def enrich(self, report, detector, network=False, reputation=False):
        report["intelligence"] = self.lookup(report["url"])
        report["network"] = {"status": "not_requested", "message": "Live network checks were not requested."}
        report["registration"] = {"status": "not_requested"}
        with self.lock:
            cached = self.cache.get(digest(report['url']))
        report["reputation"] = {**cached[1], 'cached': True} if cached and time.time() - cached[0] < 3600 else {"status": "not_requested"}
        if network or reputation:
            with ThreadPoolExecutor(max_workers=3) as pool:
                jobs = {}
                if network:
                    jobs["network"] = pool.submit(observe, report["url"])
                    jobs["registration"] = pool.submit(registration, report["host"])
                if reputation:
                    jobs["reputation"] = pool.submit(self.virustotal, report["url"])
                for name, job in jobs.items():
                    report[name] = job.result()
        if report["network"].get("status") == "observed":
            chain = report["network"].get("chain", [])
            report["redirects"] = [{**detector.analyze_url(hop["url"]), "intelligence": self.lookup(hop["url"])} for hop in chain[1:]]
            report["signals"] = [signal.replace("redirects are not followed", "inspect the redirect observations below") for signal in report["signals"]]
        return report


def evidence_score(report):
    """Transparent policy floors, deliberately separate from model probabilities."""
    floor, reasons = 0, []
    intel = report.get("intelligence", {})
    if intel.get("status") == "match":
        floor = 95 if intel.get("cache_status") == "fresh" else 70
        reasons.append(f"Phishing-feed match ({intel.get('cache_status')} cache): policy floor {floor}.")
    vt = report.get("reputation", {})
    if vt.get("status") == "observed" and vt.get("fresh"):
        malicious = vt.get("counts", {}).get("malicious", 0)
        if malicious:
            value = 90 if malicious >= 3 else 70
            floor = max(floor, value)
            reasons.append(f"{malicious} VirusTotal engines reported malicious: policy floor {value}.")
    return floor, reasons


def main():
    parser = argparse.ArgumentParser(description="Refresh or import a verified-online PhishTank JSON feed.")
    parser.add_argument("--import-json", type=Path)
    args = parser.parse_args()
    service = Intelligence()
    print(json.dumps(service.import_feed(json.loads(args.import_json.read_text(encoding="utf-8"))) if args.import_json else service.refresh(), indent=2))


if __name__ == "__main__":
    main()
