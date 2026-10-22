"""Build a Chrome/Edge installable ZIP for one trusted PhishGuard API origin."""
import argparse
import json
import zipfile
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "extension"
DEFAULT_ORIGIN = "https://phishing-detector-pink.vercel.app"
LOCAL_API = "http://127.0.0.1:8000/api"


def package(origin, destination):
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Use an HTTPS origin without a path, query, credentials or fragment.")
    origin = origin.rstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(SOURCE.iterdir()):
            if not path.is_file() or path.suffix not in (".js", ".json", ".html", ".css", ".md"):
                continue
            content = path.read_text(encoding="utf-8")
            if path.name == "background.js":
                if content.count(LOCAL_API) != 1:
                    raise ValueError("Expected exactly one local API address in background.js")
                content = content.replace(LOCAL_API, origin + "/api")
            elif path.name == "manifest.json":
                manifest = json.loads(content)
                manifest["host_permissions"] = [origin + "/*"]
                content = json.dumps(manifest, indent=2) + "\n"
            archive.writestr(path.name, content)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    parser.add_argument("--output", type=Path, default=ROOT / "output" / "extension" / "PhishGuard-Chrome-Demo.zip")
    args = parser.parse_args()
    print(package(args.origin, args.output))
