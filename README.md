# PhishGuard

## Phishing Attack Detection and Prevention Using Machine Learning

A local Computer Networks project built with React, Vite, FastAPI, scikit-learn and SQLite. The previous browser-only heuristic scanner has been replaced by trained URL and email classifiers.

### Implemented

- URL classification: 21 lexical/domain-structure features → trained Random Forest.
- Email classification: MIME headers/body, TF-IDF + Logistic Regression, sender/reply mismatch, inert HTML link inspection, attachment names/extensions and embedded URL analysis.
- Immediate in-app risk alerts, account-specific scan history and PDF/JSON security reports.
- Personal blocklist, optional automatic high risk host blocking and server-checked link-opening controls.
- Persistent protection preferences, secure password hashing, expiring HttpOnly sessions and server-authorized admin activity logs.
- Model Lab with actual metrics, confusion matrices, URL algorithm comparison, feature importance and dataset checksums.
- Responsive cyber-themed interface with animated shield artwork, scan feedback, risk charts and educational explanations. Ctrl+K opens page navigation; the top-bar motion control pauses animations, and device reduced-motion preferences are respected.
- Cached verified-online PhishTank URL matching; explicit fresh/stale/missing status and transparent risk-policy floors.
- Opt-in public DNS, verified TLS, bounded HEAD redirects and RDAP domain registration age; optional read-only VirusTotal reputation lookup.
- Original-byte `.eml` uploads, URL model sensitivity explanations and enriched PDF/JSON reports.
- Chrome/Edge Manifest V3 extension with scoped pairing tokens, click warnings and synced exact-host navigation blocks.
- Separate sigmoid calibration sets, reliability bins, Brier scores, threshold error tables and external dataset evaluation.

**Scope:** Local ML and feed matching do not contact targets. Live checks contact targets/providers only when explicitly enabled. The extension adds click checks and synced host blocks; it does not intercept every navigation or filter an inbox. Pasted SPF/DKIM/DMARC results remain unverified. Dataset calibration does not establish real-world confidence; combined policy scores are not probabilities. See [DATASETS.md](DATASETS.md) and [extension/README.md](extension/README.md).

## Run on this computer

The project-local environment, Node dependencies and trained models have already been prepared. From `phishing-detector`:

```powershell
npm run dev
```

Open **http://127.0.0.1:5173** and create an account. This starts the Python API on port 8000 and Vite on 5173. Keep the terminal running; Ctrl+C stops the launcher and its children. Ports must be free. If a separate frontend is already running, stop it in its own terminal first.

## Fresh installation

Use **Python 3.12** and **Node.js 22.12+**. The shipped models were trained with scikit-learn 1.9.1; install the lockfile to match them. A different scikit-learn version requires retraining rather than assuming serialized-model compatibility.

On Windows:

```powershell
cd "D:\College\SEM 5\Computer Networks\Project\phishing-detector"
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-lock.txt
npm ci
npm run dev
```

Or run `powershell -ExecutionPolicy Bypass -File scripts\setup.ps1` to perform project setup. This changes no persistent execution policy. `python` can replace `py -3.12` if Python 3.12 is already on PATH.

On macOS/Linux:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-lock.txt
npm ci
npm run dev
```

The pretrained model artifacts are included in `backend/models/`. Datasets are only needed for retraining, so the application works offline after dependencies are installed (fonts gracefully fall back if unavailable).

### Separate processes

Terminal 1 (Windows):

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Terminal 2:

```powershell
npm run dev:ui
```

For a production bundle served by the local API, run `npm run build`, start the API and open **http://127.0.0.1:8000**. `npm run preview` previews only frontend assets; use the API-served build for the full application. Interactive API documentation is at **http://127.0.0.1:8000/docs**; mutation requests require `X-PhishGuard: 1`, as used by the frontend.

## Retrain and evaluate

```powershell
.\.venv\Scripts\python.exe -m backend.train --download
```

The command downloads the original public datasets, uses a deterministic balanced 30,000-URL UCI sample plus the prepared modern training slice when present, trains/evaluates both classifiers and writes artifacts plus `metrics.json`. For a different UCI sample size: `--url-samples 60000`. Existing downloaded corpora are reused. Restart the API after retraining.

No training labels come from the original scoring rules. URL labels come from UCI PhiUSIIL and PhreshPhish. Phishing emails come from José Nazario; legitimate emails come from Apache SpamAssassin ham. Internal labels use `1 = phishing`. Training/evaluation never visits dataset URLs.

| Supplied model | Accuracy | Precision | Recall | F1 | Test samples |
| --- | ---: | ---: | ---: | ---: | ---: |
| URL Random Forest, mixed-source hold-out | 92.24% | 92.67% | 90.93% | 91.79% | 7,839 |
| URL Random Forest, reserved PhreshPhish test slice | 80.60% | 77.69% | 78.09% | 77.89% | 907 |
| Email TF-IDF + Logistic Regression | 99.35% | 97.14% | 97.14% | 97.14% | 615 |

These are corpus metrics at threshold 0.5, not real-world accuracy claims. URL splits have zero domain overlap; email sources differ in age/origin, creating substantial bias. The external result is a small publisher-order slice with corpus-domain exclusions, not the complete PhreshPhish benchmark. The combined policy is not evaluated by individual-model metrics. Calibration reduced email test Brier score but slightly increased URL test Brier score; see Model Lab for measured before/after values.

To reproduce the modern training preparation and reserved evaluation:

```powershell
.\.venv\Scripts\python.exe -m backend.benchmark
.\.venv\Scripts\python.exe -m backend.benchmark --prepare-training
.\.venv\Scripts\python.exe -m backend.train --download
.\.venv\Scripts\python.exe -m backend.benchmark --final
```

The first command is a diagnostic evaluation, not the final result. The second excludes diagnostic and reserved final test domains from publisher training metadata. The final command evaluates a different, reserved test shard. Only URL/label/date columns are read; remote HTML is excluded. Raw slices and provenance remain in ignored `backend/data/`.

## Live checks and optional API keys

Copy `.env.example` to `.env` in the project directory and restart the API after changes. Add `VIRUSTOTAL_API_KEY` to enable an optional existing-report lookup. Do not put API keys in React code or commit `.env`. No VirusTotal upload/rescan is performed. Full submitted URLs, including queries, are disclosed to VirusTotal only when this option is enabled; cached results may be reused locally for an hour. Reports older than seven days do not increase policy risk.

Open **Protection → Refresh PhishTank feed**, or run:

```powershell
.\.venv\Scripts\python.exe -m backend.intelligence
```

The cache is already prepared on this computer. A fresh exact verified-online match has policy floor 95, a stale match floor 70. Cache age becomes stale after 24 hours. Misses and unavailable checks never mean safe. Refresh preserves the previous cache on errors. Optional `PHISHTANK_APP_KEY` can improve provider access; manual JSON import is supported with `--import-json PATH`. Imported JSON must be obtained from PhishTank and contain `url`, `verified=yes`, `online=yes`; do not treat arbitrary labels as verified intelligence.

In the URL scanner, select **Live DNS, TLS, redirects & domain age** to enable active observations. The backend permits public addresses and ports 80/443 only, rejects credentials/private/reserved IPs, pins validated IP connections, checks each redirect, verifies TLS, follows at most three target redirects and sends HEAD requests without cookies or target bodies. DNS, certificate and registry failures are reported as unknown/unavailable, never as legitimacy. Domain age and valid TLS do not establish safety.

## Browser extension

Open **Protection**, download/unzip the extension, load it unpacked in Chrome or Edge Developer mode, and generate a pairing token. Paste it into the extension popup and sync your blocklist. Instructions: [extension/README.md](extension/README.md). Tokens expire in 30 days and can be revoked from the app. If needed, configure the exact `chrome-extension://ID` origin in `.env`; wildcard CORS is not enabled. The extension uses the API at `127.0.0.1:8000`.

Synced exact-host blocks cover browser navigation even offline. ML warnings cover ordinary clicked links, with an explicit override for unblocked targets. Address-bar URLs, forms and scripted navigation are not universally intercepted; the extension is not a firewall. A recent saved risky redirect cannot be bypassed by an offline original-URL check; perform a successful live rescan to replace the observation. Cached reputation is included in access checks.

## Evaluate your own external datasets

Model Lab accepts a labeled URL CSV with `url,label` (0 legitimate, 1 phishing), source description and collection date. Up to 1,000 rows / 500 KB per run; duplicate and model-corpus domains are excluded. Results are account scoped. Labels and provenance supplied by users are not independently audited. This never retrains the model or visits the URLs.

Larger local research runs and email datasets are supported by CLI:

```powershell
.\.venv\Scripts\python.exe -m backend.evaluate --url-csv new-urls.csv --source "Provider, collection date"
.\.venv\Scripts\python.exe -m backend.evaluate --email-jsonl new-emails.jsonl --source "Provider, collection date"
```

Email JSONL rows contain `raw` and `label`; known normalized-text prefix groups and duplicates are excluded. An independent modern email benchmark is still required before operational claims.

## Admin account

No default administrator password is shipped. To explicitly create one:

```powershell
.\.venv\Scripts\python.exe -m backend.create_admin
```

Enter a new username and password when prompted, then sign in. Ordinary registration always creates a user account. The old `admin / 1234` credentials and localStorage roles are removed. Browser-only accounts from the old app must be registered again.

## Validation

```powershell
npm run lint
npm run build
npm run test:backend
```

Backend tests use isolated temporary databases and the trained models. They cover URL validation, MIME parsing, sessions, server-side roles, cross-user isolation, saved settings, in-app prevention, and report metadata. The browser smoke test is `scripts/browser-smoke.cjs` (requires Playwright and a Chromium installation); it can run against the local API-served build.

## Project layout

```text
backend/
  app.py                 API, authentication, sessions, reports, link access
  features.py            Shared offline URL / email feature extraction
  detector.py            Model loading, prediction and risk policy
  storage.py             SQLite persistence and password hashing
  train.py               Public dataset download, training and evaluation
  network.py             Public-only pinned DNS/TLS/HEAD/RDAP observations
  intelligence.py        Cached phishing feed and optional reputation checks
  evaluate.py            External labeled URL/email evaluation
  benchmark.py           Reproducible PhreshPhish metadata preparation
  create_admin.py        Explicit local admin creation
  models/                Trained classifiers and evaluation metadata
  tests/                 Feature and API integration tests
src/
  components/            Authentication, scanner and report viewer
  pages/                 Reports, protection, model lab, lessons, settings, admin
  utils/report.js        PDF and JSON export
scripts/                 Setup, development launcher and test runners
extension/               Chrome/Edge extension and installation instructions
docs/PROJECT_REPORT.md    Abstract, methodology, architecture, results and viva notes
DATASETS.md              Attribution, licenses and evaluation limits
```

Database and raw corpora are ignored by Git. SQLite reports may include sensitive URL/subject/header metadata; raw email bodies are not stored. For deployment beyond loopback, configure HTTPS, `PHISHGUARD_SECURE_COOKIE=1`, allowed hosts and operational controls. This repository is prepared for a local college demonstration.
