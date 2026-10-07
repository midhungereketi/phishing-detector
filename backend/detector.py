import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import sklearn
from scipy.sparse import hstack

from .features import email_signals, parse_email, url_features, url_signals
from .intelligence import evidence_score

MODEL_DIR = Path(__file__).parent / "models"


class Detector:
    def __init__(self):
        self.url = self.email = self.metadata = None
        if all((MODEL_DIR / name).exists() for name in ("url_model.joblib", "email_model.joblib", "metrics.json")):
            metadata = json.loads((MODEL_DIR / "metrics.json").read_text(encoding="utf-8"))
            feature_hash = hashlib.sha256((MODEL_DIR.parent / "features.py").read_bytes()).hexdigest()
            if metadata.get("feature_extractor_sha256") != feature_hash or metadata.get("sklearn_version") != sklearn.__version__:
                return  # Retrain if the extractor or scikit-learn version changes.
            # Only our locally generated artifacts are loaded; never accept uploaded pickle files.
            self.url = joblib.load(MODEL_DIR / "url_model.joblib")
            self.email = joblib.load(MODEL_DIR / "email_model.joblib")
            self.metadata = metadata
            external_path = MODEL_DIR / "external_evaluation.json"
            if external_path.exists():
                external = json.loads(external_path.read_text(encoding="utf-8"))
                if external.get("model_sha256", {}).get("url") == hashlib.sha256((MODEL_DIR / "url_model.joblib").read_bytes()).hexdigest():
                    self.metadata["external_evaluation"] = external

    @property
    def ready(self):
        return self.metadata is not None

    def analyze_url(self, value):
        normalized, features = url_features(value)
        matrix = self.url["vectorizer"].transform([features])
        predictor = self.url.get("calibrated", self.url["model"])
        score = round(float(predictor.predict_proba(matrix)[0, 1]) * 100, 1)
        # Local perturbation explains the model's sensitivity, not causality.
        explanation = []
        defaults = {"https": 1, "ip_host": 0, "at_authority": 0, "subdomains": 0, "punycode": 0, "nonstandard_port": 0, "shortener": 0, "host_keyword_count": 0}
        variants = [(name, {**features, name: baseline}) for name, baseline in defaults.items() if features[name] != baseline]
        if variants:
            alternate = predictor.predict_proba(self.url["vectorizer"].transform([row for _, row in variants]))[:, 1]
            explanation = sorted([{"feature": name, "observed": features[name], "baseline": defaults[name], "score_change": round(score - float(probability) * 100, 1)} for (name, _), probability in zip(variants, alternate)], key=lambda row: abs(row["score_change"]), reverse=True)
        return {"url": normalized, "host": urlsplit(normalized).hostname, "model_score": score, "features": features, "signals": url_signals(features), "calibrated": "calibrated" in self.url, "explanation": explanation,
                "explanation_method": "One-feature-at-a-time sensitivity. Synthetic alternatives may be unrealistic; changes are not additive or causal."}

    def analyze_email(self, raw):
        parsed = parse_email(raw)
        if len(parsed["model_text"].strip()) < 10:
            raise ValueError("Provide an email with a subject or readable message content.")
        text = self.email["text_vectorizer"].transform([parsed["model_text"]])
        matrix = hstack([text, self.email["metadata_vectorizer"].transform([parsed["features"]])]).tocsr()
        score = round(float(self.email.get("calibrated", self.email["model"]).predict_proba(matrix)[0, 1]) * 100, 1)
        # Actual signed contributions from the linear text model, not fabricated explanations.
        contributions = text.multiply(self.email["model"].coef_[0, :text.shape[1]]).tocoo()
        tokens = self.email["text_vectorizer"].get_feature_names_out()
        influential = sorted(zip(contributions.col, contributions.data), key=lambda pair: pair[1], reverse=True)
        keywords = [{"term": str(tokens[index]), "contribution": round(float(weight), 3)} for index, weight in influential if weight > 0][:8]
        links = [self.analyze_url(url) for url in parsed["links"]]
        parsed.pop("model_text")  # Raw message bodies are not stored in reports.
        return {**parsed, "model_score": score, "calibrated": "calibrated" in self.email, "links": links, "signals": email_signals(parsed), "influential_terms": keywords}


def finalize(report, settings, blocked_hosts):
    candidates = [report] if report["kind"] == "url" else report["links"]
    candidates = [item for candidate in candidates for item in [candidate, *candidate.get("redirects", [])]]
    blocked = sorted({item["host"] for item in candidates if item["host"] in blocked_hosts})
    scores, reasons = [report["model_score"]], []
    for item in candidates:
        floor, evidence = evidence_score(item)
        scores.extend([item["model_score"], floor])
        reasons.extend(evidence)
    score = max(scores)
    report["score"] = 100 if blocked else score
    report["risk_level"] = "High" if report["score"] >= settings["high_threshold"] else "Medium" if report["score"] >= 30 else "Low"
    report["blocked_hosts"] = blocked
    report["threshold"] = settings["high_threshold"]
    report["action"] = "Blocked in this app" if blocked else "Avoid opening; verify independently" if report["risk_level"] == "High" else "Inspect before opening" if report["risk_level"] == "Medium" else "No strong signal detected; remain cautious"
    report["policy_reasons"] = reasons + (["Personal blocklist match: policy score 100."] if blocked else [])
    report["score_method"] = "Maximum of model estimates and explicit threat-intelligence policy floors; 100 for personal blocks. Combined policy is not a calibrated probability."
    report["model_version"] = "PhishGuard v2"
    return report
