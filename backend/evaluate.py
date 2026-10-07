"""Evaluate user-supplied, labeled external datasets without fitting the models.

URL CSV: url,label (phishing=1, legitimate=0). Email JSONL: raw,label.
Dataset provenance and label quality remain the evaluator's responsibility.
"""
import argparse
import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np

from .detector import Detector
from .features import domain_group, parse_email, normalize_url, url_features
from .train import metrics


def summarize(labels, probabilities, source, checksum, excluded, kind):
    if len(labels) < 10 or len(set(labels)) < 2:
        raise ValueError("Provide at least 10 distinct eligible samples, including both label 0 (legitimate) and label 1 (phishing). Dataset-overlapping groups are excluded.")
    return {"kind": kind, "source": source, "source_verified": False, "sha256": checksum, "evaluated_at": datetime.now(timezone.utc).isoformat(), "excluded": excluded,
            "metrics": metrics(np.array(labels), np.array(probabilities)), "limitations": "External labels and provenance are user supplied and unverified. Dataset-overlapping domains/text groups and duplicates are excluded. No model fitting or target visits occurred. Results depend on sample quality, collection bias and prevalence."}


def evaluate_csv(content, detector, source, max_rows=10000):
    reader = csv.DictReader(io.StringIO(content))
    if not {"url", "label"}.issubset(reader.fieldnames or []):
        raise ValueError("CSV must have url,label headers; labels must be 0 or 1.")
    labels, features, seen = [], [], set()
    excluded = {"overlapping_domain": 0, "duplicate": 0, "invalid": 0}
    for index, row in enumerate(reader):
        if index >= max_rows:
            raise ValueError(f"Dataset limit is {max_rows} rows; split larger datasets into batches.")
        try:
            label = int(row["label"])
            if label not in (0, 1):
                raise ValueError()
            url = normalize_url(row["url"])
            group = domain_group(urlsplit(url).hostname)
        except (ValueError, KeyError, TypeError):
            excluded["invalid"] += 1
            continue
        if url in seen:
            excluded["duplicate"] += 1
            continue
        seen.add(url)
        if hashlib.sha256(group.encode()).hexdigest() in detector.url.get("dataset_domains", set()):
            excluded["overlapping_domain"] += 1
            continue
        labels.append(label)
        features.append(url_features(url)[1])
    probabilities = detector.url.get("calibrated", detector.url["model"]).predict_proba(detector.url["vectorizer"].transform(features))[:, 1] if features else []
    return summarize(labels, probabilities, source, hashlib.sha256(content.encode()).hexdigest(), excluded, "url")


def evaluate_emails(content, detector, source):
    labels, probabilities, seen = [], [], set()
    excluded = {"overlapping_prefix": 0, "duplicate": 0, "invalid": 0}
    for index, line in enumerate(content.splitlines()):
        if index >= 10000:
            raise ValueError("Email evaluation limit is 10000 rows.")
        try:
            row = json.loads(line)
            if row["label"] not in (0, 1) or not isinstance(row["raw"], str) or len(row["raw"]) > 300000:
                raise ValueError()
            text = " ".join(parse_email(row["raw"])["model_text"].lower().split())
            fingerprint = hashlib.sha256(text.encode()).hexdigest()
            prefix = hashlib.sha256(text[:120].encode()).hexdigest()
            if fingerprint in seen:
                excluded["duplicate"] += 1
                continue
            seen.add(fingerprint)
            if prefix in detector.email.get("dataset_prefixes", set()):
                excluded["overlapping_prefix"] += 1
                continue
            probability = detector.analyze_email(row["raw"])["model_score"] / 100
            labels.append(row["label"])
            probabilities.append(probability)
        except (ValueError, KeyError, TypeError):
            excluded["invalid"] += 1
    return summarize(labels, probabilities, source, hashlib.sha256(content.encode()).hexdigest(), excluded, "email")


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url-csv", type=Path)
    group.add_argument("--email-jsonl", type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/external-evaluation.json"))
    args = parser.parse_args()
    detector = Detector()
    if not detector.ready:
        parser.error("Train compatible models first.")
    path = args.url_csv or args.email_jsonl
    content = path.read_text(encoding="utf-8-sig")
    report = evaluate_csv(content, detector, args.source) if args.url_csv else evaluate_emails(content, detector, args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
