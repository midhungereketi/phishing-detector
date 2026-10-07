"""Download public corpora, train models, and save reproducible held-out evaluation.

Run from the repository root: python -m backend.train --download
Only named dataset hosts are contacted. Submitted targets are never visited.
"""
import argparse
import csv
import hashlib
import io
import json
import mailbox
import random
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

import joblib
import numpy as np
import sklearn
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.frozen import FrozenEstimator
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .features import domain_group, parse_email, url_features
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
DATA = ROOT / "data"
MODELS = ROOT / "models"
SOURCES = {
    "urls.zip": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
    "phishing.mbox": "https://monkey.org/~jose/phishing/phishing-2023",
    "easy_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "hard_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
}
SEED = 42


def download():
    DATA.mkdir(exist_ok=True)
    for name, url in SOURCES.items():
        path = DATA / name
        if path.exists():
            continue
        print(f"Downloading {name} from {url}", flush=True)
        temporary = path.with_suffix(path.suffix + ".partial")
        with urlopen(url, timeout=90) as response, temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        temporary.replace(path)


def metrics(labels, probability):
    predictions = probability >= 0.5
    matrix = confusion_matrix(labels, predictions, labels=[0, 1]).tolist()
    tn, fp = matrix[0]
    observed, predicted = calibration_curve(labels, probability, n_bins=8, strategy="uniform")
    thresholds = []
    for threshold in (.3, .5, .7, .9):
        decisions = probability >= threshold
        a, b, c, d = confusion_matrix(labels, decisions, labels=[0, 1]).ravel()
        thresholds.append({"threshold": threshold, "precision": round(float(precision_score(labels, decisions, zero_division=0)), 4), "recall": round(float(recall_score(labels, decisions, zero_division=0)), 4), "false_positive_rate": round(float(b / max(a + b, 1)), 4), "false_positives": int(b), "false_negatives": int(c)})
    return {
        "accuracy": round(float(accuracy_score(labels, predictions)), 4),
        "precision": round(float(precision_score(labels, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(labels, predictions, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(labels, probability)), 4),
        "false_positive_rate": round(fp / max(tn + fp, 1), 4),
        "confusion_matrix": matrix, "test_samples": len(labels),
        "class_counts": {"legitimate": int(sum(labels == 0)), "phishing": int(sum(labels == 1))},
        "brier_score": round(float(brier_score_loss(labels, probability)), 5),
        "reliability": [{"predicted": round(float(p), 4), "observed": round(float(o), 4)} for p, o in zip(predicted, observed)],
        "thresholds": thresholds,
    }


def train_urls(max_samples):
    buckets = {0: [], 1: []}
    with zipfile.ZipFile(DATA / "urls.zip") as archive:
        name = next(n for n in archive.namelist() if n.lower().endswith(".csv"))
        with archive.open(name) as content:
            for row in csv.DictReader(io.TextIOWrapper(content, encoding="utf-8-sig")):
                # UCI's 0 means phishing; internally 1 always means phishing.
                buckets[1 - int(row["label"])].append(row["URL"])
    rng = random.Random(SEED)
    rows, seen = [], set()
    rejected = 0
    for label in (0, 1):
        rng.shuffle(buckets[label])
        count = 0
        for value in buckets[label]:
            try:
                normalized, features = url_features(value)
            except ValueError:
                rejected += 1
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            rows.append((features, label, domain_group(urlsplit(normalized).hostname)))
            count += 1
            if count >= max_samples // 2:
                break
    source_counts = {'UCI PhiUSIIL': len(rows)}
    modern = DATA / 'phreshphish-training.csv'
    if modern.exists():
        count = 0
        with modern.open(encoding='utf-8') as content:
            for row in csv.DictReader(content):
                try:
                    normalized, features = url_features(row['url'])
                    label = int(row['label'])
                    if label not in (0, 1) or normalized in seen:
                        continue
                    seen.add(normalized)
                    rows.append((features, label, domain_group(urlsplit(normalized).hostname)))
                    count += 1
                except ValueError:
                    rejected += 1
        source_counts['PhreshPhish publisher training slice'] = count
    labels = np.array([row[1] for row in rows])
    groups = np.array([row[2] for row in rows])
    indices = np.arange(len(rows))
    train_val, test = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED).split(indices, labels, groups))
    train_relative, val_relative = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=SEED + 1).split(train_val, labels[train_val], groups[train_val]))
    train, tuning_cal = train_val[train_relative], train_val[val_relative]
    tune_rel, cal_rel = next(GroupShuffleSplit(n_splits=1, test_size=.5, random_state=SEED + 2).split(tuning_cal, labels[tuning_cal], groups[tuning_cal]))
    val, calibration = tuning_cal[tune_rel], tuning_cal[cal_rel]
    splits = [train, val, calibration, test]
    assert all(not (set(groups[a]) & set(groups[b])) for i, a in enumerate(splits) for b in splits[i + 1:])
    vectorizer = DictVectorizer(sparse=False)
    x_train = vectorizer.fit_transform([rows[i][0] for i in train])
    x_val = vectorizer.transform([rows[i][0] for i in val])
    candidates = {
        "Random Forest": RandomForestClassifier(n_estimators=160, max_depth=16, min_samples_leaf=2, class_weight="balanced", random_state=SEED, n_jobs=2),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)),
    }
    validation = {}
    for name, model in candidates.items():
        print(f"Training URL {name} on {len(train)} rows", flush=True)
        model.fit(x_train, labels[train])
        validation[name] = metrics(labels[val], model.predict_proba(x_val)[:, 1])
    selected = max(validation, key=lambda name: validation[name]["f1"])
    # Refit on train+tuning only, calibrate on separate domains, evaluate untouched test.
    fit = np.concatenate([train, val])
    vectorizer.fit([rows[i][0] for i in fit])
    model = candidates[selected]
    model.fit(vectorizer.transform([rows[i][0] for i in fit]), labels[fit])
    calibrated = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid")
    calibrated.fit(vectorizer.transform([rows[i][0] for i in calibration]), labels[calibration])
    x_test = vectorizer.transform([rows[i][0] for i in test])
    before = metrics(labels[test], model.predict_proba(x_test)[:, 1])
    evaluation = metrics(labels[test], calibrated.predict_proba(x_test)[:, 1])
    importance = model.feature_importances_ if hasattr(model, "feature_importances_") else np.abs(model[-1].coef_[0])
    top = sorted(zip(vectorizer.get_feature_names_out(), importance), key=lambda p: p[1], reverse=True)[:10]
    joblib.dump({"model": model, "calibrated": calibrated, "vectorizer": vectorizer, "name": selected, "dataset_domains": {hashlib.sha256(str(group).encode()).hexdigest() for group in groups}}, MODELS / "url_model.joblib", compress=3)
    return {
        "name": selected, "dataset": "UCI PhiUSIIL (2024) + PhreshPhish modern training slice" if modern.exists() else "UCI PhiUSIIL (2024), balanced sample", "samples": len(rows), "source_counts": source_counts,
        "train_samples": len(fit), "validation_samples": len(val), "calibration_samples": len(calibration), "features": len(vectorizer.get_feature_names_out()),
        "split": "60/10/10/20 by registered domain; select on tuning, refit on train+tuning, sigmoid calibrate on separate 10%, evaluate untouched 20%",
        "calibration": {"method": "sigmoid on disjoint domains", "before_brier": before["brier_score"], "after_brier": evaluation["brier_score"], "before_metrics": before},
        "domain_overlap": 0, "invalid_rows_skipped": rejected, "metrics": evaluation,
        "validation_comparison": validation, "top_features": [{"name": str(n), "importance": round(float(v), 4)} for n, v in top],
        "limitations": "Lexical model only; live observations and feed policy are separate. Calibration is dataset-specific and may not transfer to modern URLs. Dataset patterns and balanced prevalence can inflate results. Network failures are not clean verdicts.",
    }


def email_rows():
    rows, seen = [], set()

    def add(raw, label):
        parsed = parse_email(raw)
        text = parsed["model_text"]
        # Deduplicate after normalizing addresses, digits and URL identities.
        fingerprint = hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
        if len(text.strip()) >= 20 and fingerprint not in seen:
            seen.add(fingerprint)
            rows.append((text, parsed["features"], label))

    for name in ("easy_ham.tar.bz2", "hard_ham.tar.bz2"):
        with tarfile.open(DATA / name, "r:bz2") as archive:
            for member in archive:
                if member.isfile() and not member.name.endswith("cmds"):
                    with archive.extractfile(member) as content:
                        add(content.read(500000), 0)
    corpus = mailbox.mbox(str(DATA / "phishing.mbox"), create=False)
    try:
        for message in corpus:
            add(message.as_bytes(), 1)
    finally:
        corpus.close()
    return rows


def train_emails():
    rows = email_rows()
    labels = np.array([r[2] for r in rows])
    # Group matching normalized-text prefixes to reduce simple campaign leakage.
    groups = np.array([hashlib.sha256(' '.join(row[0].lower().split())[:120].encode()).hexdigest() for row in rows])
    indices = np.arange(len(rows))
    fit_cal, test = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED).split(indices, labels, groups))
    fit_rel, cal_rel = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=SEED + 1).split(fit_cal, labels[fit_cal], groups[fit_cal]))
    train, calibration = fit_cal[fit_rel], fit_cal[cal_rel]
    assert all(len(set(labels[split])) == 2 for split in (train, calibration, test))
    assert all(not (set(groups[a]) & set(groups[b])) for a, b in ((train, calibration), (train, test), (calibration, test)))
    text_vectorizer = TfidfVectorizer(max_features=12000, ngram_range=(1, 2), min_df=2, sublinear_tf=True, strip_accents="unicode")
    metadata_vectorizer = DictVectorizer()
    x_train = hstack([text_vectorizer.fit_transform([rows[i][0] for i in train]), metadata_vectorizer.fit_transform([rows[i][1] for i in train])]).tocsr()
    x_test = hstack([text_vectorizer.transform([rows[i][0] for i in test]), metadata_vectorizer.transform([rows[i][1] for i in test])]).tocsr()
    model = LogisticRegression(max_iter=2000, class_weight="balanced", C=2, random_state=SEED)
    print(f"Training email TF-IDF + Logistic Regression on {len(train)} messages", flush=True)
    model.fit(x_train, labels[train])
    x_cal = hstack([text_vectorizer.transform([rows[i][0] for i in calibration]), metadata_vectorizer.transform([rows[i][1] for i in calibration])]).tocsr()
    calibrated = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid")
    calibrated.fit(x_cal, labels[calibration])
    before = metrics(labels[test], model.predict_proba(x_test)[:, 1])
    evaluation = metrics(labels[test], calibrated.predict_proba(x_test)[:, 1])
    joblib.dump({"model": model, "calibrated": calibrated, "text_vectorizer": text_vectorizer, "metadata_vectorizer": metadata_vectorizer, "name": "TF-IDF + Logistic Regression", "dataset_prefixes": set(groups)}, MODELS / "email_model.joblib", compress=3)
    return {
        "name": "TF-IDF + Logistic Regression", "dataset": "Nazario phishing-2023 + SpamAssassin easy/hard ham (2003)",
        "samples": len(rows), "train_samples": len(train), "calibration_samples": len(calibration), "features": x_train.shape[1], "metrics": evaluation,
        "split": "60/20/20 grouped by normalized-text prefix after deduplication; training vocabulary only; separate sigmoid calibration",
        "group_overlap": 0, "calibration": {"method": "sigmoid on disjoint normalized-prefix groups", "before_brier": before["brier_score"], "after_brier": evaluation["brier_score"], "before_metrics": before},
        "class_counts": {"legitimate": int(sum(labels == 0)), "phishing": int(sum(labels == 1))},
        "limitations": "Educational baseline: ham and phishing come from different sources and years, creating source/temporal bias. Related campaigns may remain across splits. Held-out accuracy does not demonstrate modern inbox performance. Pasted authentication headers are untrusted observations.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--url-samples", type=int, default=30000)
    args = parser.parse_args()
    if args.url_samples < 1000:
        parser.error("Use at least 1000 URL samples.")
    if args.download:
        download()
    missing = [name for name in SOURCES if not (DATA / name).exists()]
    if missing:
        parser.error("Missing corpora. Run with --download: " + ", ".join(missing))
    MODELS.mkdir(exist_ok=True)
    report = {
        "trained_at": datetime.now(timezone.utc).isoformat(), "seed": SEED, "sklearn_version": sklearn.__version__,
        "feature_extractor_sha256": hashlib.sha256((ROOT / "features.py").read_bytes()).hexdigest(),
        "positive_class": "phishing = 1", "url": train_urls(args.url_samples), "email": train_emails(),
        "sources": [{"file": name, "url": url, "sha256": hashlib.sha256((DATA / name).read_bytes()).hexdigest()} for name, url in SOURCES.items()] + ([{"file": "phreshphish-training.csv", "url": "https://huggingface.co/datasets/phreshphish/phreshphish", "sha256": hashlib.sha256((DATA / 'phreshphish-training.csv').read_bytes()).hexdigest()}] if (DATA / 'phreshphish-training.csv').exists() else []),
    }
    (MODELS / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({kind: report[kind]["metrics"] for kind in ("url", "email")}, indent=2))


if __name__ == "__main__":
    main()
