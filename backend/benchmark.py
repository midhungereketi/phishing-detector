"""Read bounded publisher-order PhreshPhish metadata for research.

Hugging Face metadata and remote Parquet column projections only; no target
visits and no HTML column reads. Raw URLs stay in the ignored data folder.
"""
import argparse
import csv
import hashlib
import io
import json
from datetime import datetime, timezone

import httpx
import duckdb

from .detector import Detector, MODEL_DIR
from .evaluate import evaluate_csv
from .intelligence import DATA

SOURCE = "https://huggingface.co/datasets/phreshphish/phreshphish"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-training', action='store_true', help='Download separate publisher training metadata; reserve diagnostic and final test domains.')
    parser.add_argument('--final', action='store_true', help='Evaluate a previously unexamined test-001 slice.')
    args = parser.parse_args()
    DATA.mkdir(exist_ok=True)
    stem = 'phreshphish-final-test-1000' if args.final else 'phreshphish-test-1000'
    path = DATA / (stem + '.csv')
    provenance = DATA / (stem + '-provenance.json')
    def remote_rows(files, limit):
        with httpx.Client(timeout=30, trust_env=False) as client:
            revision = client.get('https://huggingface.co/api/datasets/phreshphish/phreshphish')
            revision.raise_for_status()
        sha = revision.json()['sha']
        extension_dir = DATA / 'duckdb-extensions'
        extension_dir.mkdir(exist_ok=True)
        with duckdb.connect(config={'extension_directory': str(extension_dir), 'threads': 1}) as connection:
            connection.execute('INSTALL httpfs; LOAD httpfs; SET http_timeout=30;')
            urls = [f'https://huggingface.co/datasets/phreshphish/phreshphish/resolve/{sha}/data/{name}.parquet' for name in files]
            metadata = connection.execute('SELECT url,label,date FROM read_parquet(?) LIMIT ?', [urls, limit]).fetchall()
        return metadata, sha
    if not path.exists():
        rows, dates = [], []
        # Remote column projection avoids downloading the large HTML column.
        metadata, sha = remote_rows(['test-001' if args.final else 'test-000'], 1000)
        for url, label, date in metadata:
            if label not in ('phish', 'benign'):
                continue
            rows.append({'url': url, 'label': int(label == 'phish')})
            if date:
                dates.append(str(date))
        print(f'Downloaded URL/label metadata for {len(rows)} test rows; HTML column excluded', flush=True)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)
        path.write_text(output.getvalue(), encoding="utf-8")
        provenance.write_text(json.dumps({"source_url": SOURCE, "revision": sha, "downloaded_at": datetime.now(timezone.utc).isoformat(), "collection_date_range": [min(dates), max(dates)] if dates else None, "sampling": f"First 1000 publisher-order rows of {'test-001' if args.final else 'test-000'}; original phish/benign labels."}, indent=2), encoding="utf-8")
    if args.prepare_training:
        from .features import domain_group, normalize_url
        from urllib.parse import urlsplit
        # Fetch the final slice metadata for overlap exclusion, but do not evaluate it.
        final_metadata, sha = remote_rows(['test-001'], 1000)
        blocked = set()
        for row in list(csv.DictReader(io.StringIO((DATA / 'phreshphish-test-1000.csv').read_text(encoding='utf-8')))) + [{'url': row[0]} for row in final_metadata]:
            try:
                blocked.add(domain_group(urlsplit(normalize_url(row['url'])).hostname))
            except ValueError:
                continue
        metadata, sha = remote_rows(['train-000', 'train-001', 'train-002'], 15000)
        output = io.StringIO(); writer = csv.DictWriter(output, fieldnames=['url', 'label']); writer.writeheader()
        count = 0
        for url, label, date in metadata:
            if label not in ('benign', 'phish'):
                continue
            try:
                normalized = normalize_url(url)
                if domain_group(urlsplit(normalized).hostname) in blocked:
                    continue
            except ValueError:
                continue
            writer.writerow({'url': normalized, 'label': int(label == 'phish')}); count += 1
        (DATA / 'phreshphish-training.csv').write_text(output.getvalue(), encoding='utf-8')
        (DATA / 'phreshphish-training-provenance.json').write_text(json.dumps({'source_url': SOURCE, 'revision': sha, 'rows': count, 'raw_slice': 15000, 'exclusion': 'Diagnostic test-000 and reserved final test-001 registered domains removed before training; no final test predictions inspected.'}, indent=2), encoding='utf-8')
        print(f'Prepared {count} modern training URLs; test domains excluded', flush=True)
        return
    detector = Detector()
    if not detector.ready:
        raise ValueError("Train compatible models first")
    report = evaluate_csv(path.read_text(encoding="utf-8"), detector, f"PhreshPhish v1.0.1 — {'reserved final test-001' if args.final else 'diagnostic test-000'} (1000 rows)")
    report.update(json.loads(provenance.read_text(encoding="utf-8")))
    report["source_verified"] = True  # Download location verified; individual labels not independently audited.
    report["model_sha256"] = {kind: hashlib.sha256((MODEL_DIR / f"{kind}_model.joblib").read_bytes()).hexdigest() for kind in ("url", "email")}
    report["limitations"] = "Small publisher-order slice, not the full benchmark or a random representative sample. Publisher labels are not independently audited. Domains present anywhere in the model corpus are excluded. Model development used a different diagnostic slice; the final test-001 slice was reserved before modern training. No threshold tuning or fitting on these final rows. Supplemental training and final test share the publisher; this is not a completely independent-source benchmark. This checks the URL model only, not the combined policy, live services or email classifier." if args.final else 'Diagnostic publisher-order slice exposed poor generalization and informed later development. This is no longer an untouched final evaluation.'
    (MODEL_DIR / "external_evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
