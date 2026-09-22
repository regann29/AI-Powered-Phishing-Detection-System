"""Train the URL and email classifiers.

Demo data:   python -m app.ml.train --demo
Your data:   python -m app.ml.train --urls data/urls.csv --emails data/emails.csv

CSV formats (label: 1 = phishing, 0 = legitimate):
    urls.csv    url,label
    emails.csv  sender,reply_to,subject,body,label
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .email_features import NUMERIC_FEATURES, extract_email_features
from .synthetic import make_email_frame, make_url_frame
from .url_features import FEATURE_NAMES, extract_url_features

RANDOM_STATE = 42


def _metrics(y_true, y_pred, y_prob, n_train: int, n_test: int) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        "n_train": n_train,
        "n_test": n_test,
    }


def _clean_labels(frame: pd.DataFrame, required: list[str]) -> pd.DataFrame:
    missing = [c for c in required + ["label"] if c not in frame.columns]
    if missing:
        raise SystemExit(f"Missing required column(s): {', '.join(missing)}")
    frame = frame.dropna(subset=["label"]).copy()
    frame["label"] = frame["label"].astype(int)
    if not set(frame["label"]).issubset({0, 1}):
        raise SystemExit("Labels must be 0 (legitimate) or 1 (phishing).")
    if frame["label"].nunique() < 2:
        raise SystemExit("The dataset needs examples of both classes.")
    return frame


def train_url_model(frame: pd.DataFrame):
    frame = _clean_labels(frame.dropna(subset=["url"]), ["url"])
    X = pd.DataFrame([extract_url_features(u) for u in frame["url"]], columns=FEATURE_NAMES)
    y = frame["label"]
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE)
    model = RandomForestClassifier(
        n_estimators=300, min_samples_leaf=2, class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE
    )
    model.fit(X_tr, y_tr)
    prob = model.predict_proba(X_te)[:, list(model.classes_).index(1)]
    return model, _metrics(y_te, model.predict(X_te), prob, len(X_tr), len(X_te))


def build_email_pipeline() -> Pipeline:
    prep = ColumnTransformer(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=20_000,
                                      sublinear_tf=True, stop_words="english"), "text"),
            ("num", StandardScaler(), NUMERIC_FEATURES),
        ]
    )
    clf = LogisticRegression(C=2.0, max_iter=2000, class_weight="balanced")
    return Pipeline([("prep", prep), ("clf", clf)])


def train_email_model(frame: pd.DataFrame):
    frame = _clean_labels(frame.dropna(subset=["body"]), ["body"])
    for column in ("sender", "reply_to", "subject"):
        if column not in frame.columns:
            frame[column] = ""
        frame[column] = frame[column].fillna("").astype(str)
    rows = [
        extract_email_features(r.sender, r.reply_to, r.subject, str(r.body))
        for r in frame.itertuples(index=False)
    ]
    X = pd.DataFrame(rows, columns=NUMERIC_FEATURES + ["text"])
    y = frame["label"].reset_index(drop=True)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE)
    model = build_email_pipeline().fit(X_tr, y_tr)
    prob = model.predict_proba(X_te)[:, list(model.classes_).index(1)]
    return model, _metrics(y_te, model.predict(X_te), prob, len(X_tr), len(X_te))


def save_models(out_dir: Path, url_model, email_model, url_metrics: dict, email_metrics: dict, source: str) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    trained_at = datetime.now(timezone.utc)
    feature_hash = hashlib.sha256(",".join(FEATURE_NAMES + NUMERIC_FEATURES).encode()).hexdigest()[:12]
    metadata = {
        "version": f"{trained_at:%Y%m%d%H%M%S}-{'demo' if source == 'demo' else 'custom'}",
        "trained_at": trained_at.isoformat(),
        "data_source": source,
        "feature_hash": feature_hash,
        "url_metrics": url_metrics,
        "email_metrics": email_metrics,
    }
    joblib.dump(url_model, out_dir / "url_model.joblib")
    joblib.dump(email_model, out_dir / "email_model.joblib")
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return metadata


def train_all(url_frame: pd.DataFrame, email_frame: pd.DataFrame, out_dir: Path, source: str) -> dict:
    url_model, url_metrics = train_url_model(url_frame)
    email_model, email_metrics = train_email_model(email_frame)
    return save_models(Path(out_dir), url_model, email_model, url_metrics, email_metrics, source)


def train_all_demo(out_dir: Path, size: int = 3000) -> dict:
    return train_all(make_url_frame(size), make_email_frame(max(size // 2, 400)), Path(out_dir), "demo")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--demo", action="store_true", help="train on generated synthetic data")
    parser.add_argument("--urls", type=Path, help="CSV with columns: url,label")
    parser.add_argument("--emails", type=Path, help="CSV with columns: sender,reply_to,subject,body,label")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[2] / "models")
    args = parser.parse_args()

    if args.demo:
        meta = train_all_demo(args.out)
        print("WARNING: trained on synthetic demo data. These metrics say nothing about real-world accuracy.")
    elif args.urls and args.emails:
        meta = train_all(pd.read_csv(args.urls), pd.read_csv(args.emails), args.out, "custom")
    else:
        parser.error("Use --demo, or pass both --urls and --emails.")
    print(json.dumps(meta, indent=2))
    print(f"Models saved to {args.out}")


if __name__ == "__main__":
    main()
