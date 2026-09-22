"""Loads the trained models and turns their output into a risk score with explanations."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import sparse

from .email_features import NUMERIC_FEATURES, email_indicators, extract_email_features
from .url_features import FEATURE_NAMES, extract_url_features, url_indicators

LOW_MAX = 35
MEDIUM_MAX = 70
VERDICTS = {"low": "Likely legitimate", "medium": "Suspicious", "high": "Likely phishing"}


class ModelNotReady(RuntimeError):
    """Raised when the model files have not been trained or copied into MODEL_DIR."""


def risk_level(score: int) -> str:
    if score < LOW_MAX:
        return "low"
    if score < MEDIUM_MAX:
        return "medium"
    return "high"


class Predictor:
    def __init__(self, model_dir: str | Path):
        self.model_dir = Path(model_dir)
        self.url_model = None
        self.email_model = None
        self.metadata: dict = {}
        self.load()

    def load(self) -> None:
        # Model files are pickles. Only load files produced by your own training run.
        url_path = self.model_dir / "url_model.joblib"
        email_path = self.model_dir / "email_model.joblib"
        meta_path = self.model_dir / "metadata.json"
        if url_path.exists():
            self.url_model = joblib.load(url_path)
        if email_path.exists():
            self.email_model = joblib.load(email_path)
        if meta_path.exists():
            self.metadata = json.loads(meta_path.read_text())

    @property
    def ready(self) -> bool:
        return self.url_model is not None and self.email_model is not None

    @property
    def version(self) -> str:
        return self.metadata.get("version", "untrained")

    def _require(self) -> None:
        if not self.ready:
            raise ModelNotReady("Models are not trained yet. Run `python -m app.ml.train --demo` first.")

    @staticmethod
    def _phishing_probability(model, frame: pd.DataFrame) -> float:
        column = list(model.classes_).index(1)
        return float(model.predict_proba(frame)[0][column])

    def predict_url(self, url: str) -> dict:
        self._require()
        frame = pd.DataFrame([extract_url_features(url)], columns=FEATURE_NAMES)
        probability = self._phishing_probability(self.url_model, frame)
        score = int(round(probability * 100))
        level = risk_level(score)
        return {
            "risk_score": score,
            "risk_level": level,
            "verdict": VERDICTS[level],
            "indicators": url_indicators(url),
            "details": {},
        }

    def predict_email(self, sender: str, reply_to: str, subject: str, body: str) -> dict:
        self._require()
        row = extract_email_features(sender, reply_to, subject, body)
        frame = pd.DataFrame([row], columns=NUMERIC_FEATURES + ["text"])
        probability = self._phishing_probability(self.email_model, frame)
        score = int(round(probability * 100))
        level = risk_level(score)
        indicators, flagged_links = email_indicators(row, body)
        return {
            "risk_score": score,
            "risk_level": level,
            "verdict": VERDICTS[level],
            "indicators": indicators,
            "details": {
                "top_terms": self._top_terms(frame),
                "flagged_links": flagged_links,
            },
        }

    def _top_terms(self, frame: pd.DataFrame, limit: int = 6) -> list[dict]:
        """Words that pushed this email toward 'phishing' (TF-IDF weight x model coefficient)."""
        prep = self.email_model.named_steps["prep"]
        clf = self.email_model.named_steps["clf"]
        matrix = prep.transform(frame)
        values = matrix.toarray()[0] if sparse.issparse(matrix) else np.asarray(matrix)[0]
        contributions = values * clf.coef_[0]
        names = prep.get_feature_names_out()
        ranked = np.argsort(contributions)[::-1]
        terms = []
        for idx in ranked:
            name = names[idx]
            if contributions[idx] <= 0:
                break
            if name.startswith("tfidf__") and name != "tfidf__urltoken":
                terms.append({"term": name.split("__", 1)[1], "weight": round(float(contributions[idx]), 3)})
            if len(terms) == limit:
                break
        return terms
