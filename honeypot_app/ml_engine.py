from pathlib import Path

import joblib
import pandas as pd

MODEL_PATH = Path(__file__).resolve().parent / "ml" / "smartsoc_model.pkl"

_bundle = None


def _load():
    """The model is loaded only once, the first time it is used."""
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def _safe_encode(encoder, value):
    if value in encoder.classes_:
        return int(encoder.transform([value])[0])
    return -1


def risk_bucket(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def predict_event(event):
    """event: dict with the 14 raw features. Returns a result dict, or None on failure."""
    try:
        b = _load()
        row = dict(event)
        for col in b["cat_cols"]:
            row[col + "_enc"] = _safe_encode(b["encoders"][col], str(event[col]))
        X = pd.DataFrame([{k: row[k] for k in b["feature_cols"]}])

        clf = b["classifier"]
        label = clf.predict(X)[0]
        probs = dict(zip(clf.classes_, clf.predict_proba(X)[0]))
        confidence = round(float(probs[label]), 3)

        score = float(b["regressor"].predict(X)[0])
        score = round(max(0.0, min(100.0, score)), 1)

        return {
            "label": str(label),
            "confidence": confidence,
            "risk_score": score,
            "priority": risk_bucket(score),
        }
    except Exception as e:
        print("ML error:", e)
        return None