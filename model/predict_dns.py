"""Offline DNS query-name prediction + generalization (OOD) indicator."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from model.dns_features import DNS_FEATURE_COLUMNS, extract_dns_features, extract_dns_features_dict

BASE_DIR = Path(__file__).resolve().parent
SAVED = BASE_DIR / "saved"
MODEL_PATH = SAVED / "dns_model.pkl"
RANGES_PATH = SAVED / "dns_feature_ranges.json"

KEY_FEATURES = [
    "dns_domain_name_length",
    "dns_subdomain_name_length",
    "character_entropy",
    "numerical_percentage",
    "digit_count",
]


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"DNS model not found: {MODEL_PATH}")
    return joblib.load(MODEL_PATH)


@lru_cache(maxsize=1)
def _load_ranges() -> dict:
    if not RANGES_PATH.is_file():
        return {"key_features": KEY_FEATURES, "ranges": {}}
    return json.loads(RANGES_PATH.read_text(encoding="utf-8"))


def _generalization_assessment(feats: dict) -> dict:
    """
    Count how many key features fall outside [p1, p99] of the training sample.
    0 -> In-distribution, 1 -> Borderline, >=2 -> Out-of-distribution.
    Score: max(0, 100 - 35 * n_outside).
    """
    ranges = _load_ranges().get("ranges") or {}
    outside = []
    for key in KEY_FEATURES:
        bounds = ranges.get(key)
        if not bounds:
            continue
        val = float(feats.get(key, 0) or 0)
        lo, hi = float(bounds["p1"]), float(bounds["p99"])
        if val < lo or val > hi:
            outside.append(
                {
                    "feature": key,
                    "value": val,
                    "p1": lo,
                    "p99": hi,
                }
            )

    n = len(outside)
    if n == 0:
        level = "In-distribution"
        caution = None
    elif n == 1:
        level = "Borderline"
        caution = (
            "One key feature is unusual versus the synthetic training ranges. "
            "Treat the verdict cautiously."
        )
    else:
        level = "Out-of-distribution"
        caution = (
            "This query looks statistically unlike the synthetic training distribution. "
            "The model may not generalize here — do not treat the verdict as reliable."
        )

    score = max(0, min(100, 100 - 35 * n))
    return {
        "level": level,
        "score": score,
        "features_outside_p1_p99": n,
        "outside_details": outside,
        "caution": caution,
    }


def predict_dns_query(query_name: str) -> dict:
    """
    Classify a single DNS query name.
    Returns verdict fields + generalization assessment.
    """
    name = (query_name or "").strip()
    feats_dict = extract_dns_features_dict(name)
    if feats_dict is None:
        raise ValueError("Enter a valid DNS query name (no spaces).")

    X = extract_dns_features(name)
    assert X is not None
    model = _load_model()
    proba = model.predict_proba(X)[0]
    # classes_ order from sklearn
    classes = list(model.named_steps["clf"].classes_)
    # Fallback if pipeline wraps differently
    if not classes:
        classes = [0, 1]
    proba_map = {int(c): float(p) for c, p in zip(classes, proba)}
    p_benign = proba_map.get(0, 0.0) * 100.0
    p_mal = proba_map.get(1, 0.0) * 100.0
    pred = int(model.predict(X)[0])
    label = "Malicious" if pred == 1 else "Benign"
    confidence = p_mal if pred == 1 else p_benign
    if confidence >= 85:
        risk = "High" if pred == 1 else "Low"
    elif confidence >= 65:
        risk = "Medium"
    else:
        risk = "Elevated" if pred == 1 else "Low"

    gen = _generalization_assessment(feats_dict)

    return {
        "query_name": name.rstrip("."),
        "label": label,
        "result": "Malicious" if pred == 1 else "Safe",
        "benign_probability": round(p_benign, 2),
        "malicious_probability": round(p_mal, 2),
        "confidence": round(confidence, 2),
        "risk_level": risk,
        "features": {k: feats_dict[k] for k in DNS_FEATURE_COLUMNS},
        "generalization": gen,
        "dataset_caveat": (
            "Trained on the synthetic Daumel DNS tunneling/exfiltration dataset; "
            "may not reflect real-world DNS traffic."
        ),
        "verdict_source": "dns_ml_query_name",
    }
