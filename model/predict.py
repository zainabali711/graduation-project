"""Prediction and explainability logic for URL classification."""

import os

import joblib
import numpy as np
import pandas as pd

from model.features import extract_features
from model.virustotal import check_url

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model", "saved", "hybrid_model.pkl")

pipeline = joblib.load(MODEL_PATH)


def _infer_subtype(features: dict, is_malicious: bool) -> str:
    """Heuristic subtype based on extracted features."""
    if not is_malicious:
        return "Legitimate"
    if features.get("has_at_symbol") or features.get("has_ip_address"):
        return "Phishing"
    if features.get("is_shortened"):
        return "Suspicious Redirect"
    if features.get("tld_suspicious"):
        return "Suspicious TLD"
    if features.get("entropy", 0) > 4.0:
        return "Obfuscated Domain"
    return "Malware / Fraud"


def _risk_from_malicious_prob(malicious_prob: float) -> tuple[str, str]:
    if malicious_prob >= 75:
        return "High", "danger"
    if malicious_prob >= 50:
        return "Medium", "warning"
    if malicious_prob >= 25:
        return "Low", "info"
    return "Safe", "success"


def _class_proba(model, X) -> dict[int, float]:
    """Map class label → probability for a fitted classifier."""
    proba = model.predict_proba(X)[0]
    return {int(c): float(p) for c, p in zip(model.classes_, proba)}


def _hybrid_soft_vote(rf_model, svm_model, X_scaled) -> tuple[float, float]:
    """Soft-vote average of RF + SVM. Returns (malicious_pct, benign_pct)."""
    rf_p = _class_proba(rf_model, X_scaled)
    svm_p = _class_proba(svm_model, X_scaled)

    mal = (rf_p.get(1, 0.0) + svm_p.get(1, 0.0)) / 2.0
    ben = (rf_p.get(0, 0.0) + svm_p.get(0, 0.0)) / 2.0
    total = mal + ben
    if total <= 0:
        mal, ben = 0.5, 0.5
    else:
        mal, ben = mal / total, ben / total

    malicious_pct = round(mal * 100, 2)
    benign_pct = round(100 - malicious_pct, 2)
    return malicious_pct, benign_pct


def _apply_majority_verdict(result: dict) -> dict:
    """
    Final verdict = simple majority of probabilities.
    - malicious > benign → MALICIOUS / SAFE display uses Malicious
    - benign > malicious → Benign / SAFE
    Tie → Benign
    """
    mal = round(float(result.get("malicious_probability") or 0), 2)
    ben = round(float(result.get("benign_probability") or 0), 2)
    total = mal + ben
    if total <= 0:
        mal, ben = 50.0, 50.0
    elif abs(total - 100) > 0.05:
        mal = round(mal / total * 100, 2)
        ben = round(100 - mal, 2)
    else:
        ben = round(100 - mal, 2)

    is_malicious = mal > ben
    final_label = "Malicious" if is_malicious else "Benign"

    result["malicious_probability"] = mal
    result["benign_probability"] = ben
    result["is_malicious"] = is_malicious
    result["label"] = final_label
    result["final_label"] = final_label
    result["final_is_malicious"] = is_malicious
    result["confidence"] = round(mal if is_malicious else ben, 2)
    result["risk_level"], result["risk_color"] = _risk_from_malicious_prob(mal)
    result["subtype"] = _infer_subtype(result.get("features") or {}, is_malicious)
    return result


def _attach_virustotal(result: dict, vt: dict) -> dict:
    """
    Final verdict = ML + VirusTotal when VT is available.

    - Hybrid row stays ML soft-vote majority only.
    - Final blends ML malicious% with VT positives/total (50/50), then majority.
    - If VT unavailable → Final stays ML majority; UI shows yellow warning.
    """
    result = dict(result)
    result["virustotal"] = vt
    result["ml_label"] = result["label"]
    result["ml_is_malicious"] = result["is_malicious"]
    ml_mal = float(result.get("malicious_probability") or 0)
    ml_ben = float(result.get("benign_probability") or 0)

    if not vt.get("available"):
        result["verdict_source"] = "ml_only"
        result["vt_unavailable"] = True
        # UI shows the yellow unavailable card only (no technical dump).
        result["correction_note"] = ""
        print(
            f"[VirusTotal][DIAG] predict_attach available=False "
            f"error_detail={vt.get('error_detail')!r}",
            flush=True,
        )
        return result

    positives = int(vt.get("positives", 0))
    total = int(vt.get("total_engines", 0))
    vt_mal = round((positives / total) * 100, 2) if total else 0.0
    vt_ben = round(100 - vt_mal, 2)

    # 50/50 blend of ML soft-vote and VirusTotal engine ratio
    combined_mal = round((ml_mal + vt_mal) / 2.0, 2)
    combined_ben = round(100 - combined_mal, 2)
    result["malicious_probability"] = combined_mal
    result["benign_probability"] = combined_ben
    result["vt_malicious_probability"] = vt_mal
    result["vt_benign_probability"] = vt_ben
    result["vt_unavailable"] = False
    result["verdict_source"] = "ml_virustotal"

    result = _apply_majority_verdict(result)
    result["correction_note"] = (
        f"Final = ML + VirusTotal "
        f"(ML Mal {ml_mal:.2f}% / Ben {ml_ben:.2f}% · "
        f"VT {positives}/{total or '?'} → Mal {vt_mal:.2f}%). "
        f"Combined Mal {combined_mal:.2f}% vs Ben {combined_ben:.2f}% "
        f"→ {result['final_label']}."
    )
    return result


def predict_url(url: str) -> dict:
    """
    Full prediction pipeline for a single URL.
    Final decision = higher of malicious_probability vs benign_probability.
    """
    if not url or not url.strip():
        raise ValueError("URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url.strip()

    features = extract_features(url, live_enrich=True)
    if not features:
        raise ValueError("Could not extract features from URL")

    feat_names = list(pipeline.feature_names_in_)
    X = pd.DataFrame([features])[feat_names]

    scaler = pipeline.named_steps["scaler"]
    hybrid = pipeline.named_steps["model"]
    rf_model = hybrid.estimators_[0]
    svm_model = hybrid.estimators_[1]

    X_scaled = scaler.transform(X)

    rf_prob = rf_model.predict_proba(X_scaled)[0]
    svm_prob = svm_model.predict_proba(X_scaled)[0]
    rf_pred = int(rf_model.predict(X_scaled)[0])
    svm_pred = int(svm_model.predict(X_scaled)[0])

    malicious_prob, benign_prob = _hybrid_soft_vote(rf_model, svm_model, X_scaled)
    is_malicious = malicious_prob > benign_prob
    hybrid_label = "Malicious" if is_malicious else "Benign"
    confidence = round(malicious_prob if is_malicious else benign_prob, 2)

    importances = rf_model.feature_importances_
    feature_importance_pairs = sorted(
        zip(feat_names, importances, X.values[0]),
        key=lambda x: x[1],
        reverse=True,
    )[:6]

    explanation = [
        {
            "feature": name,
            "importance": round(float(imp), 4),
            "value": round(float(val), 3),
        }
        for name, imp, val in feature_importance_pairs
    ]

    rf_mal = round(float(_class_proba(rf_model, X_scaled).get(1, 0.0)) * 100, 2)
    svm_mal = round(float(_class_proba(svm_model, X_scaled).get(1, 0.0)) * 100, 2)
    rf_conf = round(float(np.max(rf_prob)) * 100, 2)
    svm_conf = round(float(np.max(svm_prob)) * 100, 2)

    svm_vote = {
        "label": "Malicious" if svm_pred == 1 else "Benign",
        "confidence": max(svm_conf, 1.0),
        "malicious_probability": svm_mal,
    }

    result = {
        "url": url,
        "label": hybrid_label,
        "subtype": _infer_subtype(features, is_malicious),
        "is_malicious": is_malicious,
        "confidence": confidence,
        "malicious_probability": malicious_prob,
        "benign_probability": benign_prob,
        "risk_level": _risk_from_malicious_prob(malicious_prob)[0],
        "risk_color": _risk_from_malicious_prob(malicious_prob)[1],
        "features": features,
        "explanation": explanation,
        "model_votes": {
            "random_forest": {
                "label": "Malicious" if rf_pred == 1 else "Benign",
                "confidence": max(rf_conf, 1.0),
                "malicious_probability": rf_mal,
            },
            "svm": svm_vote,
            "logistic_regression": svm_vote,
            "hybrid": {
                "label": hybrid_label,
                "confidence": confidence,
                "malicious_probability": malicious_prob,
                "benign_probability": benign_prob,
            },
        },
    }

    result = _apply_majority_verdict(result)
    # Hybrid row = ML majority only (before VirusTotal blend)
    result["model_votes"]["hybrid"] = {
        "label": result["final_label"],
        "confidence": result["confidence"],
        "malicious_probability": result["malicious_probability"],
        "benign_probability": result["benign_probability"],
    }

    vt = check_url(url)
    return _attach_virustotal(result, vt)
