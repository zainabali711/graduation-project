"""Training script for the hybrid URL classification model."""

import json
import os
import sys

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.brands import benign_brand_urls
from model.features import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model", "saved")
MODEL_PATH = os.path.join(MODEL_DIR, "hybrid_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")
SAMPLE_SIZE = 100000


def _make_rf():
    return RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
    )


def _make_svm():
    base_svm = SVC(kernel="rbf", random_state=42)
    return CalibratedClassifierCV(base_svm, cv=3)


def _inject_benign_brands(df: pd.DataFrame) -> pd.DataFrame:
    """Append / overweight known-good brand URLs as benign (result=0)."""
    brand_urls = benign_brand_urls()
    # Repeat so stratified 50k benign sample keeps many brand examples
    rows = []
    for _ in range(8):
        for u in brand_urls:
            rows.append({"url": u, "label": "benign", "result": 0})
    brand_df = pd.DataFrame(rows)
    out = pd.concat([df, brand_df], ignore_index=True)
    out.drop_duplicates(subset=["url"], keep="last", inplace=True)
    return out


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    df = pd.read_csv(DATA_PATH)
    df.drop_duplicates(inplace=True)
    df.dropna(inplace=True)
    df = _inject_benign_brands(df)

    if len(df) > SAMPLE_SIZE:
        n_per_class = SAMPLE_SIZE // 2
        df0 = df[df["result"] == 0].sample(n=n_per_class, random_state=42)
        df1 = df[df["result"] == 1].sample(n=n_per_class, random_state=42)
        # Force-include brand homepages even after sampling
        brands = pd.DataFrame(
            [{"url": u, "label": "benign", "result": 0} for u in benign_brand_urls()]
        )
        df = (
            pd.concat([df0, df1, brands])
            .drop_duplicates(subset=["url"], keep="last")
            .sample(frac=1, random_state=42)
            .reset_index(drop=True)
        )

    print(f"Training on {len(df)} samples (SAMPLE_SIZE={SAMPLE_SIZE})")
    print("Models: Random Forest + Calibrated SVM (RBF, soft voting)")
    print("Guards: brand allowlist feature, no has_https, rich domain priors")

    features_list = [extract_features(url, live_enrich=False) for url in df["url"]]
    X = pd.DataFrame(features_list)
    y = df["result"].reset_index(drop=True)

    valid = X.notna().all(axis=1)
    X = X.loc[valid].reset_index(drop=True)
    y = y.loc[valid.values].reset_index(drop=True)

    print(f"Feature columns ({X.shape[1]}): {list(X.columns)}")
    assert "has_https" not in X.columns
    for col in (
        "is_known_brand",
        "domain_age_days",
        "dns_resolves",
        "ssl_valid",
        "has_known_tld",
        "consonant_ratio",
        "digit_in_domain",
        "repeated_chars",
        "domain_word_count",
    ):
        assert col in X.columns, f"missing feature {col}"

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = _make_rf()
    svm = _make_svm()

    hybrid = VotingClassifier(
        estimators=[("rf", rf), ("svm", svm)],
        voting="soft",
    )

    pipeline = Pipeline([("scaler", StandardScaler()), ("model", hybrid)])
    print("Fitting hybrid model (calibrated SVM may take a while)...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    print("Accuracy: ", accuracy_score(y_test, y_pred))
    print("Precision: ", precision_score(y_test, y_pred))
    print("Recall: ", recall_score(y_test, y_pred))
    print("F1-Score: ", f1_score(y_test, y_pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    scaler = pipeline.named_steps["scaler"]
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    rf_standalone = _make_rf()
    svm_standalone = _make_svm()
    print("Fitting standalone RF and calibrated SVM for comparison metrics...")
    rf_standalone.fit(X_train_scaled, y_train)
    svm_standalone.fit(X_train_scaled, y_train)

    rf_acc = accuracy_score(y_test, rf_standalone.predict(X_test_scaled))
    svm_acc = accuracy_score(y_test, svm_standalone.predict(X_test_scaled))
    hybrid_acc = accuracy_score(y_test, y_pred)

    joblib.dump(pipeline, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    metrics = {
        "accuracy": round(hybrid_acc * 100, 2),
        "precision": round(precision_score(y_test, y_pred) * 100, 2),
        "recall": round(recall_score(y_test, y_pred) * 100, 2),
        "f1": round(f1_score(y_test, y_pred) * 100, 2),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "rf_accuracy": round(rf_acc * 100, 2),
        "svm_accuracy": round(svm_acc * 100, 2),
        "lr_accuracy": round(svm_acc * 100, 2),
        "hybrid_accuracy": round(hybrid_acc * 100, 2),
        "dataset_size": len(df),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "malicious_count": int((y == 1).sum()),
        "benign_count": int((y == 0).sum()),
        "feature_count": int(X.shape[1]),
        "ensemble": "Random Forest + Calibrated SVM (Soft Voting)",
        "ml_guards": "allowlist + 95% threshold + RF/SVM agree + rich domain features",
        "dropped_features": ["has_https"],
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved to {MODEL_PATH}")
    print(f"Metrics saved to {METRICS_PATH}")


if __name__ == "__main__":
    main()
