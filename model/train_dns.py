"""
Training script for the hybrid DNS query-name classifier.

Mirrors model/train.py (RF + Calibrated SVM soft voting) but:
  - Reads data/dns_dataset.csv
  - Uses model/dns_features.py (query-name features only)
  - Writes model/saved/dns_model.pkl and model/saved/dns_metrics.json
  - Does NOT overwrite URL hybrid_model.pkl / metrics.json

Run (after confirming SAMPLE_SIZE):
  python model/train_dns.py

Dataset caveat: Daumel DNS data is synthetic and may not reflect real-world DNS.
"""

from __future__ import annotations

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
from model.dns_features import (
    DNS_FEATURE_COLUMNS,
    dataframe_from_dns_csv,
    label_to_int,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "dns_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model", "saved")
MODEL_PATH = os.path.join(MODEL_DIR, "dns_model.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "dns_metrics.json")

# Same default as URL trainer — confirm before long runs on full 1.5M rows.
SAMPLE_SIZE = 100_000


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


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print(f"Loading {DATA_PATH} …", flush=True)
    # Only columns needed for feature rebuild + label (keeps memory down).
    usecols = ["dns_domain_name", "label"]
    df = pd.read_csv(DATA_PATH, usecols=usecols, low_memory=False)
    df = df.dropna(subset=["dns_domain_name", "label"])
    df["result"] = df["label"].map(label_to_int)

    print(
        f"Loaded rows={len(df):,} labels={df['label'].value_counts().to_dict()}",
        flush=True,
    )

    if len(df) > SAMPLE_SIZE:
        n_per_class = SAMPLE_SIZE // 2
        df0 = df[df["result"] == 0].sample(n=min(n_per_class, (df["result"] == 0).sum()), random_state=42)
        df1 = df[df["result"] == 1].sample(n=min(n_per_class, (df["result"] == 1).sum()), random_state=42)
        df = pd.concat([df0, df1], ignore_index=True).sample(frac=1, random_state=42)
        print(f"Sampled to {len(df):,} rows ({n_per_class}/class target)", flush=True)

    print("Extracting query-name features …", flush=True)
    X = dataframe_from_dns_csv(df)
    y = df["result"].astype(int).values
    assert list(X.columns) == DNS_FEATURE_COLUMNS

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                VotingClassifier(
                    estimators=[
                        ("rf", _make_rf()),
                        ("svm", _make_svm()),
                    ],
                    voting="soft",
                ),
            ),
        ]
    )

    print("Training hybrid RF + Calibrated SVM …", flush=True)
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    metrics = {
        "module": "dns_query_classifier",
        "dataset_caveat": (
            "Synthetically generated (Daumel DNS tunneling/exfiltration dataset); "
            "may not reflect real-world DNS traffic."
        ),
        "feature_columns": DNS_FEATURE_COLUMNS,
        "sample_size_cap": SAMPLE_SIZE,
        "dataset_size": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "label_mapping": {"Benign": 0, "Malicious": 1},
    }

    joblib.dump(pipeline, MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(json.dumps(metrics, indent=2), flush=True)
    print(f"Saved {MODEL_PATH}", flush=True)
    print(f"Saved {METRICS_PATH}", flush=True)


if __name__ == "__main__":
    main()
