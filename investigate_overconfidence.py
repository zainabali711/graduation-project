"""Investigate overconfident malicious scores on legitimate sites."""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from model.features import extract_features
from model.predict import _class_proba, _hybrid_soft_vote, pipeline

OUT = Path("investigation_features.json")


def main():
    urls = [
        "https://bankmuscat.com",
        "https://www.bankmuscat.com",
        "https://tiktok.com",
        "https://www.tiktok.com",
        "https://google.com",
        "https://www.google.com",
    ]

    print("=== FEATURE VALUES ===")
    rows = {}
    for u in urls:
        f = extract_features(u)
        rows[u] = f
        print(u)
        for k, v in f.items():
            print(f"  {k}: {v}")
        print()

    print("=== NEW FEATURE SANITY ===")
    checks = {
        "https://bankmuscat.com": {"has_known_tld": 1, "digit_in_domain": 0},
        "https://tiktok.com": {"has_known_tld": 1, "digit_in_domain": 0},
        "https://example123.com": {"has_known_tld": 1, "digit_in_domain": 1},
        "https://aaabb.com": {"has_known_tld": 1},
        "https://evil.tk": {"has_known_tld": 0},
    }
    for u, expect in checks.items():
        f = extract_features(u)
        print(u)
        for k, ev in expect.items():
            got = f[k]
            status = "OK" if got == ev else "BAD"
            print(f"  {k}: got={got} expected={ev} [{status}]")
        print(
            f"  consonant_ratio={f['consonant_ratio']} "
            f"domain_word_count={f['domain_word_count']} "
            f"repeated_chars={f['repeated_chars']}"
        )

    m = pipeline.named_steps["model"]
    sc = pipeline.named_steps["scaler"]
    rf = m.estimators_[0]
    feat_names = list(pipeline.feature_names_in_)

    print("=== MODEL EXPECTS", len(feat_names), "FEATURES ===")
    print(feat_names)

    imps = rf.feature_importances_
    order = np.argsort(imps)[::-1]
    print("=== RF FEATURE IMPORTANCES ===")
    imp_list = []
    for i in order:
        imp_list.append((feat_names[i], float(imps[i])))
        print(f"{feat_names[i]:20s} {imps[i]:.4f}")

    # Training-set-ish means from scaler
    means = sc.mean_
    scales = sc.scale_

    print("=== PREDICTIONS + DRIVERS ===")
    results = {}
    for u in ["https://bankmuscat.com", "https://tiktok.com", "https://google.com"]:
        f = extract_features(u)
        X = pd.DataFrame([f])[feat_names]
        Xs = sc.transform(X)
        mal, ben, is_m = _hybrid_soft_vote(rf, m.estimators_[1], Xs)
        rf_p = _class_proba(rf, Xs)
        svm_p = _class_proba(m.estimators_[1], Xs)
        print(u)
        print(f"  hybrid mal={mal} ben={ben} is_mal={is_m}")
        print(f"  rf={rf_p} svm={svm_p}")

        raw_vals = X.values[0]
        z = (raw_vals - means) / scales
        scored = []
        for i, name in enumerate(feat_names):
            scored.append(
                (
                    name,
                    float(raw_vals[i]),
                    float(means[i]),
                    float(z[i]),
                    float(imps[i]),
                    float(imps[i] * abs(z[i])),
                )
            )
        scored.sort(key=lambda t: t[5], reverse=True)
        print("  Top drivers (importance * |z-score vs train mean|):")
        for name, raw, mean, zi, imp, drive in scored[:12]:
            print(
                f"    {name:20s} raw={raw:<10} mean={mean:<10.4f} "
                f"z={zi:+.2f} imp={imp:.4f} drive={drive:.4f}"
            )

        results[u] = {
            "malicious_pct": mal,
            "benign_pct": ben,
            "is_malicious": is_m,
            "rf_malicious_pct": round(rf_p.get(1, 0) * 100, 2),
            "svm_malicious_pct": round(svm_p.get(1, 0) * 100, 2),
            "features": {k: f[k] for k in feat_names},
            "top_drivers": [
                {
                    "feature": name,
                    "value": raw,
                    "train_mean": round(mean, 4),
                    "z": round(zi, 2),
                    "importance": round(imp, 4),
                    "drive": round(drive, 4),
                }
                for name, raw, mean, zi, imp, drive in scored[:12]
            ],
            "comparison": [
                {
                    "feature": name,
                    "value": float(raw_vals[i]),
                    "train_mean": round(float(means[i]), 4),
                    "train_std": round(float(scales[i]), 4),
                    "z": round(float(z[i]), 2),
                    "importance": round(float(imps[i]), 4),
                }
                for i, name in enumerate(feat_names)
            ],
        }

    # Dataset label check for these domains if present
    print("=== DATASET LABEL CHECK ===")
    ds = pd.read_csv("data/dataset.csv")
    for needle in ["bankmuscat", "tiktok.com", "google.com"]:
        hits = ds[ds["url"].str.contains(needle, case=False, na=False)]
        print(f"{needle}: {len(hits)} rows")
        if len(hits):
            print(hits["result"].value_counts().to_dict())
            print(hits["url"].head(8).tolist())

    out = {
        "feature_names": feat_names,
        "importances": [
            {"feature": n, "importance": round(v, 6)} for n, v in imp_list
        ],
        "sites": results,
        "bankmuscat_features": rows["https://bankmuscat.com"],
        "tiktok_features": rows["https://tiktok.com"],
        "google_features": rows["https://google.com"],
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
