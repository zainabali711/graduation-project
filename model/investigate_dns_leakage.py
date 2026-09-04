"""Investigate DNS model: feature importance + source_tool artifact risk."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.dns_features import DNS_FEATURE_COLUMNS, extract_dns_features_dict, label_to_int

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "dns_dataset.csv"
MODEL = BASE / "model" / "saved" / "dns_model.pkl"
OUT = BASE / "model" / "saved" / "dns_leakage_report.json"
SAMPLE = 100_000
RANDOM_STATE = 42


def _load_sample() -> pd.DataFrame:
    usecols = ["dns_domain_name", "label", "source_tool"]
    df = pd.read_csv(DATA, usecols=usecols, low_memory=False)
    df = df.dropna(subset=["dns_domain_name", "label", "source_tool"])
    df["result"] = df["label"].map(label_to_int)
    n_per = SAMPLE // 2
    df0 = df[df["result"] == 0].sample(n=n_per, random_state=RANDOM_STATE)
    df1 = df[df["result"] == 1].sample(n=n_per, random_state=RANDOM_STATE)
    return pd.concat([df0, df1], ignore_index=True).sample(frac=1, random_state=RANDOM_STATE)


def _feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for name in df["dns_domain_name"].astype(str):
        feats = extract_dns_features_dict(name)
        if feats is None:
            feats = {c: 0 for c in DNS_FEATURE_COLUMNS}
        rows.append(feats)
    return pd.DataFrame.from_records(rows, columns=DNS_FEATURE_COLUMNS)


def main() -> None:
    print("Loading sample + features …", flush=True)
    df = _load_sample()
    X = _feature_matrix(df)
    y = df["result"].astype(int).values
    tools = df["source_tool"].astype(str).values

    # --- 1) Feature importance from trained hybrid RF branch ---
    pipe = joblib.load(MODEL)
    rf = pipe.named_steps["clf"].named_estimators_["rf"]
    importances = rf.feature_importances_
    ranked = sorted(
        zip(DNS_FEATURE_COLUMNS, importances.tolist()),
        key=lambda t: -t[1],
    )
    top2_share = sum(v for _, v in ranked[:2])
    top1_share = ranked[0][1]

    print("\n=== RF feature importance (from dns_model.pkl) ===", flush=True)
    for name, val in ranked:
        print(f"  {name:40s} {val:.6f}", flush=True)
    print(f"Top-1 share: {top1_share:.4f} | Top-2 share: {top2_share:.4f}", flush=True)

    # --- 2) Per-feature mean by label ---
    X_lab = X.copy()
    X_lab["result"] = y
    by_label = X_lab.groupby("result")[DNS_FEATURE_COLUMNS].mean()
    separation = (by_label.loc[1] - by_label.loc[0]).abs().sort_values(ascending=False)

    # --- 3) Mutual information: feature → source_tool (artifact signal) ---
    # Among malicious only, can features predict which tool?
    mal_mask = y == 1
    X_mal = X.loc[mal_mask]
    tools_mal = tools[mal_mask]
    le = LabelEncoder()
    tool_ids = le.fit_transform(tools_mal)
    mi_tool = mutual_info_classif(
        X_mal, tool_ids, discrete_features=False, random_state=RANDOM_STATE
    )
    mi_tool_ranked = sorted(
        zip(DNS_FEATURE_COLUMNS, mi_tool.tolist()),
        key=lambda t: -t[1],
    )

    # Feature → binary label MI (how predictive of Benign/Malicious)
    mi_label = mutual_info_classif(
        X, y, discrete_features=False, random_state=RANDOM_STATE
    )
    mi_label_ranked = sorted(
        zip(DNS_FEATURE_COLUMNS, mi_label.tolist()),
        key=lambda t: -t[1],
    )

    print("\n=== Mutual information feature -> label ===", flush=True)
    for name, val in mi_label_ranked:
        print(f"  {name:40s} {val:.6f}", flush=True)

    print("\n=== Mutual information feature -> source_tool (malicious only) ===", flush=True)
    for name, val in mi_tool_ranked:
        print(f"  {name:40s} {val:.6f}", flush=True)

    # --- 4) Tool-level length / entropy fingerprints ---
    stats = []
    tmp = X.copy()
    tmp["source_tool"] = tools
    tmp["result"] = y
    for tool, g in tmp.groupby("source_tool"):
        stats.append(
            {
                "source_tool": tool,
                "n": int(len(g)),
                "mean_length": float(g["dns_domain_name_length"].mean()),
                "mean_subdomain_len": float(g["dns_subdomain_name_length"].mean()),
                "mean_entropy": float(g["character_entropy"].mean()),
                "mean_numerical_pct": float(g["numerical_percentage"].mean()),
                "mean_digit_count": float(g["digit_count"].mean()),
                "mean_label_count": float(g["label_count"].mean()),
            }
        )
    tool_stats = sorted(stats, key=lambda d: d["source_tool"])

    print("\n=== Per-source_tool feature means ===", flush=True)
    for row in tool_stats:
        print(
            f"  {row['source_tool']:28s} n={row['n']:6d} "
            f"len={row['mean_length']:.1f} sub={row['mean_subdomain_len']:.1f} "
            f"H={row['mean_entropy']:.2f} num%={row['mean_numerical_pct']:.3f}",
            flush=True,
        )

    # --- 5) Single-feature RF accuracy (is one feature enough?) ---
    single_acc = {}
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    for col in DNS_FEATURE_COLUMNS:
        clf = RandomForestClassifier(
            n_estimators=50, max_depth=8, random_state=RANDOM_STATE, n_jobs=-1
        )
        clf.fit(X_tr[[col]], y_tr)
        single_acc[col] = float(accuracy_score(y_te, clf.predict(X_te[[col]])))
    single_ranked = sorted(single_acc.items(), key=lambda t: -t[1])

    print("\n=== Single-feature RF test accuracy ===", flush=True)
    for name, val in single_ranked:
        print(f"  {name:40s} {val:.6f}", flush=True)

    # --- 6) Leave-one-tool-out proxy: train on all but one malicious tool ---
    # Hold out one tool's malicious samples + matched benign sample for test.
    loot = []
    mal_tools = sorted(set(tools_mal.tolist()))
    for holdout in mal_tools:
        train_mask = tools != holdout
        # Test: holdout malicious + equal random benign from train pool? Better:
        # test = all holdout rows (malicious) + same count of benign from df
        hold_idx = np.where(tools == holdout)[0]
        ben_idx = np.where(y == 0)[0]
        n_h = len(hold_idx)
        rng = np.random.RandomState(RANDOM_STATE)
        ben_test = rng.choice(ben_idx, size=min(n_h, len(ben_idx)), replace=False)
        test_idx = np.concatenate([hold_idx, ben_test])
        # Train: everything not in test_idx, but exclude holdout tool entirely from train
        train_idx = np.where(train_mask)[0]
        train_idx = np.setdiff1d(train_idx, ben_test)

        if len(train_idx) < 1000 or len(test_idx) < 100:
            continue

        clf = RandomForestClassifier(
            n_estimators=80,
            max_depth=12,
            min_samples_leaf=5,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        clf.fit(X.iloc[train_idx], y[train_idx])
        pred = clf.predict(X.iloc[test_idx])
        acc = float(accuracy_score(y[test_idx], pred))
        # Accuracy on holdout malicious only
        mal_only = accuracy_score(y[hold_idx], clf.predict(X.iloc[hold_idx]))
        loot.append(
            {
                "held_out_tool": holdout,
                "test_size": int(len(test_idx)),
                "holdout_malicious_n": int(n_h),
                "balanced_test_accuracy": acc,
                "holdout_malicious_recall": float(mal_only),
            }
        )
        print(
            f"LOOT {holdout:28s} bal_acc={acc:.4f} mal_recall={mal_only:.4f} n_mal={n_h}",
            flush=True,
        )

    # Verdict heuristics
    dominant = top1_share >= 0.45 or top2_share >= 0.70
    single_feature_near_perfect = single_ranked[0][1] >= 0.95
    tool_mi_high = mi_tool_ranked[0][1] >= 0.4
    mean_loot_mal_recall = (
        float(np.mean([r["holdout_malicious_recall"] for r in loot])) if loot else None
    )
    loot_collapse = mean_loot_mal_recall is not None and mean_loot_mal_recall < 0.55

    if dominant or single_feature_near_perfect or loot_collapse:
        risk = "HIGH"
        headline_ok = False
        summary = (
            "Near-perfect in-distribution accuracy is NOT trustworthy as a real-world "
            "headline. Length/subdomain features alone nearly separate classes; "
            "leave-one-tool-out malicious recall collapses for several tools. "
            "The model largely fits synthetic multi-tool query-name artifacts."
        )
    elif tool_mi_high:
        risk = "MODERATE"
        headline_ok = False
        summary = (
            "Features couple strongly to source_tool. Report 99.9% only with heavy "
            "synthetic-data and artifact caveats."
        )
    else:
        risk = "LOWER"
        headline_ok = True
        summary = (
            "Importances are more distributed; still note synthetic-data limitation."
        )

    report = {
        "risk_level": risk,
        "present_99_9_as_unqualified_headline": headline_ok,
        "summary": summary,
        "dataset_caveat": (
            "Daumel DNS tunneling/exfiltration dataset is synthetically generated "
            "and may not reflect real-world DNS traffic."
        ),
        "rf_feature_importance_ranked": [
            {"feature": n, "importance": v} for n, v in ranked
        ],
        "top1_importance_share": top1_share,
        "top2_importance_share": top2_share,
        "mean_abs_separation_benign_vs_malicious": {
            k: float(v) for k, v in separation.items()
        },
        "mutual_info_feature_to_label": [
            {"feature": n, "mi": v} for n, v in mi_label_ranked
        ],
        "mutual_info_feature_to_source_tool_malicious_only": [
            {"feature": n, "mi": v} for n, v in mi_tool_ranked
        ],
        "per_source_tool_means": tool_stats,
        "single_feature_rf_test_accuracy": [
            {"feature": n, "accuracy": v} for n, v in single_ranked
        ],
        "leave_one_tool_out": loot,
        "recommendations": [
            "In the paper/report, lead with methodology + synthetic-data limitation, "
            "not 99.9% accuracy as proof of real-world DNS malware detection.",
            "State clearly that the classifier uses offline query-name lexical features "
            "on a synthetic multi-tool corpus.",
            "If presenting accuracy, always pair with this leakage investigation "
            "(feature dominance, tool MI, leave-one-tool-out).",
            "Consider future work: cross-tool evaluation, real capture validation, "
            "and comparing against length-only baselines.",
        ],
    }

    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {OUT}", flush=True)
    print(f"\nRISK={risk} | unqualified_headline_ok={headline_ok}", flush=True)
    print(summary, flush=True)


if __name__ == "__main__":
    main()
