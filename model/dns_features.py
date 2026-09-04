"""
DNS query-name feature extraction for CyberScan DNS module.

Training and live prediction use the SAME features: only values that can be
derived from a single DNS query name string (what the user types/selects).

Dataset note: Daumel DNS exfiltration/tunneling data is synthetically generated
and may not reflect real-world DNS traffic.

Excluded at train+predict time (flow / DNS-response only — not available for a
typed query name):
  flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, duration,
  total_bytes, receiving_bytes, sending_bytes, packets_rate, packets_len_rate,
  min/max/mean/std/var/cv packets_len, distinct_ttl_values, ttl_values_*,
  distinct_A_records, ans_resource_record_type, ans_resource_record_class

Excluded opaque / non-rebuildable string blobs from the CSV:
  uni_gram_domain_name, bi_gram_domain_name, tri_gram_domain_name,
  character_distribution  (serialized Python list/dict strings — we recompute
  numeric equivalents: entropy, digit ratio, run lengths, vowel/consonant stats)
"""

from __future__ import annotations

import math
import re
from collections import Counter

import pandas as pd

# Locked feature order for dns_model.pkl training / inference.
DNS_FEATURE_COLUMNS: list[str] = [
    "dns_domain_name_length",
    "dns_subdomain_name_length",
    "label_count",
    "tld_length",
    "sld_length",
    "numerical_percentage",
    "character_entropy",
    "max_continuous_numeric_len",
    "max_continuous_alphabet_len",
    "max_continuous_consonants_len",
    "max_continuous_same_alphabet_len",
    "vowels_consonant_ratio",
    "conv_freq_vowels_consonants",
    "digit_count",
    "alpha_count",
    "dot_count",
    "hyphen_count",
    "unique_char_ratio",
]

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def _normalize_query(name: str) -> str:
    name = (name or "").strip().lower().rstrip(".")
    # Strip surrounding whitespace; keep dots/hyphens/underscores as in DNS labels.
    return name


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _max_run(text: str, predicate) -> int:
    best = cur = 0
    for ch in text:
        if predicate(ch):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _max_same_char_run(text: str, alphabet_only: bool = True) -> int:
    best = cur = 0
    prev = ""
    for ch in text:
        if alphabet_only and not ch.isalpha():
            cur = 0
            prev = ""
            continue
        if ch == prev:
            cur += 1
        else:
            cur = 1
            prev = ch
        best = max(best, cur)
    return best


def _parse_labels(name: str) -> list[str]:
    return [p for p in name.split(".") if p]


def extract_dns_features_dict(query_name: str) -> dict | None:
    """Return a feature dict for one DNS query name, or None if invalid."""
    if not query_name or not isinstance(query_name, str):
        return None
    name = _normalize_query(query_name)
    if not name or " " in name:
        return None

    labels = _parse_labels(name)
    if not labels:
        return None

    # Conventional split: last label = TLD, second-level = last two when present.
    tld = labels[-1] if labels else ""
    sld = ".".join(labels[-2:]) if len(labels) >= 2 else labels[0]
    # Subdomain = everything left of SLD (labels except last two).
    if len(labels) > 2:
        subdomain = ".".join(labels[:-2])
        subdomain_len = len(subdomain)
    else:
        subdomain_len = 0

    chars = [c for c in name if c != "."]
    n_chars = len(chars) or 1
    digits = sum(c.isdigit() for c in chars)
    alphas = sum(c.isalpha() for c in chars)
    vowels = sum(c in VOWELS for c in chars)
    consonants = sum(c in CONSONANTS for c in chars)

    vowel_cons_ratio = (vowels / consonants) if consonants else float(vowels)
    # Alternation frequency between vowel/consonant classes (ignore non-letters).
    letters = [c for c in chars if c.isalpha()]
    switches = 0
    for i in range(1, len(letters)):
        a, b = letters[i - 1] in VOWELS, letters[i] in VOWELS
        if a != b:
            switches += 1
    conv_freq = (switches / (len(letters) - 1)) if len(letters) > 1 else 0.0

    return {
        "dns_domain_name_length": len(name),
        "dns_subdomain_name_length": subdomain_len,
        "label_count": len(labels),
        "tld_length": len(tld),
        "sld_length": len(sld),
        "numerical_percentage": round(digits / n_chars, 6),
        "character_entropy": round(_shannon_entropy(name), 6),
        "max_continuous_numeric_len": _max_run(name, str.isdigit),
        "max_continuous_alphabet_len": _max_run(name, str.isalpha),
        "max_continuous_consonants_len": _max_run(
            name, lambda c: c in CONSONANTS
        ),
        "max_continuous_same_alphabet_len": _max_same_char_run(name),
        "vowels_consonant_ratio": round(vowel_cons_ratio, 6),
        "conv_freq_vowels_consonants": round(conv_freq, 6),
        "digit_count": digits,
        "alpha_count": alphas,
        "dot_count": name.count("."),
        "hyphen_count": name.count("-"),
        "unique_char_ratio": round(len(set(name)) / max(len(name), 1), 6),
    }


def extract_dns_features(query_name: str) -> pd.DataFrame | None:
    """Single-query features as a 1-row DataFrame in DNS_FEATURE_COLUMNS order."""
    feats = extract_dns_features_dict(query_name)
    if feats is None:
        return None
    return pd.DataFrame([[feats[c] for c in DNS_FEATURE_COLUMNS]], columns=DNS_FEATURE_COLUMNS)


def features_from_dataset_row(row: pd.Series) -> dict:
    """
    Prefer recomputing from dns_domain_name so train features match live extract.
    Falls back to CSV numeric columns when the name is missing.
    """
    name = row.get("dns_domain_name")
    if isinstance(name, str) and name.strip():
        computed = extract_dns_features_dict(name)
        if computed is not None:
            return computed
    # Fallback: use precomputed numeric columns from the CSV when present.
    out = {}
    for col in DNS_FEATURE_COLUMNS:
        if col in row.index and pd.notna(row[col]):
            out[col] = row[col]
        else:
            out[col] = 0
    return out


def dataframe_from_dns_csv(df: pd.DataFrame) -> pd.DataFrame:
    """Build the locked feature matrix from a consolidated DNS dataframe."""
    if "dns_domain_name" not in df.columns:
        raise KeyError("dns_domain_name column required")
    records = []
    for name in df["dns_domain_name"].astype(str):
        feats = extract_dns_features_dict(name)
        if feats is None:
            feats = {c: 0 for c in DNS_FEATURE_COLUMNS}
        records.append(feats)
    return pd.DataFrame.from_records(records, columns=DNS_FEATURE_COLUMNS)


def label_to_int(label) -> int:
    """Benign=0, Malicious=1 (matches URL scanner convention)."""
    s = str(label).strip().lower()
    if s in {"malicious", "1", "true"}:
        return 1
    return 0
