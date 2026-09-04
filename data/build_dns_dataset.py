"""
Consolidate Daumel DNS exfiltration CSVs into data/dns_dataset.csv.

Source (Kaggle): dns-exfiltration-dataset / 02_generated_dataset
  - benign/benign.csv
  - malicious/<tool>/<tool>.csv  (9 tools)

Adds source_tool per row. Does not modify data/dataset.csv (URL scanner).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
OUT_CSV = BASE_DIR / "data" / "dns_dataset.csv"
OUT_SUMMARY = BASE_DIR / "data" / "dns_dataset_summary.json"

# Default Kaggle extract path (override with DNS_DATASET_ROOT env).
DEFAULT_ROOT = Path(
    r"C:\Users\zainab\Downloads\archive (1)\dns-exfiltration-dataset\02_generated_dataset"
)


def _dataset_root() -> Path:
    env = (os.environ.get("DNS_DATASET_ROOT") or "").strip()
    return Path(env) if env else DEFAULT_ROOT


def _iter_malicious_csvs(root: Path) -> list[tuple[str, Path]]:
    mal_dir = root / "malicious"
    if not mal_dir.is_dir():
        raise FileNotFoundError(f"Missing malicious folder: {mal_dir}")
    pairs: list[tuple[str, Path]] = []
    for tool_dir in sorted(mal_dir.iterdir()):
        if not tool_dir.is_dir():
            continue
        csvs = sorted(tool_dir.glob("*.csv"))
        if not csvs:
            print(f"WARN: no CSV in {tool_dir}", flush=True)
            continue
        # Prefer <tool>.csv if present; else first csv.
        preferred = tool_dir / f"{tool_dir.name}.csv"
        path = preferred if preferred.is_file() else csvs[0]
        pairs.append((tool_dir.name, path))
    return pairs


def _write_chunks(frames_info: list[tuple[str, Path]], out_path: Path) -> dict:
    """Stream-concat CSVs to out_path; return summary stats."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    total_rows = 0
    per_tool: dict[str, int] = {}
    label_counts: dict[str, int] = {}
    columns: list[str] | None = None
    first_write = True
    chunksize = 50_000

    for tool, path in frames_info:
        print(f"Reading {tool}: {path} ({path.stat().st_size / 1e6:.1f} MB)", flush=True)
        tool_rows = 0
        for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
            chunk = chunk.copy()
            chunk["source_tool"] = tool
            if columns is None:
                columns = list(chunk.columns)
            # Align columns if a file is missing/extra (should not happen).
            for col in columns:
                if col not in chunk.columns:
                    chunk[col] = pd.NA
            chunk = chunk[columns]

            if "label" in chunk.columns:
                vc = chunk["label"].astype(str).value_counts()
                for lab, cnt in vc.items():
                    label_counts[lab] = label_counts.get(lab, 0) + int(cnt)

            chunk.to_csv(
                out_path,
                mode="w" if first_write else "a",
                header=first_write,
                index=False,
            )
            first_write = False
            n = len(chunk)
            tool_rows += n
            total_rows += n

        per_tool[tool] = tool_rows
        print(f"  -> {tool_rows:,} rows", flush=True)

    return {
        "total_rows": total_rows,
        "per_source_tool": per_tool,
        "label_counts": label_counts,
        "columns": columns or [],
        "output_csv": str(out_path),
    }


def explore_unified(csv_path: Path, sample_for_dupes: int = 200_000) -> dict:
    """Compute nulls / balance / duplicate rate from the unified CSV (chunked)."""
    print(f"\nExploring {csv_path} …", flush=True)
    key_cols = [
        "dns_domain_name",
        "dns_domain_name_length",
        "dns_subdomain_name_length",
        "character_entropy",
        "numerical_percentage",
        "vowels_consonant_ratio",
        "conv_freq_vowels_consonants",
        "uni_gram_domain_name",
        "bi_gram_domain_name",
        "tri_gram_domain_name",
        "character_distribution",
        "distinct_ttl_values",
        "ttl_values_mean",
        "duration",
        "total_bytes",
        "label",
        "source_tool",
    ]

    null_counts: dict[str, int] = {}
    dtypes_sample: dict[str, str] = {}
    label_counts: dict[str, int] = {}
    tool_counts: dict[str, int] = {}
    total = 0
    names_seen: set[str] = set()
    names_sampled = 0
    dup_hits = 0

    for chunk in pd.read_csv(csv_path, chunksize=50_000, low_memory=False):
        total += len(chunk)
        for col in key_cols:
            if col not in chunk.columns:
                continue
            null_counts[col] = null_counts.get(col, 0) + int(chunk[col].isna().sum())
            if col not in dtypes_sample:
                dtypes_sample[col] = str(chunk[col].dtype)

        if "label" in chunk.columns:
            for lab, cnt in chunk["label"].astype(str).value_counts().items():
                label_counts[lab] = label_counts.get(lab, 0) + int(cnt)
        if "source_tool" in chunk.columns:
            for t, cnt in chunk["source_tool"].astype(str).value_counts().items():
                tool_counts[t] = tool_counts.get(t, 0) + int(cnt)

        if "dns_domain_name" in chunk.columns and names_sampled < sample_for_dupes:
            take = min(len(chunk), sample_for_dupes - names_sampled)
            series = chunk["dns_domain_name"].astype(str).head(take)
            for name in series:
                if name in names_seen:
                    dup_hits += 1
                else:
                    names_seen.add(name)
            names_sampled += take

    balance = {
        lab: {
            "count": cnt,
            "pct": round(100.0 * cnt / total, 4) if total else 0.0,
        }
        for lab, cnt in sorted(label_counts.items(), key=lambda x: -x[1])
    }

    # Peek n-gram / character_distribution shapes from first rows
    peek = pd.read_csv(csv_path, nrows=20, low_memory=False)
    peek_info = {}
    for col in (
        "uni_gram_domain_name",
        "bi_gram_domain_name",
        "tri_gram_domain_name",
        "character_distribution",
        "dns_top_level_domain",
        "dns_second_level_domain",
    ):
        if col in peek.columns:
            sample_vals = peek[col].head(3).tolist()
            peek_info[col] = {
                "dtype": str(peek[col].dtype),
                "sample_values": [repr(v)[:120] for v in sample_vals],
            }

    return {
        "total_rows": total,
        "label_counts": label_counts,
        "class_balance_pct": balance,
        "per_source_tool": tool_counts,
        "null_counts_key_columns": null_counts,
        "dtypes_key_columns": dtypes_sample,
        "dns_domain_name_dup_rate_approx": {
            "sampled_rows": names_sampled,
            "unique_names_in_sample": len(names_seen),
            "duplicate_row_hits_in_sample": dup_hits,
            "note": "Approximate: first N rows only; not full-dataset exact dedupe.",
        },
        "column_peek": peek_info,
        "all_columns": list(peek.columns),
    }


def main() -> int:
    root = _dataset_root()
    if not root.is_dir():
        print(f"ERROR: dataset root not found: {root}", file=sys.stderr)
        return 1

    benign_path = root / "benign" / "benign.csv"
    if not benign_path.is_file():
        print(f"ERROR: missing {benign_path}", file=sys.stderr)
        return 1

    frames: list[tuple[str, Path]] = [("benign", benign_path)]
    frames.extend(_iter_malicious_csvs(root))
    print(f"Sources ({len(frames)}):", flush=True)
    for tool, path in frames:
        print(f"  - {tool}: {path.name}", flush=True)

    summary = _write_chunks(frames, OUT_CSV)
    explore = explore_unified(OUT_CSV)
    payload = {
        "source_root": str(root),
        "consolidation": summary,
        "exploration": explore,
        "dataset_caveat": (
            "Synthetically generated (Daumel DNS tunneling/exfiltration dataset); "
            "may not reflect real-world DNS traffic."
        ),
    }
    OUT_SUMMARY.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("\n=== SUMMARY ===", flush=True)
    print(json.dumps(payload, indent=2), flush=True)
    print(f"\nWrote {OUT_CSV}", flush=True)
    print(f"Wrote {OUT_SUMMARY}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
