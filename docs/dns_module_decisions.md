# DNS Module — Methodological Decisions & Leakage Investigation

This document records decisions and measured results for CyberScan’s third detection module (offline DNS query-name classification). Use it when writing the paper/report. Numbers are from the project’s saved artifacts unless noted.

**Related artifacts**

- `data/dns_dataset.csv` / `data/dns_dataset_summary.json`
- `model/dns_features.py`, `model/train_dns.py`, `model/investigate_dns_leakage.py`
- `model/saved/dns_model.pkl`, `dns_metrics.json`, `dns_leakage_report.json`

---

## 1. Why this dataset

### Choice and authorship of tools

- Dataset: **Daumel DNS tunneling / DNS exfiltration dataset** on Kaggle  
  (`https://www.kaggle.com/datasets/daumel/dns-tunneling-dataset`).
- Local extract used:  
  `…/dns-exfiltration-dataset/02_generated_dataset/`.
- **Tool selection was inherited from the dataset author**, not chosen by this project. The nine malicious generators present in the release are:

  `cobaltstrike`, `dns2tcp`, `dnscat2`, `dnsexfiltrator`, `dnsexfiltrator_modified`, `dnspot`, `iodine`, `ozymandns`, `tcp_over_dns`.

- Benign traffic is provided as a single file: `benign/benign.csv`.
- Malicious files are per-tool CSVs named `{tool}.csv` under `malicious/{tool}/`.

### Author caveat (must be stated in UI and report)

The dataset author states the data is **synthetically generated and may not reflect real-world data**. CyberScan treats this module as an **educational / demo classifier on synthetic multi-tool query names**, not as production DNS malware detection on live resolvers.

---

## 2. Consolidation

Script: `data/build_dns_dataset.py` → `data/dns_dataset.csv` (+ `source_tool` column).

| source_tool | rows |
|-------------|------:|
| benign | 797,626 |
| cobaltstrike | 141,207 |
| dnscat2 | 144,446 |
| iodine | 130,059 |
| tcp_over_dns | 111,247 |
| dns2tcp | 65,140 |
| ozymandns | 61,988 |
| dnsexfiltrator | 58,323 |
| dnsexfiltrator_modified | 46,596 |
| dnspot | 26,531 |
| **Total** | **1,583,163** |

**Labels (exact strings):**

| label | count | share |
|-------|------:|------:|
| Benign | 797,626 | 50.3818% |
| Malicious | 785,537 | 49.6182% |

Key columns used for modeling had **0 nulls** in the unified file for the fields checked during exploration (`dns_domain_name`, lengths, entropy, ratios, selected TTL/flow columns, `label`, `source_tool`).

---

## 3. Feature design (live single-query constraint)

At inference the user supplies only a **DNS query name**. Flow / packet / TTL / answer-record fields are unavailable.

### Used (18 features, recomputed from the query string)

Defined in `model/dns_features.py` as `DNS_FEATURE_COLUMNS`:

1. `dns_domain_name_length`
2. `dns_subdomain_name_length`
3. `label_count`
4. `tld_length`
5. `sld_length`
6. `numerical_percentage`
7. `character_entropy`
8. `max_continuous_numeric_len`
9. `max_continuous_alphabet_len`
10. `max_continuous_consonants_len`
11. `max_continuous_same_alphabet_len`
12. `vowels_consonant_ratio`
13. `conv_freq_vowels_consonants`
14. `digit_count`
15. `alpha_count`
16. `dot_count`
17. `hyphen_count`
18. `unique_char_ratio`

CSV columns `uni_gram_domain_name`, `bi_gram_domain_name`, `tri_gram_domain_name`, and `character_distribution` are **serialized string blobs**; they were **not** fed to the model. Numeric lexical statistics are recomputed so train-time features match predict-time features.

### Excluded (flow / response only)

`flow_id`, `timestamp`, IPs/ports, `duration`, byte and packet statistics, all `ttl_values_*`, `distinct_ttl_values`, `distinct_A_records`, `ans_resource_record_type`, `ans_resource_record_class`.

---

## 4. Training approach

Mirror of the URL hybrid trainer (`model/train.py`), implemented in `model/train_dns.py`:

| Decision | Value |
|----------|--------|
| Sample size | `SAMPLE_SIZE = 100_000` (50k Benign + 50k Malicious), `random_state=42` |
| Split | 80/20, stratified, `random_state=42` → 80,000 train / 20,000 test |
| Preprocessing | `StandardScaler` |
| Model | Soft `VotingClassifier`: RandomForest (`n_estimators=100`, `max_depth=15`, `min_samples_leaf=5`) + `CalibratedClassifierCV(SVC(kernel="rbf"), cv=3)` |
| Outputs | `model/saved/dns_model.pkl`, `model/saved/dns_metrics.json` (does **not** overwrite URL `hybrid_model.pkl` / `metrics.json`) |
| Label mapping | Benign=0, Malicious=1 |

### In-distribution test metrics (same random split / sample)

| Metric | Value |
|--------|------:|
| Accuracy | 0.99905 |
| Precision | 0.9983025461807289 |
| Recall | 0.9998 |
| F1 | 0.9990507119660255 |
| Confusion matrix | `[[9983, 17], [2, 9998]]` |

These numbers are **in-distribution on synthetic data**. See §5 before presenting them as headline real-world performance.

---

## 5. Data leakage / artifact investigation

Script: `model/investigate_dns_leakage.py` → `model/saved/dns_leakage_report.json`.

**Overall risk level: HIGH.**  
**Do not present 99.9% accuracy as an unqualified headline** for real-world malicious DNS detection.

### 5.1 Random Forest feature importance (from fitted hybrid RF branch)

| Rank | Feature | Importance |
|-----:|---------|----------:|
| 1 | `dns_domain_name_length` | 0.188107 |
| 2 | `dns_subdomain_name_length` | 0.135553 |
| 3 | `character_entropy` | 0.108244 |
| 4 | `alpha_count` | 0.075147 |
| 5 | `max_continuous_consonants_len` | 0.074125 |
| 6 | `hyphen_count` | 0.059607 |
| 7 | `dot_count` | 0.057414 |
| 8 | `label_count` | 0.051734 |
| 9 | `sld_length` | 0.051511 |
| 10 | `digit_count` | 0.048464 |
| 11 | `max_continuous_numeric_len` | 0.037106 |
| 12 | `numerical_percentage` | 0.033101 |
| 13 | `max_continuous_alphabet_len` | 0.030915 |
| 14 | `conv_freq_vowels_consonants` | 0.017365 |
| 15 | `unique_char_ratio` | 0.015772 |
| 16 | `vowels_consonant_ratio` | 0.012378 |
| 17 | `max_continuous_same_alphabet_len` | 0.002308 |
| 18 | `tld_length` | 0.001148 |

- Top-1 share: **0.1881**
- Top-2 share: **0.3237**

Importances are distributed (not a single 90% feature), but **length-family signals dominate**.

### 5.2 Single-feature baselines (same 100k sample, 80/20 split)

| Feature alone | Test accuracy |
|---------------|-------------:|
| `dns_domain_name_length` | **0.9582** |
| `dns_subdomain_name_length` | **0.94125** |
| `alpha_count` | 0.8709 |
| `character_entropy` | 0.8537 |
| … | … |
| `tld_length` | 0.51855 |

Interpretation: the hybrid’s ~99.9% largely **refines an already near-separable length/subdomain pattern**, which is characteristic of how many synthetic exfiltration tools encode payloads into long query names versus shorter benign names.

### 5.3 Per-`source_tool` mean fingerprints (100k balanced sample)

| source_tool | n | mean length | mean subdomain len | mean entropy | mean num% |
|-------------|--:|------------:|-------------------:|-------------:|----------:|
| benign | 50000 | 31.79 | 19.32 | 3.71 | 0.120 |
| tcp_over_dns | 7012 | 43.2 | 33.2 | 4.35 | 0.204 |
| dnsexfiltrator | 3797 | 43.8 | 32.8 | 4.49 | 0.229 |
| dnsexfiltrator_modified | 3034 | 51.8 | 40.8 | 4.32 | 0.102 |
| cobaltstrike | 8888 | 87.9 | 67.2 | 4.46 | 0.392 |
| dns2tcp | 4232 | 92.5 | 76.5 | 4.46 | 0.101 |
| ozymandns | 3813 | 129.4 | 111.4 | 4.67 | 0.274 |
| dnscat2 | 9233 | 148.6 | 133.0 | 4.20 | 0.533 |
| iodine | 8278 | 158.2 | 140.7 | 4.63 | 0.100 |
| dnspot | 1713 | 251.0 | 241.0 | 5.10 | 0.281 |

Benign queries are much shorter on average than most malicious tool outputs → strong **dataset/tool artifact**.

### 5.4 Mutual information

**Feature → binary label** (top): length 0.588, subdomain length 0.568, entropy 0.525, unique_char_ratio 0.518, numerical_percentage 0.516.

**Feature → `source_tool` (malicious rows only)** (top): unique_char_ratio **1.905**, numerical_percentage **1.851**, subdomain length **1.844**, domain length **1.817**, entropy **1.635**.

High MI with `source_tool` indicates features encode **which generator produced the name**, not only a general “malicious DNS” concept.

### 5.5 Leave-one-tool-out (LOOT)

Train RF without one malicious tool; test on that tool’s malicious samples (+ balanced benign). **Holdout malicious recall:**

| Held-out tool | Malicious recall | Balanced test accuracy |
|---------------|-----------------:|-----------------------:|
| ozymandns | 0.9963 | 0.9974 |
| cobaltstrike | 0.6135 | 0.8063 |
| iodine | 0.4238 | 0.7115 |
| dns2tcp | 0.3967 | 0.6979 |
| dnsexfiltrator | 0.2984 | 0.6489 |
| dnscat2 | 0.0418 | 0.5205 |
| tcp_over_dns | 0.0023 | 0.5009 |
| dnsexfiltrator_modified | 0.0000 | 0.4995 |
| dnspot | 0.0000 | 0.4997 |

**Mean holdout malicious recall ≈ 0.308.**  
In-distribution 99.9% **does not transfer** to several unseen tools.

### 5.6 Investigation conclusion (for the paper)

- Synthetic multi-tool data + query-name lexical features → easy in-distribution separation.
- Strong length / tool fingerprinting; poor cross-tool generalization for several tools.
- Appropriate framing: **offline educational module** with explicit limitations; pair any accuracy number with length-only baseline (~95.8%) and LOOT results.

---

## 6. Limitations (honest)

1. **Synthetic data** — may not match real resolver / enterprise DNS traffic.
2. **Tool-specific fingerprints** — model may learn generator encodings (esp. length), not general “maliciousness.”
3. **Generalization** — LOOT shows collapse for tools such as `dnspot`, `dnsexfiltrator_modified`, `tcp_over_dns`, `dnscat2`.
4. **No live packet capture** — module classifies a typed query name only; no TTL/flow context.
5. **Headline metrics** — 99.9% in-distribution accuracy is **not** appropriate as unqualified real-world proof.

---

## 7. UI safeguards (Flask integration)

Implemented in the CyberScan web app:

| Safeguard | Location | Purpose |
|-----------|----------|---------|
| Persistent warning banner | `/dns-scan`, result page | States synthetic Daumel training data and limited generalization |
| Learn more | `/dns-limitations` | Length-only baseline (~95.8%), LOOT table, risk level HIGH |
| Curated examples | `/dns-scan` chips | 2 benign + 2 ozymandns (strong LOOT) + cobaltstrike + tcp_over_dns (weak LOOT, labeled harder) |
| Generalization confidence | `/dns-predict` result | Key features vs training p1–p99; In-distribution / Borderline / Out-of-distribution; score `100 - 35 * n_outside` |
| Scan logging | `dns_scans` table + `/admin/dns-scans` | Auditable history with generalization level |

These mitigations **do not fix** cross-tool or real-world generalization; they make limitations visible to users and to report readers.
