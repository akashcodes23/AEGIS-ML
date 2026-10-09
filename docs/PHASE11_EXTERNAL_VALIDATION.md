# AEGIS-ML Phase 11: External Validation & Evidence-Driven Attack Reconstruction Report

**Date:** 2026-10-09  
**Authors:** Senior Cybersecurity ML Researcher, Detection Engineer & Evaluation Specialist  
**Status:** Completed & Validated  

---

## 1. Executive Summary

Phase 11 independently verifies the Phase 10 results, resolves empirical evaluation questions, formalizes evidence-driven attack reconstruction, and builds a dedicated, isolated external evaluation pipeline for the CIC-IDS2017 benchmark.

### Core Outcomes:
1. **Resolution of Config C vs D Metric Equality**: Proved that while temporal burst features receive 13.8% feature importance in Config D, their decision splits are redundant when relational graph features (`dst_in_degree_5m`, `dst_diversity_ratio_5m`, `is_new_src_dst_pair`) are present. Across all 1,400 test samples, Configurations C and D produce **0 prediction differences**.
2. **Reconciliation of Sample Counts**: Clarified the mathematical basis for the 1,411 (Baseline Stratified) vs 1,400 (Group-Aware Holdout) test partition counts.
3. **Evidence Demarcation (Fact vs Hypothesis)**: Hardened `IncidentCorrelator` and the investigation dashboard so that cross-layer file events and outbound network connections are explicitly demarcated as analyst hypotheses with uncertainty notes, rather than asserted as proven physical exfiltration.
4. **External Dataset Framework**: Implemented [backend/evaluation/external_benchmark.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/evaluation/external_benchmark.py) to load, normalize, and evaluate real CIC-IDS2017 flow data while honestly disclosing missing endpoint telemetry and reporting `not_completed` when local files are absent.
5. **Full Test Suite Expanded**: 66 tests passing (0 failures), covering external benchmark execution, causality, and evidence demarcation.

---

## 2. Investigation: Why Configurations C and D Have Identical Metrics

In Phase 10, both Configuration C (21 features: Baseline + Relational/Graph) and Configuration D (24 features: Baseline + Temporal + Relational/Graph) reported identical summary metrics:
- **Macro-F1**: `0.8685`
- **Balanced Accuracy**: `0.9317`
- **Benign FPR**: `0.0073`
- **Lateral Movement Precision**: `0.4094`
- **Lateral Movement Recall**: `1.0000`
- **Lateral Movement F1**: `0.5810`

### Empirical Investigation:
A record-by-record comparison of model predictions across the 1,400 test records revealed:
```
Differences between C and D predictions across 1,400 test samples: 0
```

### Feature Importance Analysis:
In Config D, the 3 temporal features received non-zero tree-split importances:
- `event_rate_1m`: `0.0700` (Rank 7)
- `inter_event_time_log`: `0.0391` (Rank 12)
- `event_rate_5m`: `0.0289` (Rank 14)
- **Cumulative Temporal Importance**: `0.1380` (13.8%)

### Scientific Root Cause:
1. **Redundancy with Relational Degree**: The primary attack pattern that temporal burst rates help identify (rapid automated scanning vs human interactions) is already more cleanly separated by `dst_in_degree_5m` (importance: `0.0988`), `dst_diversity_ratio_5m` (`0.0595`), and `bytes_sent_zscore` (`0.1038`).
2. **Ambiguity Invariant**: For the remaining 87 false positive records (localhost file reads `7z.exe` misclassified as `net.exe`), both processes execute in rapid bursts on localhost. Their temporal burst rates are nearly identical.
3. **Conclusion**: Adding temporal dynamics to relational graph features provides redundant signal on this dataset. In the absence of relational features (Config A $\rightarrow$ Config B), temporal features provide an F1 boost (+0.0377). When relational features are already present (Config A $\rightarrow$ Config C), temporal features do not alter a single classification boundary.

---

## 3. Reconciliation of Evaluation Counts

| Parameter | Baseline Stratified Split | Group-Aware Holdout | Full Dataset |
|---|:---:|:---:|:---:|
| **Dataset SHA-256** | `25f2bf68...` | `25f2bf68...` | `25f2bf68...` |
| **Random Seed** | 42 | 42 | N/A |
| **Splitting Unit** | Individual records | Unique 15-field fingerprints | Entire dataset |
| **Train Samples** | 5,640 (80.0%) | 5,651 (80.14%) | 7,051 |
| **Test Samples** | 1,411 (20.0%) | 1,400 (19.86%) | N/A |
| **Duplicate Overlap** | **48.6% (686 records)** | **0.0% (0 records)** | N/A |
| **Benign Test Support** | 411 | 410 | 2,051 |
| **Brute Force Test Support**| 600 | 498 | 3,000 |
| **Data Exfil Test Support** | 264 | 359 | 1,320 |
| **C2 Beacon Test Support** | 69 | 72 | 345 |
| **Lateral Mov Test Support**| 67 | 61 | 335 |

### Reason for Test Count Difference (1,411 vs 1,400):
In the **Stratified Baseline**, individual records are randomly sampled without regard to identical payloads, yielding exact $80/20$ mathematical cuts ($5,640 / 1,411$). In the **Group-Aware Holdout**, duplicate records belonging to the same scripted loop are kept indivisible. Because cluster sizes vary, allocating 20% of clusters to the test set produces 1,400 records and guarantees **0.0% duplicate feature leakage**.

---

## 4. CIC-IDS2017 Dataset Ingestion & Evaluation Framework

### 4.1 Loader Validation ([backend/ingestion/cicids_loader.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/ingestion/cicids_loader.py))
- **Column Normalization**: Handles leading/trailing whitespace and inconsistent casing (e.g., `" Destination Port"` vs `"destination port"`).
- **Label Normalization**: Strips whitespace, converts to lowercase, and resolves em-dash variations in web attack labels (`\x96`, `–`, `—`).
- **Numeric Sanitization**: Converts negative duration/packet values (CICFlowMeter overflow bugs) and Inf/NaN values to `None`/`np.nan`.
- **Label Mapping Safety**: Unmapped labels are logged in `stats["unmapped_labels"]` and counted as `stats["rejected_records"]`. **Unsupported attack classes are never silently converted to benign.**
- **No Fabricated Telemetry**: Endpoint-layer fields (`process_name`, `parent_pid`, `file_path`, `action`) are left as `None`. The loader assigns `layer = "network"` and does not invent fake host logs.

### 4.2 External Benchmark Execution ([backend/evaluation/external_benchmark.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/evaluation/external_benchmark.py))
- Designed as an isolated evaluation path separate from the synthetic ablation study.
- When run without local data, safely logs instructions per `docs/CICIDS2017_IMPORT.md` and reports `status: "not_completed"` without inventing numbers.
- When run on the multi-class synthetic fixture, verifies that Configuration A (Baseline 15-Feature) and Configuration B (Temporal/Relational) train and evaluate cleanly on untouched test data with documented confusion matrices.

---

## 5. Evidence-Driven Incident Reconstruction (Fact vs Hypothesis)

### 5.1 Hardened Evidence Schema in `IncidentCorrelator`
For every inferred relationship, the correlation engine now explicitly populates:
- `supporting_event_ids`: IDs of concrete underlying events.
- `timestamp`: Original event timestamp in ISO format.
- `relationship_type`: Concrete telemetry link (`observed_telemetry`, `pivot_lateral_movement`, `cross_layer_co_occurrence`).
- `claim_type`: Explicit demarcation of `"observation"` (ground truth telemetry) vs `"hypothesis"` (inferred correlation).
- `correlation_rule`: The exact rule that created the link (e.g. `RULE_1_SAME_ATTACKER_CAMPAIGN`, `RULE_2_LATERAL_MOVEMENT_PIVOT`, `RULE_0_INITIAL_TRIGGER`).
- `evidence_provenance`: Origin dataset or capture file.
- `uncertainty_notes`: Explicit audit notes disclosing limitations.

### 5.2 Anti-Conflation Guarantee (Exfiltration Hypothesis)
If an endpoint file read alert and an outbound network connection occur on the same host:
- The relationship is explicitly marked:
  ```python
  "claim_type": "hypothesis",
  "relationship_type": "cross_layer_co_occurrence",
  "uncertainty_notes": "File activity and network connection co-occur on the same host within the time window. Because OS process handle lineage and packet payload bindings are unverified, data exfiltration is an inferred hypothesis, not an established fact."
  ```
- Unrelated endpoints and network events on different hosts are never merged.

### 5.3 UI Integration
In [frontend/src/components/Dashboard/IncidentCard.jsx](file:///Users/akashgpatil/major_project/AEGIS-ML/frontend/src/components/Dashboard/IncidentCard.jsx), each relationship card in the Traceable Evidence panel renders:
- An **`INFERRED HYPOTHESIS`** (purple) vs **`OBSERVED TELEMETRY`** (green) badge.
- The active correlation rule badge.
- Explicit italicized uncertainty notes detailing why the relationship is an inference.
- An **`Inspect Event {id}`** button that jumps directly to the underlying raw event in Tab 2.

---

## 6. Reproduction Suite

```bash
# 1. Run all 66 unit, regression, causality, and external benchmark tests
python3 -m pytest tests/ -v --tb=short

# 2. Run synthetic dataset ablation study
python3 -m backend.evaluation.ablation_study

# 3. Run external dataset benchmark (checks local availability)
python3 -m backend.evaluation.external_benchmark

# 4. Run controlled correlation benchmark (12 scenarios)
python3 -m backend.evaluation.correlation_benchmark

# 5. Build frontend production bundle
cd frontend && npm run build
```
