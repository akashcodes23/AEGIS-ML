# AEGIS-ML Evaluation Validation and Defect Audit

**Document:** `docs/EVALUATION_VALIDATION.md`  
**Date:** October 9, 2026  
**Auditor:** Senior ML Engineer / MLOps Researcher  
**Status:** Complete Independent Audit  

---

## 1. Executive Summary

This document presents an independent, line-by-line verification of the AEGIS-ML evaluation pipeline, comparing reported benchmark metrics against the codebase implementation and underlying dataset properties (`data/raw/combined_labeled.jsonl`).

### Summary of Audit Verdicts

| Verification Question | Audit Verdict | Key Finding |
|---|---|---|
| **1. Exact source of every evaluation label** | **Verified** | Extracted from `attack_type` or `raw_label` via `DATASET_LABEL_MAP` in `load_flexible_dataset`. |
| **2. Mapping between raw labels and canonical classes** | **Verified** | Strict mapping in `DATASET_LABEL_MAP` to 5 canonical classes (`benign`, `brute_force`, `lateral_movement`, `data_exfiltration`, `c2_beaconing`). Unmapped labels are rejected, not cast to benign. |
| **3. Training & test sample overlap** | **Flaw Identified** | Event IDs do not overlap (0 overlap), but **48.6% of test records (686/1,411)** share identical feature content fingerprints with training records due to scripted loops. |
| **4. Duplicate / near-duplicate events crossing the split** | **Flaw Identified** | Random stratified splitting scatters repeated events from the same scripted loop across both train and test partitions. |
| **5. Preprocessing fitted exclusively on train data** | **Verified** | `BehavioralBaselineProfiler` and `IsolationForestDetector` are fitted strictly on `train_events`. |
| **6. Resampling occurs only within training folds** | **Verified** | `SMOTE` is fitted and applied strictly on `X_train`, never on `X_test`. |
| **7. Reported metrics come from held-out predictions** | **Verified** | Evaluated on predictions from `classifier.model.predict(X_test)`. |
| **8. Benign FPR calculated correctly** | **Verified** | `cm[bi, j] / sum(cm[bi])` computes `FP / (FP + TN) = FPR` on benign holdout. |
| **9. Attack-recall definition explicit** | **Clarified** | Binary attack recall (`any attack pred / actual attack`) is 100%; multi-class per-category recall is also provided under `per_class`. |
| **10. All attack categories evaluated separately** | **Verified** | Per-class precision, recall, F1, and support are recorded for all 5 classes. |
| **11. Four configurations genuinely different** | **Partially Verified** | Configs A, B, C, and D represent distinct conceptual pipelines, but Config B produces identical predictions to Config A on this specific synthetic dataset. |
| **12. Anomaly detector changes predictions** | **No Impact on Benchmark** | `anomaly_additions = 0`. The Random Forest had 0 false negatives on the synthetic attacks, leaving no missed attacks for the anomaly detector to rescue. |
| **13. Incident correlator evaluated independently** | **Identified Limitation** | Evaluated as a downstream consumer of detection alerts; not evaluated independently with ground-truth cluster labels. |
| **14. Valid incident-level ground truth** | **Absent in Dataset** | `data/raw/combined_labeled.jsonl` contains per-event labels, but **no ground-truth incident identifiers or clusters**. |
| **15. Latency measurement methodology** | **Requires Hardening** | Single-pass wall-clock timing (`time.time()`); lacks CPU cache warm-up and multi-iteration averaging. |

---

## 2. In-Depth Analysis of Critical Findings

### 2.1 The Data Duplication & Leakage Phenomenon (Questions 3 & 4)

In `backend/data_generator/attack_scenarios.py`, attacks are generated via scripted loops:
- Brute-force attacks repeatedly issue login attempts from `ATTACKER_IPS` to `api.corp.com` with identical payload sizes (512 bytes sent, 256 received).
- C2 beaconing transmits fixed-interval heartbeats with invariant byte counts.

When `train_test_split(..., test_size=0.20, stratify=labels, random_state=42)` is applied:
1. `event_id` is unique per record (UUID4), so `train_ids ∩ test_ids = ∅`.
2. Content fingerprints (layer, entities, ports, protocols, action, bytes) exhibit substantial overlap:
   - Unique Train Content Fingerprints: 2,962
   - Unique Test Content Fingerprints: 779
   - Overlapping Fingerprints: 56
   - Train events with overlapping content: **2,653 out of 5,640 (47.0%)**
   - Test events with overlapping content: **686 out of 1,411 (48.6%)**

**Consequence:** The Random Forest achieves near-perfect metrics (Macro-F1 = 0.9823, Test Accuracy = 99.6%) largely because it has memorized identical feature patterns seen in training. This is a classic synthetic benchmark artifact.

### 2.2 Why a Naive Temporal Split Fails on `combined_labeled.jsonl`

An inspection of `data/raw/combined_labeled.jsonl` reveals its structural composition:
- Lines 1–2,051: Exclusively `benign` background traffic.
- Lines 2,052–5,051: Exclusively `brute_force` scenario events.
- Lines 5,052–6,371: Exclusively `data_exfiltration` scenario events.
- Lines 6,372–6,716: Exclusively `c2_beaconing` scenario events.
- Lines 6,717–7,051: Exclusively `lateral_movement` scenario events.

Because the scenarios were appended sequentially:
- A naive 80% temporal cut assigns the first 5,640 records to training and the last 1,411 to testing.
- The training split contains 100% of all benign records (`benign`: 2,051).
- The test split contains **zero benign records** (`benign`: 0).
- Consequently, False Positive Rate on benign data cannot be evaluated under a naive temporal split without interleaving background traffic across scenarios.

### 2.3 The Role of the Anomaly Detector (Question 12)

In `ablation_study.py`, Config B applies the rule:
```python
if pred == "benign":
    if_score = if_detector.predict(event)
    baseline_dev = profiler.compute_deviation_score(event)
    if if_score >= ANOMALY_THRESHOLD or baseline_dev >= 0.70:
        y_pred_b[i] = "brute_force"  # or anomaly class
```
On the synthetic holdout:
- The Random Forest classified all 1,000 actual attack events as attacks.
- None were misclassified as benign.
- For the 411 benign events, neither `if_score` nor `baseline_dev` exceeded the threshold.
- Therefore, `anomaly_additions = 0`.
- Config B produced results identical to Config A.

**Conclusion:** The anomaly detector provides a defensive fallback against novel or unmodeled attack patterns, but on this scripted dataset, it contributed zero metric differences.

### 2.4 Incident Correlation Ground Truth (Questions 13 & 14)

The previous report noted a reduction from "1,000 alerts to 188 incident dossiers (81.2% reduction)".
- This metric represents **triage item compression**: the correlator grouped 1,000 alerts into 188 incident entities.
- However, because `combined_labeled.jsonl` contains **no true incident cluster IDs**, we cannot measure:
  - Cluster Purity / Cluster F1
  - Whether events belonging to different campaigns were erroneously merged
  - Whether single campaigns were fragmented across multiple incidents

To evaluate incident correlation scientifically without fabricating dataset ground truth, we employ **dedicated fixture-based correlation evaluations** with explicit ground-truth campaign assignments.

### 2.5 The "Config C Macro-F1: 0.9331" Defect Resolved

In the original evaluation code:
```python
# Flawed implementation in original Config C:
fp = correlator.compute_event_fingerprint(event)
if correlator.is_duplicate(fp, event.timestamp):
    y_pred_c[i] = "benign"  # Deduplicated event treated as suppressed
    deduped_alerts += 1
```
- When an alert was deduplicated within the 60-second window, the original script set `y_pred_c[i] = "benign"`.
- This caused 124 detected brute force attacks to be scored as **missed attacks (false negatives)** in the classification metrics.
- Consequently, `brute_force` recall dropped from 1.000 to 0.7933, reducing Macro-F1 from 0.9823 to 0.9331.
- **Root Cause:** Conflating event-level detection with incident correlation / alert suppression.
- **Resolution:** In Phase 9, event-level predictions are decoupled from triage compression. Event-level classification is evaluated on actual model predictions (Macro-F1 = 0.9823), while alert deduplication is reported under operational triage metrics (124 duplicates suppressed, 12.4% duplicate reduction rate).

---

## 3. Corrective Engineering Actions

1. **Decoupled Evaluation Metrics (`backend/evaluation/ablation_study.py`)**:
   Event classification metrics are evaluated strictly on model predictions. Operational triage metrics (raw alerts, deduplicated alerts, retained alerts, dossiers created) are tracked under distinct, documented units.

2. **Leakage-Resistant Group-Aware Holdout (`evaluate_leakage_resistant_holdouts`)**:
   - Analyzes exact and near-duplicate feature content: 3,469 out of 7,051 events (49.2%) belong to duplicate groups.
   - Partitions events by feature fingerprint: **zero duplicate groups cross between train and test**.
   - Achieves **Balanced Accuracy = 0.9317**, **Macro-F1 = 0.8591**, **Benign FPR = 0.0073**.
   - Analyzes chronological ordering and documents the fundamental 0-benign test limitation of naive temporal splitting.

3. **Expanded Controlled Correlation Benchmark (12 Fixtures)**:
   Expanded `backend/evaluation/correlation_benchmark.py` to cover:
   - Multi-stage APT (3 steps)
   - Shared victim with independent attackers (merge prevention guard)
   - Attacker outside time window (sliding window guard)
   - Interleaved legitimate admin activity (benign isolation guard)
   - Duplicate replay flood (deduplication & priority invariance guard)
   - Out-of-order and missing timestamps (graceful recovery guard)
   - Concurrent multi-subnet campaigns (parallel campaign isolation)
   - Attacker sweeping multiple victims (Rule 1 single campaign sweep)
   - Unrelated events sharing destination (destination merge prevention)
   - False lateral pivot rejection (uninvolved host isolation)
   - Ambiguous multi-stage sequences (disjoint campaign separation)
   - Partial entity telemetry (robust correlation without crash)

4. **Evidence-Aware Incident Data Model & UI**:
   - `Incident` schema exposes `matched_rules`, `relationship_evidence`, `uncertainty_notes`, and formulaic `priority_calculation_breakdown`.
   - UI provides direct navigation from relationship evidence to underlying event telemetry in Tab 2.
   - Explicit disclaimers for simulated remediation actions.

---

## 4. Reproduced Evaluation and Correlation Benchmark Results

### 4.1 Stratified Baseline Ablation Results (`data/models/ablation_results.json`)

Reproduced via `python3 -m backend.evaluation.ablation_study`:
- **Holdout Partition**: 1,411 samples (80/20 stratified holdout on `combined_labeled.jsonl`, seed=42)
- **Config A (Classifier Only)**:
  - Macro F1: `0.9823` | Weighted F1: `0.9957` | Benign FPR: `0.0000` | Raw Alerts: `1,000`
- **Config B (Classifier + Anomaly Detection)**:
  - Macro F1: `0.9823` | Weighted F1: `0.9957` | Benign FPR: `0.0000` | Raw Alerts: `1,000`
  - Anomaly additions: `0` (RF achieves 100% attack recall on scripted patterns)
- **Config C (+ Incident Correlation)**:
  - Event-Level Macro F1: `0.9823` | Benign FPR: `0.0000`
  - Raw Alerts: `1,000` | Duplicates Suppressed: `124` | Retained Alerts: `876` | Dossiers Created: `52`
  - Displayed Triage Reduction: **94.8% reduction in displayed triage items** without loss of recall
- **Config D (+ Priority Queue Top-20)**:
  - Triage Alerts: `531` (46.9% triage reduction; prioritizes high-risk multi-stage campaigns)

### 4.2 Leakage-Resistant Group-Aware Evaluation (`data/models/ablation_results.json`)

Evaluated on untouched feature groups (zero duplicate feature content crossing train/test):
- **Train Samples**: 5,651 | **Test Samples**: 1,400
- **Duplicate Group Overlap**: **0.0%**
- **Balanced Accuracy**: `0.9317`
- **Macro-F1**: `0.8591` (Precision: 0.8662, Recall: 0.9317)
- **Weighted-F1**: `0.9251`
- **Benign FPR**: `0.0073` (3 false positives / 410 benign test events)
- **Per-Class F1 Scores**:
  - `benign`: 0.9963
  - `brute_force`: 0.9980
  - `c2_beaconing`: 1.0000
  - `data_exfiltration`: 0.7993
  - `lateral_movement`: 0.5021

### 4.3 Controlled Correlation Benchmark Results (`data/models/correlation_benchmark_results.json`)

Reproduced via `python3 -m backend.evaluation.correlation_benchmark`:
- **Scenarios Evaluated**: 12 documented fixtures (`34` total fixture events)
- **Pairwise Cluster Precision**: `1.0000` (100.0% — zero unrelated events merged)
- **Pairwise Cluster Recall**: `1.0000` (100.0% — zero related events fragmented)
- **Pairwise Cluster F1**: `1.0000`
- **Merge Errors (Unrelated Merged)**: `0`
- **Split Errors (Related Fragmented)**: `0`
- **Evidence Traceability**: `100.0%` (every incident retains full supporting event ID traceability)
- **Duplicate Risk Invariance**: `True` (repeated alert floods do not inflate priority score)
- **Displayed Triage Reduction**: `44.12%` across fixtures

### 4.4 Reproduction Commands

```bash
# 1. Run all regression tests (51 tests)
python3 -m pytest tests/ -v --tb=short

# 2. Run correlation quality benchmark (12 fixtures)
python3 -m backend.evaluation.correlation_benchmark

# 3. Run pipeline ablation study & leakage-resistant holdout evaluation
python3 -m backend.evaluation.ablation_study

# 4. Verify frontend production build
cd frontend && npm run build
```
