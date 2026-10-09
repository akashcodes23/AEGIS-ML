# AEGIS-ML Benchmark Methodology and Evaluation Guide

**Version:** 1.0 — Leakage-Resistant Evaluation Framework  
**Date:** October 9, 2026  
**Auditor / Author:** Senior ML Research Engineer & Cybersecurity Detection Engineer  
**Status:** Canonical Benchmark Reference  

---

## 1. Executive Overview & Research Question

The core objective of AEGIS-ML is to determine:
> **Can temporal incident correlation and evidence-driven prioritization reduce analyst triage volume while preserving detection coverage, avoiding incorrect incident merges, and maintaining complete evidence traceability?**

To answer this question scientifically without fabricating ground truth or confounding distinct evaluation tasks, this document defines the formal methodology, data boundaries, split strategies, mathematical formulas, and reproduction procedures for all AEGIS-ML evaluations.

---

## 2. Separation of Evaluation Tasks

In network threat detection systems, evaluating multiple architectural layers under a single composite number leads to severe methodological errors (e.g., misinterpreting alert deduplication as classifier false negatives). AEGIS-ML strictly separates the following five evaluation tasks:

| Task | Scope | Primary Unit | Metric Definitions | Ground Truth Source |
|---|---|---|---|---|
| **A. Event-Level Threat Classification** | Supervised multi-class classification | Individual telemetry event | Macro-F1, Weighted-F1, Balanced Accuracy, Per-Class P/R/F1, Benign FPR | Per-event dataset labels (`attack_type` / `raw_label`) |
| **B. Unsupervised Anomaly Detection** | Novelty & deviation scoring | Individual telemetry event | Anomaly score distribution, outlier detection rate | Unlabelled baseline traffic (`benign_only=True`) |
| **C. Hybrid Event Detection** | Supervised + Anomaly fallback | Individual telemetry event | Additional detections rescued, false positive delta | Per-event dataset labels |
| **D. Incident Correlation & Triage** | Grouping, deduplication, & linking | Multi-event incident dossiers | Pairwise Cluster Precision, Recall, F1, Merge Errors, Split Errors, Evidence Traceability | Controlled scenario fixtures (12 documented scenarios) |
| **E. Incident Prioritization** | Severity & risk queue ranking | Prioritized incident queue | Queue top-N coverage, high-priority triage compression | Ground-truth campaign severities |

---

## 3. Dataset Provenance & Structural Characteristics

### 3.1 Primary Evaluation Dataset: `data/raw/combined_labeled.jsonl`
- **Total Records:** 7,051
- **Class Distribution:**
  - `benign`: 2,051 (29.1%)
  - `brute_force`: 3,000 (42.5%)
  - `data_exfiltration`: 1,320 (18.7%)
  - `c2_beaconing`: 345 (4.9%)
  - `lateral_movement`: 335 (4.7%)
- **Provenance:** Synthetic telemetry generated via scripted scenarios (`backend/data_generator/attack_scenarios.py`).

### 3.2 Duplicate Feature Content Analysis
Events are fingerprinted using their 15 invariant telemetry attributes (excluding non-deterministic fields such as `event_id` and millisecond timestamps):
$$\text{Fingerprint} = \text{SHA256}(\text{layer} \parallel \text{src\_entity} \parallel \text{dst\_entity} \parallel \text{ports} \parallel \text{protocol} \parallel \text{action} \parallel \text{process} \parallel \text{bytes} \parallel \text{status})$$

- **Unique Feature Fingerprints:** 3,687 across 7,051 events
- **Duplicate Groups:** 105 groups contain multiple events
- **Records in Duplicate Groups:** **3,469 out of 7,051 events (49.2%)**
- **Cause:** Scripted scenario loops in the data generator emit repeated login attempts, invariant heartbeat packets, and batch file transfers.

---

## 4. Split Strategies & Leakage Prevention

### 4.1 Strategy 1: Random Stratified Holdout (Baseline)
- **Method:** `train_test_split(test_size=0.20, stratify=labels, random_state=42)`
- **Train Samples:** 5,640 | **Test Samples:** 1,411
- **Leakage Observation:**
  - Random assignment without grouping scatters events from the same scripted loop across both partitions.
  - **48.6% of test records (686 / 1,411)** share identical feature fingerprints with training events.
  - **Resulting Metric:** Macro-F1 = **0.9823**, Test Accuracy = **99.6%**.
  - **Finding:** The model memorizes repeated feature vectors, inflating performance metrics.

### 4.2 Strategy 2: Group-Aware (Deduplication-Aware) Holdout (Leakage-Resistant)
- **Method:** Events sharing identical feature content fingerprints are assigned as an atomic block to either train or test, never crossing the boundary.
- **Train Samples:** 5,651 | **Test Samples:** 1,400
- **Group Overlap:** **0.0% (Zero duplicate feature groups cross the split)**
- **Resulting Metrics:**
  - **Balanced Accuracy:** **0.9317**
  - **Macro-F1:** **0.8591** (Precision: 0.8662, Recall: 0.9317)
  - **Weighted-F1:** **0.9251**
  - **Benign FPR:** **0.0073** (3 false positives out of 410 benign test events)
  - **Per-Class Results:**
    - `benign`: Precision 1.0000, Recall 0.9927, F1 0.9963 (Support: 410)
    - `brute_force`: Precision 0.9960, Recall 1.0000, F1 0.9980 (Support: 498)
    - `c2_beaconing`: Precision 1.0000, Recall 1.0000, F1 1.0000 (Support: 72)
    - `data_exfiltration`: Precision 1.0000, Recall 0.6657, F1 0.7993 (Support: 359)
    - `lateral_movement`: Precision 0.3352, Recall 1.0000, F1 0.5021 (Support: 61)
- **Scientific Finding:** On genuinely unseen feature patterns, Macro-F1 drops from 0.9823 to 0.8591. The primary challenge lies in distinguishing unseen data exfiltration patterns from lateral movement, reflecting true model generalization limits.

### 4.3 Strategy 3: Chronological (Temporal) Holdout Analysis
- **Method:** Events sorted chronologically by timestamp; 80% assigned to train, 20% to test.
- **Dataset Limitation Discovered:**
  - In `combined_labeled.jsonl`, all 2,051 benign background events occur between `2026-10-09T02:00:00` and `2026-10-09T11:27:40`.
  - From `11:27:40` to `2026-10-10T05:10:29`, there are **zero benign events**.
  - An 80% temporal cut assigns 100% of benign events to train, leaving **0 benign events in the test partition**.
  - Consequently, Benign FPR is mathematically undefined ($0/0$), and false positive evaluation is impossible under a naive temporal split.
  - **Decision:** The Group-Aware Holdout is the justified, scientifically defensible evaluation design for this dataset.

---

## 5. Controlled Incident Correlation Quality Benchmark

Because `combined_labeled.jsonl` contains per-event attack labels but lacks authoritative ground-truth incident clusters, real-world incident clustering accuracy cannot be evaluated on it without inventing ground truth.

To validate the correlation engine independently from the classifier, AEGIS-ML employs **12 controlled scenario fixtures** with known ground-truth cluster boundaries (`backend/evaluation/correlation_benchmark.py`).

### 5.1 Documented Scenario Fixtures

1. **`SCENARIO_1_MULTI_STAGE_APT`**: External brute force $\rightarrow$ lateral pivot $\rightarrow$ data exfiltration (Expected: 1 incident cluster).
2. **`SCENARIO_2_SHARED_VICTIM_INDEPENDENT_ATTACKERS`**: Two distinct external attackers targeting the same victim server simultaneously (Expected: 2 separate incidents; validates merge prevention guard).
3. **`SCENARIO_3_SAME_ATTACKER_OUTSIDE_WINDOW`**: Same attacker targeting victim 3 hours apart (Expected: 2 separate incidents; validates sliding window expiration).
4. **`SCENARIO_4_INTERLEAVED_BENIGN_ADMIN`**: Legitimate administrative SSH activity interleaved between attack campaign events (Expected: 1 attack incident; benign traffic isolated).
5. **`SCENARIO_5_DUPLICATE_REPLAY_FLOOD`**: 5 identical alerts generated within 20 seconds (Expected: 1 incident; deduplicated; priority score remains invariant).
6. **`SCENARIO_6_OUT_OF_ORDER_AND_MISSING_TIMESTAMPS`**: Out-of-order sequence and `None` timestamps (Expected: 1 incident; graceful timestamp recovery from raw telemetry; zero engine crashes).
7. **`SCENARIO_7_CONCURRENT_SUBNET_INCIDENTS`**: Two simultaneous multi-stage campaigns across different subnets (Expected: 2 separate incidents).
8. **`SCENARIO_8_ONE_ATTACKER_MULTIPLE_VICTIMS`**: Single external attacker sweeping multiple internal hosts in quick succession (Expected: 1 incident cluster under Rule 1).
9. **`SCENARIO_9_UNRELATED_EVENTS_SHARING_DESTINATION`**: External brute force and internal workstation exfiltration connecting to the same DMZ host (Expected: 2 separate incidents; validates destination merge prevention).
10. **`SCENARIO_10_FALSE_PIVOT_REJECTION`**: Uninvolved host initiating lateral movement (Expected: 2 separate incidents; rejects false lateral pivot).
11. **`SCENARIO_11_AMBIGUOUS_SEQUENCES`**: Three distinct attackers targeting three distinct hosts simultaneously (Expected: 3 separate incidents; validates multi-campaign isolation).
12. **`SCENARIO_12_INCOMPLETE_ENTITY_IDENTIFIERS`**: Alerts with missing destination ports or partial telemetry (Expected: 1 incident cluster; graceful fallback without crash).

### 5.2 Benchmark Results ([`data/models/correlation_benchmark_results.json`](file:///Users/akashgpatil/major_project/AEGIS-ML/data/models/correlation_benchmark_results.json))

```
======================================================================
AEGIS-ML INCIDENT CORRELATION QUALITY BENCHMARK (12 SCENARIOS)
======================================================================
  pairwise_cluster_precision            : 1.0000 (0 merge errors)
  pairwise_cluster_recall               : 1.0000 (0 split errors)
  pairwise_cluster_f1                   : 1.0000
  merge_errors_unrelated_merged         : 0
  split_errors_related_fragmented       : 0
  evidence_traceability_pct             : 100.0%
  duplicate_risk_invariance_verified    : True
======================================================================
```

### 5.3 Operational Triage Metrics
- **Total Events Evaluated:** 34
- **Raw Alerts Generated:** 34
- **Duplicate Alerts Suppressed:** 4
- **Alerts Assigned to Incidents:** 30
- **Unassigned Alerts:** 0
- **Incident Dossiers Created:** 19
- **Displayed Triage Reduction Rate:** 44.12% across diverse fixture scenarios (and up to 94.8% on continuous attack streams)

---

## 6. Mathematical Formulas & Definitions

### 6.1 Pairwise Cluster Precision & Recall
For ground-truth pairs $P_{GT} = \{(e_i, e_j) \mid \text{cluster}(e_i) = \text{cluster}(e_j)\}$ and predicted pairs $P_{Pred} = \{(e_i, e_j) \mid \text{incident}(e_i) = \text{incident}(e_j)\}$:

$$\text{Precision}_{pairwise} = \frac{|P_{GT} \cap P_{Pred}|}{|P_{Pred}|}$$

$$\text{Recall}_{pairwise} = \frac{|P_{GT} \cap P_{Pred}|}{|P_{GT}|}$$

$$\text{F1}_{pairwise} = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

### 6.2 Evidence-Based Priority Score
Priority is computed via an explicit, documented linear breakdown capped at 99.0:

$$\text{Priority} = \min(99.0, W_{sev} + B_{layer} + B_{count} + C_{model})$$

Where:
- $W_{sev} \in \{20.0, 45.0, 75.0, 95.0\}$ (Base severity for Low, Medium, High, Critical)
- $B_{layer} = \min(10.0 \times |\text{unique layers}|, 20.0)$
- $B_{count} = \min(2.0 \times |\text{unique alert IDs}|, 15.0)$ (Uses unique alert IDs to ensure invariance against duplicate replay floods)
- $C_{model} = 10.0 \times \max(P_{RF})$

---

## 7. Full Reproduction Suite

To reproduce all benchmarks and tests from scratch:

```bash
# 1. Run all unit and regression tests (51 tests)
python3 -m pytest tests/ -v --tb=short

# 2. Run controlled correlation benchmark (12 fixtures)
python3 -m backend.evaluation.correlation_benchmark

# 3. Run pipeline ablation study & leakage-resistant holdout evaluation
python3 -m backend.evaluation.ablation_study

# 4. Build production frontend bundle
cd frontend && npm run build
```
