# AEGIS-ML Phase 28: Detection Quality, Performance Optimization, and Evaluation

## 1. Executive Summary

AEGIS-ML Phase 28 delivers rigorous empirical profiling of the end-to-end detection pipeline, executes statistically sound performance benchmarks comparing synchronous and asynchronous architectures, provides scenario-grouped multi-class detection quality evaluation on the Phase 19 behavioral diversity dataset, conducts granular error analysis across benign workflows, implements safe vectorized batch inference, and audits the local status of external dataset evaluations.

### Key Milestones Achieved:
1. **Granular Profiling (Phase 28.1)**: Measured micro-timings across all 10 stages of the real asynchronous detection pipeline. Identified that single-sample classifier inference consumed **86.62%** of total execution time (42.39 ms / event), with Isolation Forest consuming **12.82%** (6.27 ms / event). Together, single-sample model inference represented **99.44%** of pipeline latency.
2. **Safe Vectorized Batch Inference (Phase 28.5)**: Implemented `predict_batch()` on `ThreatClassifier` and dynamic worker batching in `AsyncDetectionQueue`. Vectorized inference preserves the 48-feature contract, isotonic probability calibration, feature importances, and host isolation while reducing model execution time per event from 42.39 ms to ~0.50 ms.
3. **Reproducible Benchmarking (Phase 28.2)**: Evaluated equivalent workloads (100, 250, 500 events) under identical configurations. Non-blocking ingestion throughput exceeded **6,200 events/sec** (a ~320x improvement over synchronous ingestion). Completed detection throughput increased from 16.03 eps (unbatched) to **81.51 - 81.67 eps (a 5.08x speedup)** with worker processing latency p50 dropping from 123.4 ms to **12.0 ms (a 10.3x reduction)**.
4. **Detection Quality Evaluation (Phase 28.3)**: Evaluated 1,085 test events on the Phase 19 behavioral diversity dataset using a strict 70/10/20 scenario-grouped split with zero scenario overlap. Achieved **99.63% Overall Accuracy**, **98.89% Balanced Accuracy**, **99.32% Macro-F1**, **0.00% Benign False Positive Rate (0 / 679)**, and **99.26% Attack Recall (403 / 406)**.
5. **False Positive & Negative Analysis (Phase 28.4)**: Zero false positives across all 6 administrative benign workflows (file sharing, sync, archiving, deployment). The 3 missed attacks were lateral movement events lacking process-level telemetry.
6. **External Dataset Status (Phase 28.6)**: Preserved **BLOCKED** status for CIC-IDS2017 evaluation due to absence of local raw CSVs and confirmed telemetry incompatibility (absence of endpoint/process features). Refused to fabricate synthetic substitutes.
7. **Regression Integrity (Phase 28.7)**: Production model SHA-256 (`98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71`) and Phase 19 dataset SHA-256 (`1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`) remain unmodified. All 300 tests pass and frontend production build succeeds with 0 errors.

---

## 2. Phase 28.1 — Pipeline Profiling & Bottleneck Analysis

### Test Environment
- **Platform**: macOS 27.0.1 (Darwin arm64, Apple Silicon)
- **CPU**: 10 Cores
- **Python**: 3.10.12
- **Memory**: 16 GB Unified Memory
- **Profiler Script**: `backend/evaluation/detection_profiler.py`
- **Output Artifact**: `data/models/pipeline_profiling_results.json`

### Profiling Methodology
To eliminate assumptions, the real execution path was instrumented using `time.perf_counter_ns()` across 200 synthetic network and endpoint events spanning multi-host scenarios. The execution was partitioned into 10 distinct stages:

```
[ Ingestion & Normalization ]
           │
           ▼
[ Isolation Forest Anomaly ]
           │
           ▼
[ Behavioral Baseline Dev ]
           │
           ▼
[ Sequence Feature Extraction ]
           │
           ▼
[ Graph Feature Extraction ]
           │
           ▼
[ 48-Feature Assembly ]
           │
           ▼
[ Classifier Inference (RF + Calibrator) ]  <-- 86.62% of CPU time
           │
           ▼
[ Evidence Fusion ]
           │
           ▼
[ Local Explainer ]
           │
           ▼
[ Incident Correlator ]
```

### Empirical Profiling Results

| Stage ID | Pipeline Stage | Total Time (ms) | Mean (ms) | Median p50 (ms) | p95 (ms) | % of Pipeline |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | `1_normalization` | 21.58 | 0.108 | 0.106 | 0.130 | 0.22% |
| 2 | `2_isolation_forest` | 1,254.63 | 6.273 | 7.281 | 7.645 | 12.82% |
| 3 | `3_baseline_profiler` | 0.27 | 0.001 | 0.001 | 0.002 | < 0.01% |
| 4 | `4_sequence_features` | 8.54 | 0.043 | 0.042 | 0.053 | 0.09% |
| 5 | `5_graph_features` | 3.84 | 0.019 | 0.019 | 0.027 | 0.04% |
| 6 | `6_48_feature_assembly` | 11.92 | 0.060 | 0.060 | 0.068 | 0.12% |
| **7** | **`7_classifier_inference`** | **8,477.53** | **42.388** | **41.765** | **46.812** | **86.62%** |
| 8 | `8_evidence_fusion` | 2.14 | 0.011 | 0.010 | 0.015 | 0.02% |
| 9 | `9_local_explainer` | 0.00 | 0.000 | 0.000 | 0.000 | 0.00% |
| 10 | `10_incident_correlator` | 5.37 | 0.027 | 0.023 | 0.054 | 0.06% |
| **Total** | **End-to-End Pipeline** | **9,785.82** | **48.929** | **49.307** | **54.806** | **100.00%** |

### Confirmed Root Causes
1. **Single-Sample Inference Overhead**: Scikit-Learn `RandomForestClassifier.predict_proba` and `CalibratedClassifierCV.predict_proba` incur significant Python-to-Cython function invocation and tree-traversal dispatch overhead when called with $N=1$ samples. For 100 trees across 5 calibrated folds, single-call dispatch takes ~42 ms.
2. **Feature Extraction Efficiency**: Causal sequence tracking, temporal graph queries, and 48-feature assembly together execute in under 0.25 ms per event (< 0.5% total CPU time), confirming that feature extraction is already highly optimized.

---

## 3. Phase 28.5 — Safe Performance Optimization

### Implementation: Vectorized Batch Inference
Rather than altering the model architecture, feature schema, or calibration mathematics, optimization was achieved through vectorized batch evaluation:

1. **`ThreatClassifier.predict_batch()`**:
   - Accepts a list of feature vectors: `features_list: List[List[float]]`.
   - Validates missing values and schema bounds for each vector independently.
   - Evaluates `model.predict_proba(X)` on the 2D matrix $X$ in a single vectorized Cython call.
   - Evaluates `calibrator.predict_proba(X)` across the batch with sum-to-one validation.
   - Maps calibrated posterior probabilities back to individual `ThreatPrediction` instances.
2. **Dynamic Worker Batching (`AsyncDetectionQueue`)**:
   - Detection worker dequeues available items up to `batch_size=16` non-blockingly.
   - Sorts unique host partition keys lexicographically to acquire locks in deterministic order, completely preventing deadlocks while preserving host causality.
   - Dispatches batch feature evaluation through `detection_batch_handler` in the thread pool.
   - Falls back to sequential single-item processing with exponential retries if any batch error occurs.
3. **Verification of Equivalence**:
   - `tests/test_phase28_quality_and_perf.py::test_predict_batch_mathematical_equivalence` verified that across all classes, confidences, and calibrated probabilities, `predict_batch` outputs match `predict` with a difference $< 10^{-9}$.

---

## 4. Phase 28.2 — Performance Benchmarking

### Methodology
- Evaluated Synchronous Baseline, Asynchronous Unbatched (Phase 27), and Asynchronous Batched (Phase 28 Optimized).
- Identical multi-host event workloads (100, 250, 500 events).
- Equivalent warm-up procedure (15 events prior to measurement).
- Distinct metrics: Ingestion throughput (enqueue) vs. Completed detection throughput (worker completion).
- Explicit `q.flush()` ensuring 100% of events completed before stopping measurements.

### Comparative Benchmark Measurements

```
Workload: 100 Events
  Synchronous Baseline:           20.02 eps (Latency p50: 49.9 ms)
  Async Unbatched (Phase 27):     16.50 eps (Worker Proc p50: 120.7 ms, E2E p50: 3146.7 ms)
  Async Batched (Phase 28):       81.54 eps (Worker Proc p50:  11.7 ms, E2E p50:  754.9 ms) -> 4.94x Speedup

Workload: 250 Events
  Synchronous Baseline:           19.34 eps (Latency p50: 51.1 ms)
  Async Unbatched (Phase 27):     16.21 eps (Worker Proc p50: 122.0 ms, E2E p50: 7792.3 ms)
  Async Batched (Phase 28):       81.67 eps (Worker Proc p50:  12.0 ms, E2E p50: 1557.0 ms) -> 5.04x Speedup

Workload: 500 Events
  Synchronous Baseline:           19.29 eps (Latency p50: 51.8 ms)
  Async Unbatched (Phase 27):     16.03 eps (Worker Proc p50: 123.4 ms, E2E p50: 15705.6 ms)
  Async Batched (Phase 28):       81.51 eps (Worker Proc p50:  12.0 ms, E2E p50: 3120.9 ms) -> 5.08x Speedup
```

### Detailed Metrics Table (Workload: 250 Events)

| Metric | Synchronous Baseline | Async Unbatched (Phase 27) | Async Batched (Phase 28) | Optimization Impact |
| :--- | :---: | :---: | :---: | :---: |
| **Ingestion Throughput** | 19.34 eps | 6,561.46 eps | 6,458.54 eps | **~334x faster enqueue** |
| **Completed Detection Throughput** | 19.34 eps | 16.21 eps | **81.67 eps** | **5.04x speedup** |
| **Worker Processing Latency p50** | 51.08 ms | 121.98 ms | **12.02 ms** | **10.1x latency reduction** |
| **Queue Wait Time p50** | N/A | 7,669.31 ms | **1,171.71 ms** | **6.5x wait reduction** |
| **End-to-End Latency p50** | 51.08 ms | 7,792.35 ms | **1,557.03 ms** | **5.0x latency reduction** |
| **Peak Queue Depth** | 0 | 248 | 240 | Bounded within capacity |
| **Peak Heap Memory Allocation** | 1.45 MB | 1.48 MB | 1.47 MB | Zero memory leak |
| **Queue Rejections / Drops** | 0 | 0 | 0 | 100% completion |

---

## 5. Phase 28.3 — Detection Quality Evaluation

### Split Methodology & Data Governance
- **Dataset**: `data/raw/behavioral_diversity_labeled.jsonl` (5,717 events).
- **Split Strategy**: Scenario-Grouped Stratified Partition (70% Train: 3,969 events, 10% Val: 663 events, 20% Test: 1,085 events).
- **Leakage Prevention**: Scenarios are partitioned strictly as intact clusters. No event belonging to a test scenario appears in the training or validation sets.
- **Preprocessing Fit**: Behavioral baseline profiler and Isolation Forest were fitted strictly on the training partition.

### Aggregate Quality Metrics (Test Split: 1,085 Samples)

| Metric | Value | Baseline Target | Status |
| :--- | :---: | :---: | :---: |
| **Overall Accuracy** | **99.63%** | $\ge 95.0\%$ | PASS |
| **Balanced Accuracy** | **98.89%** | $\ge 95.0\%$ | PASS |
| **Macro-F1 Score** | **99.32%** | $\ge 95.0\%$ | PASS |
| **Weighted-F1 Score** | **99.63%** | $\ge 95.0\%$ | PASS |
| **Benign False Alarm Rate (FPR)** | **0.00% (0 / 679)** | $\le 5.0\%$ | PASS |
| **Overall Attack Recall** | **99.26% (403 / 406)** | $\ge 95.0\%$ | PASS |
| **Calibrated Multi-Class Log-Loss** | **0.1468** | $\le 0.35$ | PASS |
| **Binary Brier Score** | **0.0042** | $\le 0.05$ | PASS |

### Per-Class Detection Breakdown

| Canonical Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| `benign` | 99.56% | 100.00% | 99.78% | 679 |
| `brute_force` | 100.00% | 100.00% | 100.00% | 150 |
| `c2_beaconing` | 100.00% | 100.00% | 100.00% | 30 |
| `data_exfiltration` | 99.35% | 100.00% | 99.68% | 154 |
| `lateral_movement` | 100.00% | 94.44% | 97.14% | 72 |

### 5x5 Multiclass Confusion Matrix

```
Predicted Class ->
Actual Class      benign    brute_force  c2_beaconing  data_exfil  lateral_mvmt
-------------------------------------------------------------------------------
benign              679           0            0            0            0
brute_force           0         150            0            0            0
c2_beaconing          0           0           30            0            0
data_exfiltration     0           0            0          154            0
lateral_movement      3           0            0            1           68
```

---

## 6. Phase 28.4 — False-Positive and False-Negative Analysis

### Benign Administrative Workflow False-Positive Audit
To evaluate resilience against legitimate administrative enterprise tasks, false alarms were categorized across 6 specific workflow types:

| Benign Workflow Type | Total Events | False Alarms | False Alarm Rate | Misclassifications |
| :--- | :---: | :---: | :---: | :---: |
| `benign_traffic` | 400 | 0 | 0.00% | None |
| `smb_file_sharing` | 106 | 0 | 0.00% | None |
| `data_synchronization` | 72 | 0 | 0.00% | None |
| `bulk_read_archive` | 47 | 0 | 0.00% | None |
| `large_file_transfer` | 29 | 0 | 0.00% | None |
| `software_deployment` | 25 | 0 | 0.00% | None |

**Finding**: The combination of relational graph features (evaluating known communication pairs) and behavioral baselines successfully prevented legitimate file transfers and bulk backups from triggering exfiltration false alarms.

### Attack False-Negative Audit
- **`lateral_movement`**: 3 events out of 72 missed as benign (FN rate: 4.17%), and 1 misclassified as data exfiltration.
  - **Feature Interaction Analysis**: The 3 missed lateral movement events represented initial SMB connection establishment probes over port 445 where byte transfer counts were indistinguishable from baseline sync traffic, and endpoint process telemetry (`process_name`, `auth_result`) was unpopulated.
  - **Remediation Requirement**: Reliable detection of stealthy initial lateral movement probes without generating false alarms on SMB file sharing requires verified endpoint process socket binding (`process_path` and `parent_process_name`). When endpoint telemetry is missing, these probes cannot be verified without risking elevated false alarm rates.
- **`data_exfiltration`, `c2_beaconing`, `brute_force`**: Achieved **100% Recall** (0 missed events across 334 total attacks).

---

## 7. Phase 28.6 — External Dataset Status (CIC-IDS2017)

### Local Availability & Compatibility Audit
- **Local Filesystem Status**: The raw CSV files for the Canadian Institute for Cybersecurity CIC-IDS2017 benchmark are not present in `data/external/cicids2017/raw/`.
- **Telemetry Incompatibility**: As documented in the Phase 24 audit, CIC-IDS2017 consists purely of bidirectional network flow summaries generated via CICFlowMeter. It does NOT contain:
  1. Endpoint process telemetry (`process_name`, `process_path`, `parent_process_name`).
  2. Authentication logs (`auth_result`, `status_code 401`).
  3. Host identifiers or local socket bindings.
- **Scientific Integrity Decision**: Direct transfer evaluation of the AEGIS-ML 48-feature classifier against CIC-IDS2017 remains strictly **BLOCKED / NOT_FEASIBLE** (`INCOMPATIBLE_TELEMETRY`). Fabricating synthetic substitutes or labeling synthetic data as CIC-IDS2017 is rejected.

---

## 8. Artifact and Regression Integrity (Phase 28.7)

### Hash Verification
Both production model and dataset hashes were verified to be identical to their baseline values:

| Artifact | File Path | Expected SHA-256 | Verified SHA-256 | Match |
| :--- | :--- | :--- | :--- | :---: |
| **Production Model** | `data/models/calibrated_threat_classifier.pkl` | `98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71` | `98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71` | YES |
| **Phase 19 Dataset** | `data/raw/behavioral_diversity_labeled.jsonl` | `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352` | `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352` | YES |

### Test Suite Execution
- **Phase 28 Unit & Integration Suite**: 6 tests passed (`tests/test_phase28_quality_and_perf.py`).
- **Phases 22–28 Regression Suite**: 151 tests passed.
- **Complete Repository Suite**: **300 tests passed** in 2m 14s.
- **Frontend Production Build**: Vite built `dist/` in 334ms with 0 errors.

---

## 9. Known Limitations

1. **Synthetic Scenario Generalization**: While the evaluation utilized scenario-grouped stratified splitting to guarantee zero scenario overlap between train and test splits, the underlying events are synthetically generated. Real-world empirical performance on organic enterprise corporate networks has not been independently established.
2. **Volatile In-Memory Queue**: The asynchronous detection queue provides process concurrency and backpressure isolation, but does not provide durable persistence across server process terminations.
3. **Telemetry Completeness Dependency**: In the absence of endpoint process telemetry, low-volume lateral movement probes over standard ports (e.g. 445/SMB) cannot be distinguished from routine administrative traffic without accepting elevated false alarm rates.
