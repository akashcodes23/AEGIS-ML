# AEGIS-ML Phase 15: Evaluation Integrity and Detection Error Analysis

## Executive Summary

Phase 15 establishes an unambiguous, mathematically verified, and independently reproducible evaluation framework for AEGIS-ML. This audit resolves historical metric terminology ambiguities, rigorously distinguishes multiclass False Positive Rates from False Negative Rates, documents the exact multi-seed variance behavior, performs an empirical error analysis on all misclassified events, and enforces automated mathematical invariants.

In accordance with **Project Safety Rules 1–10**:
1. All analysis and development was conducted strictly within `~/major_project/AEGIS-ML`. `HalluciSense` and external repositories were not touched.
2. No data, labels, or telemetry were fabricated.
3. No metrics were manually adjusted to match prior documentation; all figures were recomputed directly from underlying predictions and ground-truth labels.
4. Attribution-aware predictive modeling remains transparently designated as `NOT_COMPLETED` on the raw benchmark because host socket bindings are absent.
5. Synthetic software regression fixtures remain clearly separated from real-world external validation.

---

## 1. Corrected Metric Definitions & Resolution of the 3/410 Discrepancy

### The 3/410 Discrepancy Investigation
Prior documentation and evaluation code reported `3 / 410 = 0.0073` (0.73%) as the "Benign False Positive Rate (FPR)". Phase 15's mathematical audit revealed the exact origin of this figure:

In intrusion detection literature, researchers often adopt a **binary lens** where traffic is either "Attack" (Positive) or "Benign / Normal" (Negative). Under this binary formulation:
- Actual Benign events = Negative ($N = 410$)
- Actual Benign events falsely classified as an attack = False Positive / False Alarm ($FP = 3$)
- Binary False Positive Rate on Benign Traffic = $\frac{FP}{FP + TN} = \frac{3}{3 + 407} = \frac{3}{410} = 0.007317$ ($0.73\%$).

**However, in multiclass evaluation** where "benign" is evaluated as one of $K=5$ distinct classes using standard one-vs-rest metrics (e.g., scikit-learn):
- **Benign True Positives ($TP_{benign}$):** Actual benign predicted as benign = **407**
- **Benign False Negatives ($FN_{benign}$):** Actual benign predicted as non-benign (2 brute force, 1 lateral movement) = **3**
- **Benign False Positives ($FP_{benign}$):** Actual non-benign attacks predicted as benign = **0**
- **Benign True Negatives ($TN_{benign}$):** Actual non-benign attacks predicted as other attack classes = **990**

### Formal Multiclass Metric Formulations

$$\text{Multiclass Benign FPR} = \frac{FP_{benign}}{\text{Actual Non-Benign Events}} = \frac{FP_{benign}}{FP_{benign} + TN_{benign}} = \frac{0}{0 + 990} = \mathbf{0.0000} \quad (0.0\%)$$

$$\text{Multiclass Benign FNR} = \frac{FN_{benign}}{\text{Actual Benign Events}} = \frac{FN_{benign}}{TP_{benign} + FN_{benign}} = \frac{3}{3 + 407} = \frac{3}{410} = \mathbf{0.007317} \quad (0.73\%)$$

$$\text{Binary False Alarm Rate on Benign} = \frac{\text{Actual Benign Misclassified as Threat}}{\text{Total Actual Benign Events}} = \frac{3}{410} = \mathbf{0.007317} \quad (0.73\%)$$

The canonical artifact now records both `benign_fpr` ($0 / 990$) and `benign_fnr` ($3 / 410$), alongside `binary_false_alarm_rate_on_benign` ($3 / 410$), eliminating all conceptual ambiguity.

---

## 2. Canonical Evaluation Results ($N_{test} = 1,400$)

Evaluated on the frozen, leak-free group-aware holdout test split:
- **Canonical Class Order:** `['benign', 'brute_force', 'lateral_movement', 'data_exfiltration', 'c2_beaconing']`

### Confusion Matrix ($5 \times 5$)
Rows represent ground truth; columns represent model predictions:

$$\begin{pmatrix}
407 & 2 & 1 & 0 & 0 \\
0 & 498 & 0 & 0 & 0 \\
0 & 0 & 61 & 0 & 0 \\
0 & 33 & 87 & 239 & 0 \\
0 & 0 & 0 & 0 & 72
\end{pmatrix}$$

### Detailed Per-Class Breakdown

| Class | Support | TP | FP | FN | Precision | Recall | F1-Score |
|---|---|---|---|---|---|---|---|
| **benign** | 410 | 407 | 0 | 3 | **1.0000** | **0.9927** | **0.9963** |
| **brute_force** | 498 | 498 | 35 | 0 | **0.9343** | **1.0000** | **0.9661** |
| **lateral_movement** | 61 | 61 | 88 | 0 | **0.4094** | **1.0000** | **0.5810** |
| **data_exfiltration** | 359 | 239 | 0 | 120 | **1.0000** | **0.6657** | **0.7993** |
| **c2_beaconing** | 72 | 72 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| **Macro Average** | 1,400 | 1,277 | 123 | 123 | **0.8687** | **0.9317** | **0.8685** |
| **Weighted Average** | 1,400 | 1,277 | 123 | 123 | **0.9509** | **0.9121** | **0.9171** |

### Aggregate Summary
- **Overall Accuracy:** $\frac{1277}{1400} = \mathbf{0.9121}$ ($91.21\%$)
- **Macro-F1:** $\frac{0.9963 + 0.9661 + 0.5810 + 0.7993 + 1.0000}{5} = \mathbf{0.8685}$
- **Weighted-F1:** $\mathbf{0.9171}$
- **Balanced Accuracy:** $\frac{0.9927 + 1.0000 + 1.0000 + 0.6657 + 1.0000}{5} = \mathbf{0.9317}$
- **Multiclass Benign FPR:** $0 / 990 = \mathbf{0.0000}$ ($0.0\%$)
- **Multiclass Benign FNR:** $3 / 410 = \mathbf{0.007317}$ ($0.73\%$)
- **Binary False Alarm Rate on Benign:** $3 / 410 = \mathbf{0.007317}$ ($0.73\%$)

---

## 3. Dataset Hash and Split Provenance

- **Dataset Path:** `data/raw/combined_labeled.jsonl`
- **Total Records:** 7,051
- **Dataset SHA-256 Digest:** `25f2bf6889a563fcc220be23c709294f151be4693a8108052391c1ce594bf7f7`
- **Split Strategy:** `group_aware_holdout`
  - Every event is assigned a 15-field fingerprint: `(layer, src_entity, dst_entity, src_port, dst_port, protocol, action, process_name, file_path, bytes_sent, bytes_received, auth_result, http_method, endpoint_path, status_code)`.
  - 7,051 events collapse into 6,128 unique fingerprint groups.
  - Stratified 80/20 split performed across group identifiers with fixed seed `42`.
  - **Train partition:** 5,651 events (80.14%)
  - **Test partition:** 1,400 events (19.86%)
  - **Cross-Split Duplicate Overlap:** **0.0%** (Zero duplicate feature vectors bridge the train/test boundary).
  - **Test Identifier Integrity:** 1,400 immutable UUID event identifiers are persisted in `canonical_evaluation_artifact.json`.

---

## 4. Multi-Seed Experiment & Reproducibility Analysis

### What Changes Across Seeds?
The three-seed experiment evaluated in `backend/evaluation/attribution_experiment.py` (Seeds 42, 1337, 2026) was audited to determine the exact sources of variance:

| Dimension | Seed 42 | Seed 1337 | Seed 2026 | Changes Across Seeds? |
|---|---|---|---|---|
| **Holdout Group Split** | Shuffled via `Random(42)` ($N_{test}=1400$) | Shuffled via `Random(1337)` ($N_{test}=812$) | Shuffled via `Random(2026)` ($N_{test}=1324$) | **YES (Split changes)** |
| **Isolation Forest Randomness** | `random_state=42` | `random_state=1337` | `random_state=2026` | **YES (Preprocessing changes)** |
| **SMOTE Resampling Randomness** | `random_state=42` | `random_state=1337` | `random_state=2026` | **YES (Resampling changes)** |
| **Random Forest Estimator Randomness** | `random_state=42` | `random_state=1337` | `random_state=2026` | **YES (Model changes)** |

**Crucial Finding:** The multi-seed experiment is an **end-to-end randomized validation procedure** that tests pipeline stability across different group-aware splits, preprocessing seeds, resampling initializations, and tree partitions. It is **not** an evaluation of three model initializations on an identical test holdout.

### Seed-by-Seed Results Summary

| Metric | Seed 42 ($N_{test}=1400$) | Seed 1337 ($N_{test}=812$) | Seed 2026 ($N_{test}=1324$) | Mean across Seeds |
|---|---|---|---|---|
| **Macro-F1** | 0.8685 | 0.9215 | 0.9229 | **0.9043** |
| **Weighted-F1** | 0.9171 | 0.9515 | 0.9632 | **0.9439** |
| **Balanced Accuracy** | 0.9317 | 0.9090 | 0.9050 | **0.9152** |
| **Benign FPR** | 0.0000 (0/990) | 0.0000 (0/402) | 0.0055 (5/914) | **0.0018** |
| **Benign FNR** | 0.0073 (3/410) | 0.0000 (0/410) | 0.0122 (5/410) | **0.0065** |
| **Binary Benign False Alarm Rate** | 0.0073 (3/410) | 0.0000 (0/410) | 0.0122 (5/410) | **0.0065** |

---

## 5. Comprehensive Detection Error Analysis

Every misclassified event in the canonical test set was extracted and analyzed using raw telemetry fields:

### 1. Data Exfiltration $\rightarrow$ Lateral Movement (87 False Positives for Lateral Movement, 87 False Negatives for Data Exfiltration)
- **Event Characteristics:** All 87 events are **endpoint-layer file read operations** executed by `7z.exe` on host `10.0.0.33` (`src_entity=10.0.0.33`, `dst_entity=10.0.0.33`, `layer=endpoint`, `action=read`, `process_name=7z.exe`, `dst_port=None`, `bytes_sent=None`).
- **Root Cause:**
  1. *Missing Socket Telemetry:* Staging data into a `.7z` archive is a local disk operation. It has no network socket or outbound byte flow.
  2. *Feature Overlap:* In the feature space, local anomalous process execution without network telemetry overlaps directly with lateral movement execution/reconnaissance stages.
  3. *Model Misattribution:* Because the network flow that subsequently transfers the archive occurs later and lacks a process-to-socket binding linking it to PID `7z.exe`, the classifier cannot associate the local read with network exfiltration.

### 2. Data Exfiltration $\rightarrow$ Brute Force (33 False Positives for Brute Force, 33 False Negatives for Data Exfiltration)
- **Event Characteristics:** All 33 events are also endpoint-layer file read operations by `7z.exe` on host `10.0.0.33`.
- **Root Cause:**
  1. *Rapid Execution Burst:* High-frequency endpoint file access without network bytes exhibits elevated event rates (`event_rate_1m`, `event_rate_5m`).
  2. *Classification Bias:* In the absence of network-layer destination indicators, high-frequency internal events are pulled toward the `brute_force` cluster (which is heavily populated by high-frequency repeated actions).

### 3. Benign $\rightarrow$ Lateral Movement (1 False Positive for Lateral Movement, 1 False Negative for Benign)
- **Event Details:** `ID: 475961b2-dbc7-4c16-b5e1-9a0bdc941072`, `layer=network`, `src=10.0.0.73`, `dst=10.0.0.12`, `dst_port=445`, `protocol=SMB`, `bytes_sent=196`.
- **Root Cause:** Legitimate administrative internal SMB connection on port 445. Because port 445 has `PORT_RISK = 1.0` (heavily associated with PsExec and SMB lateral movement in training data), the model flagged it as lateral movement.

### 4. Benign $\rightarrow$ Brute Force (2 False Positives for Brute Force, 2 False Negatives for Benign)
- **Event Details:** `ID: a3904515-1b9b-43cd-9aaa-5dd9c5cb5436` and `6f732fb7-2353-4689-af59-c21476254b5b`, `layer=application`, `src=10.0.0.1`, `dst=10.0.0.10/intranet`, `dst_port=80`, `protocol=TCP`, `bytes_sent=1737` / `1301`.
- **Root Cause:** High-volume automated intranet HTTP requests on port 80 resembling web application authentication brute-force activity.

### 5. Benign False Positives (Attacks predicted as Benign)
- **Count:** **0 events** ($FP_{benign} = 0$).
- **Attack Recall:** Across all 990 attack test events, **zero attacks were misclassified as benign**. Benign class precision is **100.0%** ($407 / 407$).

---

## 6. Attribution and External Validation Status

### Attribution-Aware Predictive Modeling Status: `NOT_COMPLETED`
- Audit of all 7,051 records in `data/raw/combined_labeled.jsonl` confirmed that `socket_id`, `host_id`, `process_guid`, `pid`, and `process_start_time` are **0.0% populated**.
- In strict adherence to Safety Rules 6 & 10, real telemetry was not fabricated to force an artificial ML benchmark.
- Synthetic dual-telemetry correlation fixtures validate software logic (10/10 passed), but do not substitute for real-world predictive ML generalization.

### Real External Dataset Validation Status: `NOT_COMPLETED`
- External PCAP/NetFlow evaluation against CIC-IDS2017 remains marked `NOT_COMPLETED` because the raw PCAP CSV (`Monday-WorkingHours.pcap_ISCX.csv`) is not populated in `data/external/cicids2017/`.
- No external detection performance is claimed without measured empirical evaluation on real data.

---

## 7. Known Limitations & Methodological Constraints

1. **Endpoint Staging Blindspot:** Machine learning classifiers operating on tabular event rows cannot distinguish local archive staging (`7z.exe`) from lateral movement without OS process-to-socket lineage telemetry.
2. **SMB Port Ambiguity:** Legitimate internal SMB file sharing on port 445 cannot be differentiated from lateral movement using static port risk features alone; host process context (e.g. `psexec` vs `explorer.exe`) is required.
3. **Synthetic Holdout Scope:** The benchmark dataset consists of scripted lab scenarios; high precision on benign traffic (100%) may not reflect real enterprise environments containing untyped background daemon traffic.

---

## 8. Exact Reproduction Commands

```bash
# 1. Run all unit and invariant tests (Phase 15 test suite)
python3 -m pytest tests/ -v --tb=short

# 2. Regenerate and verify canonical evaluation artifact
python3 -m backend.evaluation.canonical_artifact

# 3. Execute feature ablation study
python3 -m backend.evaluation.ablation_study

# 4. Execute correlation engine quality benchmark
python3 -m backend.evaluation.correlation_benchmark

# 5. Check external benchmark harness status
python3 -m backend.evaluation.external_benchmark

# 6. Execute multi-seed attribution experiment
python3 -m backend.evaluation.attribution_experiment

# 7. Compile frontend production assets
cd frontend && npm run build
```
