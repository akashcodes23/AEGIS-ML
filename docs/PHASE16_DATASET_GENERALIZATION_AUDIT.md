# AEGIS-ML Phase 16: Dataset Provenance and Generalization Audit

**Status Summary:**
- **Task 1: Dataset Provenance Audit:** `COMPLETED`
- **Task 2: Split-Leakage Audit:** `COMPLETED`
- **Scenario-Level Generalization:** `NOT_ESTABLISHED` (Absence of scenario metadata)
- **Task 3: Feature and Label Audit:** `COMPLETED`
- **Task 4: Frozen-Holdout Model Randomness vs Split Variability:** `COMPLETED`
- **Task 5: Baseline and Error Analysis (120 Exfiltration Staging Errors):** `COMPLETED`
- **Task 6: Automated Test Suite:** `COMPLETED`
- **Real-World / Production Generalization:** `NOT_ESTABLISHED` (Controlled synthetic benchmark)

---

## 1. Executive Summary

Phase 16 executed an exhaustive empirical and structural audit of the synthetic cybersecurity telemetry dataset (`data/raw/combined_labeled.jsonl`), the group-aware evaluation splitting methodology, the 21-feature Config C machine learning pipeline, and the classification failure modes in AEGIS-ML.

The central research question investigated was:
> **Does the current synthetic cybersecurity dataset and evaluation procedure provide credible evidence of generalization beyond exact duplicate records?**

### Key Findings:
1. **Scenario Generalization is `NOT_ESTABLISHED`**: The synthetic generation scripts (`backend/data_generator/orchestrator.py`, `attack_scenarios.py`) dumped event dictionaries directly into JSON lines without stamping `scenario_id`, `campaign_id`, or `template_id`. As an empirical consequence, 0 out of 7,051 records (0.0%) possess scenario provenance metadata. While the group-aware split successfully eliminates exact identical feature duplicates (0.0% overlap across partitions), records produced by the same repetitive attack loop appear in both train and test. **Zero duplicate overlap does NOT imply scenario independence.**
2. **Model Seed Variance is Negligible on Frozen Holdouts**: When evaluated on an identical frozen holdout partition ($N_{test} = 1,400$), model seed variance across 5 seeds (`42, 1337, 2026, 7, 999`) is essentially zero:
   $$\text{Macro-F1} = 0.8682 \pm 0.0004 \quad (\min: 0.8677, \max: 0.8685)$$
   $$\text{Balanced Accuracy} = 0.9317 \pm 0.0000$$
   $$\text{Benign FPR} = 0.0000 \quad (0 / 990), \quad \text{Benign FNR} = 0.0073 \quad (3 / 410)$$
   Prior variance reported in earlier phases was driven by split-seed shuffling (which altered the test set size from 812 to 1,400), not model instability.
3. **Root Cause of the 120 Data Exfiltration Errors Confirmed**: 100% of the 120 misclassified `data_exfiltration` records (87 classified as `lateral_movement`, 33 as `brute_force`) are endpoint-layer file read operations executed by `7z.exe` on host `10.0.0.33`. They contain `bytes_sent: null`, `dst_port: null`, and no operating system socket link connecting the file reads to network exfiltration flows. Without socket-to-process attribution, these events reflect local file access rather than completed exfiltration, naturally overlapping with lateral movement and brute force activity. All 239 actual network exfiltration events are classified with 100% precision.

---

## 2. Dataset Schema and Field Population Audit

Audited File: `data/raw/combined_labeled.jsonl`  
Total Records: **7,051**  
Total Attributes Checked: **22**

### Class Distribution:
| Class Label | Record Count | Proportion (%) |
| :--- | :---: | :---: |
| `brute_force` | 3,000 | 42.55% |
| `benign` | 2,051 | 29.09% |
| `data_exfiltration` | 1,320 | 18.72% |
| `c2_beaconing` | 345 | 4.89% |
| `lateral_movement` | 335 | 4.75% |
| **Total** | **7,051** | **100.00%** |

### Field Population and Missingness Rates:
| Field Name | Type / Example | Populated Count | Availability (%) | Missingness (%) | Audit Notes |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `event_id` | UUID string | 7,051 | 100.00% | 0.00% | Fully unique identifier per record |
| `timestamp` | ISO-8601 string | 7,051 | 100.00% | 0.00% | Synthetic linear timestamps |
| `layer` | `network` / `endpoint` | 7,051 | 100.00% | 0.00% | Core dual-telemetry layer tag |
| `src_entity` | IP or hostname | 7,051 | 100.00% | 0.00% | Entity identifier |
| `dst_entity` | IP or hostname | 7,051 | 100.00% | 0.00% | Entity identifier |
| `src_ip` | IPv4 address | 7,051 | 100.00% | 0.00% | Present on all records |
| `src_internal` | Boolean | 7,051 | 100.00% | 0.00% | RFC 1918 internal flag |
| `dst_internal` | Boolean | 7,051 | 100.00% | 0.00% | RFC 1918 internal flag |
| `raw_label` | String | 7,051 | 100.00% | 0.00% | Ground truth label |
| `attack_type` | String | 5,000 | 70.91% | 29.09% | Null for benign records (2,051 records) |
| `bytes_sent` | Integer | 5,321 | 75.46% | 24.54% | Populated for network flows, null on endpoint |
| `bytes_received`| Integer | 5,321 | 75.46% | 24.54% | Populated for network flows, null on endpoint |
| `dst_port` | Integer | 5,321 | 75.46% | 24.54% | Populated for network flows, null on endpoint |
| `dst_ip` | IPv4 address | 3,821 | 54.19% | 45.81% | Populated for IP destinations |
| `protocol` | TCP / UDP | 3,821 | 54.19% | 45.81% | Network layer transport |
| `http_method` | GET / POST | 2,029 | 28.78% | 71.22% | HTTP/web attack events |
| `endpoint_path`| URI path | 2,029 | 28.78% | 71.22% | Web endpoint destination |
| `status_code` | HTTP status code | 2,029 | 28.78% | 71.22% | Response code (e.g. 401, 200) |
| `auth_result` | `success` / `failure` | 1,500 | 21.27% | 78.73% | Authentication events |
| `process_name` | Executable name | 230 | 3.26% | 96.74% | Endpoint process execution |
| `user_account` | Username string | 230 | 3.26% | 96.74% | Endpoint process user context |
| `action` | Action verb (`read`, etc.)| 230 | 3.26% | 96.74% | Endpoint activity action |
| `file_path` | Windows file path | 50 | 0.71% | 99.29% | File staging events |
| `parent_process`| Executable name | 30 | 0.43% | 99.57% | Process lineage |
| `duration_ms` | Milliseconds | 1 | 0.01% | 99.99% | Sparse duration field |

### Critical Provenance Identifiers Audit:
| Identifier Field | Populated Count | Status | Description |
| :--- | :---: | :---: | :--- |
| `scenario_id` | **0** | `ABSENT` | No scenario UUID or session tag exists |
| `campaign_id` | **0** | `ABSENT` | No campaign clustering metadata exists |
| `template_id` | **0** | `ABSENT` | Generator loop identity was not stored |
| `source_event_id` | **0** | `ABSENT` | No upstream source tracking exists |
| `host_id` | **0** | `ABSENT` | Hosts represented only via IP string |
| `socket_id` | **0** | `ABSENT` | No OS socket linkage between PID and flow |
| `process_guid` | **0** | `ABSENT` | No monotonic Sysmon process GUID |

**Audit Determination**: Because all scenario, campaign, and template identifiers are 100% absent, it is strictly impossible to partition by scenario using ground truth tags. Scenario-level generalization is explicitly designated **`NOT_ESTABLISHED`**.

---

## 3. Split-Leakage and Duplicate Audit

### Group-Aware Split Mechanics:
- Total events: 7,051
- Unique 11-field payload fingerprints: **3,687**
- Events belonging to duplicate clusters: **3,469 (49.20%)**
- Partitioning: Group-aware stratified splitting clusters all exact-duplicate feature representations into indivisible groups and places each group strictly into either train ($N_{train} = 5,651$) or test ($N_{test} = 1,400$).
- **Cross-Split Duplicate Overlap**: **0.0% (0 records)** verified.

### Generalization Boundary Analysis:
1. **Duplicate Isolation**: Successfully verified. No test sample has an exact identical feature fingerprint in the training set.
2. **Scenario Independence**: **`NOT_ESTABLISHED`**. Although duplicate feature vectors are isolated, events generated from the same synthetic template loops (e.g. repetitive C2 beaconing rhythms, brute force credential stuffing loops) share distributions and parameters across splits.
3. **Scientific Caution**: Zero duplicate overlap must not be conflated with scenario-level or cross-network generalization. AEGIS-ML demonstrates intra-dataset robustness against identical record memorization, but out-of-distribution scenario generalization cannot be claimed without external or scenario-partitioned datasets.

---

## 4. Feature and Label Pipeline Audit

Audited Pipeline: **21-Feature Config C + Isolation Forest + SMOTE**

### Checklist of Defects vs Risks:
| Potential Issue | Audit Finding | Classification | Details |
| :--- | :--- | :---: | :--- |
| **Direct Target Leakage** | None detected | `CLEAN` | `attack_type` and `raw_label` are completely excluded from feature matrices. |
| **Label Encoding Artifacts** | None detected | `CLEAN` | Labels are mapped directly via string list index. |
| **Preprocessing Fitted Before Split** | None detected | `ISOLATED` | `IsolationForestDetector`, `BehavioralBaselineProfiler`, and `calculate_failed_auth_rate` are fitted strictly on `tr_events`. |
| **SMOTE Applied Before Split** | None detected | `ISOLATED` | `SMOTE(k_neighbors=4)` is applied exclusively to the training matrix `(X_tr_c, y_tr)`. The test set `X_te_c` is untouched. |
| **Group IDs as Features** | None detected | `CLEAN` | Group IDs (`gid`) and event IDs (`event_id`) are excluded from feature matrices. |
| **Causal Graph Ordering** | None detected | `CLEAN` | Graph tracker respects causal timestamp ordering without forward temporal leakage. |
| **Unlinked Staging Gap** | Confirmed | `DEFECT` | 120 endpoint file reads labeled `data_exfiltration` lack socket link to exfiltration network flows. |

---

## 5. Frozen-Holdout Model Randomness vs Split Variability

To resolve whether previously reported metric variations arose from model instability or differing test populations, Phase 16 conducted an empirical trial:
1. **Model Seed Randomness**: Split frozen at Seed 42 ($N_{test}=1,400$). Evaluated across model seeds `[42, 1337, 2026, 7, 999]`.
2. **Split Variability**: Shuffled group partition seeds (which changed the test set size between 812 and 1,400).

### Frozen-Holdout Seed Stability Results ($N_{test} = 1,400$):
| Model Seed | Macro-F1 | Weighted-F1 | Balanced Accuracy | Benign FPR | Benign FNR | False Alarms |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **42** | 0.8685 | 0.9171 | 0.9317 | 0.0000 | 0.007317 | 3 / 410 |
| **1337** | 0.8677 | 0.9169 | 0.9317 | 0.0000 | 0.007317 | 3 / 410 |
| **2026** | 0.8677 | 0.9169 | 0.9317 | 0.0000 | 0.007317 | 3 / 410 |
| **7** | 0.8685 | 0.9171 | 0.9317 | 0.0000 | 0.007317 | 3 / 410 |
| **999** | 0.8685 | 0.9171 | 0.9317 | 0.0000 | 0.007317 | 3 / 410 |
| **Mean $\pm$ Std** | **0.8682 $\pm$ 0.0004** | **0.9170 $\pm$ 0.0001** | **0.9317 $\pm$ 0.0000** | **0.0000 $\pm$ 0.0000** | **0.0073 $\pm$ 0.0000** | **3 / 410** |

**Conclusion**: When the test population is frozen, the Random Forest model is extraordinarily stable ($\sigma = 0.0004$). All apparent variance in prior reports was caused by split-seed changes altering the test partition composition.

---

## 6. Baseline and Error Analysis: 120 Exfiltration Staging Errors

### Confusion Matrix Breakdown ($N_{test} = 1,400$):
$$\begin{pmatrix} 407 & 2 & 1 & 0 & 0 \\ 0 & 498 & 0 & 0 & 0 \\ 0 & 0 & 61 & 0 & 0 \\ 0 & 33 & 87 & 239 & 0 \\ 0 & 0 & 0 & 0 & 72 \end{pmatrix}$$

Class order: `[benign, brute_force, lateral_movement, data_exfiltration, c2_beaconing]`

### Per-Class Detection Performance:
| Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| `benign` | 1.0000 | 0.9927 | 0.9963 | 410 |
| `brute_force` | 0.9343 | 1.0000 | 0.9661 | 498 |
| `lateral_movement` | 0.4094 | 1.0000 | 0.5810 | 61 |
| `data_exfiltration` | 1.0000 | 0.6657 | 0.7993 | 359 |
| `c2_beaconing` | 1.0000 | 1.0000 | 1.0000 | 72 |

### Deep-Dive into the 120 Misclassifications:
- **Total Exfiltration Events in Holdout**: 359
- **Correctly Classified Network Exfiltration**: 239 (100.0% recall on actual network flows)
- **Misclassified Events**: 120 (33.43% of exfiltration class)
  - Classified as `lateral_movement`: 87
  - Classified as `brute_force`: 33
- **Event Telemetry Attributes of Misclassified Events**:
  - `layer`: `endpoint` (120 / 120)
  - `action`: `read` (120 / 120)
  - `process_name`: `7z.exe` (120 / 120)
  - `src_entity` / `host`: `10.0.0.33` (120 / 120)
  - `dst_port`: `None` (120 / 120)
  - `bytes_sent`: `None` (120 / 120)
  - `socket_id` / `attribution_link`: `None` (120 / 120)

### Root-Cause Diagnosis:
In `backend/data_generator/attack_scenarios.py`, the exfiltration scenario generates two stages:
1. Local archive creation (`7z.exe` reading local files on `10.0.0.33`).
2. Network egress (`curl.exe` transferring bytes to external destination).

However, the generator gave both stages the identical label `data_exfiltration` without providing a socket identifier, parent-child correlation, or temporal attribution feature linking the archive read to the network flow. From the perspective of single-event feature extraction, a local file read without network bytes cannot be distinguished from local reconnaissance or staging, leading the classifier to predict `lateral_movement` or `brute_force`.

---

## 7. Status of Verification Tasks

| Task | Scope | Status | Evidence |
| :--- | :--- | :---: | :--- |
| **Dataset Provenance** | Inspect 7,051 records and generator scripts | `COMPLETED` | Fully tabulated in `generalization_audit_results.json` |
| **Split Leakage** | Group-aware duplicate vs scenario isolation | `COMPLETED` | 0.0% duplicate overlap; scenario metadata absent |
| **Scenario Generalization** | Evaluation across independent attack campaigns | `NOT_ESTABLISHED` | Absent scenario tags prohibit reliable partition |
| **Feature / Target Leakage** | Audit 21-feature Config C & preprocessors | `COMPLETED` | Zero direct target leakage; train-only fitting verified |
| **Model Randomness vs Split** | Frozen holdout across 5 seeds | `COMPLETED` | Macro-F1 $\sigma = 0.0004$; zero FPR across seeds |
| **Exfiltration Error Root Cause**| Analysis of 120 staging errors | `COMPLETED` | 100% of errors traced to unlinked endpoint reads |
| **Automated Tests** | 9 comprehensive audit tests in `tests/` | `COMPLETED` | Passing in test suite |
| **Production Generalization** | External real-world telemetry validity | `NOT_ESTABLISHED` | Synthetic benchmark only |

---

## 8. Recommendations for Future Work

1. **Tag Synthetic Scenarios at Generation Time**:
   Update `backend/data_generator/orchestrator.py` to record `scenario_id` (UUID), `campaign_name`, and `stage` (`staging`, `execution`, `egress`) on all generated events.
2. **Explicit Stage Labels**:
   Label local file compression as `collection_staging` rather than `data_exfiltration`, reserving `data_exfiltration` for outbound data transfer flows.
3. **OS Socket & Process Linkage**:
   Emit simulated socket telemetry connecting endpoint processes to network 5-tuples to enable multi-event attribution fusion.
4. **External Real-World Benchmarking**:
   Preserve the canonical synthetic holdout as a regression gate, but evaluate generalization on public real-world datasets (e.g. CIC-IDS2017, UNSW-NB15, or Mordor security event logs).
