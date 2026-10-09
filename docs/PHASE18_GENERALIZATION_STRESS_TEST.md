# AEGIS-ML Phase 18: Generalization and Leakage Stress Test

**Status Summary:**
- **Task 1: Scenario Diversity Audit:** `COMPLETED`
- **Task 2: Feature and Label Leakage Audit:** `COMPLETED`
- **Task 3: Independent Metric Reconstruction:** `COMPLETED` (Exact Match Verified)
- **Task 4: Scenario-Grouped Robustness & Multi-Split Trials:** `COMPLETED`
- **Task 5: False-Positive Backup Stress Analysis ($N=1$ Limitation):** `COMPLETED`
- **Task 6: Automated Test Suite (6 tests):** `COMPLETED`
- **Synthetic Intra-Template Generalization:** `COMPLETED_ON_SYNTHETIC_HOLDOUT`
- **Unseen Admin Workflow Resilience:** `NOT_ESTABLISHED` (100% false alarms on unobserved backup jobs)
- **Real-World / Enterprise Generalization:** `NOT_ESTABLISHED` (Controlled synthetic benchmark)

---

## 1. Executive Summary

Phase 18 executed an empirical stress test to answer the central investigative question:
> **Does the Phase 17 scenario-grouped Macro-F1 of 0.9732 reflect genuine behavioral generalization, or is it partly explained by similarities between synthetic scenarios and generator-specific feature patterns?**

### Key Findings:
1. **High Template Uniformity Across Scenarios**: While Phase 17 successfully prevented exact scenario ID leakage across partitions (0.0% scenario overlap), the underlying generative templates within each attack class share identical payload constants, hard-coded target ports, identical source/destination entities, and fixed byte sizes. Thus, holding out a scenario instance tests generalization to a new *repetition* of the template, rather than an independently varied adversary behavior.
2. **Predictive Pipeline Integrity Verified**: Auditing confirmed that no provenance identifiers (`scenario_id`, `scenario_type`, `generator_version`, `event_id`, `campaign_id`) enter the 21 predictive features. Behavioral baselines, Isolation Forest, failed auth rates, and SMOTE oversampling remain strictly isolated to training partitions.
3. **Exact Metric Reconstruction Verified**: Independent mathematical reconstruction from saved instance-level prediction arrays (`data/models/scenario_evaluation_artifact.json`) verified exact numerical agreement with reported values: Macro-F1 `0.9732`, Balanced Accuracy `0.9768`, Accuracy `0.9869`, Multiclass Benign FPR `0.0000`, Benign FNR `0.0425`.
4. **Critical Vulnerability on Unobserved Admin Workflows ($N=1$ Limitation)**: The dataset contains exactly **1 false-positive backup scenario** (`scenario_fp_000`, 51 events: 50 `robocopy.exe` file reads and 1 massive 2.0 GB SMB transfer). In Phase 17, this single scenario was placed in train. When stress-tested by holding it out into the test partition:
   - **100.0% of the backup events were misclassified as attacks** (50 as `lateral_movement`, 1 as `data_exfiltration`).
   - Macro-F1 dropped from `0.9732` to `0.9120`.
   - Overall benign false-alarm rate escalated to `15.08%`.
   - **Conclusion**: With only $N=1$ backup scenario, generalizing to unobserved administrative workflows is explicitly **`NOT_ESTABLISHED`**.

---

## 2. Scenario Diversity and Template Uniformity Audit

Audited Dataset: `data/raw/scenario_aware_labeled.jsonl` (7,361 records across 81 scenarios)

### Diversity Breakdown by Scenario Type:
| Scenario Type | Unique Scenarios | Total Events | Events / Scenario (Min-Max) | Distinct Src Hosts | Distinct Dst Hosts | Distinct Dst Ports | Observed Processes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `brute_force` | 5 | 3,292 | 414 – 880 | 3 | 2 | `[443]` | *None* |
| `c2_beaconing` | 30 | 345 | 11 – 12 | 1 (`10.0.0.23`) | 2 | `[8080]` | `cmd.exe` |
| `lateral_movement` | 15 | 353 | 15 – 32 | 1 (`10.0.0.23`) | 100+ | `[445]` | `net.exe`, `psexec.exe` |
| `data_exfiltration`| 10 | 1,320 | 132 – 132 | 1 (`10.0.0.33`) | 2 | `[443]` | `7z.exe` |
| `false_positive_backup` | **1** | 51 | 51 – 51 | 1 (`10.0.0.5`) | 1 (`10.0.0.90`) | `[445]` | `robocopy.exe` |
| `benign_traffic` | 20 | 2,000 | 100 – 100 | 100 | 4 | `[25, 53, 80, 445]` | *None* |

### Detailed Template Uniformity Findings:
1. **Brute Force Scenarios (5 instances)**:
   - All 5 scenarios target the exact same URI (`/api/login`) on `api.corp.com` on port 443.
   - All 5 scenarios cycle deterministically across the exact same 3 IP addresses (`185.220.101.45`, `.46`, `.47`).
   - Every single attempt produces an application event followed by a network event with fixed sizes (512 bytes sent, 256 bytes received).
   - *Impact*: The held-out brute-force scenario is an exact parametric clone of the training scenarios.
2. **C2 Beaconing Scenarios (30 instances)**:
   - All 30 scenarios originate from the single host `10.0.0.23` connecting to `203.0.113.45:8080`.
   - On the 5th beacon, all 30 scenarios spawn `cmd.exe` from `explorer.exe` under user `jsmith`.
   - Variation across scenarios is limited strictly to jitter ($\pm 5$ seconds).
3. **Data Exfiltration Scenarios (10 instances)**:
   - All 10 scenarios originate from `10.0.0.33` transmitting 5–25 MB flows to `192.168.100.50:443`.
   - All 10 scenarios exhibit exactly 12 `7z.exe` local file reads occurring strictly every 10 network events.
4. **False Positive Backup Scenario (1 instance)**:
   - Only 1 instance exists in the entire dataset. It cannot be partitioned across train and test without causing an absence in one of the partitions.

---

## 3. Feature and Pipeline Leakage Audit

Audited Pipeline: **21-Feature Config C + Isolation Forest + SMOTE**

### Prohibited Metadata Verification:
The following provenance fields were verified **100% absent** from model inputs:
`["scenario_id", "scenario_type", "generator_version", "event_id", "raw_label", "attack_type", "campaign_id", "template_id"]`.

### Pipeline Isolation Checklist:
| Component | Partition Scope | Audit Finding | Classification |
| :--- | :--- | :---: | :---: |
| **Target Labels** | Labels excluded from features | Zero direct target leakage | `CLEAN` |
| **Behavioral Profiler** | Fitted strictly on `tr_events` (benign only) | No test event leakage | `ISOLATED` |
| **Isolation Forest** | Fitted strictly on `tr_events` | No test sample seen | `ISOLATED` |
| **Failed Auth Rate** | Computed separately for train and test | No forward leakage | `ISOLATED` |
| **Temporal Tracker** | Sequential chronological causal processing | No future lookahead | `ISOLATED` |
| **SMOTE Resampling** | Fitted strictly on `(X_tr_c, y_tr)` | Test set `X_te_c` untouched | `ISOLATED` |

### Potential Synthetic Artifact Risks:
- **Port Risk Encoding**: The static mapping `dst_port_risk` assigns elevated risk to port 8080 and 445. Because the generator strictly routes C2 beaconing through 8080 and lateral movement through 445, the feature acts as a proxy indicator for generator templates.
- **Fixed Payload Fingerprinting**: Fixed payload sizes (e.g. 512 bytes for brute force network events) allow decision trees to separate classes with threshold rules that reflect synthetic constants rather than natural statistical variance.

---

## 4. Independent Metric Reconstruction

Reconstructed directly from `data/models/scenario_evaluation_artifact.json` ($N_{test} = 1,681$):

### Reconstructed Confusion Matrix:
$$\begin{pmatrix} 383 & 12 & 5 & 0 & 0 \\ 0 & 880 & 0 & 0 & 0 \\ 0 & 0 & 69 & 0 & 0 \\ 0 & 0 & 0 & 264 & 0 \\ 0 & 0 & 5 & 0 & 63 \end{pmatrix}$$
*(Class order: `[benign, brute_force, lateral_movement, data_exfiltration, c2_beaconing]`)*

### Reconstructed Metrics vs Saved Artifact:
| Metric | Reconstructed Value | Stored Artifact Value | Discrepancy Status |
| :--- | :---: | :---: | :---: |
| **Accuracy** | `0.9869` | `0.9869` | `EXACT_MATCH` |
| **Macro-F1** | `0.9732` | `0.9732` | `EXACT_MATCH` |
| **Weighted-F1** | `0.9870` | `0.9870` | `EXACT_MATCH` |
| **Balanced Accuracy** | `0.9768` | `0.9768` | `EXACT_MATCH` |
| **Multiclass Benign FPR** | `0.0000` ($0 / 1,281$) | `0.0000` | `EXACT_MATCH` |
| **Binary False Alarm Rate** | `0.0425` ($17 / 400$) | `0.0425` | `EXACT_MATCH` |

---

## 5. Scenario Partition Robustness (Multi-Split Evaluation)

To assess whether performance is sensitive to which scenarios are held out, 5 independent scenario-grouped partitions were evaluated (with fixed model seed 42):

### Multi-Split Results:
| Split Seed | Test Scenarios | Test Events | Macro-F1 | Balanced Accuracy | Benign False Alarm Rate |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **42** | 16 | 1,681 | 0.9732 | 0.9768 | 0.0425 (17 / 400) |
| **1337** | 16 | 1,209 | 0.9851 | 0.9917 | 0.0125 (5 / 400) |
| **2026** | 16 | 1,209 | 0.9671 | 0.9766 | 0.0275 (11 / 400) |
| **7** | 16 | 1,470 | 0.9875 | 0.9882 | 0.0175 (7 / 400) |
| **999** | 16 | 1,460 | 0.9718 | 0.9763 | 0.0200 (8 / 400) |
| **Aggregate** | **16** | **$1,406 \pm 187$** | **$0.9769 \pm 0.0079$** | **$0.9819 \pm 0.0067$** | **$0.0240 \pm 0.0105$** |

### Split Variability Insights:
- Macro-F1 remains consistently high ($0.9671$ to $0.9875$) across all scenario splits because all splits evaluate clones of the same generative templates.
- Test sample counts vary from 1,209 to 1,681 due to variable event counts in brute force scenarios (414 vs 880 events).

---

## 6. False-Positive Backup Stress Analysis ($N=1$ Dilemma)

### The Structural Dilemma:
The dataset contains only one `false_positive_backup` scenario (`scenario_fp_000`):
- 50 endpoint file reads by `robocopy.exe` on host `10.0.0.5`
- 1 massive 2.0 GB network backup transfer to file server `10.0.0.90:445`

In Phase 17's stratified split, `scenario_fp_000` was placed in train. Consequently, the test set evaluated only standard workstation web/DNS traffic.

### Empirical Stress Test: Holding Out `scenario_fp_000` in Test
When `scenario_fp_000` is forced strictly into the test partition (and excluded from training):
- **Events Evaluated**: 51
- **Ground Truth**: `benign`
- **Model Predictions**:
  - Predicted as `lateral_movement`: **50 (98.0%)** (all 50 `robocopy.exe` file reads)
  - Predicted as `data_exfiltration`: **1 (2.0%)** (the 2 GB SMB network backup transfer)
  - Predicted as `benign`: **0 (0.0%)**
- **False Alarm Rate on Backup Job**: **100.0% (51 / 51)**
- **Global Impact**:
  - Macro-F1 drops from `0.9732` to **`0.9120`**
  - Benign False Alarm Rate spikes from `4.25%` to **`15.08%`**

### Scientific Conclusion:
A single scenario cannot simultaneously train a model and validate its out-of-distribution resilience. The model learned that rapid file reads indicate lateral movement staging and multi-gigabyte transfers indicate data exfiltration. Without observing backup admin behavior during training, it exhibits zero zero-shot tolerance for legitimate high-volume administrative tasks.

---

## 7. Status of Verification Tasks

| Evaluation Dimension | Verified Finding | Risk / Limitation | Explicit Status |
| :--- | :--- | :--- | :---: |
| **Scenario Provenance Isolation** | Zero scenario_id overlap across partitions | High template uniformity across scenarios | `COMPLETED` |
| **Pipeline Leakage Protection** | No metadata or preprocessors leaked | Synthetic port/byte constants act as proxies | `COMPLETED` |
| **Metric Reconstruction** | Exact numerical match from raw predictions | None | `COMPLETED` |
| **Multi-Split Robustness** | Mean Macro-F1 $0.9769 \pm 0.0079$ across splits | High score aided by template clones | `COMPLETED` |
| **Admin Backup Generalization**| 100% false alarms on unobserved backup jobs | Only $N=1$ backup scenario in dataset | `NOT_ESTABLISHED` |
| **Real-World Threat Generalization**| Not tested on live enterprise telemetry | Synthetic benchmark only | `NOT_ESTABLISHED` |

---

## 8. Recommendations

1. **Introduce Parametric Scenario Diversity**:
   Update `backend/data_generator/attack_scenarios.py` to randomize attacker subnets, target URIs, payload byte distributions, and tooling names across scenarios.
2. **Expand Benign Administrative Scenarios ($N \ge 10$)**:
   Generate multiple distinct administrative jobs (patch deployment, database backups, vulnerability scans) so that admin traffic can be held out realistically without causing a 100% false-alarm failure.
3. **External Dataset Benchmarking**:
   Import genuine PCAP captures (e.g. CIC-IDS2017) to evaluate out-of-domain cross-network generalization.
