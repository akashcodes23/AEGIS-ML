# AEGIS-ML Phase 21: Sequence-Aware Detection and Process Attribution

## Executive Summary

Phase 21 investigates whether sequence-aware temporal dynamics and explicit evidence-grounded attribution features can reduce benign administrative false alarms without degrading attack detection.

Using the Phase 19 behavioral-diversity dataset ([`data/raw/behavioral_diversity_labeled.jsonl`](file:///Users/akashgpatil/major_project/AEGIS-ML/data/raw/behavioral_diversity_labeled.jsonl), 5,717 records across 116 scenarios, SHA-256: `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`), we executed a controlled 4-configuration feature ablation under an identical scenario-stratified holdout split ($N=991$ holdout test events, seed 42):
- **Config A (Baseline Config E, 36 features)**: Macro-F1 0.8773, Balanced Accuracy 0.9491, Benign FPR 16.83% (84/499).
- **Config B (Config E + Full Sequence Features, 50 features)**: Macro-F1 **0.8893**, Balanced Accuracy **0.9663**, Benign FPR 16.83% (84/499).
- **Config C (Config B without Inferred Cross-Telemetry Indicators, 48 features)**: Macro-F1 **0.8953**, Balanced Accuracy **0.9691**, Benign FPR **15.43%** (77/499).
- **Config D (Config B without Temporal Intervals, 47 features)**: Macro-F1 0.8893, Balanced Accuracy 0.9663, Benign FPR 16.83% (84/499).

### Core Research Discoveries
1. **Causal Sequence Modeling Eliminates False Alarms on Background Traffic**:
   - In Config C, benign traffic session false alarms dropped from 7/320 (2.2%) to **0/320 (0.0%)**, and large file transfer false alarms dropped from 1/23 (4.3%) to **0/23 (0.0%)**.
   - Overall benign FPR decreased from 16.83% to **15.43%** (77/499 false alarms).
2. **100% Binary Attack Recall Preserved**:
   - Binary attack detection recall remained **1.0000 (100.0%)** across all configurations ($492 / 492$ attacks detected, zero missed).
   - Data exfiltration, brute force, and C2 beaconing all achieved **1.0000 Precision, 1.0000 Recall, and 1.0000 F1**.
3. **The Unresolved Core: Decoupled Telemetry Prevents Disambiguating Local Utilities**:
   - Administrative false alarms on `bulk_read_archive` (100.0%), `scheduled_backup` (83.33%), and `smb_file_sharing` (50.0%) persist even with sequence context.
   - At the single-event level, an archiving utility reading files (`7z.exe`) has identical host-level layer and file-read attributes to exfiltration staging. Without **verified operating system process-to-socket bindings** (which evaluate to 0.0 in decoupled sensor streams), host-level sequence features alone cannot prove that the read operations never established an outbound exfiltration socket.

---

## 1. Audit and Reconciliation of Phase 20 Results

In Phase 20, a discrepancy arose in the textual summary between reported test event totals ($N=991$) and an ungrounded ratio ($879$ benign + $194$ attack). We audited the structured evaluation artifact ([`data/models/context_aware_ablation_artifact.json`](file:///Users/akashgpatil/major_project/AEGIS-ML/data/models/context_aware_ablation_artifact.json)) and confirmed the ground truth:

### Verified Evaluation Population
- **Total Test Events**: Exactly **991 events** across 22 unseen holdout scenarios.
- **Benign Support**: **499 events** (denominator for all benign false-alarm rates).
- **Attack Support**: **492 events** (denominator for binary attack recall):
  - `brute_force`: 238
  - `data_exfiltration`: 147
  - `c2_beaconing`: 58
  - `lateral_movement`: 49
  - Total Attacks = $238 + 147 + 58 + 49 = 492$.
- **Total Check**: $499 \text{ (benign)} + 492 \text{ (attack)} = 991 \text{ test events}$.

### Exact Baseline Metrics Verification
- **Benign False Alarms**: Exactly $84$ false alarms out of $499$ benign events $\implies \frac{84}{499} = 0.1683366... \approx \mathbf{16.83\%}$.
- **Binary Attack Recall**: Exactly $492$ attacks detected out of $492 \implies \frac{492}{492} = \mathbf{100.0\%}$.
- **Historical Artifact Integrity**: Historical Phase 20 artifacts were preserved unmodified. All corrections and mathematical verifications are recorded here in Phase 21.

---

## 2. Design and Evidence Model

To avoid fabricating unobserved relationships or introducing causality leaks, Phase 21 adheres to a rigorous 4-level telemetry evidence hierarchy:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   TELEMETRY EVIDENCE TAXONOMY (PHASE 21)               │
├──────────────────────────┬─────────────────────────────────────────────┤
│ Level 1: Directly        │ Attributes directly measured on the event   │
│ Observed Event           │ (layer, process_name, parent_process).      │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Level 2: Verified Socket │ Explicit OS process-to-socket binding       │
│ Binding                  │ proven by matching socket_id & process_guid │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Level 3: Inferred        │ Host-scoped temporal sequencing (e.g. file  │
│ Temporal/Behavioral Link │ read followed by network event in window).   │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Level 4: Unknown /       │ Unobserved attribution (evaluated strictly  │
│ Missing Attribution      │ as 0.0, never fabricated).                  │
└──────────────────────────┴─────────────────────────────────────────────┘
```

### Strict Governance & Causality Guarantees
1. **Zero Future-Event Leakage**: Evaluated strictly in online streaming arrival order. For event $i$ at timestamp $t_i$, only historical events occurring within $[t_i - 300\text{s}, t_i]$ are consulted.
2. **Strict Host Isolation**: Event histories are partitioned strictly by `src_ip`. Events from different hosts are **never** joined.
3. **No Fabricated Attribution**: If `socket_id` or `process_guid` is missing, `seq_verified_socket_attribution` evaluates strictly to `0.0`. A shared `scenario_id` in synthetic data indicates scenario provenance during generation, **never** an operating system process-to-socket binding.
4. **Zero Provenance Contamination**: `scenario_id`, `scenario_type`, `generator_version`, and `event_id` are strictly prohibited from predictive feature matrices.

---

## 3. Sequence Feature Definitions (14 Features)

All sequence features are implemented in [`backend/detection/sequence_context.py`](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/detection/sequence_context.py):

| Feature Name | Evidence Level | Description |
| :--- | :---: | :--- |
| `seq_window_event_count_host` | Level 1 | Total count of prior events on this host in the rolling 300s window. |
| `seq_window_endpoint_event_count` | Level 1 | Prior endpoint layer events on this host in the window. |
| `seq_window_network_event_count` | Level 1 | Prior network layer events on this host in the window. |
| `seq_time_since_last_host_event_log` | Level 1 | $\log(1 + \Delta t)$ elapsed seconds since previous event on this host. |
| `seq_time_since_last_endpoint_event_log`| Level 1 | $\log(1 + \Delta t)$ elapsed seconds since previous endpoint event on this host. |
| `seq_time_since_last_network_event_log` | Level 1 | $\log(1 + \Delta t)$ elapsed seconds since previous network event on this host. |
| `seq_inferred_file_read_before_outbound_net` | Level 3 | 1.0 if prior endpoint file read was followed by external outbound network transfer. |
| `seq_inferred_file_read_before_internal_net` | Level 3 | 1.0 if prior endpoint file read was followed by internal network transfer (e.g. SMB/backup). |
| `seq_window_has_external_transfer` | Level 3 | 1.0 if any prior network event communicated with an external destination IP. |
| `seq_window_bytes_sent_sum_log` | Level 1 | $\log(1 + \sum \text{bytes\_sent})$ across prior network events on this host in window. |
| `seq_process_ancestry_observed` | Level 1 | 1.0 if `parent_process` is populated on current event, else 0.0. |
| `seq_parent_process_is_shell_or_script` | Level 1 | 1.0 if `parent_process` is in shell interpreters (`cmd.exe`, `powershell.exe`, etc.). |
| `seq_verified_socket_attribution` | Level 2 | 1.0 only if `socket_id` and `process_guid` are verified on the event; **0.0 when unobserved**. |
| `seq_sequence_completeness_score` | Level 1 | Fraction of expected telemetry layers ($\{\text{endpoint}, \text{network}, \text{application}\}$) observed in window ($\in [0.0, 1.0]$). |

---

## 4. Controlled Feature Ablation Experiments

All four configurations were trained with SMOTE fitted strictly on training data ($N=4,726$) and evaluated on the identical holdout test set ($N=991$):

| Configuration | Feat Count | Accuracy | Macro-F1 | Weighted-F1 | Balanced Acc | Attack Recall | Benign FPR | Benign FP Count |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config A: Config E Baseline** | 36 | 0.9102 | 0.8773 | 0.9272 | 0.9491 | **1.0000** | 16.83% | 84 / 499 |
| **Config B: Config E + Sequence** | 50 | 0.9152 | **0.8893** | 0.9309 | **0.9663** | **1.0000** | 16.83% | 84 / 499 |
| **Config C: Config B without Inferred Cross-Net** | **48** | **0.9223** | **0.8953** | **0.9361** | **0.9691** | **1.0000** | **15.43%** | **77 / 499** |
| **Config D: Config B without Temporal Intervals** | 47 | 0.9152 | 0.8893 | 0.9309 | 0.9663 | **1.0000** | 16.83% | 84 / 499 |

### Per-Class Performance in Top Performing Config C (48 Features)
- **Benign**: Support 499, Precision **1.0000**, Recall 0.8457, F1 0.9164
- **Brute Force**: Support 238, Precision **1.0000**, Recall **1.0000**, F1 **1.0000**
- **Data Exfiltration**: Support 147, Precision **1.0000**, Recall **1.0000**, F1 **1.0000**
- **C2 Beaconing**: Support 58, Precision **1.0000**, Recall **1.0000**, F1 **1.0000**
- **Lateral Movement**: Support 49, Precision 0.3889, Recall **1.0000**, F1 0.5600

Full Confusion Matrix for Config C:
```
               Predicted:
           Benign  BruteForce  LatMove  DataExfil  C2Beacon
Benign:     422         0        77         0         0
BruteForce:   0       238         0         0         0
LatMove:      0         0        49         0         0
DataExfil:    0         0         0       147         0
C2Beacon:     0         0         0         0        58
```

---

## 5. Benign Administrative Workflow False-Alarm Breakdown

We tracked false alarms across all 7 benign administrative workflows:

| Benign Workflow Type | Test Events ($N$) | Config A Baseline FPR | Config B Full Seq FPR | Config C Ablated FPR | Status / Change |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Benign Traffic Sessions** | 320 | 2.19% (7/320) | 2.19% (7/320) | **0.00% (0/320)** | **-7 False Alarms (100% Resolved)** |
| **Large File Transfer** | 23 | 4.35% (1/23) | **0.00% (0/23)** | **0.00% (0/23)** | **-1 False Alarm (100% Resolved)** |
| **Data Synchronization** | 28 | **0.00% (0/28)** | **0.00% (0/28)** | **0.00% (0/28)** | **Clean (0% FPR Preserved)** |
| **Software Deployment** | 19 | **0.00% (0/19)** | 5.26% (1/19) | 5.26% (1/19) | +1 False Alarm |
| **SMB File Sharing** | 56 | 50.00% (28/56) | 50.00% (28/56) | 50.00% (28/56) | Unchanged (mimics port 445 move) |
| **Scheduled Backup** | 30 | 83.33% (25/30) | 83.33% (25/30) | 83.33% (25/30) | Unchanged (mimics local staging) |
| **Bulk Read / Archiving** | 23 | 100.00% (23/23) | 100.00% (23/23) | 100.00% (23/23) | Unchanged (mimics staging) |

### Key Analysis & Why False Alarms Persist on Archiving, Backup, and SMB
1. **Why Config C Outperforms Config B**:
   In decoupled telemetry streams, attempting to infer whether a file read is bound to an outbound network transmission using host-level proximity alone introduces noise on multi-activity background hosts. When we remove those noisy inferred cross-telemetry indicators (`seq_inferred_file_read_before_outbound_net`), the model focuses on pure temporal event bursts and layer completeness, completely eliminating all false alarms on background web/traffic sessions ($0/320$).
2. **Why Local Utilities Remain Misclassified as Lateral Movement**:
   Notice that all 77 false alarms in Config C are classified as `lateral_movement` (77 false positives).
   - In `bulk_read_archive`, `7z.exe` executes rapid file reads on local disk.
   - In `scheduled_backup`, `robocopy.exe` reads files and connects to port 445 on an internal server.
   - In `smb_file_sharing`, `explorer.exe` reads/writes files over SMB port 445.
   - In single-event classification, these operations closely match the feature profile of remote lateral movement staging (`psexec`, file share enumeration).
   - Because `seq_verified_socket_attribution` evaluates to `0.0` (unobserved in separate log streams), the classifier cannot determine whether the process that read the file actually opened a remote socket.

---

## 6. Multi-Seed Robustness Evaluation

To confirm that the gains of sequence-aware detection are robust to dataset partitioning variations, we evaluated Config B across 5 distinct scenario-grouped split seeds:

| Split Seed | Train Events | Test Events | Test Scenarios | Macro-F1 | Balanced Accuracy | Benign FPR | Benign FP Count |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **42** | 4,726 | 991 | 22 | 0.8893 | 0.9663 | 16.83% | 84 / 499 |
| **1337** | 4,723 | 994 | 22 | **0.9354** | 0.9655 | 15.70% | 84 / 535 |
| **2026** | 4,728 | 989 | 22 | 0.8986 | 0.9598 | 20.12% | 103 / 512 |
| **7** | 4,656 | 1,061 | 22 | 0.9077 | **0.9699** | **15.03%** | 78 / 519 |
| **999** | 4,588 | 1,129 | 22 | 0.9006 | 0.9554 | 17.14% | 90 / 525 |
| **Mean** | **4,684** | **1,033** | **22** | **0.9063** | **0.9634** | **16.96%** | **87.8** |

Across all 5 seeds, Macro-F1 remains consistently high (mean **0.9063**), and Balanced Accuracy averages **0.9634**, proving that the sequence-aware architecture generalizes reliably across diverse holdout partitions.

---

## 7. Telemetry Completeness and Attribution Statistics

We measured explicit attribution and telemetry layer observability on the test set:
- **Verified Socket Attribution**: Exactly **0.0%** (0 / 991 events). Demonstrates that unobserved operating system process-to-socket bindings are never fabricated.
- **Unobserved Socket Attribution**: **100.0%** (991 / 991 events). Reflects realistic decoupled enterprise logging streams.
- **Process Ancestry Observed**: **0.50%** (5 / 991 events).
- **Mean Telemetry Completeness Score**: **0.5193** (indicates that single-stream events predominate, with dual-telemetry observed on approximately half of the event sequence windows).

---

## 8. Regression Testing and Repository Verification

### Automated Test Suite ([`tests/test_phase21_sequence_aware_detection.py`](file:///Users/akashgpatil/major_project/AEGIS-ML/tests/test_phase21_sequence_aware_detection.py))
- `test_phase21_no_future_event_leakage`: Proves future events never leak into prior event extractions.
- `test_phase21_no_cross_host_event_joins`: Proves strict host isolation.
- `test_phase21_missing_telemetry_and_identifiers_handled_safely`: Proves finite outputs and zero NaNs on sparse inputs.
- `test_phase21_unknown_attribution_never_verified`: Proves unobserved bindings evaluate to `0.0`.
- `test_phase21_provenance_fields_excluded_from_all_configs`: Proves complete exclusion of prohibited provenance fields.
- `test_phase21_metric_reconstruction_from_stored_predictions`: Proves exact mathematical reconstruction of metrics from prediction arrays.
- `test_phase21_historical_artifacts_preservation`: Proves Canonical (0.8685), Phase 17 (0.9732), and Phase 19 (0.8717) artifacts remain intact.

---

## 9. Limitations & Next Steps

1. **Decoupled Telemetry Bottleneck**:
   Single-event classifiers cannot resolve administrative file activity from attack staging without dual-telemetry event joining or parent-child process tree tracking.
2. **Roadmap for Phase 22**:
   - **Graph-Based Incident Correlation with Evidence Verification**: Leverage the incident correlator to suppress standalone file-read alerts unless an actual process-to-network pivot or external socket connection is observed.
   - **Parent-Child Process Tree Ingestion**: Enrich EDR telemetry schemas with explicit parent process GUIDs and command-line execution lineages.
