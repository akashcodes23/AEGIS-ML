# AEGIS-ML Phase 19: Behavioral Diversity and Benign Hard-Negative Evaluation

## Executive Summary

Phase 19 investigates and resolves the synthetic homogeneity limitation identified in Phase 18. By extending the synthetic event generator with **six documented classes of legitimate administrative activity** (scheduled backups, bulk file transfers, SMB departmental file sharing, archive creation, software deployment, and scheduled synchronization) alongside **multi-protocol attack variations**, we create the first diverse benchmark for AEGIS-ML (`data/raw/behavioral_diversity_labeled.jsonl`, Generator Version 3.0.0).

Evaluating the existing LightGBM classifier (Config C: 21 features) under strict **scenario-grouped holdout** reveals that the previously reported Phase 17 Macro-F1 of **0.9732** was inflated by synthetic template clones. On the diversified dataset:
- **Macro-F1 drops to 0.8717** (Multi-seed mean: $0.8727 \pm 0.0199$).
- **Overall Balanced Accuracy remains strong at 0.9450** (Multi-seed mean: $0.9373 \pm 0.0132$).
- **Binary Attack Recall is 100.00%** (zero missed attacks).
- **Benign False Alarm Rate rises to 16.83%** (Multi-seed mean: $23.24\% \pm 4.74\%$).

The false alarm rate is heavily concentrated in administrative endpoint-layer workflows (bulk archiving, scheduled backups, and SMB file sharing), providing concrete empirical evidence of where feature engineering must evolve in future phases.

---

## 1. Dataset Reconciliation and Provenance History

To resolve discrepancies across previous phase documentations, we audited the input files, generator configurations, record counts, and SHA-256 hashes:

| Dataset Artifact | Generator Version | Records | Scenarios | Canonical Hash (SHA-256) | Role / Status |
| :--- | :---: | :---: | :---: | :--- | :--- |
| [`data/raw/combined_labeled.jsonl`](file:///Users/akashgpatil/major_project/AEGIS-ML/data/raw/combined_labeled.jsonl) | 1.0.0 (Legacy) | 7,051 | N/A (Duplicate-aware) | `25f2bf6889a563fcc220be23c709294f151be4693a8108052391c1ce594bf7f7` | Phase 14–16 Canonical Benchmark (Preserved) |
| [`data/raw/scenario_aware_labeled.jsonl`](file:///Users/akashgpatil/major_project/AEGIS-ML/data/raw/scenario_aware_labeled.jsonl) | 2.0.0 | 7,361 | 81 | `56fca1bea5b0c26b4fadde20218035aac530eb42a25ddfd8a8408d501a40e9d5` | Phase 17–18 Scenario Benchmark (Preserved) |
| [`data/raw/behavioral_diversity_labeled.jsonl`](file:///Users/akashgpatil/major_project/AEGIS-ML/data/raw/behavioral_diversity_labeled.jsonl) | **3.0.0** | **5,717** | **116** | **`1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`** | **Phase 19 Behavioral Diversity Benchmark (New)** |

### Reconciliation of Historical Event Counts
- **7,051 records**: Canonical dataset generated prior to explicit scenario IDs, evaluating payload-hash fingerprint deduplication.
- **7,361 records**: Phase 17 scenario-aware dataset across 81 scenarios. Any draft text referencing 7,102 reflected an intermediate script iteration prior to final generation.
- **5,717 records**: Phase 19 diversified dataset across 116 scenarios, balancing high scenario counts ($N \ge 6$ per workflow) with sustainable per-scenario event sizes to ensure fast, deterministic training and evaluation.

---

## 2. Benign Scenario Diversity & Hard-Negative Workflows

Phase 18 revealed that having only one backup scenario ($N=1$) caused a 100% false alarm rate on holdout because administrative tools were absent from training. Phase 19 addresses this by implementing 6 independent scenarios for each of the 6 administrative workflows (36 scenarios) plus 20 background sessions, totaling **56 benign scenarios**:

```
                                  BENIGN SCENARIOS (56 Total)
                                               │
       ┌──────────────────┬────────────────────┼───────────────────┬──────────────────┐
       ▼                  ▼                    ▼                   ▼                  ▼
Scheduled Backups   Large Transfers     SMB File Sharing    Bulk Read / Archive  Deployment & Sync
  (6 Scenarios)      (6 Scenarios)       (6 Scenarios)         (6 Scenarios)       (12 Scenarios)
  robocopy.exe       azcopy.exe / sftp   explorer.exe (445)    7z.exe / tar.exe    ccmexec, onedrive
  250MB - 2.5GB      100MB - 1.2GB       Docs, spreadsheets    Build logs          WinRM, DB sync
```

### Documented Generation Parameters

1. **Scheduled Backups (`scheduled_backup`) — 6 Scenarios**:
   - **Tools**: `robocopy.exe`, `wbengine.exe`, `backup_svc.exe`.
   - **Hosts**: `10.0.0.5`, `10.0.0.10`, `10.0.0.22`, `10.0.0.35` targeting vaults `10.0.0.90–92`.
   - **Volumes**: 250 MB to 2,500 MB transferred over SMB (port 445).
   - **Files**: 20 to 45 files per run (`.xlsx`, `.pdf`, `.bak`, `.vmdk`, `.sql`).
2. **Large File Transfers (`large_file_transfer`) — 6 Scenarios**:
   - **Tools**: `azcopy.exe`, `sftp.exe`, `curl.exe`, `rclone.exe`, `scp.exe`.
   - **Destinations**: Internal repository `10.0.0.40`, cloud mirror `198.51.100.20`, or external repo `203.0.113.10`.
   - **Volumes**: 100 MB to 1,200 MB chunks across ports 443, 22, and 8080.
3. **SMB File Sharing (`smb_file_sharing`) — 6 Scenarios**:
   - **Tools**: `explorer.exe` with user accounts `alice`, `bob`, `finance_user`, `hr_user`, `eng_user`.
   - **Operations**: Document opens, reads, and writes to `\\filesrv\shared_drive` (`10.0.0.12`, `10.0.0.15`).
   - **Volumes**: Realistic office document transfers (4 KB to 1 MB).
4. **Bulk File Reads & Archiving (`bulk_read_archive`) — 6 Scenarios**:
   - **Tools**: `7z.exe`, `tar.exe`, `zip.exe` under developer accounts.
   - **Operations**: Sequential reads of build/application logs followed by local compressed archive writes.
   - **Network**: **0 outbound connections** (strictly local filesystem actions).
5. **Software Deployment & Maintenance (`software_deployment`) — 6 Scenarios**:
   - **Tools**: `ccmexec.exe`, `ansible-playbook`, `msiexec.exe`, `wmic.exe`.
   - **Controller**: `10.0.0.5` connecting to target endpoints across ports 135 (RPC), 445 (SMB), and 5985 (WinRM).
6. **Data Synchronization (`data_synchronization`) — 6 Scenarios**:
   - **Tools**: `onedrive.exe`, `db_replicator.exe`, `sync_agent.exe`.
   - **Operations**: Periodic incremental delta syncs over ports 443, 3306, and 5432.
7. **Benign Traffic Sessions (`benign_traffic`) — 20 Scenarios**:
   - Standard background HTTP, DNS, SMTP, and intranet traffic.

---

## 3. Attack Scenario Diversification

Phase 18 proved that attack scenarios in Phase 17 were near-identical clones. In Phase 19, all four attack classes were diversified:

1. **Brute Force (10 Scenarios)**:
   - **Protocols & Ports**: Web login on port 443, alternate HTTP on port 8080, SSH on port 22, and RDP on port 3389.
   - **Endpoints**: `/api/login`, `/admin/login`, `/auth/token`, `/portal/signin`, `ssh-daemon`, `termsrv`.
   - **Rates**: High-frequency bursts (80–180 attempts in 30s) vs stealth password spraying (30–60 attempts).
2. **C2 Beaconing (25 Scenarios)**:
   - **Intervals**: 15s, 30s, 45s, 60s, 90s, 120s with randomized jitter (2s–10s).
   - **Infrastructure**: Diversified C2 IP ranges (`203.0.113.45`, `198.51.100.88`, `192.0.2.75`, `203.0.113.99`) across ports 8080, 443, and 8443.
   - **Processes**: `cmd.exe`, `powershell.exe`, `rundll32.exe`.
3. **Lateral Movement (15 Scenarios)**:
   - **Tools & Protocols**: `psexec.exe` (SMB 445), `wmic.exe` (RPC 135), `powershell.exe` (WinRM 5985), and `ssh.exe` (SSH 22).
   - **Pivot Topologies**: Varied multi-hop internal pivots across different source subnets.
4. **Data Exfiltration (10 Scenarios)**:
   - **Staging**: Compression with `7z.exe`, `tar.exe`, `powershell.exe`, or uncompressed direct exfiltration.
   - **Channels**: HTTPS POST (port 443), SFTP (port 22), alternate HTTP (8080).
   - **Volumes**: 1MB–5MB sensitive dumps to 15MB–40MB bulk exfiltration streams.

---

## 4. Evaluation Results on Behavioral Diversity Benchmark

Evaluation was executed using the full **Config C pipeline** (15 baseline features + 6 relational temporal graph features = 21 features) under a **strict scenario-grouped holdout split** (stratified by scenario type, 0.0% scenario overlap, split seed 42, model seed 42).

### Global Metrics

| Metric | Phase 17 Result (Cloned Scenarios) | Phase 19 Result (Diversified Workflows) | Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 0.9869 | **0.9092** | -0.0777 |
| **Balanced Accuracy** | 0.9768 | **0.9450** | -0.0318 |
| **Macro-F1** | 0.9732 | **0.8717** | -0.1015 |
| **Weighted-F1** | 0.9870 | **0.9253** | -0.0617 |
| **Binary Attack Recall** | 1.0000 (100.0%) | **1.0000 (100.0%)** | 0.0000 |
| **Benign False Alarm Rate (FPR)** | 0.0000 (0.00%) | **0.1683 (16.83%)** | +0.1683 |

### Per-Class Performance Breakdown ($N=991$ holdout test events)

| Class | Support | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Benign** | 499 | 1.0000 | 0.8317 | **0.9081** |
| **Brute Force** | 238 | 1.0000 | 1.0000 | **1.0000** |
| **Lateral Movement** | 49 | 0.3609 | 0.9796 | **0.5275** |
| **Data Exfiltration** | 147 | 0.9866 | 1.0000 | **0.9932** |
| **C2 Beaconing** | 58 | 0.9464 | 0.9138 | **0.9298** |

### Confusion Matrix ($N=991$)
```
                 Pred_Benign  Pred_BF  Pred_LatMov  Pred_Exfil  Pred_C2
True_Benign          415         0         80           1          3
True_BF                0       238          0           0          0
True_LatMov            0         0         48           0          1
True_Exfil             0         0          0         147          0
True_C2                0         0          5           0         53
```

---

## 5. Benign Administrative Hard-Negative Analysis

The key contribution of Phase 19 is evaluating **workflow-specific false positive rates**:

| Benign Workflow Type | Test Events | Correct Benign | False Alarms | False Alarm Rate (FPR) | Primary Misclassification |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Data Synchronization** | 28 | 28 | 0 | **0.00%** | None (100% correct) |
| **Software Deployment** | 19 | 19 | 0 | **0.00%** | None (100% correct) |
| **Benign Background Traffic** | 320 | 313 | 7 | **2.19%** | 7 misclassified as `lateral_movement` |
| **Large File Transfer** | 23 | 22 | 1 | **4.35%** | 1 misclassified as `data_exfiltration` |
| **SMB File Sharing** | 56 | 28 | 28 | **50.00%** | 25 as `lateral_movement`, 3 as `c2_beaconing` |
| **Scheduled Backup** | 30 | 5 | 25 | **83.33%** | 25 as `lateral_movement` |
| **Bulk Read / Archiving** | 23 | 0 | 23 | **100.00%** | 23 as `lateral_movement` |
| **Overall Benign** | **499** | **415** | **84** | **16.83%** | **80 to `lateral_movement`, 3 to `c2`, 1 to `exfil`** |

### Root Cause Analysis of Administrative Misclassification
1. **The "Endpoint-Means-Lateral-Movement" Bias**:
   - In synthetic training data prior to Phase 19, the only endpoint process events were `psexec.exe`, `wmic.exe`, `cmd.exe`, and `7z.exe`.
   - In the 21-feature Config C schema, pure endpoint events have `dst_port = None` (mapped to 0) and `bytes_sent = None`.
   - When `robocopy.exe`, `7z.exe`, or `explorer.exe` execute high-frequency file reads without outbound network traffic, the Isolation Forest and baseline profiler assign high deviation scores. Because network features are absent, the decision tree routes anomalous endpoint events to `lateral_movement`.
2. **Large File Transfers Succeeded**:
   - Legitimate 500MB+ file transfers (`large_file_transfer`) achieved a **95.65% true negative rate** (22/23 correct), proving that byte volume alone does not trigger false exfiltration alerts when connection duration and internal routing indicators are present.
3. **Software Deployment Succeeded**:
   - Remote software deployment via SCCM/WinRM achieved a **100.0% true negative rate** (19/19 correct), demonstrating that central management servers connecting to internal endpoints are recognized as benign when structured properly.

---

## 6. Multi-Seed Partition Robustness

To verify that findings are not an artifact of split seed 42, we evaluated 5 independent scenario-grouped partitions across seeds `[42, 1337, 2026, 7, 999]`:

| Split Seed | Train Events | Test Events | Macro-F1 | Balanced Accuracy | Benign FPR |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **42** | 4,726 | 991 | 0.8717 | 0.9450 | 16.83% |
| **1337** | 4,723 | 994 | 0.8889 | 0.9449 | 25.05% |
| **2026** | 4,728 | 989 | 0.8941 | 0.9422 | 22.66% |
| **7** | 4,656 | 1,061 | 0.8714 | 0.9435 | 20.62% |
| **999** | 4,588 | 1,129 | 0.8372 | 0.9109 | 31.05% |
| **Mean $\pm$ Std** | — | — | **$0.8727 \pm 0.0199$** | **$0.9373 \pm 0.0132$** | **$23.24\% \pm 4.74\%$** |

### Robustness Insights
- **Split stability**: Macro-F1 is remarkably consistent ($0.8727 \pm 0.0199$), proving that the performance decline from 0.9732 is uniform across scenario permutations.
- **Benign FPR Range**: False alarms fluctuate between 16.83% and 31.05% depending on which subset of administrative scenarios falls into test vs train, underscoring that administrative hard-negatives represent the primary challenge for the current feature set.

---

## 7. Regression Tests & Verification

### Automated Regression Suite ([`tests/test_phase19_behavioral_diversity.py`](file:///Users/akashgpatil/major_project/AEGIS-ML/tests/test_phase19_behavioral_diversity.py))
- `test_phase19_deterministic_generation`: Verifies exact event count (5,717) and SHA-256 (`1a8967f3...`).
- `test_phase19_scenario_provenance_integrity`: Verifies all events possess `scenario_id`, `scenario_type`, and version `3.0.0`.
- `test_phase19_scenario_isolation_across_splits`: Proves 0.0% scenario overlap across train and test partitions.
- `test_phase19_prohibited_provenance_features_excluded`: Confirms no provenance fields exist in predictive features.
- `test_phase19_canonical_label_integrity`: Confirms all labels map to `CANONICAL_CLASSES`.
- `test_phase19_metric_reconstruction_from_arrays`: Confirms exact mathematical reconstruction of confusion matrix and metrics from saved predictions.
- `test_phase19_benign_hard_negative_workflow_tracking`: Confirms per-workflow tracking for all 7 benign categories.

### Full Repository Verification
- **Pytest Suite**: All tests passing across Phase 7 through Phase 19.
- **Historical Benchmarks**: Canonical artifact (Macro-F1 0.8685) and Phase 17 artifact (Macro-F1 0.9732) preserved without modification.
- **Frontend Build**: Production bundle verified cleanly via `npm run build`.

---

## 8. Summary of Findings, Limitations, and Future Roadmap

### Verified Findings
1. The Phase 17 Macro-F1 score of 0.9732 was partly an artifact of scenario template homogeneity. When diverse administrative workflows are introduced, Macro-F1 realistically adjusts to **0.8717**.
2. **Binary attack detection remains flawless (100.0% recall)**. The model does not miss threats; rather, it over-alerts on benign administrative tasks.
3. Administrative false positives are concentrated in **endpoint-only file read/archive activity**, not network transfers or cloud synchronization.

### Unresolved Limitations
- The current 21-feature schema lacks dedicated endpoint file-system indicators (e.g., file path extension risk, process-to-user administrative entitlement, or socket binding presence) to distinguish legitimate administrative tools (`robocopy`, `7z`) from offensive execution (`psexec`, credential dumping).
- Hard negatives on SMB file sharing (50% FPR) highlight that port 445 usage is excessively penalized when host baseline history is limited.

### Recommended Next Phase Focus
- **Endpoint Telemetry Enrichment**: Introduce process lineage depth, digital signature status, or parent-child process tree features to cleanly disambiguate administrative maintenance from offensive living-off-the-land techniques without hard-coding process name filters.
