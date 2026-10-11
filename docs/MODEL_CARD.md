# Model Card: AEGIS-ML Calibrated Threat Classifier

## 1. Model Details

- **Model Identifier:** `calibrated_threat_classifier.pkl`
- **Model Version:** `23.0.0`
- **Architecture:** Balanced Random Forest Classifier with Isotonic Probability Calibration
- **Underlying Estimator:** `sklearn.ensemble.RandomForestClassifier` (`n_estimators=100`, `class_weight='balanced'`, `random_state=42`)
- **Calibration Method:** `sklearn.calibration.CalibratedClassifierCV` (method=`isotonic`, `cv='prefit'`)
- **Artifact Path:** `data/models/calibrated_threat_classifier.pkl`
- **Artifact SHA-256:** `98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71`
- **Release Date:** October 2026 (AEGIS-ML v1.0.0-rc.1)

---

## 2. Intended Use & Target Scenarios

### 2.1 Intended Use
- Classification of normalized security telemetry events across 5 canonical threat classes.
- Provision of calibrated posterior probabilities $\hat{P}(Y=c|X)$ for multi-signal Bayesian evidence fusion.
- Scenario-based threat progression tracking across MITRE ATT&CK kill-chain phases in enterprise research and laboratory simulation testbeds.

### 2.2 Out-of-Scope & Misuse Cases
- **Autonomous Autonomous Firewall / Kernel Enforcement:** The model is an observational detection signal, not an automated containment actuator.
- **Unmonitored Real-World Production Deployment Without Baseline Retraining:** The model was trained and calibrated on synthetic behavioral scenarios. Deploying without localized baseline calibration on actual enterprise network traffic will experience concept drift.
- **Single-Signal Binary Thresholding:** Predictions should be consumed via the evidence fusion engine alongside unsupervised anomaly scores and entity baselines.

---

## 3. Input Feature Contract (48 Causal Dimensions)

The classifier operates on an immutable 48-feature schema (`PHASE22_BASELINE_FEATURE_NAMES`). All features are causal and computed strictly from contemporaneous or backward-looking historical events:

| Index Range | Category | Count | Features Included |
|:---|:---|:---:|:---|
| `0..14` | **Base Telemetry & Baseline** | 15 | `bytes_sent`, `bytes_received`, `duration`, `port_risk`, `failed_auth_rate`, `protocol_tcp`, `protocol_udp`, `protocol_icmp`, `entity_deviation`, `if_score`, `hour_of_day`, `is_weekend`, `is_internal_src`, `is_internal_dst`, `bytes_ratio` |
| `15..20` | **Relational Graph Context** | 6 | `src_out_degree`, `dst_in_degree`, `bipartite_ratio`, `is_multihop`, `graph_density`, `clustering_coeff` |
| `21..30` | **Telemetry Context & Privilege** | 10 | `layer_network`, `layer_endpoint`, `layer_application`, `is_admin_account`, `is_service_account`, `is_business_hours`, `port_privileged`, `high_risk_dest_port`, `cross_subnet_traffic`, `egress_traffic` |
| `31..35` | **Missingness Indicators** | 5 | `missing_parent_process`, `missing_user_id`, `missing_payload_hash`, `missing_port`, `missing_session_token` |
| `36..47` | **Host Sequence & Progression** | 12 | `rolling_event_rate_1m`, `rolling_event_rate_5m`, `burst_ratio`, `time_delta_variance`, `consecutive_auth_failures`, `seq_auth_to_exec`, `seq_exec_to_net`, `seq_net_to_egress`, `unique_dst_ips_1m`, `unique_dst_ports_1m`, `rare_process_flag`, `elevation_attempt_flag` |

---

## 4. Training & Evaluation Methodology

### 4.1 Dataset Provenance
- **Dataset Path:** `data/raw/behavioral_diversity_labeled.jsonl`
- **Dataset SHA-256:** `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`
- **Total Samples:** 5,717 labeled telemetry events across 116 unique multi-stage attack and benign operational scenarios.

### 4.2 Leakage-Free Scenario-Grouped Partitioning
- **Partitioning Strategy:** `StratifiedGroupKFold` grouped by unique `scenario_id`.
  - **Train Split:** 81 scenarios (3,969 events)
  - **Validation Split:** 11 scenarios (663 events) — used exclusively for isotonic calibration fitting
  - **Test Split:** 24 scenarios (1,085 events) — strictly held-out
- **Train/Test Scenario Overlap:** **0.00%** (proven leakage-free).
- **Preprocessor Isolation:** All feature scalers, baseline profilers, and isolation forests were fitted strictly on the training partition before scoring validation or test events.

---

## 5. Quantitative Evaluation Metrics (Held-Out Test Set)

Evaluated on the 1,085 test events from unseen scenarios:

| Metric | Score | Interpretation |
|:---|:---:|:---|
| **Overall Accuracy** | **99.45%** | 1,079 of 1,085 events correctly classified |
| **Balanced Accuracy** | **98.73%** | Mean of recall across all 5 classes |
| **Macro-F1 Score** | **99.09%** | Unweighted average F1 across classes |
| **Weighted-F1 Score** | **99.44%** | Support-weighted average F1 |
| **Benign False Alarm Rate (FPR)** | **0.15%** | Exactly 1 benign event misclassified as an attack (1 / 679) |
| **Overall Attack Recall** | **99.01%** | 402 of 406 attack events identified |
| **Calibrated Multi-Class Log-Loss** | **0.2132** | Indicates well-penalized, low-overconfidence predictions |
| **Binary Brier Score** | **0.0060** | Low mean squared probability error on attack presence |

### 5.1 Per-Class Performance
| Class | Precision | Recall | F1-Score | Support |
|:---|:---:|:---:|:---:|:---:|
| `benign` | 99.41% | 99.85% | 99.63% | 679 |
| `brute_force` | 100.00% | 100.00% | 100.00% | 150 |
| `c2_beaconing` | 100.00% | 100.00% | 100.00% | 30 |
| `data_exfiltration` | 99.35% | 99.35% | 99.35% | 154 |
| `lateral_movement` | 98.55% | 94.44% | 96.45% | 72 |

### 5.2 Confusion Matrix (Actual $\times$ Predicted)
```
Labels: [benign, brute_force, c2_beaconing, data_exfiltration, lateral_movement]
[[678,   0,   0,   0,   1],   <-- benign (1 false alarm to lateral_movement)
 [  0, 150,   0,   0,   0],   <-- brute_force
 [  0,   0,  30,   0,   0],   <-- c2_beaconing
 [  1,   0,   0, 153,   0],   <-- data_exfiltration (1 missed as benign)
 [  3,   0,   0,   1,  68]]   <-- lateral_movement (3 missed as benign, 1 as data_exfil)
```

---

## 6. Known Failure Modes & Behavioral Nuances

1. **Lateral Movement Sensitivity:**
   The primary failure mode occurs in `lateral_movement` (4 false negatives out of 72 events, 94.44% recall). When an attacker utilizes legitimate management ports (e.g., standard SMB or WMI) on hosts with minimal historical telemetry, sequence features alone may lack sufficient density to distinguish normal system administration from initial internal pivot activity.
2. **Synthetic Template Reuse:**
   Audits (`evaluation_reproducibility_audit.py`) confirmed that although scenario groups are disjoint, synthetic generators reuse common parameter distributions (e.g. standard mock C2 IP ranges). While this proves generalization across distinct execution sequences, it does not prove robustness against adversarial feature perturbation.
3. **External Benchmark Status:**
   Evaluation on the public **CIC-IDS2017** dataset is currently **BLOCKED**. Public CIC-IDS2017 flow dumps lack endpoint process telemetry, command-line arguments, and authentication logs necessary for the 48-feature schema without synthetic fabrication.

---

## 7. Model Maintenance & Security

- **Serialization Integrity:** Stored with SHA-256 integrity hash verification; any byte-level alteration fails verification checks at load time.
- **Rollback Protection:** The model reload API (`/api/model/reload`) requires admin authentication and performs dry-run validation against baseline schemas before committing hot-swaps.
