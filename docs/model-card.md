# Model Card: AEGIS-ML Threat Detection Pipeline

**Model Name:** AEGIS-ML Multi-Layer Threat Classifier & Calibrated Detector  
**Model Version:** 1.0.0  
**Model Date:** October 2026  
**Model Type:** Ensemble of Balanced Random Forest (Supervised), Isotonic Probability Calibrator, Isolation Forest (Unsupervised Anomaly), and Entity Baseline Profiler  
**Primary Language/Framework:** Python 3.10+, scikit-learn 1.7.2, imbalanced-learn 0.12.4  
**License:** Apache 2.0  

---

## 1. Intended Use

### Primary Intended Uses
- Multi-layer threat scoring for unified security events combining network flows, host endpoint process executions, and application authentication logs.
- Classifying multi-stage attack behaviors into 5 canonical MITRE ATT&CK-aligned categories:
  - `benign`
  - `brute_force`
  - `lateral_movement`
  - `data_exfiltration`
  - `c2_beaconing`
- Providing empirical, calibrated posterior probability scores $P(Y=c|X)$ to assist SOC analysts in alert prioritization.
- Providing evidence inputs to the downstream incident correlation engine.

### Out-of-Scope Uses
- Autonomous mitigation, automated firewall drop-rule installation, or unvalidated host isolation without human SOC analyst review.
- Deployment in environments lacking endpoint telemetry (e.g. pure network packet captures) without acknowledging the 35.4% feature absence gap.
- Mission-critical industrial control systems (ICS/SCADA) or safety-critical networks where false alarms or detection delays could cause physical harm.
- Detection of unobserved or out-of-taxonomy attack archetypes (e.g., DoS/DDoS, kernel rootkits) using only the supervised layer.

---

## 2. Model Architecture & Pipeline Details

The AEGIS-ML detection stack is a hybrid multi-model architecture:

1. **Causal Feature Extraction (48 dimensions):**
   - 15 base behavioral and telemetry features
   - 6 relational graph topology metrics (degrees, bipartite ratio, density)
   - 10 context flags (layer, privilege, service account, business hours)
   - 5 missingness indicators (explicit missing telemetry tracking)
   - 12 sequence transition features (burst frequency, directionality)
   - *Invariance:* All features are strictly backward-looking. No future timestamps, target labels, or raw identifier strings are used.

2. **Supervised Threat Classifier:**
   - Balanced Random Forest (100 estimators, max depth 12).
   - Training class rebalancing via SMOTE (Synthetic Minority Over-sampling Technique) applied strictly to training partitions.

3. **Probability Calibration:**
   - Multi-class Isotonic Regression (`CalibratedClassifierCV(method='isotonic')`) wrapping the frozen Random Forest estimator.
   - Fitted strictly on a held-out validation partition (15% of scenario instances), never on the test set.

4. **Defense-in-Depth Anomaly Layer:**
   - Dual Isolation Forest (network layer + endpoint layer) fitted on training data.
   - Behavioral Baseline Profiler computing per-entity Z-score deviation over rolling windows.

---

## 3. Training Data & Provenance

### Primary Dataset
- **File:** `data/raw/behavioral_diversity_labeled.jsonl`
- **SHA-256:** `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`
- **Total Records:** 5,717 events across 114 discrete scenario instances.
- **Partitioning:** Group-aware split by scenario instance (`scenario_id`):
  - Training Partition: 4,155 events (80 scenarios, ~70%)
  - Validation Partition: 676 events (17 scenarios, ~15%)
  - Held-out Test Partition: 886 events (19 scenarios, ~15%)
  - *Strict Invariance:* Zero scenario overlap across all three partitions ($0.0\%$).

---

## 4. Empirical Evaluation & Quantitative Evidence

Detailed metrics, tables, bootstrap confidence intervals, and baselines are fully documented in:
- **Pre-Registered Protocol:** [`docs/evaluation.md`](file:///Users/akashgpatil/major_project/AEGIS-ML/docs/evaluation.md)
- **Detailed Evaluation Results:** [`docs/evaluation/RESULTS.md`](file:///Users/akashgpatil/major_project/AEGIS-ML/docs/evaluation/RESULTS.md)
- **Machine-Readable Raw Data:** [`docs/evaluation/results.json`](file:///Users/akashgpatil/major_project/AEGIS-ML/docs/evaluation/results.json)

### Summary of Headline Metrics (Held-out Test Partition, Seed 42)

| Metric | Point Estimate | 95% Group-Bootstrap Confidence Interval | Interpretation |
|---|---|---|---|
| **Macro F1** | **0.9866** | [0.7803, 0.9987] | Multi-class balance across all 5 classes |
| **Weighted F1** | **0.9943** | — | Overall test set accuracy weighted by class support |
| **Benign FPR (Argmax)** | **0.0024** | [0.0000, 0.0097] | 1 false positive out of 419 true benign samples |
| **Alerts / 1M Benign Flows** | **2,386.63** | — | Extrapolated false alarm burden on benign traffic |
| **Expected Calibration Error (ECE)** | **0.0011** | [0.0003, 0.0120] | Expected difference between confidence and accuracy |
| **Multi-class Brier Score** | **0.0109** | — | Mean squared probability error (0.0 = perfect) |

---

## 5. Calibration Status & Reliability

- **Calibration Method:** Isotonic Regression fitted on validation partition.
- **Out-of-Sample Calibration Result:**
  - Raw Random Forest ECE: `0.1141` → Calibrated ECE: `0.0011` (99.0% reduction in calibration error).
  - Raw Random Forest Brier Score: `0.1144` → Calibrated Brier Score: `0.0109` (90.5% reduction in squared error).
- **Caveat:** Calibration is validated on held-out synthetic scenario test data. In the presence of real-world enterprise covariate shift, probability calibration may degrade and requires periodic re-calibration.

---

## 6. Known Failure Modes & Limitations

1. **Zero-Day Attack Generalization (Leave-One-Attack-Type-Out):**
   - When an attack category is novel/unseen in training data, the supervised classifier fails to detect it:
     - `data_exfiltration` held out: 100.0% escape as benign.
     - `lateral_movement` held out: 94.3% escape as benign.
     - `brute_force` held out: 92.4% escape as benign.
     - `c2_beaconing` held out: 44.7% escape as benign, 55.3% misclassified as data exfiltration.
   - **Mitigation:** The unsupervised anomaly layer (Isolation Forest + Profiler) flagged 38.3% of unseen C2 beaconing. Novel attacks must be caught via anomaly detection and incident correlation, not supervised class labels.

2. **Synthetic Data Constraint:**
   - All evaluation figures are derived from synthetic multi-stage scenario campaigns (`behavioral_diversity_labeled.jsonl`).
   - Synthetic data exhibits cleaner boundaries and more structured transitions than enterprise corporate networks.
   - **These numbers must not be claimed as proof of real-world enterprise detection efficacy.**

3. **External Real-Flow Gap (CIC-IDS2017 Status):**
   - Evaluation on CIC-IDS2017 is `BLOCKED_AWAITING_LOCAL_COPY`.
   - CIC-IDS2017 contains only network flow summaries; 17 of AEGIS-ML's 48 features (35.4%) are endpoint-specific and missing. Zero-filling endpoint features invalidates dual-telemetry decision boundaries.

4. **Adversarial Evasion:**
   - The model has not been evaluated against adversarial machine learning attacks (e.g. packet padding to mimic benign byte ratios, low-and-slow authentication attacks under rate limits, or deliberate timing jitter).

---

## 7. Ethical Considerations & Operational Safeguards

- **Human-in-the-Loop:** All alerts provide explainability breakdowns (feature importances and baseline deviations). The system does not take automated punitive or disciplinary actions against users.
- **Label Integrity:** Unknown or out-of-taxonomy labels are explicitly surfaced and reported, never silently mapped to benign.
- **Fail-Closed Security:** Model retraining and parameter reconfiguration endpoints require administrative API keys.
