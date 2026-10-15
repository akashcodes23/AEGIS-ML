# AEGIS-ML Detection Validation & Evaluation Protocol

**Document Version:** 1.0.0-preregistered  
**Status:** Pre-registered before final evaluation run  
**Timestamp:** 2026-10-14T13:20:00Z  
**Primary Seed:** 42  
**Bootstrap Seed:** 1337  
**Environment Specification:**
- Python: 3.10.12 (CPython, macOS arm64)
- scikit-learn: 1.7.2
- imbalanced-learn: 0.12.4
- numpy: 2.2.6
- scipy: 1.14.1
- pandas: 2.2.3

---

## 1. Ground Rules & Pre-Registration Discipline

1. **Pre-Register, Then Measure**: This evaluation protocol defines all datasets, splits, metrics, thresholds, and baseline configurations *prior* to executing test-partition scoring.
2. **No Test-Set Tuning**: All hyperparameters (number of trees, max depth, class weights), anomaly thresholds (`ANOMALY_THRESHOLD = 0.65`), alert gating thresholds (`CONFIDENCE_ALERT_MIN = 0.40`), and calibration curves are fixed based on training/validation partitions only. The held-out test partition is scored exactly once.
3. **No Metric Selection or Selective Reporting**: All evaluated classes, including failure modes, low-recall categories, and calibration degradations, must be fully disclosed with confusion matrices and bootstrap confidence intervals.
4. **Strict Isolation of Synthetic vs. Real Data**: Synthetic scenario benchmarks and external network flow benchmarks are evaluated and reported in separate tables; they must never be combined or averaged.
5. **Deterministic Reproducibility**: Execution of `python3 -m backend.evaluation.run_pre_registered_eval` with fixed seeds must reproduce all reported metrics, tables, and confidence intervals identically across repeated runs.

---

## 2. Dataset Inventory & Provenance

### 2.1 Primary Benchmark: `behavioral_diversity_labeled.jsonl`
- **Location:** `data/raw/behavioral_diversity_labeled.jsonl`
- **File Size:** 6,012,106 bytes
- **SHA-256:** `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`
- **Total Records:** 5,717 events
- **Scenario Groups:** 114 discrete scenario instances across 19 scenario archetypes
- **Telemetry Modality:** Dual-telemetry (Network flow events + Endpoint process executions + Authentication records)
- **Class Distribution:**
  - `benign`: 2,737 events (47.87%)
  - `brute_force`: 1,690 events (29.56%)
  - `data_exfiltration`: 756 events (13.22%)
  - `lateral_movement`: 293 events (5.13%)
  - `c2_beaconing`: 241 events (4.22%)
- **License / Terms:** Project synthetic research fixture. Synthetic simulation for causal algorithm validation; does not establish real-world enterprise detection efficacy.

### 2.2 Secondary Benchmark: `scenario_aware_labeled.jsonl`
- **Location:** `data/raw/scenario_aware_labeled.jsonl`
- **File Size:** 7,757,592 bytes
- **SHA-256:** `4156637e6daef31fae8efceb5b3eb3c1a850da256e29aa7b5ba77259f9393a61`
- **Total Records:** 7,361 events
- **Class Distribution:**
  - `benign`: 2,051 events (27.86%)
  - `brute_force`: 3,292 events (44.72%)
  - `data_exfiltration`: 1,320 events (17.93%)
  - `lateral_movement`: 353 events (4.80%)
  - `c2_beaconing`: 345 events (4.69%)

### 2.3 External Benchmark: CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Status:** `BLOCKED_AWAITING_LOCAL_COPY` (Documented in `data/models/external_dataset_evaluation_artifact.json` and `docs/CICIDS2017_IMPORT.md`)
- **Reasoning & Constraints:**
  - *Licensing:* UNB requires interactive web registration; non-interactive redistribution or automated scraping is prohibited. No authorized local CSV resides in `datasets/cicids2017/`.
  - *Telemetry Modality Mismatch:* CIC-IDS2017 contains pure network flows (CICFlowMeter bidirectional summaries). It contains zero host process context, PAM/auth records, or socket attribution.
  - *Feature Gap:* 17 of AEGIS-ML's 48 causal features (35.4%) are structurally unavailable. Zero-filling endpoint features invalidates dual-telemetry decision boundaries.
  - *Reporting Policy:* In compliance with Ground Rule #0, no CIC-IDS2017 numbers are fabricated. The loader interface and error handling are verified, and the blocked status is explicitly recorded.

---

## 3. Split Methodologies & Leakage Guards

### 3.1 Scenario-Instance Partitioning (In-Distribution Evaluation)
To prevent flow-correlation leakage where identical attacker infrastructure, credentials, or timestamps appear on both sides of a random row split:
- **Group Key:** `scenario_id` (e.g., `p19_backup_000`, `p20_c2_001`).
- **Partition Ratios:**
  - Training Partition: 70% of scenario instances (~70% events)
  - Calibration/Validation Partition: 15% of scenario instances (~15% events)
  - Held-out Test Partition: 15% of scenario instances (~15% events)
- **Strict Invariance Assertions:**
  $$\text{Scenarios}_{\text{train}} \cap \text{Scenarios}_{\text{cal}} = \emptyset$$
  $$\text{Scenarios}_{\text{train}} \cap \text{Scenarios}_{\text{test}} = \emptyset$$
  $$\text{Scenarios}_{\text{cal}} \cap \text{Scenarios}_{\text{test}} = \emptyset$$
  $$\text{Events}_{\text{train}} \cap \text{Events}_{\text{test}} = \emptyset$$

### 3.2 Leave-One-Attack-Type-Out Partitioning (Out-of-Distribution / Zero-Day)
To evaluate model performance on genuinely novel, unseen attack categories:
- Four distinct cross-validation folds are created.
- In each fold $k \in \{\text{brute\_force}, \text{c2\_beaconing}, \text{data\_exfiltration}, \text{lateral\_movement}\}$:
  - All instances of attack class $k$ are **completely removed from training and calibration**.
  - The model is trained on the remaining classes + benign traffic.
  - The held-out test set contains benign traffic, known attack types, and the completely unseen attack type $k$.
  - Measurements:
    1. Supervised misclassification behavior on the novel attack (which known class does it mistake it for?).
    2. Unsupervised Anomaly Layer Recall: What fraction of the unseen attack events are flagged by the Isolation Forest ($s \ge 0.65$) or Behavioral Profiler ($d \ge 0.70$)?

---

## 4. Preprocessing & Calibration Pipeline Discipline

1. **Preprocessing Isolation:**
   - `BehavioralBaselineProfiler`: Fitted strictly on `train_events` using `benign_only=True`. Entity baselines never observe validation or test traffic.
   - `IsolationForestDetector`: Fitted strictly on `train_events`.
   - `CausalTemporalGraphTracker` & `CausalSequenceTracker`: Initialized and stepped causally through time. Sequence trackers are reset between partitions.
2. **Resampling Isolation:**
   - Synthetic Minority Over-sampling Technique (SMOTE) is applied **strictly to the training feature matrix `X_train`**. Validation and test matrices are never over-sampled.
3. **Probability Calibration Isolation:**
   - The underlying classifier (Balanced Random Forest) is fitted on `X_train_resampled`.
   - Probability calibration (`CalibratedClassifierCV(method='isotonic')`) is fitted **strictly on `X_cal` (validation set)**.
   - The held-out `X_test` matrix is evaluated using the frozen calibrator to assess real-world out-of-sample calibration.

---

## 5. Metrics Specification

For every evaluation run, the following metrics are recorded:

1. **Multi-Class Classification:**
   - Macro-averaged F1 score: $\frac{1}{C} \sum_{c=1}^C F_{1, c}$
   - Weighted F1 score: $\sum_{c=1}^C \frac{N_c}{N} F_{1, c}$
   - Balanced Accuracy: $\frac{1}{C} \sum_{c=1}^C \text{Recall}_c$
   - Overall Accuracy: $\frac{\text{Correct}}{N}$
   - Complete $5 \times 5$ Confusion Matrix.
2. **Per-Class Efficacy:**
   - Precision: $\frac{\text{TP}_c}{\text{TP}_c + \text{FP}_c}$
   - Recall: $\frac{\text{TP}_c}{\text{TP}_c + \text{FN}_c}$
   - F1 score: $\frac{2 \cdot P_c \cdot R_c}{P_c + R_c}$
   - Precision-Recall Area Under Curve (PR-AUC) computed via average precision score on binarized One-vs-Rest probabilities.
3. **Operational Benign False Positive Burden:**
   - Benign False Positive Rate (FPR):
     $$\text{FPR}_{\text{benign}} = \frac{\text{False Positives on Benign}}{\text{Total True Benign Samples}}$$
   - Projected False Alarm Rate:
     $$\text{Alerts per 1,000,000 Benign Flows} = \text{FPR}_{\text{benign}} \times 1,000,000$$
   - Evaluated at both argmax classification threshold and operational threshold (`CONFIDENCE_ALERT_MIN = 0.40`).
4. **Calibration Quality:**
   - Expected Calibration Error (ECE) across $M=10$ uniform probability bins:
     $$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} |\text{acc}(B_m) - \text{conf}(B_m)|$$
   - Multi-class Brier Score:
     $$\text{Brier} = \frac{1}{N} \sum_{i=1}^N \sum_{c=1}^C (p_{ic} - y_{ic})^2$$
   - Full 10-bin Reliability Table comparing raw random forest probabilities vs isotonic calibrated probabilities on held-out test data.
5. **Statistical Uncertainty (95% Bootstrap Confidence Intervals):**
   - 1,000 bootstrap resamples grouped by scenario instance on the test set.
   - 2.5th and 97.5th percentiles reported for Macro F1, Benign FPR, and ECE.

---

## 6. Baselines for Context

To establish whether the 48-feature causal pipeline and balanced Random Forest provide authentic predictive utility, three baselines are evaluated on identical splits:
1. **Majority Class Dummy Classifier:** Predicts the most frequent class (`benign`) unconditionally.
2. **L2-Regularized Multinomial Logistic Regression:** Linear classification baseline on the standard-scaled 48-feature vector.
3. **Untuned Random Forest:** 100 trees, unweighted default settings, evaluating the contribution of balanced class weighting and SMOTE.
4. **Full AEGIS-ML Pipeline:** Balanced RF + Causal Featurization + SMOTE + Isotonic Calibration.

---

## 7. Incident-Level Correlation Benchmark

Independent from classification metrics, the incident correlation engine is evaluated using the 12 deterministic test fixtures in `backend/evaluation/correlation_benchmark.py`:
- Merge Error Count (unrelated attack campaigns incorrectly merged)
- Split Error Count (related multi-stage events incorrectly fragmented)
- Pairwise Cluster Precision, Recall, and F1
- Evidence Traceability Rate (% of supporting event IDs preserved)
- Duplicate Flood Invariance Verified
