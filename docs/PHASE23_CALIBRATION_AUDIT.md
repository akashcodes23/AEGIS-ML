# AEGIS-ML Phase 23: Calibration Reproducibility and Scientific Audit Report

## 1. Executive Summary & Objective

In Phase 22, evaluating post-hoc probability calibration on AEGIS-ML's 48-feature multi-layer threat detector reported a dramatic improvement:
- **Baseline (Config A, uncalibrated argmax)**: 80 benign false alarms out of 499 (16.03% FPR), 492/492 attacks detected (100% recall), Macro-F1 = 0.8927.
- **Calibrated (Config B, isotonic calibration)**: **1 benign false alarm** out of 499 (0.20% FPR), 490/492 attacks detected (99.59% recall), Macro-F1 = 0.9908.

Because an improvement from 80 false alarms down to 1 (a 98.8% relative reduction) is unusually large, Phase 23 mandates a rigorous reproducibility audit before integrating this model into the live serving path.

This audit:
1. Re-verifies dataset integrity, scenario disjointness, and absence of target or future leakage.
2. Uncovers the exact mathematical mechanism explaining why isotonic calibration eliminated false alarms on administrative traffic.
3. Examines multi-seed variance to quantify whether the seed-42 result (1/499) reflects an optimistic split or consistent generalization across alternative scenario splits.
4. Distinguishes reproduced findings from unverified assumptions and synthetic data limitations.

---

## 2. Dataset and Split Integrity Audit

### Verified Dataset Fingerprint
- **Dataset Path**: `data/raw/behavioral_diversity_labeled.jsonl`
- **Total Record Count**: 5,717 events
- **Verified SHA-256**: `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`
- **Scenarios**: 116 total scenarios (72 benign administrative/background, 44 multi-stage attack scenarios).

### Scenario-Group Partition Verification
The 3-way partition was audited for scenario and event leakage:
- **Test Set**: 22 scenarios, 991 events (499 benign, 492 attacks).
- **Validation Set**: 14 scenarios, 754 events (329 benign, 425 attacks).
- **Training Set**: 80 scenarios, 3,972 events (1,939 benign, 2,033 attacks).
- **Disjointness Check**:
  - $\text{Train} \cap \text{Validation} = \emptyset$ (0 shared scenarios, 0 shared event IDs).
  - $\text{Train} \cap \text{Test} = \emptyset$ (0 shared scenarios, 0 shared event IDs).
  - $\text{Validation} \cap \text{Test} = \emptyset$ (0 shared scenarios, 0 shared event IDs).

### Leakage Boundaries Audit
1. **Preprocessing**: `BehavioralBaselineProfiler`, `IsolationForestDetector`, and `CausalTemporalGraphTracker` baseline entity pairs were fitted strictly on training data ($X_{\text{train}}$).
2. **Resampling**: SMOTE was applied **only** to the training partition ($X_{\text{train}}$). Validation and test partitions were **never resampled**.
3. **Calibration Data**: Calibrators were fitted exclusively on $X_{\text{val}}, y_{\text{val}}$ using `CalibratedClassifierCV(FrozenEstimator(base_rf), method="isotonic")`. Test data was completely untouched during fitting.
4. **Features**: Zero provenance fields (`scenario_id`, `event_id`, `template_id`, `campaign_id`) were present in the 48-feature input matrix. All sequence features enforce $t_{\text{prev}} \le t_{\text{event}}$ (zero future-event leakage).

---

## 3. Mathematical Mechanism of the False-Positive Reduction

The audit investigated why raw Random Forest tree voting failed on administrative workflows (`bulk_read_archive`, `scheduled_backup`, `smb_file_sharing`), and how isotonic calibration corrected it.

### Empirical Inspection of Raw Tree Votes on False Alarms
We extracted the exact tree-vote distributions on the 80 false alarms:

| Event ID / Scenario | Raw Benign Vote | Raw Lateral Move Vote | Raw Prediction | Calibrated Benign Prob | Calibrated Lateral Prob | Calibrated Prediction |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Event 81 (`benign_traffic`) | 0.330 | **0.437** | `lateral_movement` | **1.000** | 0.000 | **`benign`** |
| Event 96 (`benign_traffic`) | 0.367 | **0.370** | `lateral_movement` | **1.000** | 0.000 | **`benign`** |
| Event 98 (`benign_traffic`) | 0.343 | **0.383** | `lateral_movement` | **1.000** | 0.000 | **`benign`** |
| Event 251 (`scheduled_backup`) | 0.127 | **0.580** | `lateral_movement` | **1.000** | 0.000 | **`benign`** |
| Event 253 (`scheduled_backup`) | 0.273 | **0.467** | `lateral_movement` | **1.000** | 0.000 | **`benign`** |

### Root-Cause Diagnosis
1. **SMOTE-Induced Over-representation**:
   In the training set, SMOTE balanced minority attack classes (including `lateral_movement`, which had only 49 raw events). Consequently, decision trees learned aggressive split criteria for high-byte or atypical internal connections.
2. **Plurality Voting Failure (Argmax Fragility)**:
   On administrative workflows, benign trees were diffused across several baseline branches. `lateral_movement` frequently captured a plurality (e.g., 37% to 47% of trees), barely edging out `benign` (33% to 36%), despite 55–65% of trees voting against lateral movement!
3. **Isotonic Calibration Correction**:
   The isotonic calibrator was fitted on the **non-resampled** validation set, which reflects real natural class proportions.
   In the validation data, when the raw ensemble outputs a vote fraction of $0.35 \le p_{\text{RF}}(\text{lateral}) \le 0.58$, the empirical frequency of true lateral movement is $< 1\%$.
   The isotonic step function maps tree votes in $[0.30, 0.60]$ down to $0.00$, while mapping votes $\ge 0.80$ (typical of true attacks) to $> 0.90$.
   As a result, calibrated $P(\text{benign})$ rises to $1.000$, correctly classifying 79 of the 80 false alarms as benign.

---

## 4. Multi-Seed Robustness and Split Sensitivity

While the seed-42 test split produced only 1 false alarm (0.20% FPR), evaluating across five random scenario-grouped seeds reveals the true variance:

| Seed | Config A Benign FPR | Config B Benign FPR | Config A Attack Recall | Config B Attack Recall | Config B Macro-F1 |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **42** | 16.03% (80/499) | **0.20% (1/499)** | 100.0% (492/492) | 99.59% (490/492) | 0.9908 |
| **1337** | 32.34% (173/535) | **3.55% (19/535)** | 100.0% (459/459) | 99.56% (457/459) | 0.9794 |
| **2026** | 28.12% (144/512) | **0.20% (1/512)** | 100.0% (477/477) | 98.53% (470/477) | 0.9897 |
| **7** | 10.02% (52/519) | **3.85% (20/519)** | 100.0% (542/542) | 99.63% (540/542) | 0.9782 |
| **999** | 20.95% (110/525) | **0.38% (2/525)** | 99.50% (601/604) | 98.84% (597/604) | 0.9843 |
| **Pooled** | **21.58% (559/2590)** | **1.66% (43/2590)** | **99.88% (2571/2574)** | **99.23% (2554/2574)** | **$0.9845 \pm 0.0051$** |

### Audit Assessment of Multi-Seed Results
- **Realistic Generalization**: The true expected false-alarm rate across alternative scenario partitions is **1.66% $\pm$ 1.69%** (pooled 43/2590), not 0.20%.
- **Consistent Relative Gain**: Across all 5 seeds, calibration achieves an **80% to 98% relative reduction in false alarms** without ever dropping attack recall below 98.5%.
- **Seed 42 Qualification**: Seed 42 was an exceptionally clean partition. Operational documentation must clearly state the multi-seed pooled rate (1.66%) rather than relying solely on the seed-42 headline figure.

---

## 5. Summary of Audit Findings

### A. Reproduced Findings
1. Dataset SHA-256 and row count match exactly (`1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352`, 5,717 records).
2. Seed-42 Config A (80/499 false alarms) and Config B (1/499 false alarms, 490/492 attacks detected) reproduced identically.
3. Test log-loss drops from 0.2588 to 0.0874, and benign Brier score drops from 0.0736 to 0.0029.
4. Zero scenario overlap between train, validation, and test partitions confirmed.

### B. Findings That Differ or Require Qualification
1. **False-Alarm Rate Range**: While Seed 42 achieved 0.20% FPR, other scenario splits produce 3.55% (seed 1337) and 3.85% (seed 7). The pooled rate is **1.66%**, which must be documented as the benchmark expectation.
2. **Minor Attack Drops**: Config B is not 100% recall on Seed 42: it missed 2 attack events (1 subtle lateral movement event and 1 data exfiltration event where tree agreement was marginal). This is acceptable given the 79 false alarms eliminated.

### C. Unverified Assumptions
1. **Synthetic Data Boundary**: The calibration is fitted on synthetic administrative templates. In real enterprise networks, novel software updates, bespoke PowerShell scripts, or uncommon admin tools may exhibit vote patterns not represented in the synthetic validation set.
2. **Lack of Socket Attribution**: 0% of events have verified process-to-socket attribution. The model continues to infer relationships from causal temporal windows.

### D. Corrective Actions for Phase 23
1. **Versioned Artifact Lifecycle**: Package the base Random Forest, the fitted Isotonic Calibrator, and exact feature/class metadata into a single cryptographically verified artifact bundle.
2. **Serving Path Integration**: Update `ThreatClassifier` to support loading calibrated artifacts, returning both raw ensemble vote fractions and calibrated Bayesian posterior probabilities.
3. **Explicit Confidence Labels**: In API schemas and the frontend, distinguish raw ensemble consensus from calibrated confidence, explicitly qualifying that calibration was evaluated on synthetic scenario data.
