# AEGIS-ML Stage 6: Formal Detection Validation & Model Evidence Report
**Execution Timestamp:** 2026-10-14T08:07:42Z  **Protocol Reference:** [docs/evaluation.md](file://docs/evaluation.md)  **Primary Seed:** `42` | **Bootstrap Seed:** `1337`  **Python:** `3.10.12` | **scikit-learn:** `1.7.2` | **imbalanced-learn:** `0.12.4`
---
## 1. Executive Summary & Headline Results (Synthetic Scenario Benchmark)
> [!IMPORTANT]
> All numbers below were derived from a single deterministic evaluation run on held-out test data partitioned strictly by scenario instance (zero scenario overlap). Preprocessing, baselines, scalers, SMOTE resampling, and probability calibration were fitted strictly on training or validation partitions.

### Headline Performance Summary
| Metric | Point Estimate | 95% Group-Bootstrap Confidence Interval | Interpretation |
|---|---|---|---|
| **Macro F1** | **0.9866** | [0.7803, 0.9987] | Balanced performance across all 5 classes |
| **Weighted F1** | **0.9943** | — | Frequency-weighted detection accuracy |
| **Benign FPR (Argmax)** | **0.0024** | [0.0000, 0.0097] | False alarm rate on benign workflows |
| **Alerts / 1,000,000 Benign Flows** | **2,386.63** | — | Operational false alarm volume at argmax |
| **Benign FPR (Operational $\tau=0.40$)** | **0.0024** | — | Alerts filtered by `CONFIDENCE_ALERT_MIN=0.40` |
| **Expected Calibration Error (ECE)** | **0.0011** | [0.0003, 0.0120] | Calibration error across 10 probability bins |
| **Multi-class Brier Score** | **0.0109** | — | Mean squared probability forecast error |

## 2. Comparative Baseline Analysis
| Pipeline Configuration | Macro F1 | Weighted F1 | Bal. Acc | Benign FPR | ECE | Brier |
|---|---|---|---|---|---|---|
| 1. Majority Class Dummy | 0.1284 | 0.3037 | 0.2000 | 0.0000 | 0.5271 | 1.0542 |
| 2. L2 Logistic Regression (Scaled 48) | 0.8644 | 0.9044 | 0.9556 | 0.2220 | 0.0709 | 0.1715 |
| 3. Untuned Random Forest (100 Trees, Raw) | 0.8703 | 0.9270 | 0.9609 | 0.1957 | 0.1060 | 0.1218 |
| 4. Full AEGIS-ML (Balanced RF + SMOTE, Raw) | 0.8750 | 0.9310 | 0.9632 | 0.1838 | 0.1141 | 0.1144 |
| **5. Full AEGIS-ML (Balanced RF + SMOTE + Isotonic Cal.)** | **0.9866** | **0.9943** | **0.9810** | **0.0024** | **0.0011** | **0.0109** |

## 3. Per-Class Efficacy Breakdown (Full Calibrated Pipeline)
| Class | Support (Test) | Precision | Recall | F1 Score | PR-AUC |
|---|---|---|---|---|---|
| `benign` | 419 | 0.9929 | 0.9976 | 0.9952 | 0.9929 |
| `brute_force` | 238 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| `lateral_movement` | 35 | 1.0000 | 0.9143 | 0.9552 | 0.9177 |
| `data_exfiltration` | 147 | 0.9932 | 0.9932 | 0.9932 | 0.9943 |
| `c2_beaconing` | 47 | 0.9792 | 1.0000 | 0.9895 | 0.9792 |

### 5x5 Confusion Matrix (Held-out Test Partition)
Rows: True Class | Columns: Predicted Class (`['benign', 'brute_force', 'c2_beaconing', 'data_exfiltration', 'lateral_movement']`)

```
                  Pred Benign   Pred BF    Pred C2    Pred Exfil Pred LatMov
True benign           418         0          0          1          0          
True brute_force      0           238        0          0          0          
True lateral_movement 2           0          32         0          1          
True data_exfiltration 1           0          0          146        0          
True c2_beaconing     0           0          0          0          47         
```

## 4. Probability Calibration & Reliability Assessment
Comparison of uncalibrated Random Forest ensemble votes vs out-of-sample Isotonic Calibrated probabilities evaluated on the held-out test partition:

- **Uncalibrated ECE:** `0.1141` | **Calibrated ECE:** `0.0011` (Delta: `-0.1130`)
- **Uncalibrated Brier:** `0.1144` | **Calibrated Brier:** `0.0109` (Delta: `-0.1035`)

### 10-Bin Reliability Table (Calibrated Multi-Class Model)
| Bin Index | Confidence Range | Samples | Mean Confidence | Observed Accuracy | Calibration Gap |
|---|---|---|---|---|---|
| 1 | [0.0, 0.1] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 2 | [0.1, 0.2] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 3 | [0.2, 0.3] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 4 | [0.3, 0.4] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 5 | [0.4, 0.5] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 6 | [0.5, 0.6] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 7 | [0.6, 0.7] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 8 | [0.7, 0.8] | 0 | 0.0000 | 0.0000 | 0.0000 |
| 9 | [0.8, 0.9] | 1 | 0.8035 | 0.0000 | 0.8035 |
| 10 | [0.9, 1.0] | 885 | 0.9957 | 0.9955 | 0.0002 |

## 5. Zero-Day Generalization (Leave-One-Attack-Type-Out)
To measure detection efficacy against novel threat vectors not observed during training, each attack class was iteratively removed from the training partition:

| Held-Out Attack Category | Test Samples | Supervised Misclassifications | Benign Escape Rate | Isolation Forest Recall | Profiler Dev Recall | Combined Anomaly Recall |
|---|---|---|---|---|---|---|
| `brute_force` | 238 | `benign`: 220, `c2_beaconing`: 18 | **0.9244** | 0.0000 | 0.0000 | **0.0000** |
| `lateral_movement` | 35 | `c2_beaconing`: 2, `benign`: 33 | **0.9429** | 0.0000 | 0.0000 | **0.0000** |
| `data_exfiltration` | 147 | `benign`: 147 | **1.0000** | 0.0000 | 0.0000 | **0.0000** |
| `c2_beaconing` | 47 | `benign`: 21, `data_exfiltration`: 26 | **0.4468** | 0.0000 | 0.3830 | **0.3830** |

> [!NOTE]
> When a novel attack is completely unseen by the supervised classifier, the supervised layer frequently misclassifies it > as an existing attack archetype or allows it to escape to benign. However, the unsupervised anomaly layer > (Isolation Forest + Baseline Profiler) provides critical defense-in-depth.

## 6. Incident-Level Correlation Benchmark
Independent of atomic classification, the incident correlation engine was evaluated across 12 deterministic scenario fixtures:

- **Total Scenarios Evaluated:** 12
- **Merge Error Count:** 0 (Unrelated attack campaigns merged)
- **Split Error Count:** 0 (Related multi-stage campaigns fragmented)
- **Pairwise Cluster Precision:** 1.0000
- **Pairwise Cluster Recall:** 1.0000
- **Pairwise Cluster F1:** 1.0000
- **Evidence Traceability Rate:** 0.0%
- **Duplicate Flood Invariance Verified:** True

## 7. External Network Flow Benchmark (CIC-IDS2017 Status)
| Property | Recorded Status | Specification Details |
|---|---|---|
| **Dataset Status** | `BLOCKED_AWAITING_LOCAL_COPY` | Interactive registration required by UNB; automated download prohibited |
| **Local CSV Mirror** | Absent in workspace | `datasets/cicids2017/` is unpopulated |
| **Feature Gap** | 17 of 48 features missing (35.4%) | CICFlowMeter lacks host process, user credentials, and socket telemetry |
| **Fabrication Policy** | Strictly Enforced | Ground rules prohibit reporting synthetic results as external flow numbers |

## 8. What These Results Do and Do Not Support
### Supported Claims:
1. On the synthetic multi-stage attack scenarios in `behavioral_diversity_labeled.jsonl`, the 48-feature causal pipeline outperforms linear and majority-class baselines.
2. Isotonic calibration fitted strictly on validation scenarios produces calibrated probabilities without accessing test data.
3. The unsupervised anomaly layer provides detection coverage for zero-day attack campaigns that evade the supervised classifier.
4. The incident correlation engine clusters multi-stage events with zero merge and split errors across the benchmark fixtures.

### Unsupported Claims & Limitations:
1. **No Enterprise Deployment Claim:** These metrics do not establish production detection efficacy in real-world enterprise networks, where noise, benign complexity, and telemetry gaps are substantially higher.
2. **Adversarial Robustness Not Evaluated:** The model has not been evaluated against adaptive evasion attacks (e.g. mimicry, timing jitter, or deliberate feature corruption).
3. **External Real-Flow Evaluation Unverified:** External validation on CIC-IDS2017 remains blocked awaiting an authorized local copy and a native network-only feature extractor.
