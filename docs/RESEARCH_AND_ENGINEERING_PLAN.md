# AEGIS-ML Research and Engineering Plan
**Version:** 4.0 — Leakage-Resistant Evaluation & Evidence-Driven Incident Intelligence (Phase 9)
**Date:** 2026-10-09
**Auditor:** Senior ML Research Engineer / Detection Engineer / Software Quality Engineer

---

## 1. Audit Findings & Reconciled Evaluation Defects

### 1.1 Confirmed Defects & Evaluation Reconciliations (Priority Order)

| # | Severity | Location | Defect & Resolution |
|---|----------|----------|---------------------|
| D1 | **Critical** | `model_trainer.py:541` | Label extraction originally used `e.attack_type` which was `None` for synthetic records. **Resolved:** Prefer `attack_type`, fallback to `DATASET_LABEL_MAP[raw_label]`. |
| D2 | **High** | `ablation_study.py:165-175` | **Task Conflation Defect (Config C F1 Drop):** Previously assigned `y_pred_c[i] = "benign"` for duplicate alerts suppressed by sliding-window deduplication, penalizing operational triage deduplication as classifier False Negatives and falsely dropping Macro-F1 from 0.9823 to 0.9331. **Resolved:** Decoupled event-level classification metrics from operational triage metrics. Classifier Macro-F1 preserved at 0.9823; triage deduplication evaluated as alert suppression ratio (124 duplicate alerts suppressed). |
| D3 | **High** | `ablation_study.py` / `model_trainer.py` | **Feature Content Leakage:** 48.6% of test records in baseline stratified 80/20 holdout shared exact feature vectors with training records due to scripted synthetic generation loops. **Resolved:** Implemented group-aware holdout grouping by feature hash fingerprints, achieving 0% duplicate overlap. |
| D4 | **Medium** | `incident_correlator.py:175-220` | Multi-incident entity overwrite in single-value dictionary mapping `entity_to_incident[dst]`. Independent incidents sharing victim destination collided. **Resolved:** Replaced with multi-incident index `entity_to_incidents: Dict[str, List[str]]` and strict rule matching. |
| D5 | **Medium** | `incident_correlator.py:236,314` | Pydantic v1 `.dict()` deprecation. **Resolved:** Migrated to `.model_dump()`. |
| D6 | **Low** | `explainer.py:25-59` | Baseline feature names mismatch. **Resolved:** Aligned with `ThreatClassifier.FEATURE_NAMES`. |
| D7 | **Low** | `main.py:490` | Deprecated `@app.on_event("startup")`. **Resolved:** Migrated to FastAPI `lifespan` context manager. |

### 1.2 Items Verified as Correct

- No fabricated predictions: outputs are genuine RF classifier results.
- Confidence values correctly documented as tree-vote consensus.
- FPR correctly reported as `None` for unlabelled live streams.
- SMOTE applied only within training fold — no test leakage.
- 80/20 stratified split performed before any fitting.
- SHA-256 fingerprint deduplication is deterministic and windowed.
- Alternative hypotheses present and grounded for all incident types.
- 15-dimensional feature vector matches classifier N_FEATURES assertion.
- Provenance (source_file, is_synthetic) propagated through alerts to incidents.

### 1.3 Missing Capabilities

| Phase | Gap |
|-------|-----|
| Phase 4 | No ablation: Classifier vs +Anomaly vs +Correlation vs +Prioritization |
| Phase 4 | No alert-volume reduction metric at fixed recall |
| Phase 4 | No duplicate-alert reduction metric |
| Phase 5 | No CIC-IDS2017 loader or compatibility documentation |
| Phase 7 | Missing tests: shared entities across independent incidents, overlapping windows |

---

## 2. Research Question

**Can temporal incident correlation and evidence-based prioritization reduce analyst alert workload without sacrificing detection coverage?**

Evaluated by comparing alert volume at a fixed recall threshold (>= 0.85) across four pipeline configurations on the same holdout test partition.

---

## 3. Implementation Plan

### Sub-Phase A: Critical Fixes

**D1** — Fix label extraction in `train_pipeline`: prefer `attack_type`; fallback to `DATASET_LABEL_MAP[raw_label]`.
**D2** — Rebuild `LocalFeatureExplainer` DEFAULT_NORMAL_MEANS/STDS to use `ThreatClassifier.FEATURE_NAMES` keys.
**D3** — Migrate `on_event("startup")` to FastAPI lifespan context manager.
**D4** — Tighten correlation Rule 2: require entity overlap AND (same threat_type OR kill-chain progression).
**D5/D6** — Replace `.dict()` with `.model_dump()` everywhere.

### Sub-Phase B: Evaluation Framework

Create `backend/evaluation/ablation_study.py` running 4 pipeline configs on the holdout set.

Metrics: Precision, Recall, macro-F1, weighted-F1, FPR, alert volume at Recall>=0.85, duplicate reduction rate, latency.

### Sub-Phase C: CIC-IDS2017 Compatibility

Create `backend/ingestion/cicids_loader.py` with column mapping, label normalization, and Inf/NaN handling.
Create `docs/CICIDS2017_IMPORT.md` with download/placement instructions.
Implement small synthetic fixture for unit testing without the real dataset.

### Sub-Phase D: Additional Tests

- `test_shared_entity_independent_incidents`
- `test_overlapping_incident_windows`
- `test_duplicate_evidence_not_double_counted`
- `test_explainer_feature_names_aligned`

---

## 4. Evaluation Data and Methodology

| Property | Value |
|----------|-------|
| Dataset | `data/raw/combined_labeled.jsonl` (synthetic) |
| Total records | 7,051 |
| Label distribution | benign=2051, brute_force=3000, data_exfiltration=1320, c2_beaconing=345, lateral_movement=335 |
| Split | 80/20 stratified holdout — split before fitting |
| Random seed | 42 |
| Primary metric | Macro F1 (avoids brute_force class dominance) |

### Limitations

- Synthetic dataset: real-world generalization is unconfirmed.
- CIC-IDS2017 results must be kept separate from synthetic results.
- Incident correlation recall requires ground-truth clusters — unavailable; estimated via label+proximity heuristics, clearly documented.

### Reproduction Commands

```bash
python3 -m backend.detection.model_trainer train
python3 -m backend.evaluation.ablation_study
python3 -m pytest tests/ -v
```

---

## 5. Dashboard Trustworthiness Checklist

- [x] FPR displayed as N/A for unlabelled live streams
- [x] Classifier probability labeled as "RF Tree Consensus"
- [x] Anomaly score and incident priority are separate fields
- [x] Synthetic data carries is_synthetic provenance badge
- [x] Alternative benign hypotheses displayed per incident
- [x] Isolation action labeled "Simulated — in-memory stream filter; no live firewall enforcement"
- [x] Feature explanation clarified as "Local Feature Contribution & Baseline Deviations"
- [x] FastAPI lifespan context manager migrated (deprecated on_event removed)

---

## 6. Ablation Experiment Benchmark Findings (Decoupled Tasks)

Reproduced via `python3 -m backend.evaluation.ablation_study`:
- **Holdout Test Set**: 1,411 samples (80/20 stratified holdout, seed=42)
- **Task A (Event Classification)**:
  - **Config A (Classifier Only)**: Macro F1 = 0.9823, Weighted F1 = 0.9957, FPR = 0.00%, Raw Alerts = 1,000.
  - **Config B (+ Anomaly Detection)**: Macro F1 = 0.9823, Weighted F1 = 0.9957, FPR = 0.00%, Raw Alerts = 1,000 (anomaly detector contributes 0 additions because RF has zero false negatives on scripted synthetic holdout).
- **Task E (Operational Triage & Correlation)**:
  - **Config C (+ Incident Correlation & Deduplication)**: Attack Recall = 100.0%, 1,000 raw alert events deduplicated to 876 retained alerts, forming 52 incident dossiers (**94.8% triage compression**). Decoupled from event-level classification metrics to avoid false-negative penalties for suppressed duplicates.
  - **Config D (+ Priority Queue Top-20)**: Focuses analyst queue on highest-severity threats first; captures critical multi-stage incidents while deferring lower-risk alerts.

---

## 7. Phase 9: Leakage-Resistant Evaluation and 12-Scenario Correlation Benchmark

### 7.1 Leakage-Resistant Holdout Analysis
- **Exact & Near-Duplicate Analysis**: 3,469 out of 7,051 records (49.2%) belong to duplicate feature fingerprint clusters.
- **Stratified Baseline Overlap**: 48.6% duplicate overlap across train and test partitions.
- **Group-Aware Holdout**:
  - Grouping strategy: Deterministic SHA-256 fingerprint of the 15-dimensional numeric feature vector.
  - Partitions: Train = 5,651 events, Test = 1,400 events. **Duplicate group overlap = 0.0%**.
  - Performance: **Balanced Accuracy = 0.9317**, **Macro-F1 = 0.8591**, **Weighted-F1 = 0.9251**, **Benign FPR = 0.0073 (1/137)**.
  - Key finding: Drop in Macro-F1 from 0.9823 to 0.8591 demonstrates that stratified random splits overstate generalization due to duplicate feature repetition; group-aware holdout provides a defensible evaluation.
- **Chronological Split Limitations**: Scripted synthetic dataset `combined_labeled.jsonl` contains 2,051 benign events all emitted before 11:28. A chronological 80/20 partition leaves zero benign records in the test split, rendering Benign False Positive Rate mathematically undefined.

### 7.2 Controlled Correlation Benchmark Results (12 Fixtures)
Evaluated across 12 standardized test fixtures (`backend/evaluation/correlation_benchmark.py`):
- **Fixtures Evaluated**:
  1. Multi-Stage APT: Reconnaissance $\rightarrow$ Lateral Movement $\rightarrow$ Exfiltration (Single Actor)
  2. Multiple Independent Attackers Targeting Common Victim Server
  3. Replayed / Duplicate Alert Flood Invariance
  4. Legitimate Administrative Maintenance Activity
  5. Out-of-Order Delayed Telemetry Handling
  6. Concurrent Independent Incident Campaigns
  7. Incomplete Telemetry Missing Timestamps
  8. One Attacker Scanning Multiple Victims (Sweep)
  9. Unrelated Events Sharing Destination (Target Server)
  10. False Pivot Rejection (Disjoint Attack Steps)
  11. Ambiguous Sequences Across Disjoint Entity Pairs
  12. Events with Missing Entity Identifiers
- **Benchmark Metrics**:
  - **Pairwise Cluster Precision**: 1.0000 (0 unrelated events erroneously merged)
  - **Pairwise Cluster Recall**: 1.0000 (0 related events fragmented)
  - **Pairwise Cluster F1**: 1.0000
  - **Merge Errors (Unrelated Merged)**: 0
  - **Split Errors (Related Fragmented)**: 0
  - **Evidence Traceability**: 100.0% of supporting event references preserved
  - **Duplicate Risk Invariance**: Verified True (repeated duplicate floods do not inflate incident priority)

### 7.3 Evidence-Aware Incident Architecture & Graph Differentiation
- **Data Model**: `Incident` schema exposes `matched_rules`, `relationship_evidence`, `observed_facts`, `inferred_hypotheses`, `alternative_explanations`, `missing_evidence`, `uncertainty_notes`, and formulaic `priority_calculation_breakdown`.
- **Frontend Evidence Navigation**: Interactive relationship evidence table in `frontend/src/components/Dashboard/IncidentCard.jsx` allows analysts to click "Inspect Event {id}" and jump directly to the underlying raw telemetry records with clear uncertainty disclosures.

---

## 8. Remaining Risks and Limitations

1. **Synthetic overfitting** — Primary benchmark relies on scripted attack scenarios (`data/raw/combined_labeled.jsonl`); real-world generalization requires external benchmark validation.
2. **External benchmark evaluation** — CIC-IDS2017 loader implemented (`backend/ingestion/cicids_loader.py`), but evaluation on full multi-gigabyte PCAP/CSV requires local download by user per `docs/CICIDS2017_IMPORT.md`.
3. **Correlation Ground Truth** — Real-world enterprise datasets with authoritative multi-stage incident boundaries remain scarce; fixture evaluation proves algorithmic correctness under defined operational assumptions.
4. **Isolation is simulated** — Network isolation blocks entities in the in-memory stream filter; production deployment requires integration with iptables, EDR agents, or SDN controllers.

---

## 9. Full Reproduction Suite

```bash
# 1. Run all unit and regression tests (51 tests)
python3 -m pytest tests/ -v --tb=short

# 2. Run independent correlation quality benchmark (12 fixtures)
python3 -m backend.evaluation.correlation_benchmark

# 3. Run leakage-resistant ablation study & holdout comparisons
python3 -m backend.evaluation.ablation_study

# 4. Build production frontend bundle
cd frontend && npm run build
```
