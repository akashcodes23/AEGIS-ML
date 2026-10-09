# AEGIS-ML Phase 17: Scenario-Aware Synthetic Data Generation and Evaluation

**Status Summary:**
- **Task 1: Generator Inspection & Provenance Mapping:** `COMPLETED`
- **Task 2: Stable Scenario Provenance Integration:** `COMPLETED`
- **Task 3: Deterministic Generation & Dataset Versioning:** `COMPLETED`
- **Task 4: Scenario-Grouped Evaluation Protocol:** `COMPLETED`
- **Task 5: Canonical Duplicate-Aware Benchmark Preservation:** `COMPLETED`
- **Task 6: Exfiltration Staging Relationship Investigation:** `COMPLETED`
- **Task 7: Automated Test Suite (9 tests):** `COMPLETED`
- **Scenario-Level Generalization on Synthetic Campaigns:** `COMPLETED_ON_SYNTHETIC_SCENARIO_HOLDOUT`
- **Real-World / Production Generalization:** `NOT_ESTABLISHED` (Controlled synthetic benchmark)

---

## 1. Executive Summary

Phase 17 resolved the foundational dataset provenance deficit discovered in Phase 16 by introducing **explicit, stable scenario provenance** directly into the synthetic data generator ([backend/data_generator/orchestrator.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/data_generator/orchestrator.py), [attack_scenarios.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/data_generator/attack_scenarios.py)) and establishing a reproducible **scenario-grouped evaluation protocol** ([backend/evaluation/scenario_evaluation.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/evaluation/scenario_evaluation.py)).

### Key Accomplishments:
1. **Explicit Scenario Provenance**: Every generated event now possesses three immutable provenance metadata fields:
   - `scenario_id`: A persistent UUID/tag shared by all events belonging to the same attack campaign or benign session.
   - `scenario_type`: Descriptive identity (`brute_force`, `c2_beaconing`, `lateral_movement`, `data_exfiltration`, `false_positive_backup`, `benign_traffic`).
   - `generator_version`: Semantic generator version (`2.0.0`).
2. **Byte-for-Byte Determinism**: Using seed-conditioned RFC 4122 `uuid.uuid5` identifiers and `random.Random(seed)` instances, dataset generation is 100% deterministic (`SHA256: 56fca1bea5b0c26b4fadde20218035aac530eb42a25ddfd8a8408d501a40e9d5`).
3. **Preservation of Canonical Benchmark**: The existing 7,051-event canonical dataset (`data/raw/combined_labeled.jsonl`) and its 1,400-event duplicate-aware holdout (`data/models/canonical_evaluation_artifact.json`) were preserved completely intact as an immutable reference baseline.
4. **Scenario-Grouped Evaluation Protocol**: 81 distinct scenarios (7,361 events) were partitioned strictly by scenario ID (65 train scenarios, 16 test scenarios) guaranteeing **0.0% scenario overlap**.
5. **Faithful Representation of Exfiltration Staging**: Verified that local file reads (`7z.exe`) and subsequent network transfers originate from the same exfiltration scenario and receive the identical `scenario_id`, without fabricating synthetic socket links or altering ground truth labels.

---

## 2. Generator Architecture & Schema Modifications

### Schema Update ([backend/core/schemas.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/core/schemas.py))
The `UnifiedEvent` model was expanded with three optional provenance attributes:
```python
class UnifiedEvent(BaseModel):
    # Core event attributes ...
    
    # Scenario provenance metadata (Phase 17)
    scenario_id: Optional[str] = None
    scenario_type: Optional[str] = None
    generator_version: Optional[str] = None
```
*Backward Compatibility Note*: All fields default to `None`, preserving 100% backward compatibility with legacy datasets, ingestion pipelines, and REST API payloads.

### Generator Functions ([backend/data_generator/attack_scenarios.py](file:///Users/akashgpatil/major_project/AEGIS-ML/backend/data_generator/attack_scenarios.py))
All scenario generator functions accept `scenario_id: Optional[str] = None`, `generator_version: str = "2.0.0"`, and `rng: Optional[random.Random] = None`:
- `generate_brute_force_attack(...)`
- `generate_c2_beaconing(...)`
- `generate_lateral_movement(...)`
- `generate_false_positive(...)`
- `generate_benign_traffic(...)`
- `generate_data_exfiltration(...)`

When generating events, `generate_event_uuid(scenario_id, event_idx, rng)` generates deterministic, collision-resistant UUIDs using `uuid.uuid5(uuid.NAMESPACE_DNS, f"{scenario_id}_{event_idx}")`.

---

## 3. Dataset Generation & Reproducibility Audit

Audited File: `data/raw/scenario_aware_labeled.jsonl`  
Dataset SHA-256: `56fca1bea5b0c26b4fadde20218035aac530eb42a25ddfd8a8408d501a40e9d5`  
Total Records: **7,361**  
Total Scenarios: **81**

### Scenario Population & Distribution:
| Scenario Type | Unique Scenarios | Total Events | Events per Scenario (Avg) | Target Attack Class |
| :--- | :---: | :---: | :---: | :--- |
| `brute_force` | 5 | 3,292 | ~658 | `brute_force` |
| `c2_beaconing` | 30 | 345 | ~11.5 | `c2_beaconing` |
| `lateral_movement` | 15 | 353 | ~23.5 | `lateral_movement` |
| `data_exfiltration`| 10 | 1,320 | 132 | `data_exfiltration` |
| `false_positive_backup` | 1 | 51 | 51 | `benign` |
| `benign_traffic` | 20 | 2,000 | 100 | `benign` |
| **Total** | **81** | **7,361** | **90.9** | — |

### Provenance Population Rates:
- `scenario_id`: **100.0% (7,361 / 7,361)**
- `scenario_type`: **100.0% (7,361 / 7,361)**
- `generator_version`: **100.0% (7,361 / 7,361)**

---

## 4. Scenario-Grouped Evaluation Protocol

### Split Methodology:
1. **Grouping**: Events are grouped strictly by `scenario_id`.
2. **Stratified Holdout**: Scenarios are allocated to train (80%) or test (20%) per class:
   - `brute_force`: 4 train, 1 test
   - `c2_beaconing`: 24 train, 6 test
   - `lateral_movement`: 12 train, 3 test
   - `data_exfiltration`: 8 train, 2 test
   - `benign`: 17 train, 4 test (1 false positive backup + 16 benign traffic in train; 4 benign traffic in test)
3. **Partition Verification**:
   - Total Scenarios: **81**
   - Train Scenarios: **65 (80.2%)**
   - Test Scenarios: **16 (19.8%)**
   - **Cross-Partition Scenario Overlap**: **0.0% (0 scenarios)**

### Partition Sample Sizes & Class Distribution:
| Class | Total Events | Train Partition ($N_{tr}=5,680$) | Test Partition ($N_{te}=1,681$) | Test Proportion (%) |
| :--- | :---: | :---: | :---: | :---: |
| `brute_force` | 3,292 | 2,412 | 880 | 26.73% |
| `benign` | 2,051 | 1,651 | 400 | 19.50% |
| `data_exfiltration`| 1,320 | 1,056 | 264 | 20.00% |
| `lateral_movement` | 353 | 284 | 69 | 19.55% |
| `c2_beaconing` | 345 | 277 | 68 | 19.71% |
| **Total** | **7,361** | **5,680** | **1,681** | **22.84%** |

---

## 5. Preprocessing & Leakage Protection

1. **Strict Preprocessor Isolation**:
   - `BehavioralBaselineProfiler`: Fitted strictly on `tr_events` (benign events only).
   - `IsolationForestDetector`: Fitted strictly on `tr_events`.
   - `calculate_failed_auth_rate`: Calculated separately for train and test partitions.
   - `CausalTemporalGraphTracker`: Fitted and extracted forward in time without cross-partition relational leakage.
2. **Prohibited Feature Audit**:
   The following metadata and ground truth attributes were audited and verified **100% absent** from the 21 model features:
   `["scenario_id", "scenario_type", "generator_version", "event_id", "raw_label", "attack_type", "campaign_id", "template_id"]`.
3. **SMOTE Oversampling Isolation**:
   `SMOTE(k_neighbors=4)` was applied strictly to the training matrix `(X_tr_c, y_tr)` to address class imbalance. The test partition `(X_te_c, y_te)` was evaluated entirely in its natural, untransformed state.

---

## 6. Evaluation Results: Scenario-Grouped Benchmark

Evaluated on held-out test scenarios ($N_{test} = 1,681$ events across 16 unseen scenarios):

### Confusion Matrix:
$$\begin{pmatrix} 383 & 12 & 5 & 0 & 0 \\ 0 & 880 & 0 & 0 & 0 \\ 0 & 0 & 69 & 0 & 0 \\ 0 & 0 & 0 & 264 & 0 \\ 0 & 0 & 5 & 0 & 63 \end{pmatrix}$$

*(Row: Actual Class, Column: Predicted Class. Order: `[benign, brute_force, lateral_movement, data_exfiltration, c2_beaconing]`)*

### Per-Class Performance:
| Class Label | Precision | Recall | F1-Score | Support (Events) | Held-Out Scenarios |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `benign` | 1.0000 | 0.9575 | 0.9783 | 400 | 4 sessions |
| `brute_force` | 0.9865 | 1.0000 | 0.9932 | 880 | 1 scenario |
| `lateral_movement` | 0.8734 | 1.0000 | 0.9324 | 69 | 3 scenarios |
| `data_exfiltration`| 1.0000 | 1.0000 | 1.0000 | 264 | 2 scenarios |
| `c2_beaconing` | 1.0000 | 0.9265 | 0.9618 | 68 | 6 scenarios |

### Global Aggregate Metrics:
- **Macro-F1**: **0.9732**
- **Weighted-F1**: **0.9870**
- **Balanced Accuracy**: **0.9768**
- **Multiclass Benign FPR**: **0.0000** ($0 / 1,281$)
- **Benign FNR (False Alarm Rate on Benign Traffic)**: **0.0425** ($17 / 400$)

---

## 7. Comparative Analysis: Scenario-Grouped vs Canonical Duplicate-Aware Holdout

| Metric / Attribute | Canonical Benchmark (Phase 15/16) | Scenario-Aware Benchmark (Phase 17) | Scientific Interpretation |
| :--- | :---: | :---: | :--- |
| **Dataset File** | `combined_labeled.jsonl` | `scenario_aware_labeled.jsonl` | Versioned dataset added; canonical preserved |
| **Total Records** | 7,051 | 7,361 | Both ~7,000 events |
| **Split Strategy** | Group-aware payload fingerprints | Scenario-grouped stratified holdout | Fingerprint clustering vs Campaign-level isolation |
| **Grouping Unit** | 11-field payload tuple | `scenario_id` | Exact duplicate suppression vs Campaign boundary |
| **Unique Groups** | 3,687 fingerprint groups | 81 scenario instances | High granularity vs Campaign granularity |
| **Test Set Size** | 1,400 events | 1,681 events | ~20% of dataset held out |
| **Macro-F1** | 0.8685 | 0.9732 | Improved scenario cohesion and graph tracking |
| **Balanced Accuracy** | 0.9317 | 0.9768 | High sensitivity across all attack classes |
| **Benign FPR** | 0.0000 (0 / 990) | 0.0000 (0 / 1,281) | 0.0% attacks classified as benign in both |
| **Binary False Alarms**| 0.0073 (3 / 410) | 0.0425 (17 / 400) | Moderate false alarm rate on unseen benign sessions |
| **Generalization Scope**| Intra-template duplicate isolation | Inter-scenario campaign holdout | Rigorous test of campaign-level generalization |

---

## 8. Investigation of Exfiltration Staging

### Observation:
In Phase 16, 120 endpoint file reads (`7z.exe`) in `combined_labeled.jsonl` were misclassified because they were unlinked from network exfiltration flows.

### Investigation Finding in Phase 17:
1. In `attack_scenarios.py`, every exfiltration scenario produces both network egress transfers and endpoint compression events (`7z.exe`).
2. With Phase 17's provenance integration, both types of events now share the **exact same `scenario_id`** (e.g. `scenario_exfil_001`).
3. In the scenario-aware split, entire exfiltration scenarios are assigned to either train or test:
   - When `scenario_exfil_000` is in train, its endpoint reads AND its network flows are in train.
   - When `scenario_exfil_001` is in test, its endpoint reads AND its network flows are in test.
4. **Result**: In the scenario-aware evaluation, `data_exfiltration` achieved **100.0% recall and 100.0% precision** across all 264 test events (including both network transfers and endpoint staging reads), because the relational graph and baseline features learned the complete campaign footprint.

---

## 9. Limitations & Next Steps

1. **Synthetic Diversity Limitation**: Although 81 distinct scenarios are generated, they are produced from synthetic parametric templates. Real-world adversary variation (e.g., zero-day tooling, polymorphic protocols) remains beyond the scope of synthetic generation.
2. **External Dataset Benchmarking**: Public datasets (CIC-IDS2017) should be imported to test out-of-domain cross-network generalization.
3. **Endpoint Socket Instrumentation**: Future phases should introduce OS socket table emulation linking endpoint PIDs directly to 5-tuple network flows.
