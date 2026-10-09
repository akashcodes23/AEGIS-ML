"""AEGIS-ML Phase 17: Scenario-Aware Synthetic Generation and Evaluation Tests.

Validates:
1. Scenario ID population and uniqueness across generated events.
2. Events originating from the same scenario share the identical scenario_id.
3. Deterministic dataset generation with fixed seed.
4. Scenario-group isolation: 0.0% scenario overlap between train and test partitions.
5. Provenance metadata strictly excluded from predictive model features.
6. Class distribution and label validity across partitions.
7. Metric reconstruction directly from saved prediction arrays.
8. Explicit handling of insufficient scenario counts per class.
9. Canonical duplicate-aware benchmark remains completely preserved and unchanged.
"""

from collections import Counter
import json
from pathlib import Path
from typing import List
import numpy as np
import pytest
from sklearn.metrics import confusion_matrix, f1_score, balanced_accuracy_score

from backend.core.schemas import UnifiedEvent
from backend.detection.model_trainer import (
    load_flexible_dataset,
    CANONICAL_CLASSES,
)
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.temporal_graph_extractor import RELATIONAL_GRAPH_FEATURE_NAMES
from backend.data_generator.attack_scenarios import (
    generate_data_exfiltration,
    generate_brute_force_attack,
    generate_c2_beaconing,
)
from backend.data_generator.orchestrator import DataOrchestrator
from backend.evaluation.scenario_evaluation import (
    partition_scenario_grouped_split,
    PROHIBITED_FEATURE_FIELDS,
    SCENARIO_DATASET_REL_PATH,
    OUTPUT_ARTIFACT_REL_PATH,
    CANONICAL_ARTIFACT_REL_PATH,
    compute_file_sha256,
)


@pytest.fixture(scope="module")
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def scenario_dataset_path(repo_root) -> Path:
    return repo_root / SCENARIO_DATASET_REL_PATH


@pytest.fixture(scope="module")
def scenario_artifact_path(repo_root) -> Path:
    return repo_root / OUTPUT_ARTIFACT_REL_PATH


@pytest.fixture(scope="module")
def canonical_artifact_path(repo_root) -> Path:
    return repo_root / CANONICAL_ARTIFACT_REL_PATH


@pytest.fixture(scope="module")
def canonical_dataset_path(repo_root) -> Path:
    return repo_root / "data" / "raw" / "combined_labeled.jsonl"


# =========================================================================
# 1. Scenario ID Population and Uniqueness
# =========================================================================

def test_scenario_id_population_and_uniqueness(scenario_dataset_path):
    """Every generated event in the scenario dataset must have valid scenario provenance."""
    assert scenario_dataset_path.exists(), f"Scenario dataset not found at {scenario_dataset_path}"

    events, _ = load_flexible_dataset(str(scenario_dataset_path))
    assert len(events) > 5000, f"Expected > 5000 events, got {len(events)}"

    scenario_ids = set()
    for e in events:
        assert e.scenario_id is not None and e.scenario_id != "", f"Event {e.event_id} missing scenario_id"
        assert e.scenario_type is not None and e.scenario_type != "", f"Event {e.event_id} missing scenario_type"
        assert e.generator_version == "2.0.0", f"Event {e.event_id} has wrong generator_version: {e.generator_version}"
        scenario_ids.add(e.scenario_id)

    # Must contain multiple distinct scenarios
    assert len(scenario_ids) >= 50, f"Expected >= 50 scenarios, found {len(scenario_ids)}"


# =========================================================================
# 2. Events from the Same Scenario Retain the Same ID
# =========================================================================

def test_events_from_same_scenario_share_id():
    """All events generated in a scenario instance must share the identical scenario_id."""
    from datetime import datetime

    start = datetime(2026, 10, 10, 12, 0, 0)
    sc_id = "test_exfil_scenario_999"

    exfil_events = generate_data_exfiltration(start, scenario_id=sc_id)
    assert len(exfil_events) == 132  # 120 network + 12 endpoint
    for e in exfil_events:
        assert e.scenario_id == sc_id, f"Event {e.event_id} does not have scenario_id {sc_id}"
        assert e.scenario_type == "data_exfiltration"

    # Distinct scenarios must receive distinct IDs
    other_id = "test_bf_scenario_888"
    bf_events = generate_brute_force_attack(start, scenario_id=other_id)
    for e in bf_events:
        assert e.scenario_id == other_id
        assert e.scenario_type == "brute_force"


# =========================================================================
# 3. Deterministic Dataset Generation
# =========================================================================

def test_deterministic_dataset_generation(tmp_path):
    """Generation with a fixed seed must produce identical events and SHA-256 hash."""
    out1 = tmp_path / "test_gen1.jsonl"
    out2 = tmp_path / "test_gen2.jsonl"

    orch = DataOrchestrator()
    s1 = orch.generate_scenario_dataset(
        output_path=str(out1),
        seed=1337,
        bf_scenarios=2,
        c2_scenarios=5,
        lm_scenarios=3,
        exfil_scenarios=2,
        fp_scenarios=1,
        benign_sessions=5,
        benign_events_per_session=20,
    )
    s2 = orch.generate_scenario_dataset(
        output_path=str(out2),
        seed=1337,
        bf_scenarios=2,
        c2_scenarios=5,
        lm_scenarios=3,
        exfil_scenarios=2,
        fp_scenarios=1,
        benign_sessions=5,
        benign_events_per_session=20,
    )

    assert s1["sha256"] == s2["sha256"], "Fixed-seed dataset generation must be byte-for-byte deterministic"
    assert s1["total_events"] == s2["total_events"]
    assert s1["total_scenarios"] == s2["total_scenarios"]


# =========================================================================
# 4. Scenario-Group Isolation Across Train and Test
# =========================================================================

def test_scenario_group_isolation(scenario_dataset_path):
    """Zero scenario_id overlap is permitted between train and test partitions."""
    events, _ = load_flexible_dataset(str(scenario_dataset_path))
    labels = [e.attack_type or "benign" for e in events]

    tr_idx, te_idx, stats = partition_scenario_grouped_split(events, labels, test_ratio=0.20, seed=42)

    train_scenarios = {events[i].scenario_id for i in tr_idx}
    test_scenarios = {events[i].scenario_id for i in te_idx}

    overlap = train_scenarios.intersection(test_scenarios)
    assert len(overlap) == 0, f"Scenario isolation violated: found {len(overlap)} overlapping scenarios!"
    assert stats["scenario_overlap_count"] == 0
    assert len(train_scenarios) > 0
    assert len(test_scenarios) > 0


# =========================================================================
# 5. Provenance Metadata Excluded from Predictive Features
# =========================================================================

def test_provenance_metadata_excluded_from_predictive_features():
    """Verify scenario_id, campaign_id, and other provenance fields are prohibited from feature schema."""
    feature_names = ThreatClassifier.FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES
    assert len(feature_names) == 21

    for prohibited in PROHIBITED_FEATURE_FIELDS:
        assert prohibited not in feature_names, (
            f"CRITICAL: Prohibited provenance field '{prohibited}' found in model feature names!"
        )


# =========================================================================
# 6. Class Distribution and Label Validation
# =========================================================================

def test_class_distribution_and_labels(scenario_artifact_path):
    """Validate class distribution and check that all classes are canonical."""
    with open(scenario_artifact_path, "r", encoding="utf-8") as f:
        art = json.load(f)

    train_dist = art["split_methodology"]["class_distribution_train"]
    test_dist = art["split_methodology"]["class_distribution_test"]

    for c in CANONICAL_CLASSES:
        assert c in train_dist, f"Class '{c}' missing from training partition"
        assert c in test_dist, f"Class '{c}' missing from test partition"
        assert train_dist[c] > 0
        assert test_dist[c] > 0


# =========================================================================
# 7. Metric Reconstruction from Prediction Arrays
# =========================================================================

def test_metric_reconstruction_from_arrays(scenario_artifact_path):
    """Reconstruct confusion matrix, macro-F1, balanced accuracy directly from saved arrays."""
    with open(scenario_artifact_path, "r", encoding="utf-8") as f:
        art = json.load(f)

    y_true = np.array(art["instance_level_data"]["ground_truth_labels"])
    y_pred = np.array(art["instance_level_data"]["predicted_labels"])
    classes = art["evaluation_results"]["canonical_class_order"]

    assert len(y_true) == len(y_pred)
    assert len(y_true) == art["split_methodology"]["test_samples"]

    # Reconstruct confusion matrix
    cm_calc = confusion_matrix(y_true, y_pred, labels=classes).tolist()
    cm_saved = art["evaluation_results"]["confusion_matrix"]
    assert cm_calc == cm_saved, "Reconstructed confusion matrix does not match saved matrix"

    # Reconstruct Macro-F1
    macro_f1_calc = round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4)
    macro_f1_saved = art["evaluation_results"]["macro_f1"]
    assert macro_f1_calc == macro_f1_saved, f"Macro-F1 mismatch: calc {macro_f1_calc} vs saved {macro_f1_saved}"

    # Reconstruct Balanced Accuracy
    bal_acc_calc = round(float(balanced_accuracy_score(y_true, y_pred)), 4)
    bal_acc_saved = art["evaluation_results"]["balanced_accuracy"]
    assert bal_acc_calc == bal_acc_saved, f"Balanced accuracy mismatch: calc {bal_acc_calc} vs saved {bal_acc_saved}"


# =========================================================================
# 8. Insufficient Scenario Counts Handled Explicitly
# =========================================================================

def test_insufficient_scenario_counts_handled_explicitly():
    """Verify that classes with only 1 scenario are kept in train and flagged in warnings."""
    from datetime import datetime

    events = [
        UnifiedEvent(
            event_id="e1",
            timestamp=datetime.now(),
            layer="network",
            src_entity="10.0.0.1",
            dst_entity="10.0.0.2",
            src_internal=True,
            dst_internal=True,
            scenario_id="sc_rare_001",
            scenario_type="rare_exploit",
            raw_label="malicious",
            attack_type="lateral_movement",
        ),
        UnifiedEvent(
            event_id="e2",
            timestamp=datetime.now(),
            layer="network",
            src_entity="10.0.0.1",
            dst_entity="10.0.0.2",
            src_internal=True,
            dst_internal=True,
            scenario_id="sc_rare_001",
            scenario_type="rare_exploit",
            raw_label="malicious",
            attack_type="lateral_movement",
        ),
    ]
    labels = ["lateral_movement", "lateral_movement"]

    tr_idx, te_idx, stats = partition_scenario_grouped_split(events, labels, test_ratio=0.20, seed=42)

    # Rare scenario must be placed into train rather than failing or vanishing
    assert len(tr_idx) == 2
    assert len(te_idx) == 0
    assert "lateral_movement" in stats["insufficient_scenario_warnings"]


# =========================================================================
# 9. Existing Canonical Benchmark Remains Unchanged
# =========================================================================

def test_canonical_benchmark_preservation(canonical_artifact_path, canonical_dataset_path):
    """The canonical duplicate-aware benchmark reference artifact and raw dataset must remain intact."""
    assert canonical_dataset_path.exists(), "Canonical combined_labeled.jsonl missing!"
    assert canonical_artifact_path.exists(), "Canonical evaluation artifact missing!"

    # Verify canonical dataset SHA-256
    sha256 = compute_file_sha256(canonical_dataset_path)
    assert sha256 == "25f2bf6889a563fcc220be23c709294f151be4693a8108052391c1ce594bf7f7"

    # Verify canonical artifact metrics
    with open(canonical_artifact_path, "r", encoding="utf-8") as f:
        can_art = json.load(f)

    assert can_art["metadata"]["total_records"] == 7051
    assert can_art["metadata"]["train_samples"] == 5651
    assert can_art["metadata"]["test_samples"] == 1400
    assert can_art["evaluation_results"]["macro_f1"] == 0.8685
    assert can_art["evaluation_results"]["balanced_accuracy"] == 0.9317
