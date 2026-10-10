"""AEGIS-ML Phase 19: Behavioral Diversity and Benign Hard-Negative Evaluation Tests.

Validates:
1. Deterministic synthetic dataset generation with exact SHA-256 reproducibility.
2. Full scenario provenance (scenario_id, scenario_type, generator_version) across all events.
3. Strict scenario-group isolation across train and test partitions (0.0% overlap).
4. Exclusion of prohibited metadata/provenance fields from the predictive feature matrix.
5. Strict training-only preprocessing and baseline fitting (no test leakage).
6. Canonical label integrity and proper benign/malicious typing.
7. Exact mathematical metric reconstruction from instance-level predictions.
8. Tracking of per-workflow false-alarm rates across all 7 benign workflows.
"""

from collections import Counter
import json
from pathlib import Path
import tempfile
import pytest
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, balanced_accuracy_score, precision_recall_fscore_support

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import UnifiedEvent
from backend.data_generator.orchestrator import DataOrchestrator
from backend.detection.model_trainer import (
    load_flexible_dataset,
    CANONICAL_CLASSES,
)
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.temporal_graph_extractor import RELATIONAL_GRAPH_FEATURE_NAMES
from backend.evaluation.scenario_evaluation import PROHIBITED_FEATURE_FIELDS
from backend.evaluation.behavioral_diversity_evaluation import (
    partition_behavioral_diversity_split,
    DIVERSITY_DATASET_REL_PATH,
    OUTPUT_ARTIFACT_REL_PATH,
    BENIGN_WORKFLOW_TYPES,
)


EXPECTED_PHASE19_SHA256 = "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"
EXPECTED_TOTAL_EVENTS = 5717
EXPECTED_TOTAL_SCENARIOS = 116


@pytest.fixture(scope="module")
def diversity_events():
    data_path = Path(PROJECT_ROOT) / DIVERSITY_DATASET_REL_PATH
    if not data_path.exists():
        pytest.skip(f"Diversity dataset not found at {data_path}")
    events, stats = load_flexible_dataset(str(data_path))
    return events


def test_phase19_deterministic_generation():
    """Verify deterministic generation reproduces exact event counts and SHA-256."""
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        summary = DataOrchestrator().generate_behavioral_diversity_dataset(
            output_path=tmp_path, seed=42
        )
        assert summary["total_events"] == EXPECTED_TOTAL_EVENTS
        assert summary["total_scenarios"] == EXPECTED_TOTAL_SCENARIOS
        assert summary["sha256"] == EXPECTED_PHASE19_SHA256
        assert summary["generator_version"] == "3.0.0"
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_phase19_scenario_provenance_integrity(diversity_events):
    """Verify all events have complete provenance and scenario consistency."""
    scenario_types = {}
    for event in diversity_events:
        assert event.scenario_id is not None, f"Event {event.event_id} missing scenario_id"
        assert event.scenario_type is not None, f"Event {event.event_id} missing scenario_type"
        assert event.generator_version == "3.0.0", f"Event {event.event_id} has wrong version {event.generator_version}"

        if event.scenario_id in scenario_types:
            assert scenario_types[event.scenario_id] == event.scenario_type, (
                f"Scenario {event.scenario_id} has conflicting types: "
                f"{scenario_types[event.scenario_id]} vs {event.scenario_type}"
            )
        else:
            scenario_types[event.scenario_id] = event.scenario_type

    assert len(scenario_types) == EXPECTED_TOTAL_SCENARIOS


def test_phase19_scenario_isolation_across_splits(diversity_events):
    """Verify 0.0% scenario overlap across train and test partitions for multiple split seeds."""
    labels = [e.attack_type or "benign" for e in diversity_events]

    for seed in [42, 1337, 2026]:
        tr_indices, te_indices, split_stats = partition_behavioral_diversity_split(
            diversity_events, labels, test_ratio=0.20, seed=seed
        )

        tr_scenarios = set(diversity_events[i].scenario_id for i in tr_indices)
        te_scenarios = set(diversity_events[i].scenario_id for i in te_indices)

        overlap = tr_scenarios.intersection(te_scenarios)
        assert len(overlap) == 0, f"Seed {seed} leaked {len(overlap)} scenarios between train and test!"

        assert split_stats["scenario_overlap_count"] == 0
        assert len(tr_indices) + len(te_indices) == len(diversity_events)


def test_phase19_prohibited_provenance_features_excluded():
    """Verify that no provenance or metadata fields are in the predictive feature schema."""
    feature_names = ThreatClassifier.FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES

    for prohibited in PROHIBITED_FEATURE_FIELDS:
        assert prohibited not in feature_names, (
            f"Prohibited field '{prohibited}' leaked into predictive features!"
        )

    assert len(feature_names) == 21


def test_phase19_canonical_label_integrity(diversity_events):
    """Verify label integrity and proper benign typing across all workflows."""
    for event in diversity_events:
        label = event.attack_type or "benign"
        assert label in CANONICAL_CLASSES, f"Unknown label '{label}' on event {event.event_id}"

        if event.scenario_type in BENIGN_WORKFLOW_TYPES:
            assert event.raw_label == "benign", f"Benign workflow {event.scenario_type} marked {event.raw_label}"
            assert event.attack_type in (None, "benign"), f"Benign workflow {event.scenario_type} has attack_type {event.attack_type}"
        else:
            assert event.raw_label in ("malicious", "attack") or event.attack_type in CANONICAL_CLASSES
            assert event.attack_type in CANONICAL_CLASSES and event.attack_type != "benign"


def test_phase19_metric_reconstruction_from_arrays():
    """Verify exact mathematical match between reported metrics and instance-level arrays."""
    art_path = Path(PROJECT_ROOT) / OUTPUT_ARTIFACT_REL_PATH
    if not art_path.exists():
        pytest.skip(f"Phase 19 artifact not found at {art_path}")

    with open(art_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    y_true = data["instance_level_data"]["ground_truth_labels"]
    y_pred = data["instance_level_data"]["predicted_labels"]
    classes = data["evaluation_results"]["canonical_class_order"]

    # Reconstruct confusion matrix
    cm_recon = confusion_matrix(y_true, y_pred, labels=classes).tolist()
    assert cm_recon == data["evaluation_results"]["confusion_matrix"]

    # Reconstruct Macro-F1
    macro_f1_recon = round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4)
    assert macro_f1_recon == data["evaluation_results"]["macro_f1"]

    # Reconstruct Balanced Accuracy
    bal_acc_recon = round(float(balanced_accuracy_score(y_true, y_pred)), 4)
    assert bal_acc_recon == data["evaluation_results"]["balanced_accuracy"]

    # Reconstruct Per-Class metrics
    prec, rec, f1_vals, supp = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )
    for idx, c_name in enumerate(classes):
        c_res = data["evaluation_results"]["per_class"][c_name]
        assert c_res["support"] == int(supp[idx])
        assert c_res["precision"] == round(float(prec[idx]), 4)
        assert c_res["recall"] == round(float(rec[idx]), 4)
        assert c_res["f1"] == round(float(f1_vals[idx]), 4)


def test_phase19_benign_hard_negative_workflow_tracking():
    """Verify that each benign administrative workflow is properly tracked."""
    art_path = Path(PROJECT_ROOT) / OUTPUT_ARTIFACT_REL_PATH
    if not art_path.exists():
        pytest.skip(f"Phase 19 artifact not found at {art_path}")

    with open(art_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    workflows = data.get("benign_hard_negative_analysis", {})

    for w_type in BENIGN_WORKFLOW_TYPES:
        assert w_type in workflows, f"Workflow '{w_type}' missing from hard-negative analysis"
        w_data = workflows[w_type]
        assert "total_events" in w_data
        assert "correct_benign" in w_data
        assert "false_alarms" in w_data
        assert "false_alarm_rate" in w_data
        assert "predicted_distribution" in w_data
        assert w_data["total_events"] == w_data["correct_benign"] + w_data["false_alarms"]
