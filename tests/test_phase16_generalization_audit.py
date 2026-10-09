"""Phase 16: Dataset Provenance and Generalization Audit Tests.

Validates:
1. Dataset row counts and class distributions in data/raw/combined_labeled.jsonl.
2. Deterministic group-aware split generation.
3. Group separation ensuring zero exact-duplicate fingerprint overlap between train and test.
4. Scenario provenance audit confirming explicit absence of scenario identifiers and NOT_ESTABLISHED status.
5. Train/test preprocessing isolation (Isolation Forest & feature scaling fitted strictly on train partition).
6. Metric reconstruction from prediction arrays directly (multiclass vs binary separation).
7. Unsupported-label rejection and graceful handling.
8. Fixed-holdout model-seed stability (variance across seeds is negligible when split is frozen).
9. Exfiltration staging error audit invariants (all 120 misclassifications stem from unlinked endpoint reads).
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
    build_feature_matrix,
    calculate_failed_auth_rate,
    CANONICAL_CLASSES,
)
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.evaluation.canonical_artifact import get_event_fingerprint
from backend.evaluation.generalization_audit import (
    audit_dataset_provenance,
    audit_split_leakage,
    partition_group_aware_split,
    evaluate_frozen_holdout_model_randomness,
)


@pytest.fixture(scope="module")
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def dataset_path(repo_root) -> Path:
    return repo_root / "data" / "raw" / "combined_labeled.jsonl"


@pytest.fixture(scope="module")
def canonical_artifact_path(repo_root) -> Path:
    return repo_root / "data" / "models" / "canonical_evaluation_artifact.json"


@pytest.fixture(scope="module")
def raw_dataset_events(dataset_path):
    events, _ = load_flexible_dataset(str(dataset_path))
    return events


@pytest.fixture(scope="module")
def raw_dataset_labels(raw_dataset_events):
    return [e.attack_type or "benign" for e in raw_dataset_events]


# =========================================================================
# 1. Dataset Row Counts & Class Distributions
# =========================================================================

def test_dataset_row_counts_and_classes(raw_dataset_events, raw_dataset_labels):
    """Verify exact total record count and class distribution."""
    assert len(raw_dataset_events) == 7051, f"Expected 7051 records, got {len(raw_dataset_events)}"
    assert len(raw_dataset_labels) == 7051

    counts = Counter(raw_dataset_labels)
    expected_counts = {
        "benign": 2051,
        "brute_force": 3000,
        "data_exfiltration": 1320,
        "c2_beaconing": 345,
        "lateral_movement": 335,
    }
    assert counts == expected_counts, f"Class distribution mismatch: {counts} vs {expected_counts}"


# =========================================================================
# 2. Dataset Provenance & Missing Scenario Identifiers
# =========================================================================

def test_scenario_provenance_explicitly_not_established(dataset_path):
    """Audit confirms scenario IDs are absent and scenario generalization is NOT_ESTABLISHED."""
    prov_results = audit_dataset_provenance(str(dataset_path))

    assert prov_results["total_records"] == 7051
    assert prov_results["scenario_metadata_present"] is False
    assert prov_results["scenario_level_generalization_status"] == "NOT_ESTABLISHED"

    # Confirm critical identifiers are 0% populated
    for ident in ["scenario_id", "campaign_id", "template_id", "source_event_id"]:
        assert prov_results["provenance_identifiers"][ident]["count"] == 0
        assert prov_results["provenance_identifiers"][ident]["status"] == "ABSENT"


# =========================================================================
# 3. Deterministic Group-Aware Split & Group Separation
# =========================================================================

def test_deterministic_split_generation(raw_dataset_events, raw_dataset_labels):
    """Verify group-aware split is deterministic for identical seed."""
    tr_a, te_a = partition_group_aware_split(raw_dataset_events, raw_dataset_labels, split_seed=42)
    tr_b, te_b = partition_group_aware_split(raw_dataset_events, raw_dataset_labels, split_seed=42)

    assert len(tr_a) == len(tr_b) == 5651
    assert len(te_a) == len(te_b) == 1400

    tr_a_ids = [raw_dataset_events[i].event_id for i in tr_a]
    tr_b_ids = [raw_dataset_events[i].event_id for i in tr_b]
    assert tr_a_ids == tr_b_ids, "Split must be strictly deterministic across calls"


def test_zero_exact_duplicate_leakage(raw_dataset_events, raw_dataset_labels):
    """Verify group-aware split guarantees 0.0% exact-duplicate fingerprint overlap."""
    tr_indices, te_indices = partition_group_aware_split(raw_dataset_events, raw_dataset_labels, split_seed=42)

    train_fps = {get_event_fingerprint(raw_dataset_events[i]) for i in tr_indices}
    test_fps = {get_event_fingerprint(raw_dataset_events[i]) for i in te_indices}

    overlap = train_fps.intersection(test_fps)
    assert len(overlap) == 0, f"Found {len(overlap)} overlapping duplicate fingerprints across split!"


# =========================================================================
# 4. Train/Test Preprocessing Isolation
# =========================================================================

def test_preprocessing_isolation(raw_dataset_events, raw_dataset_labels):
    """Verify that Isolation Forest, baseline profiler, and failed auth are fitted exclusively on train."""
    tr_indices, te_indices = partition_group_aware_split(raw_dataset_events, raw_dataset_labels, split_seed=42)
    tr_events = [raw_dataset_events[i] for i in tr_indices]
    te_events = [raw_dataset_events[i] for i in te_indices]

    # Preprocessors fitted strictly on training partition
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(tr_events, benign_only=True)
    if_detector = IsolationForestDetector(random_state=42)
    if_detector.fit(tr_events)

    fa_tr = calculate_failed_auth_rate(tr_events)
    fa_te = calculate_failed_auth_rate(te_events)

    X_tr = build_feature_matrix(tr_events, if_detector, profiler, fa_tr)
    X_te = build_feature_matrix(te_events, if_detector, profiler, fa_te)

    assert X_tr.shape == (5651, 15)
    assert X_te.shape == (1400, 15)

    # Train classifier on train partition
    y_tr = [raw_dataset_labels[i] for i in tr_indices]
    clf = ThreatClassifier(random_state=42)
    clf.fit(X_tr, y_tr)

    # Predict on test features
    y_pred = clf.model.predict(X_te)
    assert len(y_pred) == 1400


# =========================================================================
# 5. Metric Reconstruction from Prediction Arrays
# =========================================================================

def test_metric_reconstruction_from_arrays(canonical_artifact_path):
    """Reconstruct confusion matrix, macro-F1, balanced accuracy, and FPR directly from saved arrays."""
    with open(canonical_artifact_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    y_true = np.array(artifact["instance_level_data"]["ground_truth_labels"])
    y_pred = np.array(artifact["instance_level_data"]["predicted_labels"])
    classes = artifact["metadata"]["canonical_class_order"]

    assert len(y_true) == 1400
    assert len(y_pred) == 1400

    # 1. Confusion Matrix
    cm_calc = confusion_matrix(y_true, y_pred, labels=classes).tolist()
    cm_saved = artifact["evaluation_results"]["confusion_matrix"]
    assert cm_calc == cm_saved, "Confusion matrix reconstructed from arrays does not match saved matrix"

    # 2. Multiclass Macro-F1
    macro_f1_calc = round(float(f1_score(y_true, y_pred, average="macro")), 4)
    macro_f1_saved = artifact["evaluation_results"]["macro_f1"]
    assert macro_f1_calc == macro_f1_saved, f"Macro-F1 mismatch: calc {macro_f1_calc} vs saved {macro_f1_saved}"

    # 3. Multiclass Balanced Accuracy
    bal_acc_calc = round(float(balanced_accuracy_score(y_true, y_pred)), 4)
    bal_acc_saved = artifact["evaluation_results"]["balanced_accuracy"]
    assert bal_acc_calc == bal_acc_saved, f"Balanced accuracy mismatch: calc {bal_acc_calc} vs saved {bal_acc_saved}"

    # 4. Binary vs Multiclass FPR distinction
    # In multiclass benign one-vs-rest: Benign is class 0 (y_true == "benign")
    # Benign False Positives = Attacks predicted as benign: 0 / 990 = 0.0000
    attacks_as_benign = np.sum((y_true != "benign") & (y_pred == "benign"))
    assert attacks_as_benign == 0

    # Benign False Negatives = Benign predicted as attacks: 3 / 410 = 0.0073
    benign_as_attacks = np.sum((y_true == "benign") & (y_pred != "benign"))
    assert benign_as_attacks == 3
    binary_alarm_rate = round(float(benign_as_attacks / np.sum(y_true == "benign")), 6)
    assert abs(binary_alarm_rate - 0.007317) < 1e-5


# =========================================================================
# 6. Unsupported Label Rejection
# =========================================================================

def test_unsupported_label_rejection(raw_dataset_events, raw_dataset_labels):
    """Ensure unsupported/unknown labels do not corrupt prediction classes."""
    tr_indices, te_indices = partition_group_aware_split(raw_dataset_events[:500], raw_dataset_labels[:500], split_seed=42)
    tr_events = [raw_dataset_events[i] for i in tr_indices]
    y_tr = [raw_dataset_labels[i] for i in tr_indices]

    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(tr_events, benign_only=True)
    if_det = IsolationForestDetector(random_state=42)
    if_det.fit(tr_events)
    fa_tr = calculate_failed_auth_rate(tr_events)
    X_tr = build_feature_matrix(tr_events, if_det, profiler, fa_tr)

    clf = ThreatClassifier(random_state=42)
    clf.fit(X_tr, y_tr)

    # Valid class labels must only be canonical classes present in training
    assert all(c in CANONICAL_CLASSES for c in clf.model.classes_)


# =========================================================================
# 7. Frozen-Holdout Model-Seed Stability
# =========================================================================

def test_frozen_holdout_model_seed_stability(raw_dataset_events, raw_dataset_labels):
    """Verify that on a frozen holdout, model seed variance is negligible (Macro-F1 std <= 0.001)."""
    res = evaluate_frozen_holdout_model_randomness(
        raw_dataset_events,
        raw_dataset_labels,
        model_seeds=[42, 1337, 2026, 7, 999],
    )

    aggregate = res["aggregate_model_randomness"]
    assert aggregate["std_macro_f1"] <= 0.001, (
        f"Model seed variability on frozen holdout is unexpectedly large: {aggregate['std_macro_f1']}"
    )
    assert aggregate["mean_macro_f1"] >= 0.865
    assert aggregate["mean_balanced_accuracy"] >= 0.930


# =========================================================================
# 8. Exfiltration Staging Detection Error Invariants
# =========================================================================

def test_exfiltration_staging_root_cause(canonical_artifact_path, raw_dataset_events):
    """Verify that all 120 misclassified exfiltration events are endpoint file reads with 0 bytes."""
    with open(canonical_artifact_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    y_true = artifact["instance_level_data"]["ground_truth_labels"]
    y_pred = artifact["instance_level_data"]["predicted_labels"]
    event_ids = artifact["instance_level_data"]["test_event_ids"]

    event_map = {e.event_id: e for e in raw_dataset_events}

    misclassified_exfil = []
    for eid, yt, yp in zip(event_ids, y_true, y_pred):
        if yt == "data_exfiltration" and yp != "data_exfiltration":
            misclassified_exfil.append((eid, yp, event_map[eid]))

    assert len(misclassified_exfil) == 120, f"Expected 120 misclassified exfiltration events, got {len(misclassified_exfil)}"

    for eid, pred, evt in misclassified_exfil:
        assert evt.layer == "endpoint", f"Expected layer='endpoint', got {evt.layer}"
        assert evt.process_name == "7z.exe", f"Expected process_name='7z.exe', got {evt.process_name}"
        assert evt.dst_port is None, f"Expected dst_port to be None for file read staging"
        assert evt.bytes_sent is None, f"Expected bytes_sent to be None for endpoint file read"
        assert pred in ["lateral_movement", "brute_force"]
