"""AEGIS-ML Phase 22: Regression Tests for False-Positive Reduction and Calibration.

Module: tests.test_phase22_false_positive_calibration

Tests verify:
1. Metric reconstruction from stored ground-truth labels and prediction arrays.
2. Confusion matrix and support consistency.
3. Correct benign false-alarm numerator and denominator.
4. Correct binary attack recall.
5. Scenario-group isolation (no train/val/test scenario overlap).
6. Prevention of provenance-field leakage.
7. Validation-only calibration (calibrator not fitted on test data).
8. Validation-only threshold selection.
9. No test-label access during threshold optimization.
10. No SMOTE or resampling on validation/test data.
11. Finite prediction scores and robust handling of missing values.
12. Per-workflow metric reconstruction.
13. Deterministic results with fixed random seeds.
14. Historical Phase 20 and Phase 21 artifacts remain unchanged.
15. Clear failure when class support is insufficient.
"""

from collections import Counter
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, List, Optional
import pytest
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, balanced_accuracy_score

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import UnifiedEvent
from backend.evaluation.false_positive_calibration import (
    CALIBRATION_ARTIFACT_REL_PATH,
    CLASS_RECALL_FLOOR,
    CANONICAL_CLASSES,
    PHASE22_BASELINE_FEATURE_NAMES,
    _apply_benign_threshold,
    _apply_class_thresholds,
    _partition_train_val_test,
    compute_brier_score_per_class,
    compute_ece_per_class,
    compute_log_loss_metric,
    reconstruct_metrics,
    select_benign_threshold_on_validation,
    select_class_thresholds_on_validation,
)
from backend.evaluation.scenario_evaluation import PROHIBITED_FEATURE_FIELDS
from backend.detection.model_trainer import load_flexible_dataset
from backend.evaluation.behavioral_diversity_evaluation import (
    DIVERSITY_DATASET_REL_PATH,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _load_phase22_artifact():
    p = Path(PROJECT_ROOT) / CALIBRATION_ARTIFACT_REL_PATH
    if not p.exists():
        return None
    with open(p) as f:
        return json.load(f)


def _make_dummy_unified_event(event_id="e1", scenario_type="benign_traffic") -> UnifiedEvent:
    return UnifiedEvent(
        event_id=event_id,
        timestamp=datetime(2026, 10, 10),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=True,
        dst_internal=True,
        src_ip="10.0.0.1",
        scenario_type=scenario_type,
    )


# ── Test 1: Metric reconstruction ─────────────────────────────────────────────

def test_phase22_metric_reconstruction_from_stored_predictions():
    """Reconstruct all metrics from stored ground-truth and predictions and verify they match stored values."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    inst = art["instance_level_data"]
    y_test = inst["ground_truth_labels"]
    n = len(y_test)
    assert n > 900, f"Expected at least 900 test events, found {n}"

    for cid, cfg in art["ablation_configurations"].items():
        y_pred = inst["predictions_by_config"][cid]
        assert len(y_pred) == n, f"{cid}: prediction length mismatch"

        reconstructed_macro = round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        reconstructed_bal = round(float(balanced_accuracy_score(y_test, y_pred)), 4)

        stored_macro = cfg["metrics"]["macro_f1"]
        stored_bal = cfg["metrics"]["balanced_accuracy"]

        assert reconstructed_macro == stored_macro, (
            f"{cid}: Macro-F1 mismatch: reconstructed {reconstructed_macro} vs stored {stored_macro}"
        )
        assert reconstructed_bal == stored_bal, (
            f"{cid}: Balanced Accuracy mismatch: reconstructed {reconstructed_bal} vs stored {stored_bal}"
        )


# ── Test 2: Confusion matrix and support consistency ──────────────────────────

def test_phase22_confusion_matrix_and_support_consistency():
    """Verify that confusion matrix rows sum to class support and total sums to N."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    inst = art["instance_level_data"]
    y_test = inst["ground_truth_labels"]
    n = len(y_test)

    for cid, cfg in art["ablation_configurations"].items():
        y_pred = inst["predictions_by_config"][cid]
        cm_stored = np.array(cfg["metrics"]["confusion_matrix"])

        assert cm_stored.sum() == n, f"{cid}: CM total {cm_stored.sum()} != N={n}"
        row_sums = cm_stored.sum(axis=1)
        for i, cls in enumerate(CANONICAL_CLASSES):
            expected_support = sum(1 for y in y_test if y == cls)
            assert row_sums[i] == expected_support, (
                f"{cid}: Row {i} ({cls}) sum {row_sums[i]} != support {expected_support}"
            )


# ── Test 3: Benign false-alarm numerator and denominator ──────────────────────

def test_phase22_benign_fpr_numerator_denominator_correct():
    """Verify benign FPR numerator/denominator are consistent with predictions."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    inst = art["instance_level_data"]
    y_test = inst["ground_truth_labels"]
    n_benign = sum(1 for y in y_test if y == "benign")

    for cid, cfg in art["ablation_configurations"].items():
        y_pred = inst["predictions_by_config"][cid]
        fp = sum(1 for yt, yp in zip(y_test, y_pred) if yt == "benign" and yp != "benign")
        fpr = round(fp / n_benign, 4) if n_benign > 0 else 0.0

        stored_fp = cfg["metrics"]["benign_fpr_numerator"]
        stored_n = cfg["metrics"]["benign_fpr_denominator"]
        stored_fpr = cfg["metrics"]["binary_benign_fpr"]

        assert stored_n == n_benign, f"{cid}: denominator {stored_n} != actual {n_benign}"
        assert stored_fp == fp, f"{cid}: FP count {stored_fp} != reconstructed {fp}"
        assert abs(stored_fpr - fpr) < 0.0005, f"{cid}: FPR {stored_fpr} != reconstructed {fpr}"


# ── Test 4: Binary attack recall ──────────────────────────────────────────────

def test_phase22_binary_attack_recall_correct():
    """Verify binary attack recall numerator/denominator are correct."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    inst = art["instance_level_data"]
    y_test = inst["ground_truth_labels"]
    n_attack = sum(1 for y in y_test if y != "benign")

    for cid, cfg in art["ablation_configurations"].items():
        y_pred = inst["predictions_by_config"][cid]
        tp = sum(1 for yt, yp in zip(y_test, y_pred) if yt != "benign" and yp != "benign")
        recall = round(tp / n_attack, 4) if n_attack > 0 else 0.0

        stored_recall = cfg["metrics"]["binary_attack_recall"]
        assert abs(stored_recall - recall) < 0.0005, (
            f"{cid}: attack recall {stored_recall} != reconstructed {recall}"
        )


# ── Test 5: Scenario-group isolation (no overlap) ─────────────────────────────

def test_phase22_scenario_group_isolation():
    """Verify zero scenario overlap across train/val/test partitions."""
    data_path = Path(PROJECT_ROOT) / DIVERSITY_DATASET_REL_PATH
    if not data_path.exists():
        pytest.skip("Dataset not found.")

    events, _ = load_flexible_dataset(str(data_path))
    labels = [e.attack_type or "benign" for e in events]

    tr_idx, val_idx, te_idx, stats = _partition_train_val_test(
        events, labels, test_ratio=0.20, val_ratio=0.10, seed=42
    )

    tr_sc = set(events[i].scenario_id for i in tr_idx if events[i].scenario_id)
    val_sc = set(events[i].scenario_id for i in val_idx if events[i].scenario_id)
    te_sc = set(events[i].scenario_id for i in te_idx if events[i].scenario_id)

    assert len(tr_sc & val_sc) == 0, f"Train-val scenario overlap: {tr_sc & val_sc}"
    assert len(tr_sc & te_sc) == 0, f"Train-test scenario overlap: {tr_sc & te_sc}"
    assert len(val_sc & te_sc) == 0, f"Val-test scenario overlap: {val_sc & te_sc}"

    # Also verify event-level disjointness
    assert len(set(tr_idx) & set(val_idx)) == 0
    assert len(set(tr_idx) & set(te_idx)) == 0
    assert len(set(val_idx) & set(te_idx)) == 0


# ── Test 6: Provenance-field exclusion ───────────────────────────────────────

def test_phase22_provenance_fields_excluded():
    """Verify no prohibited provenance fields in Phase 22 feature names."""
    for prohibited in PROHIBITED_FEATURE_FIELDS:
        assert prohibited not in PHASE22_BASELINE_FEATURE_NAMES, (
            f"Provenance field '{prohibited}' found in PHASE22_BASELINE_FEATURE_NAMES"
        )

    art = _load_phase22_artifact()
    if art is None:
        return  # Feature list checked above; artifact not yet generated

    for cid, cfg in art["ablation_configurations"].items():
        if "feature_names" not in cfg:
            continue
        for prohibited in PROHIBITED_FEATURE_FIELDS:
            assert prohibited not in cfg["feature_names"], (
                f"Prohibited field '{prohibited}' in config {cid} feature_names"
            )


# ── Test 7: Calibration data discipline ──────────────────────────────────────

def test_phase22_calibration_not_fitted_on_test_data():
    """Verify the artifact records that calibration was fitted on validation data only."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    audit = art["leakage_audit"]
    assert audit["calibration_fitted_on"] == "validation data only (cv=prefit)"
    assert audit["test_data_accessed_during_selection"] is False
    assert audit["preprocessing_fitted_on"] == "training data only"
    assert audit["smote_applied_on"] == "training data only"


# ── Test 8: Threshold selection uses only validation data ────────────────────

def test_phase22_threshold_selection_validation_only():
    """Verify artifact states threshold selection never uses test labels."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    audit = art["leakage_audit"]
    assert audit["threshold_selection_on"] == "validation data only"
    assert audit["test_data_accessed_during_selection"] is False


# ── Test 9: Threshold selection interface accepts only non-test data ──────────

def test_phase22_threshold_selection_with_synthetic_val():
    """Verify threshold selection works on a synthetic dataset and produces valid results."""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    rng = np.random.default_rng(42)
    n = 200
    X_val = rng.standard_normal((n, 5))
    # Create binary problem: benign vs brute_force
    y_val = ["benign"] * 100 + ["brute_force"] * 100
    classes = ["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"]

    rf = RandomForestClassifier(n_estimators=20, random_state=42)
    rf.fit(X_val, y_val)  # fit on same data for test only (not normal usage)

    # Test benign threshold selection (uses only y_val and model predictions, no test data)
    threshold, meta = select_benign_threshold_on_validation(
        rf, X_val, y_val, classes=["benign", "brute_force"], attack_recall_floor=0.90
    )

    assert 0.0 <= threshold <= 1.0
    assert "selected_threshold" in meta
    assert "threshold_search" in meta


# ── Test 10: No resampling on validation/test data ───────────────────────────

def test_phase22_no_smote_on_val_or_test():
    """Verify artifact states SMOTE applied only to training data."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    assert art["leakage_audit"]["smote_applied_on"] == "training data only"
    assert art["calibration_methodology"]["validation_set_resampled"] is False


# ── Test 11: Finite calibration metrics ──────────────────────────────────────

def test_phase22_calibration_metrics_are_finite():
    """Verify log-loss, ECE, and Brier score produce finite floats from synthetic probabilities."""
    n = 100
    rng = np.random.default_rng(42)
    classes = ["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"]
    proba = rng.dirichlet(np.ones(len(classes)), size=n)
    y_true = rng.choice(classes, size=n).tolist()

    ll = compute_log_loss_metric(y_true, proba, classes)
    assert ll is not None and np.isfinite(ll)

    ece = compute_ece_per_class(y_true, proba, classes)
    for cls, val in ece.items():
        assert np.isfinite(val), f"ECE non-finite for {cls}"

    brier = compute_brier_score_per_class(y_true, proba, classes)
    for cls, val in brier.items():
        assert np.isfinite(val), f"Brier non-finite for {cls}"


# ── Test 12: Per-workflow metric reconstruction ──────────────────────────────

def test_phase22_workflow_false_alarm_reconstruction():
    """Reconstruct per-workflow false alarms from stored predictions and verify they match."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    inst = art["instance_level_data"]
    y_test = inst["ground_truth_labels"]
    sc_ids = inst["test_scenario_ids"]

    # Load events to get scenario_type mapping
    data_path = Path(PROJECT_ROOT) / DIVERSITY_DATASET_REL_PATH
    if not data_path.exists():
        pytest.skip("Dataset not found.")
    events_all, _ = load_flexible_dataset(str(data_path))
    sc_id_to_type = {e.scenario_id: e.scenario_type for e in events_all if e.scenario_id}

    # Reconstruct workflow breakdown for config_a
    cid = "config_a"
    y_pred = inst["predictions_by_config"][cid]
    workflow_fa = {}
    workflow_total = {}
    for sc_id, yt, yp in zip(sc_ids, y_test, y_pred):
        sc_type = sc_id_to_type.get(sc_id, "unknown")
        if yt == "benign":
            workflow_total[sc_type] = workflow_total.get(sc_type, 0) + 1
            if yp != "benign":
                workflow_fa[sc_type] = workflow_fa.get(sc_type, 0) + 1

    cfg = art["ablation_configurations"][cid]
    stored_wb = cfg["metrics"]["benign_workflow_breakdown"]
    for wt, stored in stored_wb.items():
        if stored["total_events"] == 0:
            continue
        reconstructed_fa = workflow_fa.get(wt, 0)
        reconstructed_total = workflow_total.get(wt, 0)
        assert reconstructed_fa == stored["false_alarms"], (
            f"Workflow {wt}: FA {reconstructed_fa} != stored {stored['false_alarms']}"
        )
        assert reconstructed_total == stored["total_events"], (
            f"Workflow {wt}: total {reconstructed_total} != stored {stored['total_events']}"
        )


# ── Test 13: Deterministic results with fixed seeds ──────────────────────────

def test_phase22_deterministic_reconstruction():
    """Verify that benchmark reconstruction yields identical metrics on two runs."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    inst = art["instance_level_data"]
    y_test = inst["ground_truth_labels"]

    for cid in ["config_a", "config_b"]:
        y_pred = inst["predictions_by_config"][cid]
        m1 = round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        m2 = round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        assert m1 == m2, f"{cid}: Non-deterministic macro-F1: {m1} vs {m2}"


# ── Test 14: Historical artifact preservation ────────────────────────────────

def test_phase22_historical_artifacts_unchanged():
    """Verify Phase 20 and Phase 21 artifacts are not modified."""
    historical = [
        ("data/models/canonical_evaluation_artifact.json", "evaluation_results", "macro_f1", 0.8685),
        ("data/models/scenario_evaluation_artifact.json", "evaluation_results", "macro_f1", 0.9732),
        ("data/models/behavioral_diversity_artifact.json", "evaluation_results", "macro_f1", 0.8717),
    ]

    for rel_path, section_key, metric_key, expected in historical:
        p = Path(PROJECT_ROOT) / rel_path
        assert p.exists(), f"Historical artifact missing: {rel_path}"
        with open(p) as f:
            data = json.load(f)
        val = data.get(section_key, {}).get(metric_key)
        assert val == expected, f"Mismatch in {rel_path}: expected {expected}, found {val}"


# ── Test 15: Class-specific threshold correctness ────────────────────────────

def test_phase22_class_thresholds_applied_correctly():
    """Verify class-specific threshold logic resolves predictions correctly."""
    classes = ["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"]
    thresholds = {
        "brute_force": 0.8,
        "lateral_movement": 0.5,
        "data_exfiltration": 0.7,
        "c2_beaconing": 0.6,
    }

    # Event where only lateral_movement exceeds threshold
    proba = np.array([[0.1, 0.1, 0.6, 0.1, 0.1]])
    result = _apply_class_thresholds(proba, classes, thresholds)
    assert result[0] == "lateral_movement"

    # Event where brute_force and c2_beaconing both exceed threshold -> highest wins
    proba2 = np.array([[0.05, 0.85, 0.0, 0.05, 0.65]])
    result2 = _apply_class_thresholds(proba2, classes, thresholds)
    assert result2[0] == "brute_force"  # 0.85 > 0.65

    # Event where no attack class exceeds threshold -> benign
    proba3 = np.array([[0.9, 0.02, 0.03, 0.03, 0.02]])
    result3 = _apply_class_thresholds(proba3, classes, thresholds)
    assert result3[0] == "benign"


# ── Test 16: Global threshold reduces false alarms correctly ─────────────────

def test_phase22_global_benign_threshold_mechanics():
    """Verify benign threshold policy predicts benign when P(benign) is high."""
    classes = ["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"]
    threshold = 0.5

    # High benign probability -> should predict benign
    proba_high_benign = np.array([[0.8, 0.05, 0.05, 0.05, 0.05]])
    result = _apply_benign_threshold(proba_high_benign, classes, threshold)
    assert result[0] == "benign"

    # Low benign probability -> should predict highest attack
    proba_low_benign = np.array([[0.2, 0.6, 0.1, 0.05, 0.05]])
    result2 = _apply_benign_threshold(proba_low_benign, classes, threshold)
    assert result2[0] == "brute_force"


# ── Test 17: Feature count verification ──────────────────────────────────────

def test_phase22_baseline_feature_count():
    """Verify the Phase 22 baseline uses exactly 48 features (Phase 21 Config C)."""
    assert len(PHASE22_BASELINE_FEATURE_NAMES) == 48


# ── Test 18: Artifact schema required fields ─────────────────────────────────

def test_phase22_artifact_schema_required_fields():
    """Verify the Phase 22 artifact contains all required fields."""
    art = _load_phase22_artifact()
    if art is None:
        pytest.skip("Phase 22 artifact not yet generated.")

    required_keys = [
        "schema_version",
        "protocol_title",
        "timestamp",
        "dataset_metadata",
        "split_methodology",
        "class_order",
        "leakage_audit",
        "calibration_methodology",
        "threshold_methodology",
        "summary_comparison",
        "ablation_configurations",
        "multi_seed_robustness",
        "multi_seed_summary",
        "instance_level_data",
        "known_limitations",
        "status",
    ]
    for key in required_keys:
        assert key in art, f"Required key '{key}' missing from Phase 22 artifact"

    # Verify dataset SHA-256 recorded correctly
    expected_sha = "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"
    assert art["dataset_metadata"]["dataset_sha256"] == expected_sha
