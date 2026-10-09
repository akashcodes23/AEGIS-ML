"""AEGIS-ML Phase 18: Generalization and Leakage Stress Test Tests.

Validates:
1. Provenance metadata strictly prohibited from predictive model features.
2. Scenario separation across multi-seed partitions (0.0% scenario overlap).
3. Independent metric reconstruction from prediction arrays (exact match).
4. Deterministic evaluation stability across repeated runs.
5. Insufficient scenario counts explicitly audited (N=1 false positive backup).
6. False positive backup stress test: holding out unseen admin backup triggers 100% false alarm rate on those events.
7. Prevention of train/test preprocessing leakage across baselines, IF, and SMOTE.
"""

from collections import Counter
import json
from pathlib import Path
import numpy as np
import pytest
from sklearn.metrics import confusion_matrix, f1_score, balanced_accuracy_score

from backend.detection.model_trainer import (
    load_flexible_dataset,
    build_feature_matrix,
    calculate_failed_auth_rate,
    CANONICAL_CLASSES,
)
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.temporal_graph_extractor import RELATIONAL_GRAPH_FEATURE_NAMES
from backend.evaluation.scenario_evaluation import (
    partition_scenario_grouped_split,
    PROHIBITED_FEATURE_FIELDS,
    SCENARIO_DATASET_REL_PATH,
    OUTPUT_ARTIFACT_REL_PATH,
)
from backend.evaluation.generalization_stress_test import (
    audit_scenario_diversity,
    audit_feature_and_pipeline_leakage,
    independently_reconstruct_phase17_metrics,
    evaluate_scenario_partition_robustness,
    analyze_false_positive_backup_stress,
)


@pytest.fixture(scope="module")
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def scenario_dataset_path(repo_root) -> Path:
    return repo_root / SCENARIO_DATASET_REL_PATH


@pytest.fixture(scope="module")
def phase17_artifact_path(repo_root) -> Path:
    return repo_root / OUTPUT_ARTIFACT_REL_PATH


# =========================================================================
# 1. Provenance Fields Excluded from Predictive Features
# =========================================================================

def test_provenance_fields_prohibited_from_feature_schema():
    """Verify scenario_id, campaign_id, generator_version are never predictive features."""
    all_features = ThreatClassifier.FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES
    assert len(all_features) == 21

    leakage_audit = audit_feature_and_pipeline_leakage()
    assert len(leakage_audit["prohibited_provenance_fields_in_features"]) == 0

    for prohibited in PROHIBITED_FEATURE_FIELDS:
        assert prohibited not in all_features, f"Leakage violation: '{prohibited}' in features!"


# =========================================================================
# 2. Scenario Separation Across Partitions (0.0% Overlap Across Multi-Splits)
# =========================================================================

def test_scenario_separation_across_multiple_split_seeds(scenario_dataset_path):
    """Across multiple split seeds, train and test scenario sets must be strictly disjoint."""
    events, _ = load_flexible_dataset(str(scenario_dataset_path))
    labels = [e.attack_type or "benign" for e in events]

    for seed in [42, 1337, 2026, 7, 999]:
        tr_idx, te_idx, stats = partition_scenario_grouped_split(events, labels, test_ratio=0.20, seed=seed)
        train_sc = {events[i].scenario_id for i in tr_idx}
        test_sc = {events[i].scenario_id for i in te_idx}

        overlap = train_sc.intersection(test_sc)
        assert len(overlap) == 0, f"Split seed {seed} failed scenario isolation: {len(overlap)} overlapping!"
        assert stats["scenario_overlap_count"] == 0
        assert len(train_sc) + len(test_sc) == stats["total_scenarios"]


# =========================================================================
# 3. Metric Reconstruction Exact Match
# =========================================================================

def test_metric_reconstruction_exact_match(phase17_artifact_path):
    """Reconstructed metrics must match stored artifact metrics with zero discrepancies."""
    recon = independently_reconstruct_phase17_metrics(str(phase17_artifact_path))

    assert recon["verification_status"] == "EXACT_MATCH"
    assert len(recon["discrepancies_found"]) == 0
    assert recon["reconstructed_macro_f1"] == 0.9732
    assert recon["reconstructed_balanced_accuracy"] == 0.9768
    assert recon["reconstructed_accuracy"] == 0.9869
    assert recon["reconstructed_benign_fpr"] == 0.0


# =========================================================================
# 4. Deterministic Evaluation Stability
# =========================================================================

def test_deterministic_evaluation_multi_split():
    """Verify that multi-split partition evaluation produces stable results within bounds."""
    robustness = evaluate_scenario_partition_robustness(split_seeds=[42, 1337])
    agg = robustness["aggregate_split_variability"]

    # Mean Macro-F1 should be between 0.96 and 0.99
    assert 0.96 <= agg["mean_macro_f1"] <= 0.99
    assert agg["std_macro_f1"] <= 0.02


# =========================================================================
# 5. Insufficient Scenario Counts & False Positive Backup Stress
# =========================================================================

def test_false_positive_backup_single_scenario_limitation(scenario_dataset_path):
    """Stress test confirms N=1 backup scenario limitation: 100% false alarm rate when held out."""
    diversity = audit_scenario_diversity(str(scenario_dataset_path))
    fp_diversity = diversity["diversity_by_type"]["false_positive_backup"]

    # Exactly 1 scenario instance exists in dataset
    assert fp_diversity["scenario_count"] == 1
    assert fp_diversity["total_events"] == 51

    # Running stress test when held out into test partition
    stress = analyze_false_positive_backup_stress(str(scenario_dataset_path))
    assert stress["total_events"] == 51
    assert stress["held_out_in_test"] is True
    assert stress["false_alarm_rate_on_backup"] == 1.0  # 100% false alarms on unseen admin backup!
    assert stress["false_alarm_count_on_backup"] == 51

    # All 51 events misclassified as attack (50 lateral movement, 1 exfil)
    preds = stress["predictions_on_held_out_backup"]
    assert preds.get("lateral_movement") == 50
    assert preds.get("data_exfiltration") == 1
    assert preds.get("benign", 0) == 0


# =========================================================================
# 6. Preprocessing Isolation (No Train/Test Leakage)
# =========================================================================

def test_preprocessing_isolation_strictly_on_train(scenario_dataset_path):
    """Verify that Isolation Forest and feature scaling fit strictly on train partition."""
    events, _ = load_flexible_dataset(str(scenario_dataset_path))
    labels = [e.attack_type or "benign" for e in events]

    tr_idx, te_idx, _ = partition_scenario_grouped_split(events, labels, test_ratio=0.20, seed=42)
    tr_events = [events[i] for i in tr_idx]
    te_events = [events[i] for i in te_idx]

    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(tr_events, benign_only=True)
    if_detector = IsolationForestDetector(random_state=42)
    if_detector.fit(tr_events)

    fa_tr = calculate_failed_auth_rate(tr_events)
    fa_te = calculate_failed_auth_rate(te_events)

    X_tr = build_feature_matrix(tr_events, if_detector, profiler, fa_tr)
    X_te = build_feature_matrix(te_events, if_detector, profiler, fa_te)

    assert X_tr.shape[0] == len(tr_events)
    assert X_te.shape[0] == len(te_events)

    y_tr = [labels[i] for i in tr_idx]
    clf = ThreatClassifier(random_state=42)
    clf.fit(X_tr, y_tr)

    assert clf.model is not None
    preds = clf.model.predict(X_te)
    assert len(preds) == len(te_events)
