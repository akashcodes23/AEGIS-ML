"""AEGIS-ML Phase 17: Scenario-Aware Synthetic Data Generation and Evaluation.

Module: backend.evaluation.scenario_evaluation

Implements:
1. Scenario-grouped stratified partitioning (assigns entire scenario groups exclusively to train or test).
2. Strict scenario isolation guarantee: set(train_scenarios) & set(test_scenarios) == empty set.
3. Feature and preprocessor isolation (BehavioralBaselineProfiler, IsolationForest, SMOTE fitted strictly on train).
4. Provenance metadata exclusion (scenario_id, scenario_type, generator_version excluded from model features).
5. Mathematical evaluation: Confusion matrix, per-class P/R/F1, Macro-F1, Weighted-F1, Balanced Accuracy, Binary false alarm rate.
6. Explicit comparison against the canonical duplicate-aware benchmark.
"""

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import random
from typing import Dict, Any, List, Tuple, Set

import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
)
from imblearn.over_sampling import SMOTE

from backend.core.config import PROJECT_ROOT
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
from backend.detection.temporal_graph_extractor import (
    CausalTemporalGraphTracker,
    RELATIONAL_GRAPH_FEATURE_NAMES,
)


SCENARIO_DATASET_REL_PATH = "data/raw/scenario_aware_labeled.jsonl"
OUTPUT_ARTIFACT_REL_PATH = "data/models/scenario_evaluation_artifact.json"
CANONICAL_ARTIFACT_REL_PATH = "data/models/canonical_evaluation_artifact.json"

# Explicit list of metadata/provenance attributes prohibited from predictive features
PROHIBITED_FEATURE_FIELDS: Set[str] = {
    "scenario_id",
    "scenario_type",
    "generator_version",
    "event_id",
    "raw_label",
    "attack_type",
    "campaign_id",
    "template_id",
    "source_event_id",
}


def compute_file_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def partition_scenario_grouped_split(
    events: List[UnifiedEvent],
    labels: List[str],
    test_ratio: float = 0.20,
    seed: int = 42,
) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """
    Partition dataset by entire scenario_id groups.
    Guarantees 0.0% scenario overlap across train and test partitions.
    """
    rng = random.Random(seed)

    # 1. Map scenario_id -> list of event indices and dominant class
    scenario_indices: Dict[str, List[int]] = defaultdict(list)
    scenario_classes: Dict[str, str] = {}

    for idx, (e, lbl) in enumerate(zip(events, labels)):
        sc_id = e.scenario_id or f"unlabeled_scenario_{idx}"
        scenario_indices[sc_id].append(idx)
        if sc_id not in scenario_classes:
            scenario_classes[sc_id] = lbl

    # 2. Group scenarios by class for stratified holdout
    class_to_scenarios: Dict[str, List[str]] = defaultdict(list)
    for sc_id, sc_cls in scenario_classes.items():
        class_to_scenarios[sc_cls].append(sc_id)

    train_scenarios: Set[str] = set()
    test_scenarios: Set[str] = set()
    insufficient_scenario_warnings: Dict[str, str] = {}

    for cls_name, sc_list in class_to_scenarios.items():
        sc_list_sorted = sorted(sc_list)
        rng.shuffle(sc_list_sorted)

        total_sc_for_class = len(sc_list_sorted)
        if total_sc_for_class < 2:
            insufficient_scenario_warnings[cls_name] = (
                f"Class '{cls_name}' only has {total_sc_for_class} scenario(s). "
                f"Placed into train to preserve training representation."
            )
            train_scenarios.update(sc_list_sorted)
            continue

        n_test = max(1, int(round(total_sc_for_class * test_ratio)))
        test_selected = sc_list_sorted[:n_test]
        train_selected = sc_list_sorted[n_test:]

        test_scenarios.update(test_selected)
        train_scenarios.update(train_selected)

    # 3. Gather event indices
    tr_indices = [idx for sc in train_scenarios for idx in scenario_indices[sc]]
    te_indices = [idx for sc in test_scenarios for idx in scenario_indices[sc]]

    # Sort indices chronologically
    tr_indices.sort()
    te_indices.sort()

    # 4. Rigorous verification: NO scenario overlap
    overlap = train_scenarios.intersection(test_scenarios)
    assert len(overlap) == 0, f"Critical split failure: {len(overlap)} overlapping scenarios!"

    split_stats = {
        "total_scenarios": len(scenario_indices),
        "train_scenarios_count": len(train_scenarios),
        "test_scenarios_count": len(test_scenarios),
        "scenario_overlap_count": len(overlap),
        "train_scenarios": sorted(list(train_scenarios)),
        "test_scenarios": sorted(list(test_scenarios)),
        "scenarios_per_class": {k: len(v) for k, v in class_to_scenarios.items()},
        "insufficient_scenario_warnings": insufficient_scenario_warnings,
    }

    return tr_indices, te_indices, split_stats


def evaluate_scenario_aware_holdout(
    data_path: str = SCENARIO_DATASET_REL_PATH,
    split_seed: int = 42,
    model_seed: int = 42,
    output_path: str = OUTPUT_ARTIFACT_REL_PATH,
) -> Dict[str, Any]:
    """Execute end-to-end scenario-grouped evaluation and export artifact."""
    full_data_path = Path(PROJECT_ROOT) / data_path if not Path(data_path).is_absolute() else Path(data_path)
    if not full_data_path.exists():
        raise FileNotFoundError(f"Scenario dataset not found at: {full_data_path}")

    dataset_sha256 = compute_file_sha256(full_data_path)

    # Load dataset
    events, _ = load_flexible_dataset(str(full_data_path))
    labels = [e.attack_type or "benign" for e in events]
    classes = CANONICAL_CLASSES

    # Verify scenario provenance population
    populated_scenarios = sum(1 for e in events if e.scenario_id is not None)
    if populated_scenarios != len(events):
        raise ValueError(
            f"Dataset provenance incomplete: only {populated_scenarios} of {len(events)} events have scenario_id"
        )

    # Group-partition by scenario
    tr_indices, te_indices, split_stats = partition_scenario_grouped_split(
        events, labels, test_ratio=0.20, seed=split_seed
    )

    tr_events = [events[i] for i in tr_indices]
    y_tr = [labels[i] for i in tr_indices]
    te_events = [events[i] for i in te_indices]
    y_te = [labels[i] for i in te_indices]

    # Preprocessors fitted strictly on training partition
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(tr_events, benign_only=True)

    if_detector = IsolationForestDetector(random_state=model_seed)
    if_detector.fit(tr_events)

    fa_tr = calculate_failed_auth_rate(tr_events)
    fa_te = calculate_failed_auth_rate(te_events)

    X_tr_base = build_feature_matrix(tr_events, if_detector, profiler, fa_tr)
    X_te_base = build_feature_matrix(te_events, if_detector, profiler, fa_te)

    # Causal relational features
    tracker = CausalTemporalGraphTracker()
    tracker.fit_baseline_pairs(tr_events)
    tr_tg = tracker.extract_sequence(tr_events)
    te_tg = tracker.extract_sequence(te_events)

    tr_rel_arr = np.array([[f[k] for k in RELATIONAL_GRAPH_FEATURE_NAMES] for f in tr_tg], dtype=np.float64)
    te_rel_arr = np.array([[f[k] for k in RELATIONAL_GRAPH_FEATURE_NAMES] for f in te_tg], dtype=np.float64)

    X_tr_c = np.hstack([X_tr_base, tr_rel_arr])
    X_te_c = np.hstack([X_te_base, te_rel_arr])

    feats_c = ThreatClassifier.FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES
    assert len(feats_c) == 21, f"Expected 21 features in Config C, got {len(feats_c)}"

    # Audit: Ensure NO provenance fields entered feature matrix
    for prohibited in PROHIBITED_FEATURE_FIELDS:
        assert prohibited not in feats_c, f"Leakage violation: prohibited field {prohibited} in features!"

    # SMOTE oversampling fitted strictly on training partition
    min_count = min(Counter(y_tr).values())
    smote = SMOTE(k_neighbors=max(1, min(4, min_count - 1)), random_state=model_seed)
    X_tr_res, y_tr_res = smote.fit_resample(X_tr_c, y_tr)

    # Model training
    clf = ThreatClassifier(random_state=model_seed, feature_names=feats_c)
    clf.fit(X_tr_res, y_tr_res)

    y_pred = list(clf.model.predict(X_te_c))

    # Metrics calculation
    cm = confusion_matrix(y_te, y_pred, labels=classes)
    prec, rec, f1, supp = precision_recall_fscore_support(
        y_te, y_pred, labels=classes, zero_division=0
    )

    per_class_results = {}
    for i, cls in enumerate(classes):
        per_class_results[cls] = {
            "precision": round(float(prec[i]), 4),
            "recall": round(float(rec[i]), 4),
            "f1": round(float(f1[i]), 4),
            "support": int(supp[i]),
        }

    bi = classes.index("benign")
    total_test = len(y_te)
    actual_benign = int(sum(cm[bi]))
    actual_non_benign = int(total_test - actual_benign)

    # Benign false positives = actual attacks (rows != bi) predicted as benign (col == bi)
    benign_fp = int(sum(cm[i, bi] for i in range(len(classes)) if i != bi))
    # Benign false negatives = actual benign (row == bi) predicted as attack (cols != bi)
    benign_fn = int(sum(cm[bi, j] for j in range(len(classes)) if j != bi))

    multiclass_benign_fpr = round(benign_fp / max(actual_non_benign, 1), 6)
    benign_fnr = round(benign_fn / max(actual_benign, 1), 6)
    binary_false_alarm_rate = round(benign_fn / max(actual_benign, 1), 6)

    macro_f1 = round(float(f1_score(y_te, y_pred, average="macro", zero_division=0)), 4)
    weighted_f1 = round(float(f1_score(y_te, y_pred, average="weighted", zero_division=0)), 4)
    balanced_acc = round(float(balanced_accuracy_score(y_te, y_pred)), 4)

    # Comparison against existing canonical duplicate-aware benchmark
    canonical_artifact_path = Path(PROJECT_ROOT) / CANONICAL_ARTIFACT_REL_PATH
    canonical_summary = {}
    if canonical_artifact_path.exists():
        with open(canonical_artifact_path, "r", encoding="utf-8") as f:
            can_art = json.load(f)
            canonical_summary = {
                "split_strategy": "group_aware_fingerprint_holdout (clusters identical payloads)",
                "total_events": can_art["metadata"]["total_records"],
                "train_samples": can_art["metadata"]["train_samples"],
                "test_samples": can_art["metadata"]["test_samples"],
                "macro_f1": can_art["evaluation_results"]["macro_f1"],
                "weighted_f1": can_art["evaluation_results"]["weighted_f1"],
                "balanced_accuracy": can_art["evaluation_results"]["balanced_accuracy"],
                "benign_fpr": can_art["evaluation_results"]["benign_fpr"],
                "binary_false_alarm_rate": can_art["evaluation_results"]["binary_false_alarm_rate_on_benign"],
            }

    results = {
        "protocol_title": "AEGIS-ML Phase 17: Scenario-Aware Synthetic Evaluation",
        "timestamp": datetime.utcnow().isoformat(),
        "dataset_metadata": {
            "dataset_path": str(full_data_path),
            "dataset_sha256": dataset_sha256,
            "total_records": len(events),
            "split_seed": split_seed,
            "model_seed": model_seed,
            "generator_version": "2.0.0",
        },
        "split_methodology": {
            "strategy": "scenario_grouped_stratified_holdout",
            "description": (
                "Partitions entire scenario groups into train or test. "
                "Guarantees 0.0% scenario_id overlap across partitions."
            ),
            "total_scenarios": split_stats["total_scenarios"],
            "train_scenarios_count": split_stats["train_scenarios_count"],
            "test_scenarios_count": split_stats["test_scenarios_count"],
            "scenario_overlap_count": split_stats["scenario_overlap_count"],
            "scenarios_per_class": split_stats["scenarios_per_class"],
            "train_samples": len(tr_events),
            "test_samples": len(te_events),
            "class_distribution_train": dict(Counter(y_tr)),
            "class_distribution_test": dict(Counter(y_te)),
            "insufficient_scenario_warnings": split_stats["insufficient_scenario_warnings"],
        },
        "evaluation_results": {
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "balanced_accuracy": balanced_acc,
            "multiclass_benign_fpr": multiclass_benign_fpr,
            "benign_fpr_denominator": actual_non_benign,
            "benign_fpr_numerator": benign_fp,
            "benign_fnr": benign_fnr,
            "binary_false_alarm_rate_on_benign": binary_false_alarm_rate,
            "confusion_matrix": cm.tolist(),
            "per_class": per_class_results,
            "canonical_class_order": classes,
        },
        "instance_level_data": {
            "test_event_ids": [te_events[i].event_id for i in range(len(te_events))],
            "test_scenario_ids": [te_events[i].scenario_id for i in range(len(te_events))],
            "ground_truth_labels": y_te,
            "predicted_labels": y_pred,
        },
        "comparison_with_canonical_benchmark": {
            "canonical_benchmark": canonical_summary,
            "methodology_difference": (
                "The canonical benchmark uses fingerprint-grouped holdout, which isolates exact duplicate "
                "payloads but allows different loops of the same attack template in both partitions. "
                "The scenario-aware benchmark strictly holds out entire attack campaigns (scenario_id), "
                "measuring generalization to unobserved scenario instances."
            ),
        },
        "generalization_status": "COMPLETED_ON_SYNTHETIC_SCENARIO_HOLDOUT",
    }

    # Save artifact
    target_out = Path(PROJECT_ROOT) / output_path if not Path(output_path).is_absolute() else Path(output_path)
    target_out.parent.mkdir(parents=True, exist_ok=True)
    with open(target_out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(
        f"Scenario evaluation completed! Test Samples: {len(te_events)}, "
        f"Scenarios: {split_stats['train_scenarios_count']} train / {split_stats['test_scenarios_count']} test, "
        f"Macro-F1: {macro_f1}, Balanced Acc: {balanced_acc}"
    )
    return results


if __name__ == "__main__":
    evaluate_scenario_aware_holdout()
