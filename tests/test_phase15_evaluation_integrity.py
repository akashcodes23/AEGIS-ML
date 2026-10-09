"""AEGIS-ML Phase 15 Evaluation Integrity & Invariant Tests.

Asserts:
1. Confusion-matrix totals equal the number of test samples.
2. Row totals equal true-class supports.
3. Column totals equal predicted-class supports.
4. Precision, recall, and F1 match the confusion matrix calculations.
5. Macro-F1 equals the unweighted arithmetic mean of class F1 scores.
6. Balanced accuracy equals the unweighted mean of class recall scores.
7. Multiclass benign FPR and FNR use distinct, correct denominators.
8. Canonical ground-truth labels and predictions have equal lengths.
9. Unsupported labels are rejected or tracked, never silently mapped to benign.
"""

import json
from pathlib import Path
import numpy as np
import pytest
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
)

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import UnifiedEvent
from backend.detection.model_trainer import (
    CANONICAL_CLASSES,
    load_flexible_dataset,
)
from backend.evaluation.canonical_artifact import (
    compute_consistent_metrics,
    verify_canonical_artifact_consistency,
)


ARTIFACT_PATH = Path(PROJECT_ROOT) / "data" / "models" / "canonical_evaluation_artifact.json"
DATASET_PATH = Path(PROJECT_ROOT) / "data" / "raw" / "combined_labeled.jsonl"


@pytest.fixture(scope="module")
def canonical_artifact():
    assert ARTIFACT_PATH.exists(), f"Canonical artifact missing at {ARTIFACT_PATH}"
    with open(ARTIFACT_PATH, "r") as f:
        return json.load(f)


def test_confusion_matrix_total_equals_sample_count(canonical_artifact):
    """Invariant 1: Sum of all cells in confusion matrix must equal test sample count."""
    cm = np.array(canonical_artifact["evaluation_results"]["confusion_matrix"])
    n_samples = canonical_artifact["metadata"]["test_samples"]
    y_true = canonical_artifact["instance_level_data"]["ground_truth_labels"]
    y_pred = canonical_artifact["instance_level_data"]["predicted_labels"]

    assert len(y_true) == n_samples
    assert len(y_pred) == n_samples
    assert cm.sum() == n_samples


def test_row_totals_equal_true_class_supports(canonical_artifact):
    """Invariant 2: Confusion matrix row sums must equal ground-truth class supports."""
    cm = np.array(canonical_artifact["evaluation_results"]["confusion_matrix"])
    classes = canonical_artifact["metadata"]["canonical_class_order"]
    per_class = canonical_artifact["evaluation_results"]["per_class"]

    for i, cls in enumerate(classes):
        row_sum = int(cm[i].sum())
        expected_support = per_class[cls]["support"]
        assert row_sum == expected_support, f"Row sum for {cls} ({row_sum}) != support ({expected_support})"


def test_column_totals_equal_predicted_class_supports(canonical_artifact):
    """Invariant 3: Confusion matrix column sums must equal total predictions for that class."""
    cm = np.array(canonical_artifact["evaluation_results"]["confusion_matrix"])
    classes = canonical_artifact["metadata"]["canonical_class_order"]
    y_pred = canonical_artifact["instance_level_data"]["predicted_labels"]

    for j, cls in enumerate(classes):
        col_sum = int(cm[:, j].sum())
        actual_pred_count = sum(1 for p in y_pred if p == cls)
        assert col_sum == actual_pred_count, f"Column sum for {cls} ({col_sum}) != pred count ({actual_pred_count})"


def test_precision_recall_f1_match_confusion_matrix(canonical_artifact):
    """Invariant 4: Precision, recall, and F1 must derive exactly from TP, FP, FN in the confusion matrix."""
    cm = np.array(canonical_artifact["evaluation_results"]["confusion_matrix"])
    classes = canonical_artifact["metadata"]["canonical_class_order"]
    per_class = canonical_artifact["evaluation_results"]["per_class"]

    for i, cls in enumerate(classes):
        tp = float(cm[i, i])
        fp = float(cm[:, i].sum() - tp)
        fn = float(cm[i, :].sum() - tp)

        expected_prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        expected_rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        expected_f1 = (
            (2 * expected_prec * expected_rec) / (expected_prec + expected_rec)
            if (expected_prec + expected_rec) > 0
            else 0.0
        )

        reported = per_class[cls]
        assert abs(reported["precision"] - round(expected_prec, 4)) < 1e-4
        assert abs(reported["recall"] - round(expected_rec, 4)) < 1e-4
        assert abs(reported["f1"] - round(expected_f1, 4)) < 1e-4


def test_macro_f1_equals_mean_class_f1(canonical_artifact):
    """Invariant 5: Macro-F1 must equal unweighted arithmetic mean of per-class F1 scores."""
    classes = canonical_artifact["metadata"]["canonical_class_order"]
    per_class = canonical_artifact["evaluation_results"]["per_class"]
    reported_macro_f1 = canonical_artifact["evaluation_results"]["macro_f1"]

    f1_list = [per_class[cls]["f1"] for cls in classes]
    calculated_mean_f1 = round(float(np.mean(f1_list)), 4)

    assert abs(reported_macro_f1 - calculated_mean_f1) < 1e-3


def test_balanced_accuracy_equals_mean_class_recall(canonical_artifact):
    """Invariant 6: Balanced accuracy must equal unweighted arithmetic mean of per-class recall scores."""
    classes = canonical_artifact["metadata"]["canonical_class_order"]
    per_class = canonical_artifact["evaluation_results"]["per_class"]
    reported_bal_acc = canonical_artifact["evaluation_results"]["balanced_accuracy"]

    rec_list = [per_class[cls]["recall"] for cls in classes]
    calculated_mean_rec = round(float(np.mean(rec_list)), 4)

    assert abs(reported_bal_acc - calculated_mean_rec) < 1e-3


def test_benign_fpr_and_fnr_use_distinct_correct_denominators(canonical_artifact):
    """Invariant 7: Multiclass benign FPR and FNR must use distinct, mathematically correct denominators."""
    cm = np.array(canonical_artifact["evaluation_results"]["confusion_matrix"])
    res = canonical_artifact["evaluation_results"]

    actual_benign = int(cm[0].sum())  # Row 0
    actual_non_benign = int(cm.sum() - actual_benign)  # Rows 1..4

    benign_fp = int(cm[1:, 0].sum())  # Column 0 except row 0
    benign_fn = int(cm[0, 1:].sum())  # Row 0 except col 0

    assert actual_benign == 410
    assert actual_non_benign == 990
    assert benign_fp == 0
    assert benign_fn == 3

    # FPR denominator must be actual non-benign (990)
    assert res["benign_fpr_denominator"] == actual_non_benign
    assert res["benign_fpr_numerator"] == benign_fp
    assert res["benign_fpr"] == 0.0

    # FNR denominator must be actual benign (410)
    assert res["benign_fnr_denominator"] == actual_benign
    assert res["benign_fnr_numerator"] == benign_fn
    assert abs(res["benign_fnr"] - (3 / 410)) < 1e-4

    # Binary false alarm rate on benign traffic equals benign_fn / actual_benign
    assert abs(res["binary_false_alarm_rate_on_benign"] - (3 / 410)) < 1e-4


def test_canonical_labels_and_predictions_equal_lengths(canonical_artifact):
    """Invariant 8: Ground-truth labels and prediction arrays must be non-empty and equal length."""
    y_true = canonical_artifact["instance_level_data"]["ground_truth_labels"]
    y_pred = canonical_artifact["instance_level_data"]["predicted_labels"]
    test_ids = canonical_artifact["instance_level_data"]["test_event_ids"]

    assert len(y_true) > 0
    assert len(y_true) == len(y_pred)
    assert len(y_true) == len(test_ids)
    assert len(y_true) == canonical_artifact["metadata"]["test_samples"]


def test_unsupported_labels_never_silently_mapped_to_benign(tmp_path):
    """Invariant 9: Unsupported labels must be rejected or counted, never silently converted to benign."""
    synthetic_file = tmp_path / "test_unsupported.jsonl"
    events_content = [
        {"timestamp": "2026-10-09T10:00:00", "layer": "network", "src_entity": "10.0.0.1", "dst_entity": "10.0.0.2", "attack_type": "benign"},
        {"timestamp": "2026-10-09T10:00:01", "layer": "network", "src_entity": "10.0.0.1", "dst_entity": "10.0.0.3", "attack_type": "unknown_exploit_xyz"},
        {"timestamp": "2026-10-09T10:00:02", "layer": "network", "src_entity": "10.0.0.1", "dst_entity": "10.0.0.4", "attack_type": "quantum_ransomware_abc"},
    ]
    with open(synthetic_file, "w") as f:
        for ev in events_content:
            f.write(json.dumps(ev) + "\n")

    loaded_events, stats = load_flexible_dataset(str(synthetic_file))

    # Exactly 1 valid benign event should be loaded
    assert len(loaded_events) == 1
    assert loaded_events[0].attack_type == "benign"

    # Both unknown labels must be counted as rejected, NOT mapped to benign
    assert stats["rejected_records"] == 2
    assert "unknown_exploit_xyz" in stats["unmapped_labels_encountered"]
    assert "quantum_ransomware_abc" in stats["unmapped_labels_encountered"]
    for ev in loaded_events:
        assert ev.attack_type in CANONICAL_CLASSES


def test_independent_scikit_learn_verification(canonical_artifact):
    """Verify that all canonical metrics match scikit-learn standard library calculations exactly."""
    classes = canonical_artifact["metadata"]["canonical_class_order"]
    y_true = canonical_artifact["instance_level_data"]["ground_truth_labels"]
    y_pred = canonical_artifact["instance_level_data"]["predicted_labels"]

    skl_cm = confusion_matrix(y_true, y_pred, labels=classes)
    skl_macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    skl_weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    skl_bal_acc = balanced_accuracy_score(y_true, y_pred)

    rep_results = canonical_artifact["evaluation_results"]
    assert (np.array(rep_results["confusion_matrix"]) == skl_cm).all()
    assert abs(rep_results["macro_f1"] - skl_macro_f1) < 1e-4
    assert abs(rep_results["weighted_f1"] - skl_weighted_f1) < 1e-4
    assert abs(rep_results["balanced_accuracy"] - skl_bal_acc) < 1e-4
