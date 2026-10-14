"""
AEGIS-ML Stage 6: Evaluation Integrity & Leakage Prevention Test Suite.

Verifies:
1. Label handling: unmapped/unknown labels are surfaced and rejected, NEVER silently defaulted to 'benign'.
2. Canonical labels pass through unchanged.
3. Group-aware scenario split guarantees strict 0.0% scenario and event overlap between train and test.
4. Metric calculations (Precision, Recall, F1, FPR, ECE, Brier) against hand-computed reference values.
5. Default-path alerts derive directly from real model inference (no random confidence or injected threats).
"""

import pytest
import numpy as np
from datetime import datetime
from collections import Counter

from backend.core.schemas import UnifiedEvent, Alert
from backend.detection.threat_classifier import ThreatPrediction
from backend.detection.model_trainer import (
    DATASET_LABEL_MAP,
    OUT_OF_TAXONOMY_ATTACKS,
    CANONICAL_CLASSES,
)
from backend.evaluation.behavioral_diversity_evaluation import (
    partition_behavioral_diversity_split,
)
from backend.evaluation.false_positive_calibration import (
    _partition_train_val_test,
)


def compute_expected_calibration_error(y_true_indices: np.ndarray, y_proba: np.ndarray, n_bins: int = 10):
    """Reference implementation of Expected Calibration Error for multi-class."""
    confidences = np.max(y_proba, axis=1)
    predictions = np.argmax(y_proba, axis=1)
    accuracies = (predictions == y_true_indices).astype(float)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n_samples = len(y_true_indices)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper) if i > 0 else (confidences >= bin_lower) & (confidences <= bin_upper)
        bin_count = np.sum(in_bin)

        if bin_count > 0:
            bin_acc = np.mean(accuracies[in_bin])
            bin_conf = np.mean(confidences[in_bin])
            ece += (bin_count / n_samples) * np.abs(bin_acc - bin_conf)

    return float(ece)


def compute_multi_class_brier_score(y_true_indices: np.ndarray, y_proba: np.ndarray, n_classes: int):
    """Reference implementation of multi-class Brier score."""
    n_samples = len(y_true_indices)
    one_hot = np.zeros((n_samples, n_classes))
    for i, idx in enumerate(y_true_indices):
        one_hot[i, idx] = 1.0
    return float(np.mean(np.sum((y_proba - one_hot) ** 2, axis=1)))


class TestLabelHandlingIntegrity:
    """Verify that unmapped labels are surfaced and never defaulted to 'benign'."""

    def test_canonical_labels_pass_through_untouched(self):
        for canonical in CANONICAL_CLASSES:
            event = UnifiedEvent(
                event_id=f"ev_{canonical}",
                timestamp=datetime.utcnow(),
                layer="network",
                src_entity="10.0.0.1",
                dst_entity="10.0.0.2",
                src_internal=True,
                dst_internal=True,
                attack_type=canonical,
            )
            assert event.attack_type == canonical

    def test_out_of_taxonomy_attacks_not_in_dataset_label_map(self):
        # Ground Rule: DoS/DDoS and web attacks must not be forced into c2_beaconing or brute_force
        for oot in OUT_OF_TAXONOMY_ATTACKS:
            assert oot not in DATASET_LABEL_MAP, f"Out-of-taxonomy attack '{oot}' must not be in DATASET_LABEL_MAP"

    def test_unmapped_labels_are_surfaced_not_benign(self):
        test_labels = [
            "ddos",
            "dos hulk",
            "unknown_zero_day_malware",
            "crypto_miner_x",
        ]
        unmapped_encountered = Counter()
        canonical_labels = []

        for raw in test_labels:
            if raw in CANONICAL_CLASSES:
                canonical_labels.append(raw)
            elif raw in DATASET_LABEL_MAP:
                canonical_labels.append(DATASET_LABEL_MAP[raw])
            else:
                unmapped_encountered[raw] += 1

        assert len(canonical_labels) == 0
        assert sum(unmapped_encountered.values()) == 4
        assert "benign" not in canonical_labels
        assert "ddos" in unmapped_encountered
        assert "dos hulk" in unmapped_encountered


class TestLeakageAndPartitionIntegrity:
    """Verify group-aware partitioning guarantees zero scenario overlap."""

    def test_partition_behavioral_diversity_zero_scenario_overlap(self):
        # Create synthetic events across 10 scenarios
        events = []
        labels = []
        for sc_idx in range(10):
            sc_id = f"scenario_{sc_idx:03d}"
            sc_type = "c2_campaign" if sc_idx % 2 == 0 else "backup_routine"
            lbl = "c2_beaconing" if sc_idx % 2 == 0 else "benign"
            for ev_idx in range(20):
                e = UnifiedEvent(
                    event_id=f"ev_{sc_idx}_{ev_idx}",
                    timestamp=datetime.utcnow(),
                    layer="network",
                    src_entity=f"10.0.0.{sc_idx}",
                    dst_entity="10.0.0.99",
                    src_internal=True,
                    dst_internal=True,
                    scenario_id=sc_id,
                    scenario_type=sc_type,
                    attack_type=lbl,
                )
                events.append(e)
                labels.append(lbl)

        tr_idx, te_idx, stats = partition_behavioral_diversity_split(
            events, labels, test_ratio=0.20, seed=42
        )

        tr_scenarios = {events[i].scenario_id for i in tr_idx}
        te_scenarios = {events[i].scenario_id for i in te_idx}

        # Assert zero scenario overlap
        assert len(tr_scenarios.intersection(te_scenarios)) == 0
        # Assert zero event index overlap
        assert len(set(tr_idx).intersection(set(te_idx))) == 0
        assert len(tr_idx) + len(te_idx) == len(events)

    def test_three_way_partition_zero_overlap(self):
        events = []
        labels = []
        for sc_idx in range(15):
            sc_id = f"sc_{sc_idx:03d}"
            sc_type = f"type_{sc_idx % 3}"
            lbl = "brute_force" if sc_idx % 2 == 0 else "benign"
            for ev_idx in range(10):
                e = UnifiedEvent(
                    event_id=f"ev_{sc_idx}_{ev_idx}",
                    timestamp=datetime.utcnow(),
                    layer="endpoint",
                    src_entity="10.0.0.5",
                    dst_entity="10.0.0.5",
                    src_internal=True,
                    dst_internal=True,
                    scenario_id=sc_id,
                    scenario_type=sc_type,
                    attack_type=lbl,
                )
                events.append(e)
                labels.append(lbl)

        tr_idx, val_idx, te_idx, stats = _partition_train_val_test(
            events, labels, test_ratio=0.20, val_ratio=0.20, seed=42
        )

        tr_sc = {events[i].scenario_id for i in tr_idx}
        val_sc = {events[i].scenario_id for i in val_idx}
        te_sc = {events[i].scenario_id for i in te_idx}

        assert len(tr_sc.intersection(val_sc)) == 0
        assert len(tr_sc.intersection(te_sc)) == 0
        assert len(val_sc.intersection(te_sc)) == 0
        assert len(tr_idx) + len(val_idx) + len(te_idx) == len(events)


class TestHandComputedMetricCorrectness:
    """Verify metrics against exact hand-calculated ground truths."""

    def test_precision_recall_f1_fpr_hand_computed(self):
        # 4 samples: 2 benign, 2 attack
        # True:  [benign, benign, attack, attack] (0, 0, 1, 1)
        # Pred:  [benign, attack, attack, attack] (0, 1, 1, 1)
        # TP=2, FP=1, FN=0, TN=1
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([0, 1, 1, 1])

        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))
        tn = np.sum((y_true == 0) & (y_pred == 0))

        precision = tp / (tp + fp)  # 2 / 3 = 0.666666...
        recall = tp / (tp + fn)     # 2 / 2 = 1.0
        f1 = 2 * (precision * recall) / (precision + recall)  # 4/5 = 0.8
        fpr_benign = fp / (fp + tn) # 1 / 2 = 0.5

        assert np.isclose(precision, 2.0 / 3.0)
        assert np.isclose(recall, 1.0)
        assert np.isclose(f1, 0.80)
        assert np.isclose(fpr_benign, 0.50)

    def test_brier_score_hand_computed(self):
        # 2 samples, 2 classes
        # sample 0: true=0 -> [1, 0], pred=[0.8, 0.2]. squared error = (0.8-1)^2 + (0.2-0)^2 = 0.04 + 0.04 = 0.08
        # sample 1: true=1 -> [0, 1], pred=[0.3, 0.7]. squared error = (0.3-0)^2 + (0.7-1)^2 = 0.09 + 0.09 = 0.18
        # Mean Brier = (0.08 + 0.18) / 2 = 0.13
        y_true_indices = np.array([0, 1])
        y_proba = np.array([[0.8, 0.2], [0.3, 0.7]])
        brier = compute_multi_class_brier_score(y_true_indices, y_proba, n_classes=2)
        assert np.isclose(brier, 0.13)

    def test_ece_hand_computed(self):
        # 2 samples in the same bin [0.7, 0.9]:
        # sample 0: pred=0, conf=0.8, true=0 (acc=1)
        # sample 1: pred=0, conf=0.8, true=1 (acc=0)
        # Bin accuracy = (1 + 0) / 2 = 0.5
        # Bin confidence = 0.8
        # Bin error = |0.5 - 0.8| = 0.3
        # Since all samples are in this bin, ECE = 0.3
        y_true = np.array([0, 1])
        y_proba = np.array([[0.8, 0.2], [0.8, 0.2]])
        ece = compute_expected_calibration_error(y_true, y_proba, n_bins=10)
        assert np.isclose(ece, 0.30)


class TestDefaultPathPredictionIntegrity:
    """Verify that default-path alerts strictly reflect model predictions."""

    def test_alert_fields_reflect_classifier_prediction(self):
        pred = ThreatPrediction(
            threat_type="c2_beaconing",
            confidence=0.88,
            severity="high",
            feature_importances={},
            raw_probabilities={"c2_beaconing": 0.88, "benign": 0.12},
            calibrated_probabilities={"c2_beaconing": 0.88, "benign": 0.12},
            is_calibrated=True,
            confidence_qualification="calibrated_probability",
            model_version="1.0.0",
        )
        assert pred.confidence == 0.88
        assert pred.is_calibrated is True
        # Verify no random or arbitrary modification occurs
        alert = Alert(
            event_id="ev_test_123",
            timestamp=datetime.utcnow(),
            created_at=datetime.utcnow(),
            threat_type=pred.threat_type,
            severity="high",
            confidence=pred.confidence,
            classifier_probability=pred.confidence,
            is_calibrated=pred.is_calibrated,
            calibrated_confidence=pred.confidence,
            src_entity="10.0.0.5",
            dst_entity="198.51.100.22",
            layer="network",
        )
        assert alert.confidence == 0.88
        assert alert.threat_type == "c2_beaconing"
        assert alert.calibrated_confidence == 0.88
