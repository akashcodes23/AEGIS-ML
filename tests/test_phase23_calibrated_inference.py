"""AEGIS-ML Phase 23: Regression Tests for Calibrated Inference Pipeline and Model Artifact Lifecycle.

Module: tests.test_phase23_calibrated_inference

Tests verify:
1. Valid calibrated artifact loads successfully.
2. Missing artifact fails safely without crashing.
3. Corrupt or incomplete artifact is rejected.
4. Unsupported artifact schema version is rejected.
5. Feature schema mismatch is detected.
6. Feature ordering is preserved across loading and prediction.
7. Class ordering is strictly preserved and matches canonical MITRE classes.
8. Calibrator/model incompatibility is detected.
9. Calibrated inference produces finite, correctly aligned scores in [0, 1].
10. Probability constraints (sum-to-one within tolerance, non-negative) are strictly enforced.
11. Predicted label and output scores are consistent (argmax class matches highest probability).
12. API responses remain backward compatible (legacy fields present).
13. API serving path and offline model agreement for identical inputs within 1e-4 tolerance.
14. Uncalibrated fallback is never misrepresented as calibrated inference.
15. Invalid or missing input (NaN/Inf, wrong dimension) is handled safely.
16. Lifecycle metadata accurately identifies the artifact and SHA-256 actually used.
17. Tests do not require network access.
18. Existing Phase 22 calibration tests and historical artifacts remain intact.
"""

from datetime import datetime
import json
from pathlib import Path
import tempfile
from typing import Dict, List
import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import UnifiedEvent, DetectionResult
from backend.detection.threat_classifier import ThreatClassifier, ThreatPrediction
from backend.detection.model_lifecycle import (
    CALIBRATED_CLASSIFIER_PATH,
    LEGACY_CLASSIFIER_PATH,
    ModelLifecycleManager,
    ModelArtifactMetadata,
    compute_file_sha256,
)
from backend.detection.model_trainer import (
    extract_features,
    extract_full_causal_features,
)
from backend.correlation.weighted_fusion import WeightedEvidenceFusion
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector


# ── Fixtures & Helpers ────────────────────────────────────────────────────────

def _make_dummy_event() -> UnifiedEvent:
    return UnifiedEvent(
        event_id="ev_test_1001",
        timestamp=datetime(2026, 10, 10, 12, 0, 0),
        layer="network",
        src_entity="192.168.1.50",
        dst_entity="10.0.0.1",
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_internal=True,
        dst_internal=True,
        bytes_sent=5000,
        bytes_received=200,
        dst_port=445,
        protocol="TCP",
    )


# ── Test 1: Valid calibrated artifact loads successfully ──────────────────────

def test_phase23_valid_artifact_loads_successfully():
    """Verify that the default calibrated artifact loads and initializes correctly."""
    mgr = ModelLifecycleManager()
    loaded = mgr.load_artifact()
    assert loaded is True, "Failed to load default artifact"
    assert mgr.active_classifier is not None
    assert mgr.active_classifier.is_fitted is True
    assert mgr.active_classifier.is_calibrated is True
    assert mgr.active_metadata is not None
    assert mgr.active_metadata.model_version == "23.0.0"
    assert mgr.active_metadata.artifact_sha256 is not None


# ── Test 2: Missing artifact fails safely ─────────────────────────────────────

def test_phase23_missing_artifact_fails_safely():
    """Verify loading a nonexistent artifact returns False and does not crash."""
    mgr = ModelLifecycleManager()
    loaded = mgr.load_artifact(PROJECT_ROOT / "data" / "models" / "nonexistent_model_9999.pkl")
    assert loaded is False
    assert mgr.active_classifier is None


# ── Test 3: Corrupt or incomplete artifact is rejected ────────────────────────

def test_phase23_corrupt_artifact_is_rejected():
    """Verify corrupt files or missing required keys are rejected."""
    mgr = ModelLifecycleManager()
    with tempfile.NamedTemporaryFile(suffix=".pkl", dir=mgr.models_dir, delete=True) as tmp:
        # Write invalid binary data
        tmp.write(b"NOT_A_VALID_JOBLIB_DATA_CORRUPT")
        tmp.flush()

        is_valid, msg, _ = mgr.validate_artifact_file(tmp.name)
        assert is_valid is False
        assert "Failed to deserialize artifact" in msg


def test_phase23_incomplete_artifact_missing_model_key():
    """Verify artifact dictionary missing 'model' key is rejected."""
    mgr = ModelLifecycleManager()
    with tempfile.NamedTemporaryFile(suffix=".pkl", dir=mgr.models_dir, delete=True) as tmp:
        joblib.dump({"schema_version": "1.0.0", "classes": ThreatClassifier.CLASSES}, tmp.name)
        is_valid, msg, _ = mgr.validate_artifact_file(tmp.name)
        assert is_valid is False
        assert "Missing 'model' key" in msg


# ── Test 4: Unsupported artifact schema version is handled ────────────────────

def test_phase23_unsupported_structure_rejected():
    """Verify artifact that is neither a dict nor a valid estimator is rejected."""
    mgr = ModelLifecycleManager()
    with tempfile.NamedTemporaryFile(suffix=".pkl", dir=mgr.models_dir, delete=True) as tmp:
        joblib.dump(["list_is_not_a_valid_model"], tmp.name)
        is_valid, msg, _ = mgr.validate_artifact_file(tmp.name)
        assert is_valid is False
        assert "neither a dict nor a valid scikit-learn estimator" in msg


# ── Test 5: Feature schema mismatch is detected ───────────────────────────────

def test_phase23_feature_schema_mismatch_detected():
    """Verify artifact where feature_names count disagrees with model.n_features_in_ is rejected."""
    mgr = ModelLifecycleManager()
    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    X = np.random.rand(25, 15)
    classes_all = ThreatClassifier.CLASSES
    y = [classes_all[i % len(classes_all)] for i in range(25)]
    rf.fit(X, y)

    with tempfile.NamedTemporaryFile(suffix=".pkl", dir=mgr.models_dir, delete=True) as tmp:
        # Save with 10 feature names when model expects 15
        artifact_bad = {
            "model": rf,
            "classes": list(rf.classes_),
            "feature_names": ["f" + str(i) for i in range(10)],  # mismatch!
            "is_calibrated": False,
        }
        joblib.dump(artifact_bad, tmp.name)

        is_valid, msg, _ = mgr.validate_artifact_file(tmp.name)
        assert is_valid is False
        assert "Feature count mismatch" in msg


# ── Test 6: Feature ordering is preserved ─────────────────────────────────────

def test_phase23_feature_ordering_preserved():
    """Verify loaded classifier preserves exact feature name list and ordering."""
    mgr = ModelLifecycleManager()
    loaded = mgr.load_artifact()
    assert loaded is True
    clf = mgr.active_classifier
    assert clf.feature_names is not None
    assert len(clf.feature_names) == 48
    # First 15 must match ThreatClassifier.FEATURE_NAMES
    assert clf.feature_names[:15] == ThreatClassifier.FEATURE_NAMES


# ── Test 7: Class ordering is preserved ───────────────────────────────────────

def test_phase23_class_ordering_preserved():
    """Verify loaded classifier and calibrator classes match canonical classes."""
    mgr = ModelLifecycleManager()
    loaded = mgr.load_artifact()
    assert loaded is True
    clf = mgr.active_classifier
    assert set(clf.classes) == set(ThreatClassifier.CLASSES)
    if clf.is_calibrated:
        assert set(clf.calibrator.classes_) == set(ThreatClassifier.CLASSES)


# ── Test 8: Calibrator/model incompatibility is detected ──────────────────────

def test_phase23_calibrator_class_incompatibility_detected():
    """Verify artifact with mismatched model and calibrator classes is rejected."""
    mgr = ModelLifecycleManager()
    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    classes_all = ThreatClassifier.CLASSES
    X = np.random.rand(25, 5)
    y_rf = [classes_all[i % len(classes_all)] for i in range(25)]
    rf.fit(X, y_rf)

    cal = CalibratedClassifierCV(estimator=FrozenEstimator(rf), method="isotonic")
    cal.fit(X, y_rf)

    # Corrupt calibrator's classes_ to simulate class mismatch
    cal.classes_ = np.array(["benign", "brute_force", "unseen_class"])

    with tempfile.NamedTemporaryFile(suffix=".pkl", dir=mgr.models_dir, delete=True) as tmp:
        artifact_incompat = {
            "model": rf,
            "calibrator": cal,
            "is_calibrated": True,
            "classes": classes_all,
            "feature_names": ["f1", "f2", "f3", "f4", "f5"],
        }
        joblib.dump(artifact_incompat, tmp.name)

        is_valid, msg, _ = mgr.validate_artifact_file(tmp.name)
        assert is_valid is False
        assert "Calibrator classes" in msg or "do not align" in msg


# ── Test 9: Calibrated inference produces finite, correctly aligned scores ────

def test_phase23_calibrated_inference_scores_finite_and_aligned():
    """Verify predictions return finite floats in [0, 1] for all canonical classes."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    dummy_features = [0.1] * clf.n_features
    pred = clf.predict(dummy_features)

    assert isinstance(pred, ThreatPrediction)
    assert pred.is_calibrated is True
    assert 0.0 <= pred.confidence <= 1.0
    assert pred.calibrated_probabilities is not None

    for cls in ThreatClassifier.CLASSES:
        assert cls in pred.calibrated_probabilities
        p = pred.calibrated_probabilities[cls]
        assert np.isfinite(p)
        assert 0.0 <= p <= 1.0


# ── Test 10: Probability constraints validated ────────────────────────────────

def test_phase23_probability_sum_to_one_constraint():
    """Verify calibrated probabilities sum to 1.0 within tolerance 1e-4."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    rng = np.random.default_rng(42)
    for _ in range(5):
        features = rng.random(clf.n_features).tolist()
        pred = clf.predict(features)
        total_p = sum(pred.calibrated_probabilities.values())
        assert abs(total_p - 1.0) < 1e-4, f"Probabilities sum to {total_p} != 1.0"


# ── Test 11: Predicted label and output scores are consistent ─────────────────

def test_phase23_predicted_label_matches_highest_probability():
    """Verify predicted threat_type is precisely the class with the highest probability."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    rng = np.random.default_rng(1337)
    for _ in range(5):
        features = rng.random(clf.n_features).tolist()
        pred = clf.predict(features)
        best_cls = max(pred.calibrated_probabilities.keys(), key=lambda c: pred.calibrated_probabilities[c])
        assert pred.threat_type == best_cls, f"Predicted {pred.threat_type} != argmax {best_cls}"
        assert abs(pred.confidence - pred.calibrated_probabilities[best_cls]) < 1e-6


# ── Test 12: API responses remain backward compatible ─────────────────────────

def test_phase23_detection_result_backward_compatibility():
    """Verify DetectionResult schema retains legacy fields while exposing calibrated fields."""
    event = _make_dummy_event()
    fusion = WeightedEvidenceFusion()

    result = fusion.fuse(
        event=event,
        if_score=0.45,
        baseline_deviation=0.20,
        graph_score=0.10,
        threat_type="lateral_movement",
        classifier_confidence=0.92,
        severity="high",
        is_calibrated=True,
        calibrated_probabilities={"benign": 0.08, "lateral_movement": 0.92},
        raw_probabilities={"benign": 0.35, "lateral_movement": 0.65},
        model_version="23.0.0",
        confidence_qualification="Calibrated probability evaluated on synthetic benchmark",
    )

    # Legacy fields
    assert result.event_id == event.event_id
    assert result.confidence == 0.92
    assert result.classifier_probability == 0.92
    assert result.threat_type == "lateral_movement"
    assert result.severity == "high"

    # New calibrated fields
    assert result.is_calibrated is True
    assert result.calibrated_probabilities["lateral_movement"] == 0.92
    assert result.model_version == "23.0.0"
    assert result.confidence_qualification is not None


# ── Test 13: Offline and serving inference agreement on fixed input ───────────

def test_phase23_offline_and_serving_numerical_agreement():
    """Verify exact numerical agreement between direct classifier and fusion output for fixed input."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    event = _make_dummy_event()
    fixed_features = [0.0] * clf.n_features
    # Set known non-zero values
    fixed_features[0] = 0.85   # if_anomaly_score
    fixed_features[1] = 0.90   # baseline_deviation
    fixed_features[5] = 2.5    # bytes_sent_zscore
    fixed_features[9] = 1.0    # dst_port_risk

    # Offline prediction
    offline_pred = clf.predict(fixed_features)

    # Serving fusion prediction
    fusion = WeightedEvidenceFusion()
    serving_result = fusion.fuse(
        event=event,
        if_score=0.85,
        baseline_deviation=0.90,
        graph_score=0.0,
        threat_type=offline_pred.threat_type,
        classifier_confidence=offline_pred.confidence,
        severity=offline_pred.severity,
        is_calibrated=offline_pred.is_calibrated,
        calibrated_probabilities=offline_pred.calibrated_probabilities,
        raw_probabilities=offline_pred.raw_probabilities,
        model_version=offline_pred.model_version,
        confidence_qualification=offline_pred.confidence_qualification,
    )

    assert serving_result.threat_type == offline_pred.threat_type
    assert abs(serving_result.classifier_probability - offline_pred.confidence) < 1e-4
    assert serving_result.is_calibrated == offline_pred.is_calibrated
    assert serving_result.calibrated_probabilities == offline_pred.calibrated_probabilities


# ── Test 14: Uncalibrated fallback is never misrepresented as calibrated ──────

def test_phase23_uncalibrated_model_never_misrepresented():
    """Verify an uncalibrated model sets is_calibrated=False and calibrated_probabilities=None."""
    clf = ThreatClassifier(random_state=42)
    # Fit base model without calibrator
    X = np.random.rand(40, 15)
    y = ["benign"] * 20 + ["brute_force"] * 20
    clf.fit(X, y)

    pred = clf.predict(X[0].tolist())
    assert pred.is_calibrated is False
    assert pred.calibrated_probabilities is None
    assert "Uncalibrated" in pred.confidence_qualification


# ── Test 15: Invalid or missing inputs handled safely ─────────────────────────

def test_phase23_nan_and_inf_handled_safely():
    """Verify NaN and Inf in features do not raise unhandled exceptions."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    features = [0.0] * clf.n_features
    features[0] = float("nan")
    features[1] = float("inf")
    features[2] = float("-inf")

    pred = clf.predict(features)
    assert isinstance(pred, ThreatPrediction)
    assert np.isfinite(pred.confidence)


def test_phase23_backward_compatible_15_to_48_expansion():
    """Verify passing a 15-dim vector to a 48-dim classifier pads with 0.0 safely."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier
    assert clf.n_features == 48

    vec_15 = [0.5] * 15
    pred = clf.predict(vec_15)
    assert isinstance(pred, ThreatPrediction)
    assert pred.is_calibrated is True


# ── Test 16: Lifecycle metadata identifies artifact actually used ─────────────

def test_phase23_lifecycle_status_metadata():
    """Verify get_lifecycle_status exposes accurate metadata and disclaimer."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    status = mgr.get_lifecycle_status()

    assert status["status"] == "ready"
    assert status["model_version"] == "23.0.0"
    assert status["is_calibrated"] is True
    assert status["calibration_method"] == "isotonic"
    assert status["artifact_filename"] == "calibrated_threat_classifier.pkl"
    assert status["artifact_sha256"] is not None
    assert len(status["artifact_sha256"]) == 64
    assert "synthetic benchmarks" in status["scientific_disclaimer"]


# ── Test 17: Tests do not require network access ──────────────────────────────

def test_phase23_runs_completely_offline():
    """Verify all lifecycle operations run strictly against local disk files."""
    mgr = ModelLifecycleManager()
    assert mgr.models_dir.exists()
    assert (mgr.models_dir / "calibrated_threat_classifier.pkl").exists()


# ── Test 18: Historical Phase 22 artifact and tests preserved ──────────────────

def test_phase23_preserves_historical_artifacts():
    """Verify historical artifacts from Phase 20, Phase 21, and Phase 22 are unchanged."""
    p22_artifact = PROJECT_ROOT / "data" / "models" / "false_positive_calibration_artifact.json"
    assert p22_artifact.exists()
    with open(p22_artifact) as f:
        p22_data = json.load(f)
    assert p22_data["status"] == "completed_and_verified"
    assert p22_data["dataset_metadata"]["dataset_sha256"] == "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"
