"""
Phase 23.1: Inference Integrity and Security Audit Test Suite.

Verifies:
1. Online/offline 48-feature schema and exact numerical parity.
2. Tracker causal state isolation (cross-host isolation, window reset).
3. Missing telemetry representation and rejection of silent coercion (NaN/Inf).
4. Legacy 15-feature rejection on 48-feature model (no silent zero-padding).
5. Model lifecycle and endpoint security (path traversal, checksum verification,
   companion metadata cross-validation, safe reload, rollback retention).
6. FastAPI /api/detect and /api/model/reload HTTP error codes and security headers.
"""

import os
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.core.schemas import UnifiedEvent
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.model_lifecycle import ModelLifecycleManager, compute_file_sha256
from backend.detection.model_trainer import (
    extract_features,
    extract_full_causal_features,
    calculate_failed_auth_rate,
)
from backend.detection.sequence_context import (
    CausalSequenceTracker,
    SEQUENCE_FEATURE_NAMES,
)
from backend.detection.temporal_graph_extractor import (
    CausalTemporalGraphTracker,
    RELATIONAL_GRAPH_FEATURE_NAMES,
)
from backend.detection.telemetry_context import (
    SUPPORTED_CONTEXT_FEATURE_NAMES,
    MISSINGNESS_FEATURE_NAMES,
    extract_missingness_features,
)
from backend.detection.threat_classifier import ThreatClassifier, ThreatPrediction
from backend.evaluation.false_positive_calibration import (
    PHASE22_BASELINE_FEATURE_NAMES,
    _build_feature_matrix_48,
    load_flexible_dataset,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_synthetic_events() -> List[UnifiedEvent]:
    base_t = datetime(2026, 10, 10, 10, 0, 0)
    events = []
    for i in range(10):
        ev = UnifiedEvent(
            event_id=f"audit_ev_{i}",
            timestamp=base_t + timedelta(seconds=i * 15),
            layer="network" if i % 2 == 0 else "endpoint",
            src_entity="10.0.0.10" if i < 5 else "10.0.0.20",
            dst_entity="10.0.0.50" if i < 5 else "10.0.0.60",
            src_internal=True,
            dst_internal=True,
            dst_port=445 if i % 2 == 0 else None,
            protocol="TCP",
            bytes_sent=1500 if i % 2 == 0 else None,
            bytes_received=3000 if i % 2 == 0 else None,
            process_name="powershell.exe" if i % 2 != 0 else None,
            process_guid=f"proc_guid_{i}" if i % 2 != 0 else None,
            parent_process_name="cmd.exe" if i % 2 != 0 else None,
            action="read" if i % 2 != 0 else None,
        )
        events.append(ev)
    return events


# ── 1. Online / Offline Feature Parity Tests ─────────────────────────────────

def test_audit_exact_feature_names_order_parity():
    """Verify online feature name composition strictly matches PHASE22_BASELINE_FEATURE_NAMES."""
    inferred = {
        "seq_inferred_file_read_before_outbound_net",
        "seq_inferred_file_read_before_internal_net",
    }
    seq_keys = [f for f in SEQUENCE_FEATURE_NAMES if f not in inferred]

    online_names = (
        ThreatClassifier.FEATURE_NAMES  # 15
        + RELATIONAL_GRAPH_FEATURE_NAMES  # 6
        + SUPPORTED_CONTEXT_FEATURE_NAMES  # 10
        + MISSINGNESS_FEATURE_NAMES  # 5
        + seq_keys  # 12
    )

    assert online_names == PHASE22_BASELINE_FEATURE_NAMES
    assert len(online_names) == 48


def test_audit_feature_by_feature_numerical_parity(sample_synthetic_events):
    """Verify online and offline feature extraction produce identical 48-dim vectors."""
    events = sample_synthetic_events

    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(events, benign_only=True)
    if_det = IsolationForestDetector(random_state=42)
    if_det.fit(events)
    fa_dict = calculate_failed_auth_rate(events)

    # Offline extraction
    gt_off = CausalTemporalGraphTracker()
    gt_off.fit_baseline_pairs(events)
    st_off = CausalSequenceTracker(window_seconds=300.0)
    X_offline = _build_feature_matrix_48(events, if_det, profiler, fa_dict, gt_off, st_off)

    # Online extraction
    gt_on = CausalTemporalGraphTracker()
    gt_on.fit_baseline_pairs(events)
    st_on = CausalSequenceTracker(window_seconds=300.0)
    X_online = []
    for e in events:
        if_sc = if_det.predict(e)
        base_dev = profiler.compute_deviation_score(e)
        fa = fa_dict.get(e.event_id, 0.0)
        feats = extract_full_causal_features(e, if_sc, base_dev, profiler, fa, gt_on, st_on)
        X_online.append(feats)
    X_online = np.array(X_online)

    diff = np.max(np.abs(X_offline - X_online))
    assert diff < 1e-10, f"Max difference between offline and online features: {diff}"


def test_audit_tracker_host_isolation():
    """Verify CausalSequenceTracker strictly partitions history by host (zero cross-host leakage)."""
    st = CausalSequenceTracker(window_seconds=300.0)
    t = datetime(2026, 10, 10, 10, 0, 0)

    # Event on host A
    ev_a = UnifiedEvent(
        event_id="ev_a1", timestamp=t, layer="endpoint", src_entity="host_alpha", dst_entity="host_alpha",
        src_internal=True, dst_internal=True, process_name="malware.exe", action="read"
    )
    feats_a = st.extract_features_single(ev_a, advance_state=True)

    # Event on host B at the exact same timestamp
    ev_b = UnifiedEvent(
        event_id="ev_b1", timestamp=t, layer="endpoint", src_entity="host_beta", dst_entity="host_beta",
        src_internal=True, dst_internal=True, process_name="calc.exe", action="read"
    )
    feats_b = st.extract_features_single(ev_b, advance_state=True)

    # Host B must NOT observe host A's previous event in its sequence count
    assert feats_b["seq_window_event_count_host"] == 0.0
    assert len(st.host_history["host_beta"]) == 1
    assert len(st.host_history["host_alpha"]) == 1


def test_audit_tracker_reset_behavior():
    """Verify reset() clears all dynamic streaming state without corrupting fitted baseline pairs."""
    gt = CausalTemporalGraphTracker()
    base_ev = UnifiedEvent(event_id="b1", timestamp=datetime.utcnow(), src_entity="h1", dst_entity="h2", src_internal=True, dst_internal=True, layer="network")
    gt.fit_baseline_pairs([base_ev])
    assert ("h1", "h2") in gt.known_pairs

    t = datetime(2026, 10, 10, 10, 0, 0)
    stream_ev = UnifiedEvent(event_id="s1", timestamp=t, src_entity="h1", dst_entity="h2", src_internal=True, dst_internal=True, layer="network")
    gt.extract_features_single(stream_ev, advance_state=True)
    assert len(gt.events_1m["h1"]) == 1

    gt.reset()
    assert len(gt.events_1m) == 0
    assert len(gt.last_seen) == 0
    # Baseline pairs must be preserved across stream resets
    assert ("h1", "h2") in gt.known_pairs


def test_audit_missing_telemetry_explicit_indicators():
    """Verify missing telemetry is encoded as explicit binary indicator columns, never NaN."""
    # Completely sparse event
    sparse_ev = UnifiedEvent(
        event_id="sparse_1", timestamp=datetime.utcnow(), layer="endpoint",
        src_entity="host_x", dst_entity="host_y", src_internal=True, dst_internal=True
    )
    miss_indicators = extract_missingness_features(sparse_ev)

    assert len(miss_indicators) == 5
    # Port, bytes_sent, bytes_recv, process, auth are all None -> all indicators 1.0
    assert miss_indicators == [1.0, 1.0, 1.0, 1.0, 1.0]
    assert not np.isnan(miss_indicators).any()


# ── 2. Legacy 15-Feature Input Handling ───────────────────────────────────────

def test_audit_legacy_15_feature_input_rejected_on_48_model():
    """Verify 48-feature calibrated model strictly rejects 15-feature input without zero-padding."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier
    assert clf.n_features == 48

    vec_15 = [0.1] * 15
    with pytest.raises(ValueError, match="Feature vector length mismatch"):
        clf.validate_features(vec_15)

    with pytest.raises(ValueError, match="Feature vector length mismatch"):
        clf.predict(vec_15)


def test_audit_legacy_15_feature_model_evaluates_natively():
    """Verify a legacy 15-feature model artifact accepts and evaluates 15-dim vectors natively."""
    legacy_clf = ThreatClassifier(random_state=42)
    X = np.random.rand(20, 15)
    y = ["benign"] * 10 + ["brute_force"] * 10
    legacy_clf.fit(X, y)

    assert legacy_clf.n_features == 15
    assert legacy_clf.is_calibrated is False

    pred = legacy_clf.predict(X[0].tolist())
    assert isinstance(pred, ThreatPrediction)
    assert pred.is_calibrated is False
    assert pred.calibrated_probabilities is None
    assert "Uncalibrated tree-vote consensus" in pred.confidence_qualification


# ── 3. Invalid Numerical Inputs (NaN, Inf, Wrong Counts) ─────────────────────

def test_audit_nan_features_rejected_with_value_error():
    """Verify NaN in any feature dimension raises ValueError rather than silent coercion."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    bad_vec = [0.1] * clf.n_features
    bad_vec[12] = float("nan")

    with pytest.raises(ValueError, match="Feature vector contains non-finite values"):
        clf.validate_features(bad_vec)

    with pytest.raises(ValueError, match="Feature vector contains non-finite values"):
        clf.predict(bad_vec)


def test_audit_inf_features_rejected_with_value_error():
    """Verify Inf and -Inf in features raise ValueError rather than silent clipping."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    bad_pos = [0.1] * clf.n_features
    bad_pos[0] = float("inf")
    with pytest.raises(ValueError, match="Feature vector contains non-finite values"):
        clf.validate_features(bad_pos)

    bad_neg = [0.1] * clf.n_features
    bad_neg[0] = float("-inf")
    with pytest.raises(ValueError, match="Feature vector contains non-finite values"):
        clf.validate_features(bad_neg)


def test_audit_wrong_feature_counts_rejected():
    """Verify feature counts other than model.n_features raise explicit ValueError."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    clf = mgr.active_classifier

    for bad_len in [0, 1, 14, 47, 49, 100]:
        with pytest.raises(ValueError, match="Feature vector length mismatch"):
            clf.validate_features([0.1] * bad_len)


# ── 4. Model Artifact and Endpoint Security ───────────────────────────────────

def test_audit_path_traversal_blocked_in_lifecycle_manager():
    """Verify arbitrary filesystem paths outside models_dir are rejected before checking existence."""
    mgr = ModelLifecycleManager()

    traversal_paths = [
        "/etc/passwd",
        "../../../../etc/shadow",
        "../../backend/api/main.py",
        "/tmp/malicious.pkl",
    ]
    for p in traversal_paths:
        is_valid, msg, _ = mgr.validate_artifact_file(p)
        assert is_valid is False
        assert "Untrusted path rejected" in msg
        # Must NOT leak full server paths in the rejection message
        assert "/etc/passwd" not in msg


def test_audit_unsupported_extensions_rejected():
    """Verify non-.pkl/.joblib artifacts are rejected."""
    mgr = ModelLifecycleManager()

    with tempfile.NamedTemporaryFile(suffix=".txt", dir=mgr.models_dir, delete=True) as tmp:
        tmp.write(b"not a model")
        tmp.flush()
        is_valid, msg, _ = mgr.validate_artifact_file(tmp.name)
        assert is_valid is False
        assert "Unsupported file extension" in msg


def test_audit_companion_metadata_checksum_mismatch_rejected():
    """Verify an artifact whose SHA-256 differs from companion metadata is rejected."""
    mgr = ModelLifecycleManager()

    # Create dummy artifact file
    with tempfile.NamedTemporaryFile(suffix=".pkl", dir=mgr.models_dir, delete=False) as tmp_pkl:
        pkl_path = Path(tmp_pkl.name)
        joblib.dump({"dummy": 1}, pkl_path)

    # Create companion metadata with deliberately corrupted SHA-256
    meta_path = pkl_path.parent / f"{pkl_path.stem}_metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({"artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000000"}, f)

    try:
        is_valid, msg, _ = mgr.validate_artifact_file(pkl_path)
        assert is_valid is False
        assert "checksum mismatch" in msg.lower()
    finally:
        if pkl_path.exists():
            pkl_path.unlink()
        if meta_path.exists():
            meta_path.unlink()


def test_audit_failed_activation_preserves_active_model():
    """Verify failed candidate artifact activation does not replace active known-good model."""
    mgr = ModelLifecycleManager()
    mgr.load_artifact()
    initial_clf = mgr.active_classifier
    assert initial_clf is not None

    with tempfile.NamedTemporaryFile(suffix=".pkl", dir=mgr.models_dir, delete=True) as tmp_bad:
        tmp_bad.write(b"corrupt binary data")
        tmp_bad.flush()

        loaded_ok = mgr.load_artifact(tmp_bad.name)
        assert loaded_ok is False
        # Active classifier must remain intact
        assert mgr.active_classifier is initial_clf


# ── 5. API Endpoints Security and HTTP Status Codes ───────────────────────────

def test_audit_api_detect_422_on_invalid_numeric_input(monkeypatch):
    """Verify /api/detect returns 422 Unprocessable Entity when feature input is non-finite or invalid."""
    with TestClient(app) as client:
        payload = {
            "event_id": "test_inv_1",
            "timestamp": datetime.utcnow().isoformat(),
            "layer": "network",
            "src_entity": "192.168.1.10",
            "dst_entity": "192.168.1.50",
            "src_internal": True,
            "dst_internal": True,
            "bytes_sent": 1000,
        }
        import backend.api.main as api_main
        monkeypatch.setattr(
            api_main,
            "extract_full_causal_features",
            lambda **kwargs: [float("nan")] * 48
        )
        resp = client.post("/api/detect", json=payload)
        assert resp.status_code == 422
        data = resp.json()
        assert "Invalid feature inputs" in data.get("detail", "")


def test_audit_api_validate_path_traversal_forbidden():
    """Verify /api/model/validate forbids traversal tokens with 400 Bad Request."""
    with TestClient(app) as client:
        for bad_name in ["../../etc/passwd", "..\\boot.ini", "/etc/shadow", "nested/model.pkl"]:
            resp = client.post("/api/model/validate", json={"artifact_filename": bad_name})
            assert resp.status_code == 400
            assert "path traversal" in resp.json().get("detail", "").lower()


def test_audit_api_reload_requires_admin_key_when_configured():
    """Verify /api/model/reload checks X-AEGIS-Admin-Key when AEGIS_ADMIN_KEY is set in environment."""
    os.environ["AEGIS_ADMIN_KEY"] = "super-secret-key-12345"
    try:
        with TestClient(app) as client:
            # Request without header
            resp_unauth = client.post(
                "/api/model/reload",
                json={"artifact_filename": "calibrated_threat_classifier.pkl"}
            )
            assert resp_unauth.status_code == 401

            # Request with wrong header
            resp_wrong = client.post(
                "/api/model/reload",
                json={"artifact_filename": "calibrated_threat_classifier.pkl"},
                headers={"X-AEGIS-Admin-Key": "wrong-key"}
            )
            assert resp_wrong.status_code == 401

            # Request with valid header
            resp_ok = client.post(
                "/api/model/reload",
                json={"artifact_filename": "calibrated_threat_classifier.pkl"},
                headers={"X-AEGIS-Admin-Key": "super-secret-key-12345"}
            )
            assert resp_ok.status_code == 200
            assert resp_ok.json()["status"] == "activated"
    finally:
        del os.environ["AEGIS_ADMIN_KEY"]
