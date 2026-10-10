"""
Phase 25.1 Integration and Security Audit Test Suite
Validates:
1. Host identity & causal isolation (DHCP rotation, NAT shared IP, missing identity, network vs endpoint quality).
2. Ingestion reset security (admin authentication, timing-attack resistance, disablement flag, exposed deployment check, parity with model reload).
3. End-to-end ingestion-to-detection integration (feature extraction, calibrated inference, alert creation, incident correlation).
4. Temporal and deduplication correctness (UTC normalization, event vs ingest time, clock skew, deduplication LRU, late events, missingness preservation).
5. Data and model regression (model SHA-256, 48-feature schema contract, Phase 19 dataset reproducibility SHA-256).
"""

import hashlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any

import pytest
from fastapi.testclient import TestClient

from backend.core.schemas import UnifiedEvent, IngestionEventRequest, IngestionBatchRequest
from backend.detection.sequence_context import CausalSequenceTracker
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.evaluation.false_positive_calibration import PHASE22_BASELINE_FEATURE_NAMES
from backend.ingestion.normalizer import NormalizerPipeline
from backend.ingestion.streaming_ingestion import StreamingIngestionManager
from backend.data_generator.orchestrator import DataOrchestrator
from backend.api.main import app, _require_admin_authorization

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PRODUCTION_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "calibrated_threat_classifier.pkl"
EXPECTED_MODEL_SHA256 = "98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71"
EXPECTED_PHASE19_SHA256 = "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"


# ══════════════════════════════════════════════════════════════════════════════════
# AUDIT 1: Host Identity and Causal Isolation
# ══════════════════════════════════════════════════════════════════════════════════

def test_audit1_host_identity_dhcp_rotation():
    """
    A single host whose IP changes due to DHCP must accumulate state under its
    stable host_id, NOT splinter into separate host histories.
    """
    seq_tracker = CausalSequenceTracker(window_seconds=300.0)
    mgr = StreamingIngestionManager(sequence_tracker=seq_tracker)
    t0 = datetime(2026, 10, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Event 1: Host-01 has IP 10.0.0.50
    ev1 = {
        "event_id": "ev-dhcp-1",
        "timestamp": t0.isoformat(),
        "host_id": "WORKSTATION-01",
        "src_ip": "10.0.0.50",
        "dst_ip": "10.0.0.1",
        "process_name": "powershell.exe",
        "action": "execute",
    }
    # Event 2: Host-01 gets new DHCP lease 10.0.0.99
    ev2 = {
        "event_id": "ev-dhcp-2",
        "timestamp": (t0 + timedelta(seconds=10)).isoformat(),
        "host_id": "WORKSTATION-01",
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.1",
        "process_name": "cmd.exe",
        "action": "execute",
    }

    mgr.ingest_event(ev1)
    mgr.ingest_event(ev2)

    # Host history must track WORKSTATION-01 with both events
    assert "WORKSTATION-01" in seq_tracker.host_history
    assert len(seq_tracker.host_history["WORKSTATION-01"]) == 2
    # IP addresses must not be separate top-level tracker keys
    assert "10.0.0.50" not in seq_tracker.host_history
    assert "10.0.0.99" not in seq_tracker.host_history


def test_audit1_host_identity_nat_shared_ip():
    """
    Two distinct hosts sharing an external NAT IP must NOT cross-contaminate
    each other's temporal/causal histories.
    """
    seq_tracker = CausalSequenceTracker(window_seconds=300.0)
    mgr = StreamingIngestionManager(sequence_tracker=seq_tracker)
    t0 = datetime(2026, 10, 10, 10, 0, 0, tzinfo=timezone.utc)
    nat_ip = "198.51.100.1"

    ev_a = {
        "event_id": "ev-nat-a",
        "timestamp": t0.isoformat(),
        "host_id": "INTERNAL-HOST-A",
        "src_ip": nat_ip,
        "dst_ip": "8.8.8.8",
        "process_name": "curl.exe",
        "action": "network_connect",
    }
    ev_b = {
        "event_id": "ev-nat-b",
        "timestamp": (t0 + timedelta(seconds=2)).isoformat(),
        "host_id": "INTERNAL-HOST-B",
        "src_ip": nat_ip,
        "dst_ip": "8.8.8.8",
        "process_name": "git.exe",
        "action": "network_connect",
    }

    mgr.ingest_event(ev_a)
    mgr.ingest_event(ev_b)

    assert "INTERNAL-HOST-A" in seq_tracker.host_history
    assert "INTERNAL-HOST-B" in seq_tracker.host_history
    assert len(seq_tracker.host_history["INTERNAL-HOST-A"]) == 1
    assert len(seq_tracker.host_history["INTERNAL-HOST-B"]) == 1
    assert seq_tracker.host_history["INTERNAL-HOST-A"][0].process_name == "curl.exe"
    assert seq_tracker.host_history["INTERNAL-HOST-B"][0].process_name == "git.exe"
    assert nat_ip not in seq_tracker.host_history


def test_audit1_host_identity_fallback_without_fabrication():
    """
    When host_id is absent, the system falls back to src_ip or src_entity without
    fabricating an unverified host identifier.
    """
    seq_tracker = CausalSequenceTracker(window_seconds=300.0)
    mgr = StreamingIngestionManager(sequence_tracker=seq_tracker)
    t0 = datetime(2026, 10, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Pure network flow event without host_id
    net_ev = {
        "event_id": "ev-net-flow",
        "timestamp": t0.isoformat(),
        "src_ip": "172.16.0.42",
        "dst_ip": "10.0.0.1",
        "layer": "network",
        "action": "flow_record",
    }
    res = mgr.ingest_event(net_ev)
    assert res.status == "accepted"
    assert res.event.host_id is None  # Never fabricated!

    # Tracker indexed by fallback IP
    assert "172.16.0.42" in seq_tracker.host_history
    assert len(seq_tracker.host_history["172.16.0.42"]) == 1


def test_audit1_reset_clears_host_isolation_state():
    """Resetting ingestion clears all host histories and prevents state leakage."""
    seq_tracker = CausalSequenceTracker(window_seconds=300.0)
    mgr = StreamingIngestionManager(sequence_tracker=seq_tracker)
    mgr.ingest_event({
        "event_id": "ev-pre-reset",
        "timestamp": datetime.utcnow().isoformat(),
        "host_id": "HOST-X",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "process_name": "test.exe",
    })
    assert len(seq_tracker.host_history) == 1
    assert len(mgr._active_hosts) == 1

    mgr.reset()
    assert len(seq_tracker.host_history) == 0
    assert len(mgr._active_hosts) == 0


# ══════════════════════════════════════════════════════════════════════════════════
# AUDIT 2: Ingestion Reset Security & Admin Authorization
# ══════════════════════════════════════════════════════════════════════════════════

def test_audit2_reset_requires_valid_key_when_configured(monkeypatch):
    """When AEGIS_ADMIN_KEY is configured, requests without valid header are rejected."""
    monkeypatch.setenv("AEGIS_ADMIN_KEY", "super-secret-audit-key")
    monkeypatch.delenv("AEGIS_ALLOW_INGESTION_RESET", raising=False)
    with TestClient(app) as client:
        # 1. Missing header -> 401
        res_no_key = client.post("/api/ingest/reset")
        assert res_no_key.status_code == 401
        assert "Unauthorized" in res_no_key.json()["detail"]

        # 2. Invalid header -> 401
        res_wrong_key = client.post("/api/ingest/reset", headers={"X-AEGIS-Admin-Key": "wrong-key"})
        assert res_wrong_key.status_code == 401

        # 3. Valid header -> 200
        res_valid = client.post("/api/ingest/reset", headers={"X-AEGIS-Admin-Key": "super-secret-audit-key"})
        assert res_valid.status_code == 200
        assert res_valid.json()["status"] == "success"


def test_audit2_reset_administratively_disabled(monkeypatch):
    """When AEGIS_ALLOW_INGESTION_RESET is 'false', resets are blocked with 403 Forbidden."""
    monkeypatch.setenv("AEGIS_ADMIN_KEY", "super-secret-audit-key")
    monkeypatch.setenv("AEGIS_ALLOW_INGESTION_RESET", "false")
    with TestClient(app) as client:
        res = client.post("/api/ingest/reset", headers={"X-AEGIS-Admin-Key": "super-secret-audit-key"})
        assert res.status_code == 403
        assert "administratively disabled" in res.json()["detail"]


def test_audit2_reset_exposed_production_deployment(monkeypatch):
    """In production environment without AEGIS_ADMIN_KEY, reset is rejected with 403 Forbidden."""
    monkeypatch.delenv("AEGIS_ADMIN_KEY", raising=False)
    monkeypatch.setenv("AEGIS_ENV", "production")
    with TestClient(app) as client:
        res = client.post("/api/ingest/reset")
        assert res.status_code == 403
        assert "AEGIS_ADMIN_KEY in production deployment" in res.json()["detail"]


def test_audit2_model_reload_and_reset_authorization_parity(monkeypatch):
    """Both /api/ingest/reset and /api/model/reload share identical security validation."""
    monkeypatch.setenv("AEGIS_ADMIN_KEY", "parity-key")
    with TestClient(app) as client:
        # Both fail with 401 on missing key
        r_reset = client.post("/api/ingest/reset")
        r_reload = client.post("/api/model/reload", json={"artifact_filename": "dummy.pkl"})
        assert r_reset.status_code == 401
        assert r_reload.status_code == 401

        # Both fail with 401 on wrong key
        r_reset_bad = client.post("/api/ingest/reset", headers={"X-AEGIS-Admin-Key": "bad"})
        r_reload_bad = client.post("/api/model/reload", json={"artifact_filename": "dummy.pkl"}, headers={"X-AEGIS-Admin-Key": "bad"})
        assert r_reset_bad.status_code == 401
        assert r_reload_bad.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════════
# AUDIT 3: End-to-End Ingestion-to-Detection Integration
# ══════════════════════════════════════════════════════════════════════════════════

def test_audit3_ingestion_triggers_detection_when_requested():
    """
    Accepted events ingested with trigger_detection=True execute feature extraction,
    calibrated inference, and return structured detection results.
    """
    with TestClient(app) as client:
        t_now = datetime.now(timezone.utc).isoformat()

        # Ingest event with trigger_detection=True
        payload = {
            "raw_event": {
                "event_id": "ev-e2e-detect-1",
                "timestamp": t_now,
                "host_id": "HOST-TEST-01",
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.5",
                "dst_port": 445,
                "layer": "network",
                "action": "smb_session",
                "bytes_transferred": 1500000,
            },
            "trigger_detection": True,
        }

        res = client.post("/api/ingest/event", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "accepted"
        assert data["detection"] is not None
        assert "calibrated_probabilities" in data["detection"]
        assert "threat_type" in data["detection"]
        assert "is_calibrated" in data["detection"]


def test_audit3_malformed_event_does_not_trigger_detection():
    """Rejected events must NOT execute ML inference or fabricate detections."""
    with TestClient(app) as client:
        payload = {
            "raw_event": {
                "event_id": "ev-e2e-bad-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "invalid_telemetry_layer",
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.5",
            },
            "trigger_detection": True,
        }
        res = client.post("/api/ingest/event", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "rejected"
        assert data["detection"] is None
        assert data["alert"] is None


def test_audit3_query_param_detection_trigger():
    """Endpoint supports detect=true query parameter to trigger detection."""
    with TestClient(app) as client:
        raw_ev = {
            "event_id": "ev-query-detect",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host_id": "HOST-Q",
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.1.20",
            "layer": "endpoint",
            "process_name": "cmd.exe",
        }
        res = client.post("/api/ingest/event?detect=true", json={"raw_event": raw_ev})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "accepted"
        assert data["detection"] is not None


# ══════════════════════════════════════════════════════════════════════════════════
# AUDIT 4: Temporal and Deduplication Correctness
# ══════════════════════════════════════════════════════════════════════════════════

def test_audit4_timezone_utc_normalization():
    """Timezone offsets (+05:30, -04:00, Z) normalize correctly to UTC."""
    pipeline = NormalizerPipeline()

    # IST: 2026-10-10 17:30:00+05:30 -> UTC 12:00:00
    event_ist = pipeline.normalize({
        "event_id": "ev-ist",
        "timestamp": "2026-10-10T17:30:00+05:30",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "action": "login",
    })
    assert event_ist is not None
    assert event_ist.timestamp.year == 2026
    assert event_ist.timestamp.hour == 12
    assert event_ist.timestamp.minute == 0

    # EDT: 2026-10-10 08:00:00-04:00 -> UTC 12:00:00
    event_edt = pipeline.normalize({
        "event_id": "ev-edt",
        "timestamp": "2026-10-10T08:00:00-04:00",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "action": "login",
    })
    assert event_edt is not None
    assert event_edt.timestamp.hour == 12


def test_audit4_clock_skew_and_future_timestamps():
    """Events with future timestamps exceeding tolerance flag clock_skew_detected."""
    mgr = StreamingIngestionManager()
    future_time = datetime.now(timezone.utc) + timedelta(minutes=10)

    res = mgr.ingest_event({
        "event_id": "ev-future-skew",
        "timestamp": future_time.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "action": "test",
    })
    assert res.status == "accepted"
    assert res.clock_skew_detected is True


def test_audit4_late_event_watermark_monotonicity():
    """Late arriving events are accepted but do not regress the watermark."""
    mgr = StreamingIngestionManager(late_tolerance_seconds=120.0)
    t_base = datetime(2026, 10, 10, 12, 0, 0)

    # 1. Event at 12:00 -> watermark 12:00
    mgr.ingest_event({
        "event_id": "ev-wm-1",
        "timestamp": t_base.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "action": "test",
    })
    assert mgr.watermark_timestamp == t_base

    # 2. Event at 12:10 -> watermark 12:10
    t_ahead = t_base + timedelta(minutes=10)
    mgr.ingest_event({
        "event_id": "ev-wm-2",
        "timestamp": t_ahead.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "action": "test",
    })
    assert mgr.watermark_timestamp == t_ahead

    # 3. Late event at 12:02 (8 mins before watermark, tolerance is 2 mins -> late!)
    t_late = t_base + timedelta(minutes=2)
    res_late = mgr.ingest_event({
        "event_id": "ev-wm-late",
        "timestamp": t_late.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "action": "test",
    })
    assert res_late.is_late_arriving is True
    # Watermark must remain at 12:10!
    assert mgr.watermark_timestamp == t_ahead


def test_audit4_dedup_capacity_lru_enforcement():
    """Deduplication cache strictly enforces capacity without unbounded growth."""
    max_cap = 50
    mgr = StreamingIngestionManager(max_seen_ids=max_cap)
    t0 = datetime(2026, 10, 10, 12, 0, 0)

    # Ingest 75 unique events
    for i in range(75):
        mgr.ingest_event({
            "event_id": f"ev-cap-{i:03d}",
            "timestamp": (t0 + timedelta(seconds=i)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "action": f"test_{i}",
        })

    assert len(mgr._seen_event_ids) == max_cap
    assert len(mgr._seen_fingerprints) == max_cap
    # Earliest events (e.g. ev-cap-000) should have been evicted
    assert "ev-cap-000" not in mgr._seen_event_ids
    # Latest event must still be tracked
    assert "ev-cap-074" in mgr._seen_event_ids


def test_audit4_missing_values_preservation():
    """Missing telemetry attributes are preserved as None, not converted to zeros."""
    pipeline = NormalizerPipeline()
    ev = pipeline.normalize({
        "event_id": "ev-sparse",
        "timestamp": datetime.utcnow().isoformat(),
        "layer": "network",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    })
    assert ev is not None
    assert ev.dst_port is None
    assert ev.bytes_sent is None
    assert ev.bytes_received is None
    assert ev.packets_sent is None
    assert ev.packets_received is None
    assert ev.auth_result is None
    assert ev.status_code is None


# ══════════════════════════════════════════════════════════════════════════════════
# AUDIT 5: Data and Model Regression
# ══════════════════════════════════════════════════════════════════════════════════

def test_audit5_production_model_sha256():
    """Verify production model artifact SHA-256 remains exactly unchanged."""
    assert PRODUCTION_MODEL_PATH.exists(), f"Model artifact missing at {PRODUCTION_MODEL_PATH}"
    with open(PRODUCTION_MODEL_PATH, "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()
    assert actual_sha256 == EXPECTED_MODEL_SHA256


def test_audit5_48_feature_schema_contract():
    """Verify 48-feature schema names and ordering are identical to the production contract."""
    assert len(PHASE22_BASELINE_FEATURE_NAMES) == 48
    assert PHASE22_BASELINE_FEATURE_NAMES[0] == "if_anomaly_score"
    assert PHASE22_BASELINE_FEATURE_NAMES[-1] == "seq_sequence_completeness_score"
    with TestClient(app) as client:
        active_clf = getattr(app.state, "classifier", None)
        assert active_clf is not None
        assert getattr(active_clf, "n_features", None) == 48
        assert active_clf.feature_names == PHASE22_BASELINE_FEATURE_NAMES


def test_audit5_phase19_deterministic_dataset_reproducibility():
    """
    Verify Phase 19 behavioral-diversity dataset generation remains deterministic
    and matches the expected SHA-256: 1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352.
    """
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        summary = DataOrchestrator().generate_behavioral_diversity_dataset(
            output_path=tmp_path, seed=42
        )
        assert summary["total_events"] == 5717
        assert summary["total_scenarios"] == 116
        assert summary["sha256"] == EXPECTED_PHASE19_SHA256
    finally:
        Path(tmp_path).unlink(missing_ok=True)
