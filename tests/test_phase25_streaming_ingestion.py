"""
tests/test_phase25_streaming_ingestion.py
──────────────────────────────────────────────────────────────────────────────
Phase 25 Test Suite: Streaming Ingestion, Telemetry Normalization, Evidence
Provenance, Deduplication, and Causal Host Isolation.

Covers all 18 quality requirements:
  1. Valid event normalization (network, endpoint, application).
  2. Invalid required fields rejection.
  3. Missing optional telemetry auditing and tracking.
  4. Timestamp timezone conversion to canonical UTC.
  5. Distinction between event-time and ingestion-time.
  6. Invalid numerical values and metric sanitation.
  7. Strict IP address and port validation.
  8. Evidence provenance taxonomy preservation.
  9. Duplicate event handling (exact ID & sliding payload fingerprint).
  10. Out-of-order, late-arriving events, and clock skew detection.
  11. Host isolation in temporal sequence state.
  12. Ingestion and tracker reset behavior.
  13. Batch ingestion and partial failure tolerance.
  14. API error responses and batch size enforcement.
  15. Backward compatibility of schemas and /api/detect endpoint.
  16. Preservation of the 48-feature causal model schema.
  17. Production model artifact hash immutability.
  18. Deterministic, reproducible normalization for identical inputs.
"""

from datetime import datetime, timezone, timedelta
import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.core.schemas import (
    UnifiedEvent,
    IngestionEventRequest,
    IngestionBatchRequest,
    IngestionItemResult,
    IngestionBatchResponse,
    StreamingIngestionStats,
)
from backend.ingestion.normalizer import (
    NormalizerPipeline,
    NormalizationError,
    redact_sensitive_payload,
)
from backend.ingestion.streaming_ingestion import StreamingIngestionManager
from backend.detection.sequence_context import CausalSequenceTracker
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.api.main import app

EXPECTED_MODEL_SHA256 = "98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71"


# ── Test 1: Valid Event Normalization ─────────────────────────────────────────

def test_valid_event_normalization():
    # Network layer
    net_raw = {
        "timestamp": "2026-10-10T12:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "6",
        "bytes_sent": 1200,
        "bytes_received": 3400,
    }
    net_ev = NormalizerPipeline.normalize_strict(net_raw)
    assert net_ev.layer == "network"
    assert net_ev.src_ip == "10.0.0.1"
    assert net_ev.dst_ip == "10.0.0.2"
    assert net_ev.protocol == "TCP"
    assert net_ev.bytes_sent == 1200
    assert net_ev.dst_internal is True
    assert net_ev.bytes_ratio is not None

    # Endpoint layer
    ep_raw = {
        "timestamp": "2026-10-10T12:05:00Z",
        "host_id": "HOST-CORP-01",
        "process_name": "cmd.exe",
        "parent_process": "explorer.exe",
        "pid": 2048,
        "parent_pid": 1024,
        "user_account": "admin",
        "action": "execute",
        "file_path": "C:\\Windows\\System32\\cmd.exe",
    }
    ep_ev = NormalizerPipeline.normalize_strict(ep_raw)
    assert ep_ev.layer == "endpoint"
    assert ep_ev.process_name == "cmd.exe"
    assert ep_ev.pid == 2048
    assert ep_ev.src_entity == "admin"
    assert ep_ev.dst_entity == "C:\\Windows\\System32\\cmd.exe"

    # Application layer
    app_raw = {
        "timestamp": "2026-10-10T12:10:00Z",
        "src_ip": "192.168.1.50",
        "http_method": "post",
        "endpoint_path": "/api/v1/login",
        "status_code": "200",
        "auth_result": "success",
    }
    app_ev = NormalizerPipeline.normalize_strict(app_raw)
    assert app_ev.layer == "application"
    assert app_ev.http_method == "POST"
    assert app_ev.status_code == 200
    assert app_ev.auth_result == "success"


# ── Test 2: Invalid Required Fields ───────────────────────────────────────────

def test_invalid_required_fields():
    # Missing entities and IP
    with pytest.raises(NormalizationError) as exc_info:
        NormalizerPipeline.normalize_strict({"timestamp": "2026-10-10T12:00:00Z"})
    assert "layer" in exc_info.value.message.lower() or "entity" in exc_info.value.message.lower()

    # Invalid layer specified
    with pytest.raises(NormalizationError) as exc_info:
        NormalizerPipeline.normalize_strict({
            "layer": "invalid_telemetry_layer",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "timestamp": "2026-10-10T12:00:00Z",
        })
    assert "Invalid telemetry layer" in exc_info.value.message


# ── Test 3: Missing Optional Telemetry ────────────────────────────────────────

def test_missing_optional_telemetry():
    # Minimal network event missing bytes_received, src_port, tcp_flags
    raw = {
        "timestamp": "2026-10-10T12:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "bytes_sent": 500,
    }
    ev = NormalizerPipeline.normalize_strict(raw)
    assert ev is not None
    assert ev.bytes_received is None
    assert ev.src_port is None
    # Audited missing fields
    assert "bytes_received" in ev.missing_fields
    assert "src_port" in ev.missing_fields
    assert "protocol" in ev.missing_fields
    # Verify missing fields are not fabricated
    assert ev.provenance["unavailable_telemetry"] == ev.missing_fields


# ── Test 4: Timestamp Timezone Conversion ─────────────────────────────────────

def test_timestamp_timezone_conversion():
    # Offset +05:30 (15:30 +05:30 = 10:00 UTC)
    raw_ist = {
        "timestamp": "2026-10-10T15:30:00+05:30",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
    }
    ev_ist = NormalizerPipeline.normalize_strict(raw_ist)
    assert ev_ist.timestamp == datetime(2026, 10, 10, 10, 0, 0)
    assert ev_ist.hour_of_day == 10

    # UTC with Z
    raw_utc = {
        "timestamp": "2026-10-10T14:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
    }
    ev_utc = NormalizerPipeline.normalize_strict(raw_utc)
    assert ev_utc.timestamp == datetime(2026, 10, 10, 14, 0, 0)
    assert ev_utc.hour_of_day == 14

    # Epoch milliseconds (1760097600000 = 2025-10-10 12:00:00 UTC)
    raw_epoch = {
        "timestamp": 1760097600000,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
    }
    ev_epoch = NormalizerPipeline.normalize_strict(raw_epoch)
    assert ev_epoch.timestamp == datetime(2025, 10, 10, 12, 0, 0)


# ── Test 5: Event Time vs Ingestion Time ───────────────────────────────────────

def test_event_time_versus_ingestion_time():
    past_event_time = datetime(2026, 1, 15, 8, 30, 0)
    raw = {
        "timestamp": past_event_time.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
    }
    ev = NormalizerPipeline.normalize_strict(raw)
    assert ev.timestamp == past_event_time
    assert ev.ingestion_timestamp is not None
    # Ingestion time should reflect current UTC time, distinct from event occurrence time
    time_diff = (ev.ingestion_timestamp - ev.timestamp).total_seconds()
    assert time_diff > 3600.0  # Months apart


# ── Test 6: Invalid Numerical Values ──────────────────────────────────────────

def test_invalid_numerical_values():
    # Negative bytes_sent
    with pytest.raises(NormalizationError):
        NormalizerPipeline.normalize_strict({
            "timestamp": "2026-10-10T12:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "bytes_sent": -50,
        })

    # Non-numeric bytes_sent
    with pytest.raises(NormalizationError):
        NormalizerPipeline.normalize_strict({
            "timestamp": "2026-10-10T12:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "bytes_sent": "one_thousand",
        })

    # Microsecond duration conversion (>100,000 microseconds -> ms)
    raw = {
        "timestamp": "2026-10-10T12:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "duration_ms": 500_000,  # 500k us = 500 ms
    }
    ev = NormalizerPipeline.normalize_strict(raw)
    assert ev.duration_ms == 500


# ── Test 7: IP and Port Validation ────────────────────────────────────────────

def test_ip_and_port_validation():
    # Invalid IP address string
    with pytest.raises(NormalizationError) as exc_info:
        NormalizerPipeline.normalize_strict({
            "timestamp": "2026-10-10T12:00:00Z",
            "src_ip": "999.999.999.999",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
        })
    assert "Invalid IP address" in exc_info.value.message or "Malformed IP" in exc_info.value.message

    # Port out of range (>65535)
    with pytest.raises(NormalizationError) as exc_info:
        NormalizerPipeline.normalize_strict({
            "timestamp": "2026-10-10T12:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 70000,
        })
    assert "Port number out of range" in exc_info.value.message

    # Negative port
    with pytest.raises(NormalizationError) as exc_info:
        NormalizerPipeline.normalize_strict({
            "timestamp": "2026-10-10T12:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": -1,
        })
    assert "Port number out of range" in exc_info.value.message


# ── Test 8: Evidence Provenance Preservation ──────────────────────────────────

def test_evidence_provenance_preservation():
    # Telemetry without verified process socket binding -> unverified
    raw_unverified = {
        "timestamp": "2026-10-10T12:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "bytes_sent": 1000,
    }
    ev1 = NormalizerPipeline.normalize_strict(raw_unverified)
    assert ev1.provenance["attribution_status"] == "unverified"
    assert "bytes_sent" in ev1.provenance["observed_fields"]
    assert "bytes_ratio" in ev1.provenance["derived_fields"]

    # Telemetry with genuine PID + process_guid + socket_id -> verified
    raw_verified = {
        "timestamp": "2026-10-10T12:00:00Z",
        "layer": "endpoint",
        "host_id": "HOST-01",
        "pid": 1337,
        "process_name": "curl.exe",
        "socket_id": "sock-9912",
        "process_guid": "guid-7711",
        "user_account": "user1",
        "action": "connect",
    }
    ev2 = NormalizerPipeline.normalize_strict(raw_verified)
    assert ev2.provenance["attribution_status"] == "verified"


# ── Test 9: Duplicate Event Handling ──────────────────────────────────────────

def test_duplicate_event_handling():
    mgr = StreamingIngestionManager(dedup_window_seconds=60.0)

    t0 = datetime(2026, 10, 10, 12, 0, 0)
    ev_dict = {
        "event_id": "unique-id-001",
        "timestamp": t0.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "bytes_sent": 500,
    }

    # First ingestion -> accepted
    res1 = mgr.ingest_event(ev_dict)
    assert res1.status == "accepted"

    # Exact event_id duplicate -> duplicate_event_id
    res2 = mgr.ingest_event(ev_dict)
    assert res2.status == "duplicate"
    assert res2.reason == "duplicate_event_id"

    # Duplicate payload with different event_id within 60s window
    ev_dict_diff_id = dict(ev_dict)
    ev_dict_diff_id["event_id"] = "different-uuid-999"
    res3 = mgr.ingest_event(ev_dict_diff_id)
    assert res3.status == "duplicate"
    assert res3.reason == "duplicate_payload_fingerprint"


# ── Test 10: Out-of-Order, Late-Arriving, and Clock Skew ───────────────────────

def test_out_of_order_and_late_arriving_events():
    mgr = StreamingIngestionManager(late_tolerance_seconds=300.0)

    t_watermark = datetime(2026, 10, 10, 12, 10, 0)
    ev_base = {
        "timestamp": t_watermark.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "bytes_sent": 100,
    }
    mgr.ingest_event(ev_base)
    assert mgr.watermark_timestamp == t_watermark

    # Arriving event older than watermark by 600s (>300s tolerance)
    t_late = t_watermark - timedelta(seconds=600)
    ev_late = {
        "timestamp": t_late.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "bytes_sent": 200,
    }
    res_late = mgr.ingest_event(ev_late)
    assert res_late.status == "accepted"
    assert res_late.is_late_arriving is True

    # Clock skew event: >300s into the future relative to ingestion UTC
    t_skew = datetime.utcnow() + timedelta(seconds=1200)
    ev_skew = {
        "timestamp": t_skew.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 8080,
    }
    res_skew = mgr.ingest_event(ev_skew)
    assert res_skew.status == "accepted"
    assert res_skew.clock_skew_detected is True


# ── Test 11: Host Isolation in Temporal Sequence State ────────────────────────

def test_host_isolation_in_temporal_state():
    seq_tracker = CausalSequenceTracker(window_seconds=300.0)
    mgr = StreamingIngestionManager(sequence_tracker=seq_tracker)

    t0 = datetime(2026, 10, 10, 12, 0, 0)
    # Event on Host A
    ev_a = {
        "timestamp": t0.isoformat(),
        "src_ip": "192.168.1.10",
        "host_id": "HOST-A",
        "layer": "endpoint",
        "process_name": "powershell.exe",
        "pid": 111,
        "user_account": "userA",
        "action": "execute",
    }
    # Event on Host B
    ev_b = {
        "timestamp": (t0 + timedelta(seconds=1)).isoformat(),
        "src_ip": "192.168.1.20",
        "host_id": "HOST-B",
        "layer": "endpoint",
        "process_name": "cmd.exe",
        "pid": 222,
        "user_account": "userB",
        "action": "execute",
    }
    mgr.ingest_event(ev_a)
    mgr.ingest_event(ev_b)

    # Verify history is strictly segregated
    assert "192.168.1.10" in seq_tracker.host_history
    assert "192.168.1.20" in seq_tracker.host_history
    assert len(seq_tracker.host_history["192.168.1.10"]) == 1
    assert len(seq_tracker.host_history["192.168.1.20"]) == 1
    assert seq_tracker.host_history["192.168.1.10"][0].process_name == "powershell.exe"
    assert seq_tracker.host_history["192.168.1.20"][0].process_name == "cmd.exe"


# ── Test 12: Sequence Tracker Reset Behavior ──────────────────────────────────

def test_sequence_tracker_reset_behavior():
    seq_tracker = CausalSequenceTracker(window_seconds=300.0)
    graph_tracker = CausalTemporalGraphTracker()
    mgr = StreamingIngestionManager(sequence_tracker=seq_tracker, graph_tracker=graph_tracker)

    ev = {
        "timestamp": "2026-10-10T12:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
    }
    mgr.ingest_event(ev)
    assert mgr.total_ingested == 1
    assert len(mgr._seen_event_ids) == 1

    # Reset
    mgr.reset()
    assert mgr.total_ingested == 0
    assert len(mgr._seen_event_ids) == 0
    assert mgr.watermark_timestamp is None
    assert len(seq_tracker.host_history) == 0


# ── Test 13: Batch Ingestion and Partial Failures ──────────────────────────────

def test_batch_ingestion_and_partial_failures():
    mgr = StreamingIngestionManager()

    t0 = datetime(2026, 10, 10, 12, 0, 0)
    batch = [
        # Valid 1
        {"event_id": "b1", "timestamp": t0.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80},
        # Malformed (missing entities and layer)
        {"event_id": "b2", "unsupported": 123},
        # Duplicate of b1
        {"event_id": "b1", "timestamp": t0.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80},
        # Valid 2
        {"event_id": "b3", "timestamp": (t0 + timedelta(seconds=1)).isoformat(), "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "dst_port": 443},
    ]

    res = mgr.ingest_batch(batch)
    assert res.total_received == 4
    assert res.accepted_count == 2
    assert res.rejected_count == 1
    assert res.duplicate_count == 1
    assert res.results[0].status == "accepted"
    assert res.results[1].status == "rejected"
    assert res.results[2].status == "duplicate"
    assert res.results[3].status == "accepted"


# ── Test 14: API Error Responses and Limits ───────────────────────────────────

def test_api_error_responses():
    client = TestClient(app)

    # Exceed batch limit (>500)
    oversized = [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80}] * 501
    resp = client.post("/api/ingest/batch", json={"events": oversized})
    assert resp.status_code == 400
    assert "exceeds maximum permitted limit of 500 events" in resp.json()["detail"]

    # Stats endpoint works
    resp_stats = client.get("/api/ingest/stats")
    assert resp_stats.status_code == 200
    data = resp_stats.json()
    assert "total_ingested" in data
    assert "watermark_timestamp" in data

    # Reset endpoint works
    resp_reset = client.post("/api/ingest/reset")
    assert resp_reset.status_code == 200
    assert resp_reset.json()["status"] == "success"


# ── Test 15: Backward Compatibility ───────────────────────────────────────────

def test_backward_compatibility():
    # Legacy event constructor with standard positional and keyword args
    legacy_ev = UnifiedEvent(
        timestamp=datetime(2026, 10, 10, 12, 0, 0),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=False,
        dst_internal=False,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=80,
    )
    assert legacy_ev.schema_version == "25.0.0"
    assert legacy_ev.missing_fields == []
    assert legacy_ev.event_id is not None

    # Test /api/detect with legacy event
    client = TestClient(app)
    detect_resp = client.post("/api/detect", json=legacy_ev.model_dump(mode="json"))
    # Either 200 (if models fitted) or 503 (if models not loaded), not 422 schema crash
    assert detect_resp.status_code in (200, 503)


# ── Test 16: Preservation of 48-Feature Model Schema ──────────────────────────

def test_preservation_of_48_feature_model_schema():
    from backend.detection.model_trainer import extract_full_causal_features
    from backend.detection.baseline_profiler import BehavioralBaselineProfiler

    ev = UnifiedEvent(
        timestamp=datetime(2026, 10, 10, 12, 0, 0),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=False,
        dst_internal=False,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
        bytes_sent=1500,
        bytes_received=3000,
        hour_of_day=12,
        is_business_hours=True,
        bytes_ratio=1.5,
        port_risk_score=0.1,
    )
    profiler = BehavioralBaselineProfiler()
    graph_tracker = CausalTemporalGraphTracker()
    seq_tracker = CausalSequenceTracker()

    feats = extract_full_causal_features(
        event=ev,
        if_score=0.0,
        baseline_deviation=0.0,
        profiler=profiler,
        failed_auth_rate=0.0,
        graph_tracker=graph_tracker,
        sequence_tracker=seq_tracker,
    )
    assert len(feats) == 48


# ── Test 17: Production Model Artifact Immutability ───────────────────────────

def test_no_modification_of_production_model_artifact():
    model_path = Path(__file__).resolve().parent.parent / "data" / "models" / "calibrated_threat_classifier.pkl"
    assert model_path.exists(), f"Production model not found at {model_path}"

    with open(model_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()

    assert digest == EXPECTED_MODEL_SHA256, (
        f"Production model artifact modified! Expected {EXPECTED_MODEL_SHA256}, got {digest}"
    )


# ── Test 18: Reproducible Normalization for Identical Inputs ───────────────────

def test_reproducible_normalization_for_identical_inputs():
    raw1 = {
        "event_id": "fixed-id-42",
        "timestamp": "2026-10-10T12:00:00+02:00",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 5000,
        "dst_port": 443,
        "protocol": "6",
        "bytes_sent": 1200,
        "bytes_received": 2400,
        "password": "secret_dont_leak",
    }
    raw2 = dict(raw1)

    ev1 = NormalizerPipeline.normalize_strict(raw1)
    ev2 = NormalizerPipeline.normalize_strict(raw2)

    assert ev1.timestamp == ev2.timestamp
    assert ev1.bytes_ratio == ev2.bytes_ratio
    assert ev1.port_risk_score == ev2.port_risk_score
    assert ev1.provenance == ev2.provenance
    assert ev1.missing_fields == ev2.missing_fields
    assert ev1.protocol == ev2.protocol
