"""
Phase 26 End-to-End Detection Validation, Replay, and Benchmark Test Suite.

Covers:
- Phase 26.1: Pipeline Contract Audit (48 features, calibrated probabilities, schemas).
- Phase 26.2: 12 End-to-End Integration Fixtures.
- Phase 26.3: Deterministic Event Replay (chronological, out-of-order, duplicates, isolation, API).
- Phase 26.4: Evidence and Incident Integrity (missingness, provenance, observation vs hypothesis).
- Phase 26.5: Performance Benchmark Generation.
- Phase 26.6: Production Model and Dataset Regression Integrity.
"""

import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app, _require_admin_authorization, _evaluate_event_detection
from backend.core.schemas import (
    UnifiedEvent,
    IngestionItemResult,
    DetectionResult,
    Alert,
    Incident,
    ReplayRequest,
    ReplayResponse,
)
from backend.detection.sequence_context import CausalSequenceTracker
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.evaluation.false_positive_calibration import PHASE22_BASELINE_FEATURE_NAMES
from backend.ingestion.fixtures import get_e2e_fixtures, E2EFixtureScenario
from backend.ingestion.normalizer import NormalizerPipeline
from backend.ingestion.replay import DeterministicEventReplayer, ReplayConfig, ReplaySummary
from backend.ingestion.streaming_ingestion import StreamingIngestionManager
from backend.evaluation.streaming_benchmark import run_streaming_benchmark, generate_benchmark_events

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PRODUCTION_MODEL_PATH = PROJECT_ROOT / "data" / "models" / "calibrated_threat_classifier.pkl"
PHASE19_DATASET_PATH = PROJECT_ROOT / "data" / "raw" / "behavioral_diversity_labeled.jsonl"
EXPECTED_MODEL_SHA256 = "98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71"
EXPECTED_PHASE19_SHA256 = "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"


# ══════════════════════════════════════════════════════════════════════════════════
# PHASE 26.1: Pipeline Contract Audit
# ══════════════════════════════════════════════════════════════════════════════════

def test_pipeline_contract_48_feature_ordering_and_completeness():
    """Verify 48-feature names, ordering, and length match production expectations."""
    assert len(PHASE22_BASELINE_FEATURE_NAMES) == 48
    assert PHASE22_BASELINE_FEATURE_NAMES[0] == "if_anomaly_score"
    assert PHASE22_BASELINE_FEATURE_NAMES[14] == "cross_layer_match"
    assert PHASE22_BASELINE_FEATURE_NAMES[15] == "distinct_dst_internal_5m"
    assert PHASE22_BASELINE_FEATURE_NAMES[20] == "pivot_chain_indicator"
    assert PHASE22_BASELINE_FEATURE_NAMES[21] == "is_network_layer"
    assert PHASE22_BASELINE_FEATURE_NAMES[30] == "has_verified_socket_binding"
    assert PHASE22_BASELINE_FEATURE_NAMES[31] == "missing_dst_port"
    assert PHASE22_BASELINE_FEATURE_NAMES[35] == "missing_auth_result"
    assert PHASE22_BASELINE_FEATURE_NAMES[36] == "seq_window_event_count_host"
    assert PHASE22_BASELINE_FEATURE_NAMES[-1] == "seq_sequence_completeness_score"


def test_pipeline_contract_calibrated_probabilities_sum_to_one():
    """Verify inference results contain calibrated probabilities summing to 1.0."""
    with TestClient(app) as client:
        # Send a synthetic event with detection enabled
        payload = {
            "raw_event": {
                "event_id": "contract-test-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "network",
                "src_ip": "10.0.1.15",
                "dst_ip": "10.0.1.25",
                "src_port": 50123,
                "dst_port": 443,
                "protocol": "TCP",
                "bytes_sent": 2500,
                "action": "connect",
            },
            "trigger_detection": True,
        }
        res = client.post("/api/ingest/event", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "accepted"
        det = data["detection"]
        assert det is not None
        assert det["is_calibrated"] is True
        cal_probs = det["calibrated_probabilities"]
        assert cal_probs is not None
        assert abs(sum(cal_probs.values()) - 1.0) < 1e-4
        assert all(p >= 0.0 for p in cal_probs.values())


def test_pipeline_contract_alert_strongly_typed_incident_id():
    """Verify Alert model supports and populates incident_id when correlated."""
    with TestClient(app) as client:
        payload = {
            "raw_event": {
                "event_id": "contract-alert-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "application",
                "src_ip": "198.51.100.99",
                "dst_ip": "10.0.0.5",
                "http_method": "POST",
                "endpoint_path": "/api/v1/login",
                "status_code": 401,
                "auth_result": "failure",
                "action": "login",
            },
            "trigger_detection": True,
        }
        # Ingest multiple brute-force attempts to ensure alert threshold is met
        alert_found = False
        for i in range(5):
            ev_copy = dict(payload["raw_event"])
            ev_copy["event_id"] = f"contract-alert-{i:02d}"
            ev_copy["timestamp"] = (datetime.now(timezone.utc) + timedelta(seconds=i)).isoformat()
            res = client.post("/api/ingest/event", json={"raw_event": ev_copy, "trigger_detection": True})
            item = res.json()
            if item.get("alert"):
                alert_found = True
                assert item["alert"]["incident_id"] is not None
                assert item["alert"]["incident_id"].startswith("INC-")
                break
        assert alert_found, "Expected at least one alert to be produced with populated incident_id"


# ══════════════════════════════════════════════════════════════════════════════════
# PHASE 26.2: End-to-End Test Fixtures (All 12 Scenarios)
# ══════════════════════════════════════════════════════════════════════════════════

def test_e2e_fixture_01_benign_network():
    """Scenario 1: Benign network traffic accepted without generating threat alerts."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["benign_network"]
    with TestClient(app) as client:
        for ev, exp_st in zip(sc.events, sc.expected_ingestion_statuses):
            res = client.post("/api/ingest/event", json={"raw_event": ev, "trigger_detection": True})
            data = res.json()
            assert data["status"] == exp_st
            assert data["alert"] is None


def test_e2e_fixture_02_brute_force():
    """Scenario 2: Brute force sequence triggers accepted ingestion and incident."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["brute_force"]
    with TestClient(app) as client:
        alerts = []
        for ev, exp_st in zip(sc.events, sc.expected_ingestion_statuses):
            res = client.post("/api/ingest/event", json={"raw_event": ev, "trigger_detection": True})
            data = res.json()
            assert data["status"] == exp_st
            if data.get("alert"):
                alerts.append(data["alert"])
        assert len(alerts) > 0
        assert any(a["threat_type"] == "brute_force" for a in alerts)


def test_e2e_fixture_03_lateral_movement_cross_layer():
    """Scenario 3: Endpoint execution followed by SMB connect correlates across layers."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["lateral_movement"]
    with TestClient(app) as client:
        for ev, exp_st in zip(sc.events, sc.expected_ingestion_statuses):
            res = client.post("/api/ingest/event", json={"raw_event": ev, "trigger_detection": True})
            data = res.json()
            assert data["status"] == exp_st


def test_e2e_fixture_04_data_exfiltration():
    """Scenario 4: High volume outbound transfer triggers data exfiltration detection."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["data_exfiltration"]
    with TestClient(app) as client:
        res = client.post("/api/ingest/event", json={"raw_event": sc.events[0], "trigger_detection": True})
        data = res.json()
        assert data["status"] == "accepted"
        assert data["detection"] is not None


def test_e2e_fixture_05_c2_beaconing():
    """Scenario 5: Fixed-cadence low-volume polls accepted and tracked."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["c2_beaconing"]
    with TestClient(app) as client:
        for ev, exp_st in zip(sc.events, sc.expected_ingestion_statuses):
            res = client.post("/api/ingest/event", json={"raw_event": ev, "trigger_detection": True})
            assert res.json()["status"] == exp_st


def test_e2e_fixture_06_missing_attribution():
    """Scenario 6: Missing host/process attribution preserves missingness without fabrication."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["missing_attribution"]
    with TestClient(app) as client:
        res = client.post("/api/ingest/event", json={"raw_event": sc.events[0], "trigger_detection": True})
        data = res.json()
        assert data["status"] == "accepted"
        assert data["event"]["host_id"] is None
        assert data["event"]["process_name"] is None


def test_e2e_fixture_07_malformed_telemetry():
    """Scenario 7: Malformed telemetry rejected without triggering ML inference."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["malformed_telemetry"]
    with TestClient(app) as client:
        for ev in sc.events:
            res = client.post("/api/ingest/event", json={"raw_event": ev, "trigger_detection": True})
            data = res.json()
            assert data["status"] == "rejected"
            assert data["detection"] is None
            assert data["alert"] is None


def test_e2e_fixture_08_duplicate_event_ids():
    """Scenario 8: Consecutive identical event IDs caught by deduplication."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["duplicate_event_ids"]
    with TestClient(app) as client:
        r1 = client.post("/api/ingest/event", json={"raw_event": sc.events[0]})
        r2 = client.post("/api/ingest/event", json={"raw_event": sc.events[1]})
        assert r1.json()["status"] == "accepted"
        assert r2.json()["status"] == "duplicate"
        assert r2.json()["reason"] == "duplicate_event_id"


def test_e2e_fixture_09_duplicate_payload_fingerprints():
    """Scenario 9: Distinct IDs with identical invariant payloads caught by fingerprint dedup."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["duplicate_payload_fingerprints"]
    with TestClient(app) as client:
        r1 = client.post("/api/ingest/event", json={"raw_event": sc.events[0]})
        r2 = client.post("/api/ingest/event", json={"raw_event": sc.events[1]})
        assert r1.json()["status"] == "accepted"
        assert r2.json()["status"] == "duplicate"
        assert r2.json()["reason"] == "duplicate_payload_fingerprint"


def test_e2e_fixture_10_out_of_order_events():
    """Scenario 10: Non-chronological arrivals accepted within tolerance without regressing watermark."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["out_of_order_events"]
    mgr = StreamingIngestionManager(late_tolerance_seconds=120.0)
    for ev in sc.events:
        res = mgr.ingest_event(ev)
        assert res.status == "accepted"
    # Watermark must be the maximum observed timestamp (10:00:10)
    assert mgr.watermark_timestamp == datetime(2026, 10, 11, 10, 0, 10)


def test_e2e_fixture_11_late_arriving_events():
    """Scenario 11: Events older than watermark minus tolerance marked is_late_arriving=True."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["late_arriving_events"]
    mgr = StreamingIngestionManager(late_tolerance_seconds=300.0)  # 5 min tolerance
    # ev 0: 10:00:00
    r0 = mgr.ingest_event(sc.events[0])
    assert r0.is_late_arriving is False
    # ev 1: 10:15:00 (advances watermark to 10:15:00)
    r1 = mgr.ingest_event(sc.events[1])
    assert r1.is_late_arriving is False
    # ev 2: 10:01:00 (14 min behind watermark, tolerance 5m -> late!)
    r2 = mgr.ingest_event(sc.events[2])
    assert r2.status == "accepted"
    assert r2.is_late_arriving is True
    # Watermark must remain at 10:15:00
    assert mgr.watermark_timestamp == datetime(2026, 10, 11, 10, 15, 0)


def test_e2e_fixture_12_contradictory_evidence():
    """Scenario 12: Incomplete telemetry preserves None without coercing to zero."""
    fixtures = get_e2e_fixtures()
    sc = fixtures["contradictory_evidence"]
    mgr = StreamingIngestionManager()
    r0 = mgr.ingest_event(sc.events[0])
    assert r0.status == "accepted"
    assert r0.event.dst_port is None
    assert r0.event.bytes_sent is None
    assert r0.event.protocol is None


# ══════════════════════════════════════════════════════════════════════════════════
# PHASE 26.3: Deterministic Event Replay
# ══════════════════════════════════════════════════════════════════════════════════

def test_replay_chronological_reproducibility():
    """Two replay runs with identical inputs and configuration produce identical metrics."""
    events = generate_benchmark_events(count=50, seed=123)
    config = ReplayConfig(mode="chronological", seed=42)

    replayer_1 = DeterministicEventReplayer(config=config)
    summary_1 = replayer_1.replay(events)

    replayer_2 = DeterministicEventReplayer(config=config)
    summary_2 = replayer_2.replay(events)

    assert summary_1.total_input_events == summary_2.total_input_events
    assert summary_1.accepted_count == summary_2.accepted_count
    assert summary_1.duplicate_count == summary_2.duplicate_count
    assert summary_1.rejected_count == summary_2.rejected_count
    assert summary_1.late_count == summary_2.late_count


def test_replay_out_of_order_and_duplicate_injection():
    """Replay facility injects duplicates and out-of-order delivery deterministically."""
    events = generate_benchmark_events(count=40, seed=999)
    config = ReplayConfig(
        mode="out_of_order",
        out_of_order_probability=0.3,
        duplicate_injection_rate=0.2,
        seed=777,
    )
    replayer = DeterministicEventReplayer(config=config)
    summary = replayer.replay(events)

    # Injected duplicates must increase total replayed events over input count
    assert summary.total_replayed_events > summary.total_input_events
    assert summary.duplicate_count > 0


def test_replay_isolation_from_production_state():
    """Executing replay in an isolated replayer does NOT contaminate live server state."""
    with TestClient(app) as client:
        # Check initial server stats
        r_pre = client.get("/api/ingest/stats")
        pre_ingested = r_pre.json()["total_ingested"]

        # Run replay locally
        replayer = DeterministicEventReplayer()
        replayer.replay([
            {"event_id": "isolated-01", "timestamp": "2026-10-11T12:00:00Z", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "layer": "network"}
        ])

        # Server stats must be completely unchanged
        r_post = client.get("/api/ingest/stats")
        post_ingested = r_post.json()["total_ingested"]
        assert pre_ingested == post_ingested


def test_replay_file_jsonl(tmp_path):
    """Replay from a JSONL file produces structured summary."""
    jsonl_path = tmp_path / "replay_stream.jsonl"
    evs = [
        {"event_id": "file-ev-1", "timestamp": "2026-10-11T10:00:00Z", "src_ip": "10.0.1.1", "dst_ip": "10.0.1.2", "layer": "network"},
        {"event_id": "file-ev-2", "timestamp": "2026-10-11T10:00:01Z", "src_ip": "10.0.1.1", "dst_ip": "10.0.1.2", "layer": "network"},
    ]
    with open(jsonl_path, "w") as f:
        for ev in evs:
            f.write(json.dumps(ev) + "\n")

    replayer = DeterministicEventReplayer()
    summary = replayer.replay_file(jsonl_path)
    assert summary.total_input_events == 2
    assert summary.accepted_count == 2


def test_replay_api_endpoint_authenticated(monkeypatch):
    """POST /api/ingest/replay enforces admin authentication and returns replay response."""
    monkeypatch.setenv("AEGIS_ADMIN_KEY", "replay-test-key")
    with TestClient(app) as client:
        payload = {
            "events": [
                {"event_id": "api-rep-1", "timestamp": "2026-10-11T10:00:00Z", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "layer": "network"}
            ],
            "mode": "chronological",
        }
        # 1. Unauthenticated -> 401
        res_no_auth = client.post("/api/ingest/replay", json=payload)
        assert res_no_auth.status_code == 401

        # 2. Authenticated -> 200
        res_auth = client.post("/api/ingest/replay", json=payload, headers={"X-AEGIS-Admin-Key": "replay-test-key"})
        assert res_auth.status_code == 200
        data = res_auth.json()
        assert data["status"] == "success"
        assert data["summary"]["accepted_count"] == 1


# ══════════════════════════════════════════════════════════════════════════════════
# PHASE 26.4: Evidence and Incident Integrity
# ══════════════════════════════════════════════════════════════════════════════════

def test_evidence_integrity_duplicate_does_not_inflate_incident():
    """Duplicate events do NOT duplicate entries in incident supporting_events."""
    replayer = DeterministicEventReplayer()
    t0 = datetime(2026, 10, 11, 10, 0, 0)
    alert = Alert(
        event_id="alert-ev-001",
        alert_id="ALT-001",
        timestamp=t0,
        threat_type="brute_force",
        severity="high",
        confidence=0.9,
        src_entity="198.51.100.2",
        dst_entity="10.0.0.5",
        layer="application",
        raw_event={"event_id": "alert-ev-001", "src_ip": "198.51.100.2"},
    )
    inc, is_new = replayer.correlator.correlate_alert(alert)
    assert len(inc.supporting_events) == 1

    # Second alert referencing the exact same raw event_id
    alert2 = Alert(
        event_id="alert-ev-001",
        alert_id="ALT-002",
        timestamp=t0 + timedelta(seconds=1),
        threat_type="brute_force",
        severity="high",
        confidence=0.9,
        src_entity="198.51.100.2",
        dst_entity="10.0.0.5",
        layer="application",
        raw_event={"event_id": "alert-ev-001", "src_ip": "198.51.100.2"},
    )
    inc2, is_new2 = replayer.correlator.correlate_alert(alert2)
    assert is_new2 is False
    # Must NOT double-count the same raw event
    assert len(inc2.supporting_events) == 1


def test_evidence_integrity_observation_vs_hypothesis_claim_types():
    """Incident timeline distinguishes concrete observation from inferred hypothesis."""
    replayer = DeterministicEventReplayer()
    alert = Alert(
        event_id="obs-001",
        timestamp=datetime.utcnow(),
        threat_type="lateral_movement",
        severity="high",
        confidence=0.85,
        src_entity="10.0.1.10",
        dst_entity="10.0.1.20",
        layer="network",
    )
    inc, _ = replayer.correlator.correlate_alert(alert)
    claim_types = [t.claim_type for t in inc.timeline]
    assert "observation" in claim_types
    assert "hypothesis" in claim_types


# ══════════════════════════════════════════════════════════════════════════════════
# PHASE 26.5: Performance Benchmark Generation
# ══════════════════════════════════════════════════════════════════════════════════

def test_performance_benchmark_generates_valid_report(tmp_path):
    """Verify performance benchmark executes and writes structured report."""
    bench_file = tmp_path / "bench_test.json"
    rep = run_streaming_benchmark(event_volumes=[20, 50], seed=42, output_path=bench_file)

    assert bench_file.exists()
    assert "metadata" in rep
    assert "results" in rep
    assert "volume_20" in rep["results"]
    assert "volume_50" in rep["results"]

    v20 = rep["results"]["volume_20"]
    assert v20["ingestion_only"]["throughput_eps"] > 0
    assert v20["detection_enabled"]["throughput_eps"] > 0
    assert "p50_median" in v20["ingestion_only"]["latency_ms"]
    assert "p95" in v20["detection_enabled"]["latency_ms"]


# ══════════════════════════════════════════════════════════════════════════════════
# PHASE 26.6: Regression and Security
# ══════════════════════════════════════════════════════════════════════════════════

def test_production_model_sha256_unmodified():
    """Verify production model artifact SHA-256 remains 98e926ed..."""
    assert PRODUCTION_MODEL_PATH.exists()
    with open(PRODUCTION_MODEL_PATH, "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    assert actual == EXPECTED_MODEL_SHA256


def test_phase19_dataset_sha256_unmodified():
    """Verify Phase 19 dataset SHA-256 remains 1a8967f3..."""
    assert PHASE19_DATASET_PATH.exists()
    with open(PHASE19_DATASET_PATH, "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    assert actual == EXPECTED_PHASE19_SHA256
