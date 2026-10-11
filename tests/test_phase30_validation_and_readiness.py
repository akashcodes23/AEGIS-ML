"""
AEGIS-ML Phase 30: Final System Validation, Release Readiness, and Repository Integrity Tests.

Validates:
1. Security Regressions: Fail-closed admin auth, conflicting/malformed headers, traversal, replay bounds.
2. Queue Lifecycle & Exact Accounting Reconciliation: Zero unexplained loss across all terminal dispositions.
3. End-to-End Detection: Ingestion, normalization, 48-feature extraction, calibrated prediction, incident correlation.
4. Model & Artifact Integrity: Exact SHA-256 hashes, feature order, and blocked external dataset status.
"""

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.api.main import app, _require_admin_authorization, _extract_admin_token, _sanitize_artifact_filename
from backend.core.schemas import (
    UnifiedEvent,
    AsyncQueueConfig,
    QueueBackpressurePolicy,
)
from backend.detection.model_trainer import (
    CANONICAL_CLASSES,
    extract_full_causal_features,
)
from backend.evaluation.false_positive_calibration import PHASE22_BASELINE_FEATURE_NAMES
from backend.detection.threat_classifier import ThreatClassifier
from backend.ingestion.async_queue import (
    AsyncDetectionQueue,
    TransientDetectionError,
    PermanentDetectionError,
    SimulatedTransientError,
)
from backend.ingestion.normalizer import redact_sensitive_payload

client = TestClient(app)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "calibrated_threat_classifier.pkl"
DATASET_PATH = PROJECT_ROOT / "data" / "raw" / "behavioral_diversity_labeled.jsonl"

EXPECTED_MODEL_SHA256 = "98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71"
EXPECTED_DATASET_SHA256 = "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"


# ═══════════════════════════════════════════════════════════════════════════════
# Phase C — Security Regressions
# ═══════════════════════════════════════════════════════════════════════════════

def test_security_fail_closed_production_environment():
    """Verify that sensitive administrative operations fail-closed with 403 when key is missing in production."""
    with patch.dict(os.environ, {"AEGIS_ENV": "production"}, clear=False):
        os.environ.pop("AEGIS_ADMIN_KEY", None)

        endpoints = [
            ("GET", "/api/ingest/queue/dead-letter", None),
            ("POST", "/api/ingest/reset", None),
            ("POST", "/api/ingest/replay", {"events": []}),
            ("POST", "/api/model/reload", {"artifact_filename": "test.pkl"}),
        ]
        for method, path, json_data in endpoints:
            if method == "GET":
                res = client.get(path)
            else:
                res = client.post(path, json=json_data)
            assert res.status_code == 403, f"{method} {path} did not fail-closed with 403 (got {res.status_code})"


def test_security_auth_schemes_and_conflicting_headers():
    """Verify handling of custom header, Bearer token, and conflicting header configurations."""
    valid_key = "correct-admin-key-30"
    wrong_key = "incorrect-admin-key"

    with patch.dict(os.environ, {"AEGIS_ADMIN_KEY": valid_key}, clear=False):
        # 1. Custom header valid
        res = client.get("/api/ingest/queue/dead-letter", headers={"X-AEGIS-Admin-Key": valid_key})
        assert res.status_code == 200

        # 2. Authorization Bearer valid
        res = client.get("/api/ingest/queue/dead-letter", headers={"Authorization": f"Bearer {valid_key}"})
        assert res.status_code == 200

        # 3. Invalid credentials
        res = client.get("/api/ingest/queue/dead-letter", headers={"X-AEGIS-Admin-Key": wrong_key})
        assert res.status_code == 401

        # 4. Conflicting headers: custom header takes precedence if both provided
        res = client.get("/api/ingest/queue/dead-letter", headers={
            "X-AEGIS-Admin-Key": valid_key,
            "Authorization": f"Bearer {wrong_key}",
        })
        assert res.status_code == 200

        # 5. Malformed Authorization header without Bearer prefix
        assert _extract_admin_token(None, "") is None
        assert _extract_admin_token(None, "   ") is None
        assert _extract_admin_token(None, "Basic dXNlcjpwYXNz") == "Basic dXNlcjpwYXNz"


def test_security_path_traversal_sanitization():
    """Verify directory traversal attempts in artifact filenames are blocked."""
    invalid_filenames = [
        "../models/evil.pkl",
        "../../etc/passwd",
        "/etc/shadow",
        "..\\windows\\system32",
        "subdir/model.pkl",
        "",
        "   ",
    ]
    for fn in invalid_filenames:
        with pytest.raises(Exception) as exc_info:
            _sanitize_artifact_filename(fn)
        assert exc_info.value.status_code == 400


def test_security_replay_bounds_and_empty_requests():
    """Verify replay endpoint limits enforce upper bound and reject empty requests."""
    admin_key = "replay-audit-key"
    with patch.dict(os.environ, {"AEGIS_ADMIN_KEY": admin_key}, clear=False):
        headers = {"X-AEGIS-Admin-Key": admin_key}

        # Empty payload
        res = client.post("/api/ingest/replay", json={"events": []}, headers=headers)
        assert res.status_code == 400
        assert "empty" in res.json()["detail"].lower()

        # Excess payload (> 2000 events)
        oversized = [{"event_id": f"ev-{i}", "layer": "network"} for i in range(2001)]
        res = client.post("/api/ingest/replay", json={"events": oversized}, headers=headers)
        assert res.status_code == 400
        assert "exceeds" in res.json()["detail"].lower()


# ═══════════════════════════════════════════════════════════════════════════════
# Phase B & F — Queue Accounting & Failure Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_queue_exact_accounting_reconciliation():
    """Verify that submitted events reconcile exactly across all terminal categories with 0 unexplained loss."""
    config = AsyncQueueConfig(
        max_queue_size=10,
        worker_concurrency=2,
        backpressure_policy=QueueBackpressurePolicy.REJECT,
        max_retries=2,
        retry_backoff_base_seconds=0.01,
        retry_backoff_multiplier=1.2,
    )

    completed_ids = set()

    def detection_handler(ev: UnifiedEvent):
        completed_ids.add(ev.event_id)
        if ev.event_id == "fail-permanent":
            raise PermanentDetectionError("Corrupted payload")
        if ev.event_id == "fail-retry-exhausted":
            raise TransientDetectionError("Lock timeout")
        return None, None

    queue = AsyncDetectionQueue(config=config, detection_handler=detection_handler)
    await queue.start()

    # 1. Enqueue 5 normal events
    for i in range(5):
        ev = UnifiedEvent(
            event_id=f"norm-ev-{i}",
            timestamp=datetime.now(timezone.utc),
            layer="network",
            src_entity="10.0.0.1",
            dst_entity="10.0.0.2",
            src_internal=True,
            dst_internal=True,
        )
        ok, _, _ = await queue.enqueue(ev)
        assert ok

    # 2. Enqueue permanent failure event
    ev_perm = UnifiedEvent(
        event_id="fail-permanent",
        timestamp=datetime.now(timezone.utc),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=True,
        dst_internal=True,
    )
    ok, _, _ = await queue.enqueue(ev_perm)
    assert ok

    # 3. Enqueue retry-exhausted failure event
    ev_retry = UnifiedEvent(
        event_id="fail-retry-exhausted",
        timestamp=datetime.now(timezone.utc),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=True,
        dst_internal=True,
    )
    ok, _, _ = await queue.enqueue(ev_retry)
    assert ok

    # Flush current queue to ensure norm-ev-0 completes
    flushed = await queue.flush(timeout_seconds=5.0)
    assert flushed

    # 4. Enqueue duplicate of already completed event (ingest duplicate)
    ev_dup_ingest = UnifiedEvent(
        event_id="norm-ev-0",
        timestamp=datetime.now(timezone.utc),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=True,
        dst_internal=True,
    )
    ok, reason, _ = await queue.enqueue(ev_dup_ingest)
    assert not ok
    assert reason == "duplicate_event_already_processed"

    # Stop workers and fill queue to trigger backpressure rejection
    await queue.stop()
    for i in range(12):
        ev_fill = UnifiedEvent(
            event_id=f"fill-ev-{i}",
            timestamp=datetime.now(timezone.utc),
            layer="network",
            src_entity="10.0.0.1",
            dst_entity="10.0.0.2",
            src_internal=True,
            dst_internal=True,
        )
        await queue.enqueue(ev_fill)

    # Check accounting summary
    acct = queue.get_accounting_summary()
    assert acct["reconciliation_passed"]
    assert acct["unexplained_loss"] == 0
    assert acct["completed_events"] == 5
    assert acct["failed_dead_letter_events"] == 2
    assert acct["ingest_duplicate_events"] == 1
    assert acct["rejected_events"] == 2
    assert acct["currently_queued_events"] == 10


# ═══════════════════════════════════════════════════════════════════════════════
# Phase D — End-to-End Detection Regression
# ═══════════════════════════════════════════════════════════════════════════════

def test_e2e_streaming_ingestion_to_detection():
    """Verify live endpoint ingestion flows through normalization, model, and correlation."""
    payload = {
        "event_id": "e2e-test-ev-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "network",
        "src_ip": "185.220.101.45",
        "dst_ip": "10.0.0.10",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "bytes_sent": 1200,
        "bytes_received": 3500,
        "action": "http_request",
    }
    # Synchronous detection trigger with lifespan-initialized services
    with TestClient(app) as test_client:
        res = test_client.post("/api/ingest/event?detect=true", json={"raw_event": payload})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "accepted"
        assert data["event"] is not None
        assert data["detection"] is not None
        assert "threat_type" in data["detection"]
        assert data["detection"]["threat_type"] in CANONICAL_CLASSES


# ═══════════════════════════════════════════════════════════════════════════════
# Phase E — Model and Evaluation Integrity
# ═══════════════════════════════════════════════════════════════════════════════

def test_production_model_sha256_unmodified():
    """Assert production model artifact SHA-256 matches exact ground-truth hash."""
    assert MODEL_PATH.exists()
    computed_hash = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    assert computed_hash == EXPECTED_MODEL_SHA256


def test_phase19_dataset_sha256_unmodified():
    """Assert Phase 19 behavioral-diversity dataset SHA-256 matches exact ground-truth hash."""
    assert DATASET_PATH.exists()
    computed_hash = hashlib.sha256(DATASET_PATH.read_bytes()).hexdigest()
    assert computed_hash == EXPECTED_DATASET_SHA256


def test_production_48_feature_ordering_and_schema():
    """Verify feature schema ordering and length match the immutable 48-feature contract."""
    clf = ThreatClassifier()
    clf.load(str(MODEL_PATH))
    assert clf.n_features == 48
    assert len(clf.feature_names) == 48
    assert clf.feature_names == PHASE22_BASELINE_FEATURE_NAMES


def test_external_dataset_cicids2017_status_blocked():
    """Verify CIC-IDS2017 remains strictly in BLOCKED status."""
    audit_path = PROJECT_ROOT / "data" / "models" / "evaluation_reproducibility_audit.json"
    assert audit_path.exists()
    import json
    with open(audit_path, "r") as f:
        data = json.load(f)
    assert data["external_benchmark_status"]["cic_ids2017"]["status"] == "BLOCKED"
