"""
AEGIS-ML Phase 29 Tests: Production Hardening, Security, Batch Equivalence,
Queue Reliability, and Observability.
"""

import asyncio
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.api.main import app, _require_admin_authorization, _extract_admin_token
from backend.core.schemas import (
    UnifiedEvent,
    AsyncQueueConfig,
    QueueBackpressurePolicy,
)
from backend.detection.threat_classifier import ThreatClassifier, ThreatPrediction
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


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 29.1 — Security Audit Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_extract_admin_token_variants():
    """Verify admin token extraction from both custom header and Bearer auth."""
    assert _extract_admin_token("test-secret", None) == "test-secret"
    assert _extract_admin_token(None, "Bearer bearer-secret") == "bearer-secret"
    assert _extract_admin_token(None, "bearer bearer-secret-lower") == "bearer-secret-lower"
    assert _extract_admin_token(None, "raw-token") == "raw-token"
    assert _extract_admin_token(None, None) is None


def test_admin_authorization_fail_closed_in_production():
    """Verify administrative operations fail-closed when key is missing in exposed deployments."""
    with patch.dict(os.environ, {"AEGIS_ENV": "production", "AEGIS_ADMIN_KEY": ""}, clear=False):
        os.environ.pop("AEGIS_ADMIN_KEY", None)
        with pytest.raises(Exception) as exc_info:
            _require_admin_authorization("any-token", action_description="test-action")
        assert exc_info.value.status_code == 403


def test_admin_authorization_fail_closed_when_auth_required():
    """Verify fail-closed enforcement when AEGIS_REQUIRE_ADMIN_AUTH=true without key configured."""
    with patch.dict(os.environ, {"AEGIS_REQUIRE_ADMIN_AUTH": "true", "AEGIS_ADMIN_KEY": ""}, clear=False):
        os.environ.pop("AEGIS_ADMIN_KEY", None)
        with pytest.raises(Exception) as exc_info:
            _require_admin_authorization("any-token", action_description="test-action")
        assert exc_info.value.status_code == 403


def test_admin_endpoints_unauthorized_access():
    """Test that all administrative endpoints reject invalid or missing keys when auth is required."""
    with patch.dict(os.environ, {"AEGIS_ADMIN_KEY": "super-secret-key-12345"}, clear=False):
        # 1. Dead letter queue
        res = client.get("/api/ingest/queue/dead-letter")
        assert res.status_code == 401

        # 2. Reset ingestion
        res = client.post("/api/ingest/reset")
        assert res.status_code == 401

        # 3. Replay
        res = client.post("/api/ingest/replay", json={"events": []})
        assert res.status_code == 401

        # 4. Model reload
        res = client.post("/api/model/reload", json={"artifact_filename": "test.pkl"})
        assert res.status_code == 401


def test_admin_endpoints_authorized_access():
    """Verify that administrative endpoints succeed with valid token via custom header or Bearer."""
    test_key = "test-secret-phase29"
    with patch.dict(os.environ, {"AEGIS_ADMIN_KEY": test_key}, clear=False):
        # Header auth
        res = client.get("/api/ingest/queue/dead-letter", headers={"X-AEGIS-Admin-Key": test_key})
        assert res.status_code == 200

        # Bearer auth
        res = client.post("/api/ingest/reset", headers={"Authorization": f"Bearer {test_key}"})
        assert res.status_code == 200


def test_replay_request_limits():
    """Verify replay endpoint validates input size bounds to prevent DoS."""
    test_key = "test-secret-replay"
    with patch.dict(os.environ, {"AEGIS_ADMIN_KEY": test_key}, clear=False):
        headers = {"X-AEGIS-Admin-Key": test_key}

        # Empty replay rejected
        res = client.post("/api/ingest/replay", json={"events": []}, headers=headers)
        assert res.status_code == 400
        assert "empty" in res.json()["detail"].lower()

        # Excessively large replay rejected (> 2000 events)
        oversized = [{"event_id": f"ev-{i}", "layer": "network"} for i in range(2001)]
        res = client.post("/api/ingest/replay", json={"events": oversized}, headers=headers)
        assert res.status_code == 400
        assert "exceeds" in res.json()["detail"].lower()


def test_sensitive_credential_redaction_in_dead_letter():
    """Verify that credentials and sensitive tokens are scrubbed from dead-letter entries."""
    raw_payload = {
        "event_id": "test-sec-01",
        "password": "ClearTextPassword123",
        "api_key": "sk-secret-token-xyz",
        "auth_token": "bearer-jwt-token",
        "user": {
            "name": "admin",
            "private_key": "BEGIN PRIVATE KEY...",
        },
        "public_data": "benign-query",
    }
    redacted = redact_sensitive_payload(raw_payload)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["auth_token"] == "[REDACTED]"
    assert redacted["user"]["private_key"] == "[REDACTED]"
    assert redacted["public_data"] == "benign-query"


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 29.2 — Batch Inference Correctness Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_predict_vs_predict_batch_equivalence():
    """Verify bit-for-bit mathematical equivalence between predict() and predict_batch()."""
    clf = ThreatClassifier()
    if MODEL_PATH.exists():
        clf.load(str(MODEL_PATH))
    else:
        clf.load()

    assert clf.is_fitted
    rng = np.random.RandomState(42)
    n_features = clf.n_features

    # Generate 50 test feature vectors
    test_vectors = [rng.uniform(-2.0, 5.0, size=n_features).tolist() for _ in range(50)]

    # Single-event predictions
    single_preds = [clf.predict(vec) for vec in test_vectors]

    # Vectorized batch predictions
    batch_preds = clf.predict_batch(test_vectors)

    assert len(single_preds) == len(batch_preds)

    for i, (sp, bp) in enumerate(zip(single_preds, batch_preds)):
        # Predicted threat type
        assert sp.threat_type == bp.threat_type, f"Mismatch at index {i}: {sp.threat_type} vs {bp.threat_type}"
        # Confidence score
        assert abs(sp.confidence - bp.confidence) < 1e-7
        # Severity
        assert sp.severity == bp.severity
        # Calibration status
        assert sp.is_calibrated == bp.is_calibrated

        # Calibrated probabilities dictionary
        if sp.calibrated_probabilities and bp.calibrated_probabilities:
            for cls_name, prob in sp.calibrated_probabilities.items():
                assert abs(prob - bp.calibrated_probabilities[cls_name]) < 1e-7

        # Raw probabilities dictionary
        for cls_name, prob in sp.raw_probabilities.items():
            assert abs(prob - bp.raw_probabilities[cls_name]) < 1e-7


def test_predict_batch_invalid_inputs_raise():
    """Verify invalid feature vectors in batch prediction trigger ValueError identically."""
    clf = ThreatClassifier()
    if MODEL_PATH.exists():
        clf.load(str(MODEL_PATH))
    else:
        clf.load()

    # Empty batch returns empty list
    assert clf.predict_batch([]) == []

    # Vector with wrong length
    invalid_len = [0.0] * (clf.n_features - 5)
    with pytest.raises(ValueError):
        clf.predict_batch([invalid_len])

    # Vector containing NaN
    nan_vector = [0.0] * clf.n_features
    nan_vector[3] = float("nan")
    with pytest.raises(ValueError):
        clf.predict_batch([nan_vector])

    # Vector containing Inf
    inf_vector = [0.0] * clf.n_features
    inf_vector[5] = float("inf")
    with pytest.raises(ValueError):
        clf.predict_batch([inf_vector])


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 29.3 — Queue Reliability Tests
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_queue_saturation_backpressure_rejection():
    """Verify queue enforces max_queue_size and rejects excess events cleanly."""
    config = AsyncQueueConfig(
        max_queue_size=5,
        worker_concurrency=1,
        backpressure_policy=QueueBackpressurePolicy.REJECT,
    )
    async_queue = AsyncDetectionQueue(config=config, detection_handler=None)
    # Do not start workers so queue fills up
    enqueued = 0
    rejected = 0

    for i in range(10):
        ev = UnifiedEvent(
            event_id=f"sat-ev-{i}",
            timestamp=datetime.now(timezone.utc),
            layer="network",
            src_entity="10.0.0.1",
            dst_entity="10.0.0.2",
            src_internal=True,
            dst_internal=True,
        )
        ok, reason, _ = await async_queue.enqueue(ev)
        if ok:
            enqueued += 1
        else:
            rejected += 1

    assert enqueued == 5
    assert rejected == 5
    assert async_queue.queue_depth == 5
    assert async_queue.rejected_count == 5


@pytest.mark.asyncio
async def test_queue_retry_and_dead_letter_classification():
    """Verify transient faults trigger retries with backoff and permanent faults route to dead-letter."""
    config = AsyncQueueConfig(
        max_queue_size=20,
        worker_concurrency=1,
        max_retries=2,
        retry_backoff_base_seconds=0.01,
        retry_backoff_multiplier=1.2,
    )

    attempt_counts = {}

    def test_handler(event: UnifiedEvent):
        attempt_counts[event.event_id] = attempt_counts.get(event.event_id, 0) + 1
        if event.event_id == "transient-fail":
            raise TransientDetectionError("Simulated temporary lock timeout")
        if event.event_id == "permanent-fail":
            raise PermanentDetectionError("Simulated unparseable payload")
        return None, None

    async_queue = AsyncDetectionQueue(config=config, detection_handler=test_handler)
    await async_queue.start()

    ev_transient = UnifiedEvent(
        event_id="transient-fail",
        timestamp=datetime.now(timezone.utc),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=True,
        dst_internal=True,
    )
    ev_permanent = UnifiedEvent(
        event_id="permanent-fail",
        timestamp=datetime.now(timezone.utc),
        layer="network",
        src_entity="10.0.0.3",
        dst_entity="10.0.0.4",
        src_internal=True,
        dst_internal=True,
    )

    await async_queue.enqueue(ev_transient)
    await async_queue.enqueue(ev_permanent)

    flushed = await async_queue.flush(timeout_seconds=5.0)
    assert flushed
    await async_queue.stop()

    # Transient failed after 2 attempts -> Dead letter
    assert attempt_counts.get("transient-fail") == 2
    # Permanent failed immediately on 1 attempt -> Dead letter
    assert attempt_counts.get("permanent-fail") == 1

    dl_items = async_queue.get_dead_letter_items()
    dl_ids = [item.event_id for item in dl_items]
    assert "transient-fail" in dl_ids
    assert "permanent-fail" in dl_ids
    assert async_queue.failed_events == 2
    assert async_queue.retry_count == 2
    assert async_queue.inference_failure_count >= 2


@pytest.mark.asyncio
async def test_queue_repeated_start_stop():
    """Verify queue handles multiple consecutive start/stop cycles cleanly."""
    config = AsyncQueueConfig(max_queue_size=10, worker_concurrency=2)
    async_queue = AsyncDetectionQueue(config=config, detection_handler=lambda e: (None, None))

    for cycle in range(3):
        assert not async_queue.is_running
        await async_queue.start()
        assert async_queue.is_running
        ev = UnifiedEvent(
            event_id=f"cycle-ev-{cycle}",
            timestamp=datetime.now(timezone.utc),
            layer="network",
            src_entity="10.0.0.1",
            dst_entity="10.0.0.2",
            src_internal=True,
            dst_internal=True,
        )
        await async_queue.enqueue(ev)
        await async_queue.flush(timeout_seconds=2.0)
        await async_queue.stop()
        assert not async_queue.is_running


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 29.4 — Observability Tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_health_check_observability_fields():
    """Verify /health exposes model readiness and queue status without secret leakage."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "ok"
    assert "model_readiness" in data
    mr = data["model_readiness"]
    assert "is_fitted" in mr
    assert "model_version" in mr
    assert "calibrated" in mr
    assert "feature_count" in mr
    assert mr["feature_count"] == 48

    # Verify no secrets or private keys leaked in response
    resp_text = res.text.lower()
    assert "aegis_admin_key" not in resp_text
    assert "password" not in resp_text
    assert "secret" not in resp_text


def test_queue_metrics_endpoint():
    """Verify /api/ingest/queue/metrics provides latency percentiles and queue counters."""
    res = client.get("/api/ingest/queue/metrics")
    assert res.status_code == 200
    data = res.json()

    assert "queue_depth" in data
    assert "queue_capacity" in data
    assert "worker_health" in data
    assert "queue_wait_time_ms" in data
    assert "processing_time_ms" in data
    assert "end_to_end_latency_ms" in data
    assert "inference_failure_count" in data
    assert data["is_durable"] is False
    assert "in_memory_volatile" in data["durability_guarantee"]
