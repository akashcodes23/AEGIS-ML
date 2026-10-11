"""
Phase 27 Test Suite: Asynchronous Detection Pipeline, Queue Reliability, and Observability.

Validates:
1. Queue Contract: State lifecycle, backpressure policies, non-durable memory semantics.
2. Async Workers: Decoupled ingestion, worker thread offloading, graceful shutdown, flush.
3. Host Isolation: Serialized ordering within host partitions, concurrent multi-host dispatch.
4. Failure & Retry Policy: Transient error classification, exponential backoff, retry exhaustion.
5. Permanent Errors: Direct dead-letter routing without wasteful retries.
6. Incident Idempotency: Duplicate/retried delivery does not inflate incident evidence.
7. Observability: Queue depth, latency percentiles (wait, proc, e2e), worker health metrics.
8. API Endpoints: Asynchronous ingestion query param, dead-letter admin authorization, reset.
9. Artifact Hashes: Unchanged production classifier hash and Phase 19 dataset hash.
"""

import asyncio
import hashlib
import json
import os
import pytest
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.core.schemas import (
    UnifiedEvent,
    DetectionResult,
    Alert,
    EventProcessingState,
    QueueBackpressurePolicy,
    AsyncQueueConfig,
    QueueMetrics,
)
from backend.ingestion.async_queue import (
    AsyncDetectionQueue,
    TransientDetectionError,
    PermanentDetectionError,
    SimulatedTransientError,
)
from backend.ingestion.streaming_ingestion import StreamingIngestionManager

EXPECTED_MODEL_SHA256 = "98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71"
EXPECTED_PHASE19_SHA256 = "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"
ADMIN_KEY = os.environ.get("AEGIS_ADMIN_KEY", "aegis-super-admin-key-2026")


def _make_test_event(event_id: str, host_id: str = "host-01", **kwargs) -> UnifiedEvent:
    """Helper to construct valid UnifiedEvent for queue testing."""
    return UnifiedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        layer="network",
        src_entity=kwargs.get("src_ip", "10.0.1.10"),
        dst_entity=kwargs.get("dst_ip", "10.0.2.20"),
        src_internal=True,
        dst_internal=True,
        src_ip=kwargs.get("src_ip", "10.0.1.10"),
        dst_ip=kwargs.get("dst_ip", "10.0.2.20"),
        src_port=kwargs.get("src_port", 54321),
        dst_port=kwargs.get("dst_port", 80),
        protocol="TCP",
        bytes_sent=kwargs.get("bytes_sent", 500),
        host_id=host_id,
        action="connect",
    )


# ══════════════════════════════════════════════════════════════════════════════════
# 1. Queue Contract & State Machine
# ══════════════════════════════════════════════════════════════════════════════════

def test_queue_contract_states_enum():
    """Verify all 8 explicit event processing lifecycle states are defined."""
    expected_states = {
        "accepted", "queued", "processing", "completed",
        "duplicate", "rejected", "retry_pending", "failed"
    }
    actual_states = {s.value for s in EventProcessingState}
    assert expected_states == actual_states


def test_queue_non_durable_volatility_contract():
    """Verify queue metrics explicitly state non-durable in-memory volatility."""
    q = AsyncDetectionQueue()
    m = q.get_metrics()
    assert m.is_durable is False
    assert "in_memory_volatile_queue" in m.durability_guarantee


# ══════════════════════════════════════════════════════════════════════════════════
# 2. Asynchronous Workers & Backpressure
# ══════════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_queue_saturation_reject_policy():
    """Under REJECT policy, enqueuing beyond capacity immediately returns queue_full."""
    cfg = AsyncQueueConfig(max_queue_size=3, backpressure_policy=QueueBackpressurePolicy.REJECT)
    q = AsyncDetectionQueue(config=cfg)

    # Enqueue up to capacity
    for i in range(3):
        ev = _make_test_event(f"ev-sat-{i}")
        ok, reason, pos = await q.enqueue(ev)
        assert ok is True
        assert reason == "queued"

    # Enqueue 4th item beyond capacity
    ev_overflow = _make_test_event("ev-sat-overflow")
    ok, reason, pos = await q.enqueue(ev_overflow)
    assert ok is False
    assert reason == "queue_full"
    assert pos is None
    assert q.rejected_count == 1


@pytest.mark.asyncio
async def test_queue_saturation_block_timeout_policy():
    """Under BLOCK_TIMEOUT policy, enqueuing on full queue times out and returns queue_saturated."""
    cfg = AsyncQueueConfig(
        max_queue_size=2,
        backpressure_policy=QueueBackpressurePolicy.BLOCK_TIMEOUT,
        timeout_seconds=0.05,
    )
    q = AsyncDetectionQueue(config=cfg)

    # Fill queue
    await q.enqueue(_make_test_event("ev-block-1"))
    await q.enqueue(_make_test_event("ev-block-2"))

    # Next enqueue should block and time out
    start = time.perf_counter()
    ok, reason, pos = await q.enqueue(_make_test_event("ev-block-3"))
    elapsed = time.perf_counter() - start

    assert ok is False
    assert reason == "queue_saturated"
    assert elapsed >= 0.04


@pytest.mark.asyncio
async def test_async_worker_execution_and_flush():
    """Workers dequeue, process items asynchronously, and complete via flush."""
    processed = []

    def mock_handler(event: UnifiedEvent):
        processed.append(event.event_id)
        return None, None

    cfg = AsyncQueueConfig(max_queue_size=10, worker_concurrency=2)
    q = AsyncDetectionQueue(config=cfg, detection_handler=mock_handler)
    await q.start()

    try:
        for i in range(5):
            await q.enqueue(_make_test_event(f"ev-flush-{i}"))

        flushed = await q.flush(timeout_seconds=2.0)
        assert flushed is True
        assert len(processed) == 5
        assert q.completed_events == 5
        assert q.queue_depth == 0

        metrics = q.get_metrics()
        assert metrics.completed_events == 5
        assert metrics.worker_health == "healthy"
        assert metrics.processing_time_ms["mean"] >= 0.0
    finally:
        await q.stop()


# ══════════════════════════════════════════════════════════════════════════════════
# 3. Host Partition Ordering & Race Prevention
# ══════════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_host_partition_serial_ordering():
    """Events for the same host are processed in strict arrival order without concurrency races."""
    order_log = []

    def slow_host_handler(event: UnifiedEvent):
        time.sleep(0.01)  # Simulate CPU feature extraction
        order_log.append((event.host_id, event.event_id))
        return None, None

    cfg = AsyncQueueConfig(max_queue_size=20, worker_concurrency=4)
    q = AsyncDetectionQueue(config=cfg, detection_handler=slow_host_handler)
    await q.start()

    try:
        # Enqueue 6 events for host-A in order
        for i in range(6):
            await q.enqueue(_make_test_event(f"A-{i}", host_id="host-A"))

        await q.flush(timeout_seconds=3.0)
        assert len(order_log) == 6
        expected_seq = [f"A-{i}" for i in range(6)]
        actual_seq = [item[1] for item in order_log]
        assert actual_seq == expected_seq, f"Expected strict sequence {expected_seq}, got {actual_seq}"
    finally:
        await q.stop()


# ══════════════════════════════════════════════════════════════════════════════════
# 4. Failure Classification, Retries, and Dead Letter
# ══════════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_transient_failure_retries_and_recovers():
    """Transient failures retry with exponential backoff and succeed on subsequent attempt."""
    attempt_tracker = {}

    def flaky_handler(event: UnifiedEvent):
        count = attempt_tracker.get(event.event_id, 0) + 1
        attempt_tracker[event.event_id] = count
        if count < 3:
            raise SimulatedTransientError(f"Temporary database timeout on attempt {count}")
        return None, None

    cfg = AsyncQueueConfig(
        max_queue_size=5,
        worker_concurrency=1,
        max_retries=3,
        retry_backoff_base_seconds=0.01,
        retry_backoff_multiplier=1.5,
    )
    q = AsyncDetectionQueue(config=cfg, detection_handler=flaky_handler)
    await q.start()

    try:
        await q.enqueue(_make_test_event("ev-flaky-1"))
        flushed = await q.flush(timeout_seconds=2.0)
        assert flushed is True

        # Should have succeeded on 3rd attempt
        assert attempt_tracker["ev-flaky-1"] == 3
        assert q.completed_events == 1
        assert q.retry_count == 2
        assert q.failed_events == 0
        assert len(q.get_dead_letter_items()) == 0
    finally:
        await q.stop()


@pytest.mark.asyncio
async def test_permanent_failure_bypasses_retry_to_dead_letter():
    """Permanent error bypasses retry loop and records directly to dead-letter queue."""
    def corrupt_handler(event: UnifiedEvent):
        raise PermanentDetectionError("Invalid feature dimensions: expected 48, got 12")

    cfg = AsyncQueueConfig(max_queue_size=5, worker_concurrency=1, max_retries=3)
    q = AsyncDetectionQueue(config=cfg, detection_handler=corrupt_handler)
    await q.start()

    try:
        await q.enqueue(_make_test_event("ev-perm-fail"))
        await q.flush(timeout_seconds=2.0)

        assert q.completed_events == 0
        assert q.retry_count == 0  # Permanent error is not retried!
        assert q.failed_events == 1

        dl_items = q.get_dead_letter_items()
        assert len(dl_items) == 1
        assert dl_items[0].event_id == "ev-perm-fail"
        assert dl_items[0].transient is False
        assert "Invalid feature dimensions" in dl_items[0].failure_reason
    finally:
        await q.stop()


@pytest.mark.asyncio
async def test_retry_exhaustion_routes_to_dead_letter():
    """Transient errors that persist beyond max_retries route to dead letter."""
    def constantly_failing_handler(event: UnifiedEvent):
        raise SimulatedTransientError("Persistent connection reset")

    cfg = AsyncQueueConfig(
        max_queue_size=5,
        worker_concurrency=1,
        max_retries=2,
        retry_backoff_base_seconds=0.01,
    )
    q = AsyncDetectionQueue(config=cfg, detection_handler=constantly_failing_handler)
    await q.start()

    try:
        await q.enqueue(_make_test_event("ev-exhausted"))
        await q.flush(timeout_seconds=2.0)

        assert q.failed_events == 1
        assert q.completed_events == 0
        assert q.retry_count == 2

        dl_items = q.get_dead_letter_items()
        assert len(dl_items) == 1
        assert dl_items[0].event_id == "ev-exhausted"
        assert dl_items[0].transient is True
        assert dl_items[0].attempts == 2
    finally:
        await q.stop()


# ══════════════════════════════════════════════════════════════════════════════════
# 5. Incident Idempotency & Duplicate Protection
# ══════════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_idempotent_event_processing_prevents_duplicate_executions():
    """Re-enqueuing an event already completed does not re-execute detection."""
    execution_count = 0

    def counting_handler(event: UnifiedEvent):
        nonlocal execution_count
        execution_count += 1
        return None, None

    cfg = AsyncQueueConfig(max_queue_size=10, worker_concurrency=1)
    q = AsyncDetectionQueue(config=cfg, detection_handler=counting_handler)
    await q.start()

    try:
        ev = _make_test_event("ev-idempotent-01")
        ok1, reason1, _ = await q.enqueue(ev)
        assert ok1 is True
        await q.flush(timeout_seconds=2.0)
        assert execution_count == 1

        # Attempt to re-enqueue identical event
        ok2, reason2, _ = await q.enqueue(ev)
        assert ok2 is False
        assert reason2 == "duplicate_event_already_processed"
        assert q.duplicate_count == 1
        assert execution_count == 1  # Did not re-execute!
    finally:
        await q.stop()


# ══════════════════════════════════════════════════════════════════════════════════
# 6. API Integration & Admin Authorization
# ══════════════════════════════════════════════════════════════════════════════════

def test_api_async_ingestion_endpoint():
    """POST /api/ingest/event?async=true enqueues and returns processing_state='queued'."""
    with TestClient(app) as client:
        raw_ev = {
            "event_id": f"api-async-{int(time.time()*1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "network",
            "src_ip": "10.0.1.55",
            "dst_ip": "10.0.2.66",
            "dst_port": 80,
            "bytes_sent": 1200,
            "action": "http_request",
        }
        res = client.post("/api/ingest/event?async=true", json={"raw_event": raw_ev})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "accepted"
        assert data["processing_state"] == "queued"
        assert data["queue_position"] is not None
        assert data["detection"] is None  # Async: detection decoupled from HTTP thread!


def test_api_batch_async_ingestion_endpoint():
    """POST /api/ingest/batch?async=true enqueues batch items asynchronously."""
    with TestClient(app) as client:
        now_str = datetime.now(timezone.utc).isoformat()
        events = [
            {
                "event_id": f"api-batch-async-{i}-{int(time.time()*1000)}",
                "timestamp": now_str,
                "layer": "network",
                "src_ip": "10.0.1.55",
                "dst_ip": "10.0.2.66",
                "dst_port": 80 + i,
                "bytes_sent": 500,
                "action": "connect",
            }
            for i in range(3)
        ]
        res = client.post("/api/ingest/batch?async=true", json={"events": events})
        assert res.status_code == 200
        data = res.json()
        assert data["accepted_count"] == 3
        for item in data["results"]:
            assert item["status"] == "accepted"
            assert item["processing_state"] == "queued"


def test_api_queue_metrics_endpoint():
    """GET /api/ingest/queue/metrics returns structured observability metrics."""
    with TestClient(app) as client:
        res = client.get("/api/ingest/queue/metrics")
        assert res.status_code == 200
        m = res.json()
        assert "queue_depth" in m
        assert "queue_capacity" in m
        assert "worker_health" in m
        assert "queue_wait_time_ms" in m
        assert "processing_time_ms" in m
        assert "end_to_end_latency_ms" in m
        assert m["is_durable"] is False


def test_api_dead_letter_requires_admin_authorization(monkeypatch):
    """GET /api/ingest/queue/dead-letter requires valid admin key."""
    test_key = "super-secret-test-dead-letter-key"
    monkeypatch.setenv("AEGIS_ADMIN_KEY", test_key)
    with TestClient(app) as client:
        # Unauthorized without key
        r_unauth = client.get("/api/ingest/queue/dead-letter")
        assert r_unauth.status_code == 401
        assert "Unauthorized" in r_unauth.json()["detail"]

        # Authorized with admin key
        r_auth = client.get(
            "/api/ingest/queue/dead-letter",
            headers={"X-AEGIS-Admin-Key": test_key},
        )
        assert r_auth.status_code == 200
        assert isinstance(r_auth.json(), list)


def test_api_ingestion_reset_clears_queue():
    """POST /api/ingest/reset with admin key clears queue and metrics."""
    with TestClient(app) as client:
        res = client.post(
            "/api/ingest/reset",
            headers={"X-AEGIS-Admin-Key": ADMIN_KEY},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "success"

        # Verify queue metrics reset
        m_res = client.get("/api/ingest/queue/metrics")
        assert m_res.status_code == 200
        m = m_res.json()
        assert m["queue_depth"] == 0


def test_malformed_event_never_enqueued():
    """Malformed event is rejected at normalization and never added to async queue."""
    with TestClient(app) as client:
        raw_ev = {
            "event_id": "malformed-ev-99",
            "timestamp": "invalid-timestamp",
            "layer": "unknown_layer",
            "src_ip": "invalid_ip",
        }
        res = client.post("/api/ingest/event?async=true", json={"raw_event": raw_ev})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "rejected"
        assert data["processing_state"] == "rejected"


# ══════════════════════════════════════════════════════════════════════════════════
# 7. Artifact Integrity Verification
# ══════════════════════════════════════════════════════════════════════════════════

def test_production_model_sha256_unmodified():
    """Strictly verify the 48-feature calibrated threat classifier artifact SHA-256."""
    path = Path("data/models/calibrated_threat_classifier.pkl")
    assert path.exists(), f"Missing production model artifact at {path}"
    with open(path, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest()
    assert actual_sha == EXPECTED_MODEL_SHA256, (
        f"Production model SHA-256 mismatch!\nExpected: {EXPECTED_MODEL_SHA256}\nActual:   {actual_sha}"
    )


def test_phase19_dataset_sha256_unmodified():
    """Strictly verify the Phase 19 behavioral-diversity evaluation dataset SHA-256."""
    path = Path("data/raw/behavioral_diversity_labeled.jsonl")
    assert path.exists(), f"Missing Phase 19 dataset at {path}"
    with open(path, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest()
    assert actual_sha == EXPECTED_PHASE19_SHA256, (
        f"Phase 19 dataset SHA-256 mismatch!\nExpected: {EXPECTED_PHASE19_SHA256}\nActual:   {actual_sha}"
    )
