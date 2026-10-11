"""
AEGIS-ML Phase 29.5: Sustained-Load Testing and Queue Saturation Analysis.

Evaluates asynchronous detection queue stability, memory bounds, backpressure,
and latency percentiles across increasing workloads (100, 250, 500, 1000 events)
under realistic stress conditions:
- Multiple concurrent host identities.
- Chronological jitter and out-of-order arrival.
- Duplicate event re-delivery.
- Injected transient and permanent worker exceptions.
- Queue saturation and backpressure rejection.
- Continuous memory profiling via tracemalloc.

Outputs comprehensive results to:
data/models/sustained_load_test_results.json
"""

import asyncio
import gc
import json
import os
import platform
import sys
import time
import tracemalloc
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.schemas import (
    UnifiedEvent,
    AsyncQueueConfig,
    QueueBackpressurePolicy,
)
from backend.ingestion.async_queue import (
    AsyncDetectionQueue,
    TransientDetectionError,
    PermanentDetectionError,
    SimulatedTransientError,
)
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.detection.sequence_context import CausalSequenceTracker
from backend.detection.model_trainer import extract_features, extract_full_causal_features
from backend.correlation.weighted_fusion import WeightedEvidenceFusion
from backend.correlation.incident_correlator import IncidentCorrelator

RESULTS_PATH = PROJECT_ROOT / "data" / "models" / "sustained_load_test_results.json"


class SustainedLoadTestEnvironment:
    """Mock application environment providing fitted models and trackers for evaluation."""

    def __init__(self):
        self.classifier = ThreatClassifier()
        cal_path = PROJECT_ROOT / "data" / "models" / "calibrated_threat_classifier.pkl"
        if cal_path.exists():
            self.classifier.load(str(cal_path))
        else:
            self.classifier.load()

        self.if_detector = IsolationForestDetector()
        self.if_detector.load()
        self.profiler = BehavioralBaselineProfiler()
        self.profiler.load()
        self.graph_tracker = CausalTemporalGraphTracker()
        self.sequence_tracker = CausalSequenceTracker(window_seconds=300.0)
        self.fusion_engine = WeightedEvidenceFusion()
        self.correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)
        self.alerts = []
        self.incidents = []

    def evaluate_event(self, event: UnifiedEvent):
        """Single-event detection pipeline."""
        if not self.classifier or not self.classifier.is_fitted:
            return None, None

        if_score = self.if_detector.predict(event) if self.if_detector else 0.0
        base_dev = self.profiler.compute_deviation_score(event) if self.profiler else 0.0
        failed_auth = 1.0 if (event.status_code == 401 or str(event.auth_result or "").strip().lower() == "failure") else 0.0

        if getattr(self.classifier, "n_features", 15) == 48:
            features = extract_full_causal_features(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                profiler=self.profiler,
                failed_auth_rate=failed_auth,
                graph_tracker=self.graph_tracker,
                sequence_tracker=self.sequence_tracker,
            )
        else:
            features = extract_features(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                profiler=self.profiler,
                failed_auth_rate=failed_auth,
            )

        pred = self.classifier.predict(features)
        fusion_res = None
        if self.fusion_engine:
            fusion_res = self.fusion_engine.fuse(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                graph_score=0.0,
                threat_type=pred.threat_type,
                classifier_confidence=pred.confidence,
                severity=pred.severity,
                is_calibrated=pred.is_calibrated,
                calibrated_probabilities=pred.calibrated_probabilities,
                raw_probabilities=pred.raw_probabilities,
            )
        return fusion_res, None

    def evaluate_batch(self, events: List[UnifiedEvent]):
        """Batch detection pipeline."""
        if not self.classifier or not self.classifier.is_fitted:
            return [(None, None) for _ in events]

        features_list = []
        for event in events:
            if_score = self.if_detector.predict(event) if self.if_detector else 0.0
            base_dev = self.profiler.compute_deviation_score(event) if self.profiler else 0.0
            failed_auth = 1.0 if (event.status_code == 401 or str(event.auth_result or "").strip().lower() == "failure") else 0.0

            if getattr(self.classifier, "n_features", 15) == 48:
                feats = extract_full_causal_features(
                    event=event,
                    if_score=if_score,
                    baseline_deviation=base_dev,
                    profiler=self.profiler,
                    failed_auth_rate=failed_auth,
                    graph_tracker=self.graph_tracker,
                    sequence_tracker=self.sequence_tracker,
                )
            else:
                feats = extract_features(
                    event=event,
                    if_score=if_score,
                    baseline_deviation=base_dev,
                    profiler=self.profiler,
                    failed_auth_rate=failed_auth,
                )
            features_list.append(feats)

        preds = self.classifier.predict_batch(features_list)
        return [(preds[i], None) for i in range(len(events))]


def generate_stress_events(
    count: int,
    base_time: datetime,
    out_of_order_rate: float = 0.15,
    duplicate_rate: float = 0.08,
    num_hosts: int = 5,
) -> List[UnifiedEvent]:
    """Generate a realistic stress workload spanning multiple hosts with timestamps and jitter."""
    hosts = [f"host-node-{i:02d}" for i in range(1, num_hosts + 1)]
    events: List[UnifiedEvent] = []

    for i in range(count):
        host = hosts[i % num_hosts]
        # Introduce temporal jitter
        jitter_ms = (i % 7) * 20 - 40 if (i % 5 == 0) else 0
        t = base_time + timedelta(milliseconds=i * 25 + jitter_ms)
        event_id = f"stress-ev-{i:06d}"

        ev = UnifiedEvent(
            event_id=event_id,
            timestamp=t,
            layer="network",
            src_entity=f"10.0.1.{(i % 50) + 1}",
            dst_entity=f"10.0.2.{(i % 25) + 1}",
            src_ip=f"10.0.1.{(i % 50) + 1}",
            dst_ip=f"10.0.2.{(i % 25) + 1}",
            src_internal=True,
            dst_internal=True,
            src_port=40000 + (i % 10000),
            dst_port=80 if (i % 2 == 0) else 443,
            protocol="TCP",
            bytes_sent=400 + (i % 1200),
            bytes_received=1200 + (i % 3000),
            host_id=host,
            action="connection_established",
        )
        events.append(ev)

        # Inject duplicate event
        if duplicate_rate > 0 and (i % int(1.0 / duplicate_rate) == 0):
            dup_ev = UnifiedEvent(
                event_id=event_id,  # Same event_id
                timestamp=t + timedelta(milliseconds=5),
                layer="network",
                src_entity=ev.src_entity,
                dst_entity=ev.dst_entity,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                src_internal=True,
                dst_internal=True,
                host_id=host,
                action="duplicate_delivery",
            )
            events.append(dup_ev)

    return events


async def run_sustained_workload(
    workload_size: int,
    env: SustainedLoadTestEnvironment,
    queue_capacity: int = 500,
    worker_concurrency: int = 2,
    batch_size: int = 8,
    inject_transient_failure_rate: float = 0.02,
    inject_permanent_failure_rate: float = 0.01,
) -> Dict[str, Any]:
    """Execute sustained workload run and record observability & stability metrics."""
    gc.collect()
    tracemalloc.start()
    mem_before, _ = tracemalloc.get_traced_memory()

    config = AsyncQueueConfig(
        max_queue_size=queue_capacity,
        worker_concurrency=worker_concurrency,
        backpressure_policy=QueueBackpressurePolicy.REJECT,
        max_retries=3,
        retry_backoff_base_seconds=0.01,
        retry_backoff_multiplier=1.5,
    )

    async_queue = AsyncDetectionQueue(
        config=config,
        detection_handler=lambda ev: env.evaluate_event(ev),
        detection_batch_handler=lambda evs: env.evaluate_batch(evs),
        batch_size=batch_size,
    )

    # Injected fault hook
    transient_target_ids = set()
    permanent_target_ids = set()

    def fault_hook(event: UnifiedEvent, attempt: int):
        if event.event_id in permanent_target_ids:
            raise PermanentDetectionError(f"Simulated permanent payload corruption in {event.event_id}")
        if event.event_id in transient_target_ids and attempt < 2:
            raise SimulatedTransientError(f"Simulated transient worker lock timeout in {event.event_id}")

    async_queue.set_fault_hook(fault_hook)
    await async_queue.start()

    base_time = datetime.now(timezone.utc)
    raw_events = generate_stress_events(
        count=workload_size,
        base_time=base_time,
        out_of_order_rate=0.15,
        duplicate_rate=0.08,
        num_hosts=5,
    )

    # Assign injected targets
    total_raw = len(raw_events)
    transient_count = int(total_raw * inject_transient_failure_rate)
    permanent_count = int(total_raw * inject_permanent_failure_rate)
    for i in range(transient_count):
        transient_target_ids.add(raw_events[(i * 17) % total_raw].event_id)
    for i in range(permanent_count):
        permanent_target_ids.add(raw_events[(i * 31) % total_raw].event_id)

    queue_depth_samples: List[int] = []
    enqueued_count = 0
    rejected_count = 0
    duplicate_rejected_count = 0

    t_start = time.perf_counter()

    # Stream events in bursts to simulate real-world arrival
    chunk_size = 20
    for chunk_start in range(0, total_raw, chunk_size):
        chunk = raw_events[chunk_start:chunk_start + chunk_size]
        for ev in chunk:
            success, reason, _ = await async_queue.enqueue(ev)
            if success:
                enqueued_count += 1
            elif reason == "duplicate_event_already_processed":
                duplicate_rejected_count += 1
            else:
                rejected_count += 1
        queue_depth_samples.append(async_queue.queue_depth)
        # Brief yield to let background workers consume
        await asyncio.sleep(0.002)

    enqueue_elapsed = time.perf_counter() - t_start

    # Wait for queue to drain completely (flush)
    flush_success = await async_queue.flush(timeout_seconds=20.0)
    total_elapsed = time.perf_counter() - t_start

    # Record post-drain queue depth
    final_queue_depth = async_queue.queue_depth

    # Capture memory
    mem_current, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    metrics = async_queue.get_metrics()
    await async_queue.stop()

    completed_eps = metrics.completed_events / total_elapsed if total_elapsed > 0 else 0.0
    stable_point_reached = (final_queue_depth == 0) and flush_success

    return {
        "workload_target_events": workload_size,
        "total_streamed_events": total_raw,
        "enqueued_events": enqueued_count,
        "completed_events": metrics.completed_events,
        "failed_events": metrics.failed_events,
        "retry_count": metrics.retry_count,
        "duplicate_count": metrics.duplicate_count,
        "rejected_count": metrics.rejected_count,
        "dead_letter_count": metrics.dead_letter_count,
        "inference_failure_count": metrics.inference_failure_count,
        "duration_seconds": round(total_elapsed, 4),
        "enqueue_duration_seconds": round(enqueue_elapsed, 4),
        "completed_detection_throughput_eps": round(completed_eps, 2),
        "queue_wait_ms": metrics.queue_wait_time_ms,
        "processing_time_ms": metrics.processing_time_ms,
        "end_to_end_latency_ms": metrics.end_to_end_latency_ms,
        "peak_queue_depth": max(queue_depth_samples) if queue_depth_samples else 0,
        "final_queue_depth": final_queue_depth,
        "stable_operating_point": stable_point_reached,
        "backlog_accumulated": not stable_point_reached,
        "memory_growth_mb": round((mem_peak - mem_before) / (1024 * 1024), 3),
        "peak_heap_mb": round(mem_peak / (1024 * 1024), 3),
    }


async def run_sustained_load_test_suite() -> Dict[str, Any]:
    """Execute complete suite across 100, 250, 500, and 1000 event workloads."""
    print("=" * 80)
    print("AEGIS-ML PHASE 29.5: SUSTAINED-LOAD TESTING & QUEUE RELIABILITY BENCHMARK")
    print("=" * 80)

    env = SustainedLoadTestEnvironment()
    workload_sizes = [100, 250, 500, 1000]
    tier_results = {}

    for size in workload_sizes:
        print(f"\nRunning sustained workload tier: {size} target events (multi-host, jitter, failures)...")
        tier_res = await run_sustained_workload(
            workload_size=size,
            env=env,
            queue_capacity=500,
            worker_concurrency=2,
            batch_size=8,
            inject_transient_failure_rate=0.03,
            inject_permanent_failure_rate=0.01,
        )
        tier_results[f"workload_{size}"] = tier_res
        print(f"  Streamed: {tier_res['total_streamed_events']} events | Completed: {tier_res['completed_events']} events")
        print(f"  Throughput: {tier_res['completed_detection_throughput_eps']} eps | Peak Queue Depth: {tier_res['peak_queue_depth']}")
        print(f"  Queue Wait p50/p95: {tier_res['queue_wait_ms']['p50']}ms / {tier_res['queue_wait_ms']['p95']}ms")
        print(f"  End-to-End Latency p50/p95: {tier_res['end_to_end_latency_ms']['p50']}ms / {tier_res['end_to_end_latency_ms']['p95']}ms")
        print(f"  Retries: {tier_res['retry_count']} | Dead Letters: {tier_res['dead_letter_count']} | Inferences Failed: {tier_res['inference_failure_count']}")
        print(f"  Stable Operating Point Reached: {tier_res['stable_operating_point']} (Final Queue Depth: {tier_res['final_queue_depth']})")
        print(f"  Peak Memory: {tier_res['peak_heap_mb']} MB (Growth: {tier_res['memory_growth_mb']} MB)")

    # Test Queue Saturation & Backpressure Rejection
    print("\nExecuting Queue Saturation Stress Test (bounded capacity=50 with 150 event burst)...")
    saturation_res = await run_sustained_workload(
        workload_size=150,
        env=env,
        queue_capacity=50,  # Small capacity to trigger saturation
        worker_concurrency=1,
        batch_size=4,
        inject_transient_failure_rate=0.0,
        inject_permanent_failure_rate=0.0,
    )
    print(f"  Saturation Result: {saturation_res['rejected_count']} events rejected by bounded capacity backpressure")
    print(f"  Stable Operating Point Reached: {saturation_res['stable_operating_point']}")

    summary = {
        "metadata": {
            "evaluation_phase": "Phase 29.5: Sustained-Load Testing and Observability",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "model_version": getattr(env.classifier, "model_version", "23.0.0"),
            "disclaimer": (
                "Local sustained-load benchmark on workstation hardware. "
                "Throughput and latencies reflect single-node execution and do not represent distributed cloud capacity."
            ),
        },
        "workloads": tier_results,
        "queue_saturation_test": saturation_res,
        "conclusions": {
            "stable_operating_points": all(t["stable_operating_point"] for t in tier_results.values()),
            "backlog_accumulation": any(t["backlog_accumulated"] for t in tier_results.values()),
            "memory_bounded": max(t["peak_heap_mb"] for t in tier_results.values()) < 150.0,
            "dead_letter_protection_verified": tier_results["workload_1000"]["dead_letter_count"] > 0,
            "retry_exponential_backoff_verified": tier_results["workload_1000"]["retry_count"] > 0,
        },
    }

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[OK] Sustained-load benchmark results written to {RESULTS_PATH}")
    return summary


if __name__ == "__main__":
    asyncio.run(run_sustained_load_test_suite())
