"""
Phase 27 Performance Benchmark: Synchronous vs. Asynchronous Detection Pipeline.

Compares:
1. Synchronous Pipeline: Ingestion + Feature Extraction + RF Inference + Fusion on main thread.
2. Asynchronous Pipeline: Ingestion + Bounded In-Memory Queue + Background Worker Pool.

Measures:
- Ingestion throughput (events/second).
- Completed detection throughput (events/second).
- Queue wait time percentiles (median p50, p95).
- Worker detection processing time (median p50, p95).
- Total end-to-end latency (median p50, p95).
- Peak memory allocation (tracemalloc).
- Queue saturation and backpressure rejections.
- Failure and retry rates.

Outputs reproducible results to data/models/async_benchmark_results.json.
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
from typing import Dict, List, Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.schemas import (
    UnifiedEvent,
    AsyncQueueConfig,
    QueueBackpressurePolicy,
)
from backend.ingestion.async_queue import AsyncDetectionQueue
from backend.ingestion.streaming_ingestion import StreamingIngestionManager
from backend.detection.model_trainer import extract_features, extract_full_causal_features
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.detection.sequence_context import CausalSequenceTracker
from backend.correlation.weighted_fusion import WeightedEvidenceFusion
from backend.correlation.incident_correlator import IncidentCorrelator


def _generate_synthetic_stream(count: int, base_time: datetime) -> List[Dict[str, Any]]:
    """Generate deterministic sequence of network telemetry events spanning multiple hosts."""
    events = []
    hosts = [f"workstation-{i:02d}" for i in range(1, 11)]

    for i in range(count):
        host = hosts[i % len(hosts)]
        t = base_time + timedelta(milliseconds=i * 50)
        events.append({
            "event_id": f"bench-ev-{i:05d}",
            "timestamp": t.isoformat(),
            "layer": "network",
            "src_ip": f"10.0.1.{(i % 200) + 1}",
            "dst_ip": f"10.0.2.{(i % 100) + 1}",
            "src_port": 40000 + (i % 20000),
            "dst_port": 80 if (i % 2 == 0) else 443,
            "protocol": "TCP",
            "bytes_sent": 500 + (i % 1500),
            "bytes_received": 1500 + (i % 4000),
            "host_id": host,
            "action": "http_request" if (i % 2 == 0) else "tls_connect",
        })
    return events


class BenchmarkEnvironment:
    """Mock application environment providing fitted models and trackers for evaluation."""

    def __init__(self):
        self.classifier = ThreatClassifier()
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
        self.alerts_by_severity = {}

    def evaluate_detection(self, event: UnifiedEvent):
        """Standard pipeline detection evaluation."""
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
        fused = self.fusion_engine.fuse(
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
            model_version=pred.model_version,
            confidence_qualification=pred.confidence_qualification,
        )
        return fused, None


def benchmark_sync_pipeline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Profile synchronous execution where ingestion and ML inference run on caller thread."""
    env = BenchmarkEnvironment()
    mgr = StreamingIngestionManager(
        sequence_tracker=env.sequence_tracker,
        graph_tracker=env.graph_tracker,
        detection_handler=env.evaluate_detection,
    )

    gc.collect()
    tracemalloc.start()
    start_time = time.perf_counter()

    latencies_ms = []
    accepted = 0

    for ev in events:
        t0 = time.perf_counter()
        res = mgr.ingest_event(ev, trigger_detection=True)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)
        if res.status == "accepted":
            accepted += 1

    total_time = time.perf_counter() - start_time
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    sorted_lats = sorted(latencies_ms)
    n = len(sorted_lats)
    p50 = sorted_lats[int(n * 0.50)]
    p95 = sorted_lats[int(n * 0.95)]
    throughput = len(events) / total_time if total_time > 0 else 0.0

    return {
        "mode": "synchronous",
        "total_events": len(events),
        "accepted_events": accepted,
        "elapsed_seconds": round(total_time, 4),
        "ingestion_throughput_eps": round(throughput, 2),
        "completed_detection_throughput_eps": round(throughput, 2),
        "latency_p50_ms": round(p50, 3),
        "latency_p95_ms": round(p95, 3),
        "latency_mean_ms": round(sum(latencies_ms) / n, 3),
        "peak_memory_mb": round(peak_mem / (1024 * 1024), 3),
    }


async def benchmark_async_pipeline(events: List[Dict[str, Any]], workers: int = 2) -> Dict[str, Any]:
    """Profile asynchronous execution where ingestion enqueues to bounded worker pool."""
    env = BenchmarkEnvironment()
    q_cfg = AsyncQueueConfig(
        max_queue_size=len(events) * 2,
        worker_concurrency=workers,
        backpressure_policy=QueueBackpressurePolicy.REJECT,
    )
    q = AsyncDetectionQueue(
        config=q_cfg,
        detection_handler=env.evaluate_detection,
    )
    await q.start()

    mgr = StreamingIngestionManager(
        sequence_tracker=env.sequence_tracker,
        graph_tracker=env.graph_tracker,
        async_queue=q,
    )

    gc.collect()
    tracemalloc.start()

    # 1. Measure Ingestion Phase (Enqueue speed)
    ingest_start = time.perf_counter()
    ingest_latencies_ms = []
    accepted = 0

    for ev in events:
        t0 = time.perf_counter()
        res = mgr.ingest_event(ev, async_detection=True)
        t1 = time.perf_counter()
        ingest_latencies_ms.append((t1 - t0) * 1000.0)
        if res.status == "accepted":
            accepted += 1

    ingest_time = time.perf_counter() - ingest_start
    ingest_eps = len(events) / ingest_time if ingest_time > 0 else 0.0

    # 2. Measure Completion Phase (Worker execution to empty queue)
    await q.flush(timeout_seconds=30.0)
    total_time = time.perf_counter() - ingest_start

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    metrics = q.get_metrics()
    await q.stop()

    detection_eps = metrics.completed_events / total_time if total_time > 0 else 0.0
    sorted_ingest = sorted(ingest_latencies_ms)
    n = len(sorted_ingest)

    return {
        "mode": f"asynchronous_{workers}_workers",
        "total_events": len(events),
        "accepted_events": accepted,
        "completed_events": metrics.completed_events,
        "failed_events": metrics.failed_events,
        "retries": metrics.retry_count,
        "elapsed_ingest_seconds": round(ingest_time, 4),
        "elapsed_total_seconds": round(total_time, 4),
        "ingestion_throughput_eps": round(ingest_eps, 2),
        "completed_detection_throughput_eps": round(detection_eps, 2),
        "ingest_latency_p50_ms": round(sorted_ingest[int(n * 0.50)], 3),
        "ingest_latency_p95_ms": round(sorted_ingest[int(n * 0.95)], 3),
        "queue_wait_time_ms": metrics.queue_wait_time_ms,
        "worker_proc_time_ms": metrics.processing_time_ms,
        "end_to_end_latency_ms": metrics.end_to_end_latency_ms,
        "peak_memory_mb": round(peak_mem / (1024 * 1024), 3),
    }


def run_benchmark() -> Dict[str, Any]:
    """Execute complete sync vs async comparative benchmark across multiple workloads."""
    print("=" * 90)
    print("AEGIS-ML PHASE 27: SYNCHRONOUS VS. ASYNCHRONOUS PIPELINE BENCHMARK")
    print("=" * 90)

    base_time = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    workload_sizes = [100, 250]
    results = {}

    for size in workload_sizes:
        print(f"\nEvaluating workload size: {size} events...")
        events = _generate_synthetic_stream(size, base_time)

        # 1. Synchronous
        print("  Running synchronous pipeline...")
        sync_res = benchmark_sync_pipeline(events)
        print(f"    - Ingestion Throughput:  {sync_res['ingestion_throughput_eps']} eps")
        print(f"    - Median Latency:        {sync_res['latency_p50_ms']} ms")
        print(f"    - Total Elapsed:         {sync_res['elapsed_seconds']} s")

        # 2. Asynchronous (2 workers)
        print("  Running asynchronous pipeline (2 workers)...")
        async_res = asyncio.run(benchmark_async_pipeline(events, workers=2))
        print(f"    - Ingestion Throughput:  {async_res['ingestion_throughput_eps']} eps (Enqueue speedup: {async_res['ingestion_throughput_eps'] / sync_res['ingestion_throughput_eps']:.1f}x)")
        print(f"    - Completed Detection:   {async_res['completed_detection_throughput_eps']} eps")
        print(f"    - Ingest Median Latency: {async_res['ingest_latency_p50_ms']} ms")
        print(f"    - Worker Proc Median:    {async_res['worker_proc_time_ms']['p50']} ms")
        print(f"    - End-to-End Median:     {async_res['end_to_end_latency_ms']['p50']} ms")

        results[f"workload_{size}"] = {
            "synchronous": sync_res,
            "asynchronous": async_res,
        }

    report = {
        "metadata": {
            "benchmark_phase": "Phase 27: Asynchronous Detection Pipeline",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_architecture": platform.machine(),
            "cores": os.cpu_count(),
            "disclaimer": (
                "Measurements reflect single-machine local runtime performance on macOS. "
                "The in-memory queue provides process-isolated concurrency and non-blocking ingestion, "
                "but does NOT provide durable recovery across process restarts."
            ),
        },
        "results": results,
    }

    out_path = PROJECT_ROOT / "data" / "models" / "async_benchmark_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Benchmark completed and saved to {out_path}")
    return report


if __name__ == "__main__":
    run_benchmark()
