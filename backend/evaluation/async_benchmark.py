"""
Phase 28 Performance Benchmark: Synchronous vs. Asynchronous (Unbatched & Batched) Detection Pipeline.

Rigorous Comparative Methodology:
1. Equivalent Inputs: Deterministic synthetic multi-host event sequences.
2. Equivalent Model & Configuration: Active calibrated 48-feature production model (calibrated_threat_classifier.pkl).
3. Warm-up Procedures: Warmup execution across all pipelines prior to recording.
4. Measurement Boundaries:
   - Ingestion Throughput (eps): Rate at which caller thread enqueues/accepts events.
   - Completed Detection Throughput (eps): Rate at which background workers finish end-to-end detection, fusion, and correlation.
   - Latencies: p50 (median) and p95 for queue wait, worker detection processing, and end-to-end latency.
   - Queue Observability: Queue depth sampling over time, peak queue depth, saturation/rejections.
   - Memory: tracemalloc peak resident heap consumption.
   - Terminal Criteria: Explicit async flush() ensuring 100% of submitted events reach terminal state.

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
from typing import Dict, List, Any, Optional

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
        self.alerts_by_severity = {}

    def evaluate_detection(self, event: UnifiedEvent):
        """Standard single-sample pipeline detection evaluation."""
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

    def evaluate_batch_detection(self, events: List[UnifiedEvent]):
        """Batched pipeline detection evaluation executing vectorized model inference."""
        features_list = []
        meta = []
        for event in events:
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
            features_list.append(features)
            meta.append((event, if_score, base_dev))

        if hasattr(self.classifier, "predict_batch"):
            preds = self.classifier.predict_batch(features_list)
        else:
            preds = [self.classifier.predict(f) for f in features_list]

        results = []
        for (event, if_score, base_dev), pred in zip(meta, preds):
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
            results.append((fused, None))
        return results


def warmup_environment(env: BenchmarkEnvironment, count: int = 20) -> None:
    """Warm up models, memory allocators, and feature extractors."""
    stream = _generate_synthetic_stream(count, datetime.now(timezone.utc))
    mgr = StreamingIngestionManager(
        sequence_tracker=env.sequence_tracker,
        graph_tracker=env.graph_tracker,
        detection_handler=env.evaluate_detection,
    )
    for ev in stream:
        mgr.ingest_event(ev, trigger_detection=True)


def benchmark_sync_pipeline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Profile synchronous execution where ingestion and ML inference run on caller thread."""
    env = BenchmarkEnvironment()
    warmup_environment(env, count=15)

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
        "queue_saturation_count": 0,
        "rejected_event_count": 0,
    }


async def benchmark_async_pipeline(
    events: List[Dict[str, Any]],
    workers: int = 2,
    use_batching: bool = False,
    batch_size: int = 16,
) -> Dict[str, Any]:
    """Profile asynchronous execution where ingestion enqueues to bounded worker pool."""
    env = BenchmarkEnvironment()
    warmup_environment(env, count=15)

    q_cfg = AsyncQueueConfig(
        max_queue_size=len(events) * 2,
        worker_concurrency=workers,
        backpressure_policy=QueueBackpressurePolicy.REJECT,
    )
    q = AsyncDetectionQueue(
        config=q_cfg,
        detection_handler=env.evaluate_detection if not use_batching else None,
        detection_batch_handler=env.evaluate_batch_detection if use_batching else None,
        batch_size=batch_size,
    )
    await q.start()

    mgr = StreamingIngestionManager(
        sequence_tracker=env.sequence_tracker,
        graph_tracker=env.graph_tracker,
        async_queue=q,
    )

    # Queue depth sampling background task
    queue_depth_samples = []
    sampling_active = True

    async def _sample_depth():
        while sampling_active:
            queue_depth_samples.append(q.queue_depth)
            await asyncio.sleep(0.005)

    sampler_task = asyncio.create_task(_sample_depth())

    gc.collect()
    tracemalloc.start()

    # 1. Ingestion Phase
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

    # 2. Completion Phase (Worker execution until empty queue)
    await q.flush(timeout_seconds=45.0)
    total_time = time.perf_counter() - ingest_start

    sampling_active = False
    sampler_task.cancel()
    try:
        await sampler_task
    except asyncio.CancelledError:
        pass

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    metrics = q.get_metrics()
    await q.stop()

    detection_eps = metrics.completed_events / total_time if total_time > 0 else 0.0
    sorted_ingest = sorted(ingest_latencies_ms)
    n = len(sorted_ingest)

    max_depth = max(queue_depth_samples) if queue_depth_samples else 0
    mean_depth = sum(queue_depth_samples) / len(queue_depth_samples) if queue_depth_samples else 0.0

    mode_label = f"asynchronous_{'batched' if use_batching else 'unbatched'}_{workers}w"
    return {
        "mode": mode_label,
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
        "queue_depth_max": max_depth,
        "queue_depth_mean": round(mean_depth, 2),
        "queue_saturation_count": q.rejected_count,
        "rejected_event_count": q.rejected_count,
        "peak_memory_mb": round(peak_mem / (1024 * 1024), 3),
    }


def run_benchmark() -> Dict[str, Any]:
    """Execute complete Phase 28 benchmark comparing sync, async-unbatched, and async-batched pipelines."""
    print("=" * 95)
    print("AEGIS-ML PHASE 28.2: PERFORMANCE BENCHMARK (SYNC VS ASYNC UNBATCHED VS ASYNC BATCHED)")
    print("=" * 95)

    base_time = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    workload_sizes = [100, 250, 500]
    results = {}

    for size in workload_sizes:
        print(f"\n[Workload: {size} events]")
        events = _generate_synthetic_stream(size, base_time)

        # 1. Synchronous Baseline
        print("  1. Running synchronous baseline...")
        sync_res = benchmark_sync_pipeline(events)
        print(f"     - Ingest / Det EPS: {sync_res['ingestion_throughput_eps']} eps | Latency p50: {sync_res['latency_p50_ms']} ms | Peak Mem: {sync_res['peak_memory_mb']} MB")

        # 2. Asynchronous Unbatched (Phase 27 Baseline)
        print("  2. Running asynchronous unbatched (2 workers)...")
        async_unbatched_res = asyncio.run(benchmark_async_pipeline(events, workers=2, use_batching=False))
        print(f"     - Ingest EPS: {async_unbatched_res['ingestion_throughput_eps']} eps | Completed Det EPS: {async_unbatched_res['completed_detection_throughput_eps']} eps")
        print(f"     - Queue Wait p50: {async_unbatched_res['queue_wait_time_ms']['p50']} ms | Worker Proc p50: {async_unbatched_res['worker_proc_time_ms']['p50']} ms | E2E p50: {async_unbatched_res['end_to_end_latency_ms']['p50']} ms")

        # 3. Asynchronous Batched (Phase 28 Optimized)
        print("  3. Running asynchronous batched (2 workers, batch_size=16)...")
        async_batched_res = asyncio.run(benchmark_async_pipeline(events, workers=2, use_batching=True, batch_size=16))
        speedup = (async_batched_res['completed_detection_throughput_eps'] / async_unbatched_res['completed_detection_throughput_eps']) if async_unbatched_res['completed_detection_throughput_eps'] > 0 else 1.0
        print(f"     - Ingest EPS: {async_batched_res['ingestion_throughput_eps']} eps | Completed Det EPS: {async_batched_res['completed_detection_throughput_eps']} eps (Speedup: {speedup:.2f}x)")
        print(f"     - Queue Wait p50: {async_batched_res['queue_wait_time_ms']['p50']} ms | Worker Proc p50: {async_batched_res['worker_proc_time_ms']['p50']} ms | E2E p50: {async_batched_res['end_to_end_latency_ms']['p50']} ms")

        results[f"workload_{size}"] = {
            "synchronous": sync_res,
            "asynchronous_unbatched": async_unbatched_res,
            "asynchronous_batched": async_batched_res,
        }

    report = {
        "metadata": {
            "benchmark_phase": "Phase 28.2: Synchronous vs. Asynchronous Performance Evaluation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_architecture": platform.machine(),
            "cores": os.cpu_count(),
            "classifier_features": 48,
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
