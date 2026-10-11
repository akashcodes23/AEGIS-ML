"""
AEGIS-ML Streaming Ingestion and Detection Performance Benchmark.

Measures:
- Ingestion-only vs Detection-enabled throughput (events/sec)
- Latency statistics (min, median/p50, p95, p99, mean) in milliseconds
- Ingestion outcomes (accepted, duplicate, rejected, late, clock-skew)
- Memory consumption (peak and delta via tracemalloc)
- System and runtime configuration

Disclaimer:
All figures represent local synthetic benchmark measurements on the current host
and must not be claimed as guaranteed production throughput or cluster scalability.
"""

import json
import logging
import math
import os
import platform
import time
import tracemalloc
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import numpy as np

from backend.core.schemas import UnifiedEvent, IngestionItemResult
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.model_trainer import extract_full_causal_features
from backend.detection.model_lifecycle import ModelLifecycleManager
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.detection.sequence_context import CausalSequenceTracker
from backend.correlation.weighted_fusion import WeightedEvidenceFusion
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.ingestion.streaming_ingestion import StreamingIngestionManager

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def generate_benchmark_events(
    count: int = 500,
    seed: int = 42,
    base_time: Optional[datetime] = None,
    duplicate_fraction: float = 0.05,
    malformed_fraction: float = 0.02,
) -> List[Dict[str, Any]]:
    """
    Generate a deterministic synthetic telemetry stream for benchmarking.
    Includes mixed layers, realistic volume counters, intentional duplicates,
    and a small fraction of malformed payloads.
    """
    rng = np.random.RandomState(seed)
    if base_time is None:
        base_time = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)

    events: List[Dict[str, Any]] = []
    hosts = [f"WORKSTATION-{i:02d}" for i in range(1, 11)]
    users = ["alice", "bob", "charlie", "svc_backup", "admin"]
    dst_ips = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "142.250.190.46", "203.0.113.5"]

    for i in range(count):
        t_event = base_time + timedelta(milliseconds=i * 200)

        # 1. Malformed payload
        if rng.rand() < malformed_fraction:
            events.append({
                "event_id": f"bench-malformed-{i:05d}",
                "timestamp": t_event.isoformat(),
                "layer": "invalid_layer",
                "src_ip": "10.0.0.1",
            })
            continue

        # 2. Duplicate of an earlier event
        if rng.rand() < duplicate_fraction and len(events) > 5:
            dup_target = events[rng.randint(max(0, len(events) - 5), len(events))]
            dup_ev = dict(dup_target)
            events.append(dup_ev)
            continue

        # 3. Layer distribution: 60% network, 30% endpoint, 10% application
        layer_roll = rng.rand()
        host = rng.choice(hosts)

        if layer_roll < 0.60:
            events.append({
                "event_id": f"bench-ev-{i:05d}",
                "timestamp": t_event.isoformat(),
                "layer": "network",
                "host_id": host,
                "src_ip": f"10.0.1.{rng.randint(10, 50)}",
                "dst_ip": rng.choice(dst_ips),
                "src_port": int(rng.randint(49152, 65535)),
                "dst_port": int(rng.choice([80, 443, 22, 445, 8080])),
                "protocol": str(rng.choice(["TCP", "UDP"])),
                "bytes_sent": int(rng.exponential(2000)),
                "bytes_received": int(rng.exponential(5000)),
                "action": "flow_record",
            })
        elif layer_roll < 0.90:
            events.append({
                "event_id": f"bench-ev-{i:05d}",
                "timestamp": t_event.isoformat(),
                "layer": "endpoint",
                "host_id": host,
                "src_ip": f"10.0.1.{rng.randint(10, 50)}",
                "process_name": str(rng.choice(["cmd.exe", "powershell.exe", "curl.exe", "chrome.exe", "svchost.exe"])),
                "pid": int(rng.randint(1000, 9999)),
                "user_account": str(rng.choice(users)),
                "action": "process_create",
            })
        else:
            events.append({
                "event_id": f"bench-ev-{i:05d}",
                "timestamp": t_event.isoformat(),
                "layer": "application",
                "host_id": host,
                "src_ip": f"10.0.1.{rng.randint(10, 50)}",
                "dst_ip": "10.0.0.1",
                "http_method": str(rng.choice(["GET", "POST"])),
                "endpoint_path": "/api/v1/auth",
                "status_code": int(rng.choice([200, 200, 200, 401])),
                "auth_result": "failure" if rng.rand() < 0.25 else "success",
                "action": "web_request",
            })

    return events


def _build_benchmark_detection_pipeline() -> Tuple[StreamingIngestionManager, Any]:
    """Instantiate a self-contained streaming pipeline with loaded models."""
    if_detector = IsolationForestDetector()
    if_detector.load()

    profiler = BehavioralBaselineProfiler()
    profiler.load()

    graph_tracker = CausalTemporalGraphTracker()
    seq_tracker = CausalSequenceTracker(window_seconds=300.0)

    lifecycle = ModelLifecycleManager()
    clf_loaded = lifecycle.load_artifact()
    classifier = lifecycle.active_classifier if clf_loaded and lifecycle.active_classifier else ThreatClassifier()
    if not clf_loaded:
        classifier.load()

    fusion_engine = WeightedEvidenceFusion()
    correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)

    class PipelineState:
        pass

    state = PipelineState()
    state.if_detector = if_detector
    state.profiler = profiler
    state.graph_tracker = graph_tracker
    state.sequence_tracker = seq_tracker
    state.classifier = classifier
    state.fusion_engine = fusion_engine
    state.correlator = correlator

    def detection_handler(event: UnifiedEvent):
        try:
            if_score = if_detector.predict(event)
            base_dev = profiler.compute_deviation_score(event)
            failed_auth = 1.0 if (event.status_code == 401 or str(event.auth_result or "").strip().lower() == "failure") else 0.0

            feats = extract_full_causal_features(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                profiler=profiler,
                failed_auth_rate=failed_auth,
                graph_tracker=graph_tracker,
                sequence_tracker=seq_tracker,
            )
            prediction = classifier.predict(feats)
            fusion_res = fusion_engine.fuse(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                graph_score=0.0,
                threat_type=prediction.threat_type,
                classifier_confidence=prediction.confidence,
                severity=prediction.severity,
                is_calibrated=prediction.is_calibrated,
                calibrated_probabilities=prediction.calibrated_probabilities,
                raw_probabilities=prediction.raw_probabilities,
                model_version=prediction.model_version,
            )
            return fusion_res, None
        except Exception as e:
            logger.error("Benchmark detection failed: %s", e)
            return None, None

    mgr = StreamingIngestionManager(
        sequence_tracker=seq_tracker,
        graph_tracker=graph_tracker,
        detection_handler=detection_handler,
    )
    return mgr, state


def run_benchmark_run(
    events: List[Dict[str, Any]],
    mode: str = "ingestion_only",
) -> Dict[str, Any]:
    """Execute a single benchmark run under tracemalloc profiling."""
    tracemalloc.start()
    tracemalloc.reset_peak()

    if mode == "detection_enabled":
        mgr, _ = _build_benchmark_detection_pipeline()
        trigger_det = True
    else:
        mgr = StreamingIngestionManager()
        trigger_det = False

    latencies_ms: List[float] = []
    t_start = time.perf_counter()

    for ev in events:
        t0 = time.perf_counter()
        mgr.ingest_event(ev, trigger_detection=trigger_det)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    t_end = time.perf_counter()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_duration = t_end - t_start
    events_count = len(events)
    throughput = events_count / max(total_duration, 1e-6)

    lat_arr = np.array(latencies_ms)
    stats = mgr.stats

    return {
        "mode": mode,
        "event_count": events_count,
        "total_duration_seconds": round(total_duration, 4),
        "throughput_eps": round(throughput, 2),
        "latency_ms": {
            "min": round(float(np.min(lat_arr)), 3),
            "p50_median": round(float(np.percentile(lat_arr, 50)), 3),
            "mean": round(float(np.mean(lat_arr)), 3),
            "p95": round(float(np.percentile(lat_arr, 95)), 3),
            "p99": round(float(np.percentile(lat_arr, 99)), 3),
            "max": round(float(np.max(lat_arr)), 3),
        },
        "outcomes": {
            "accepted": stats.total_ingested,
            "duplicate": stats.total_duplicates,
            "rejected": stats.total_rejected,
            "late_arriving": stats.total_late_arriving,
            "clock_skew": stats.total_clock_skew,
        },
        "memory": {
            "current_mb": round(current_mem / (1024 * 1024), 3),
            "peak_mb": round(peak_mem / (1024 * 1024), 3),
        },
    }


def run_streaming_benchmark(
    event_volumes: List[int] = (200, 1000),
    seed: int = 42,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Run complete benchmark suite across multiple event volumes for both
    ingestion-only and detection-enabled workloads.
    """
    if output_path is None:
        output_path = PROJECT_ROOT / "data" / "models" / "streaming_benchmark_results.json"

    results_by_volume = {}

    for vol in event_volumes:
        events = generate_benchmark_events(count=vol, seed=seed)
        res_ingest = run_benchmark_run(events, mode="ingestion_only")
        res_detect = run_benchmark_run(events, mode="detection_enabled")

        results_by_volume[f"volume_{vol}"] = {
            "ingestion_only": res_ingest,
            "detection_enabled": res_detect,
        }

    report = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "benchmark_type": "streaming_ingestion_and_detection_benchmark",
            "seed": seed,
            "disclaimer": (
                "These figures represent local synthetic benchmark measurements on the test machine. "
                "They demonstrate relative performance between ingestion-only and ML-detection paths "
                "and must not be interpreted as guaranteed production cluster throughput."
            ),
            "system_environment": {
                "system": platform.system(),
                "node": platform.node(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python_version": platform.python_version(),
            },
        },
        "results": results_by_volume,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("Benchmark report saved to %s", output_path)
    return report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    rep = run_streaming_benchmark(event_volumes=[200, 1000])
    print(json.dumps(rep, indent=2))
