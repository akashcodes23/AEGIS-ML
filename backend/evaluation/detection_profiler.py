"""
AEGIS-ML Phase 28.1: Granular Detection Pipeline Profiler.

Profiles the real execution path of the detection pipeline to quantify exact CPU time
spent across every stage:
1. Event Normalization & Validation (NormalizerPipeline)
2. Anomaly Scoring (Isolation Forest)
3. Baseline Deviation Profiling (BehavioralBaselineProfiler)
4. Causal Feature Extraction:
   - Sequence Context Features (CausalSequenceTracker)
   - Temporal Graph Features (CausalTemporalGraphTracker)
   - Full 48-feature assembly & ordering
5. Calibrated Classifier Inference (ThreatClassifier / Random Forest)
6. Evidence Fusion (WeightedEvidenceFusion)
7. Local Explanation Generation (LocalFeatureExplainer)
8. Incident Correlation & Graph Merging (IncidentCorrelator)
9. Serialization & Model Dumps (Pydantic model_dump)
10. Queue & Concurrency Synchronization (AsyncDetectionQueue lock & executor dispatch)

Provides hard numbers rather than assumptions to drive Phase 28.5 optimizations.
"""

import gc
import json
import os
import platform
import sys
import time
import tracemalloc
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.schemas import UnifiedEvent, Alert, Incident
from backend.ingestion.normalizer import NormalizerPipeline
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.model_lifecycle import ModelLifecycleManager
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.detection.sequence_context import CausalSequenceTracker
from backend.detection.model_trainer import extract_full_causal_features
from backend.correlation.weighted_fusion import WeightedEvidenceFusion
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.explainability.explainer import LocalFeatureExplainer
from backend.ingestion.async_queue import AsyncDetectionQueue, AsyncQueueConfig


def generate_profiling_stream(count: int = 200) -> List[Dict[str, Any]]:
    """Generate realistic mixed event stream representing normal and attack events."""
    base_time = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    hosts = [f"host-node-{i:02d}" for i in range(1, 11)]

    for i in range(count):
        t = base_time + timedelta(milliseconds=i * 100)
        host = hosts[i % len(hosts)]
        is_attack = (i % 7 == 0)

        if is_attack:
            # Adversarial event (triggers alert and correlation)
            events.append({
                "event_id": f"prof-atk-{i:04d}",
                "timestamp": t.isoformat(),
                "layer": "application",
                "src_ip": "198.51.100.44",
                "dst_ip": f"10.0.1.{(i % 5) + 1}",
                "http_method": "POST",
                "endpoint_path": "/api/v1/auth",
                "status_code": 401,
                "auth_result": "failure",
                "user_account": f"admin_{i % 3}",
                "host_id": host,
                "action": "login",
            })
        else:
            # Normal network flow
            events.append({
                "event_id": f"prof-norm-{i:04d}",
                "timestamp": t.isoformat(),
                "layer": "network",
                "src_ip": f"10.0.1.{(i % 100) + 1}",
                "dst_ip": f"10.0.2.{(i % 50) + 1}",
                "src_port": 35000 + (i % 20000),
                "dst_port": 80 if (i % 2 == 0) else 443,
                "protocol": "TCP",
                "bytes_sent": 850 + (i % 1200),
                "bytes_received": 3500 + (i % 5000),
                "host_id": host,
                "action": "http_request" if (i % 2 == 0) else "tls_connect",
            })
    return events


def profile_pipeline_stages(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Execute micro-timed stage-by-stage profiling."""
    print("=" * 80)
    print("AEGIS-ML DETAILED STAGE-BY-STAGE PIPELINE PROFILER")
    print("=" * 80)
    print(f"Platform: {platform.platform()} | Python: {platform.python_version()} | Cores: {os.cpu_count()}")
    print(f"Profiling workload: {len(events)} events (warm-up: 20 events)")

    # Initialize components
    if_detector = IsolationForestDetector()
    if_detector.load()
    profiler = BehavioralBaselineProfiler()
    profiler.load()
    lifecycle_manager = ModelLifecycleManager()
    if lifecycle_manager.load_artifact():
        classifier = lifecycle_manager.active_classifier
    else:
        classifier = ThreatClassifier()
        classifier.load("data/models/calibrated_threat_classifier.pkl")
    graph_tracker = CausalTemporalGraphTracker()
    sequence_tracker = CausalSequenceTracker(window_seconds=300.0)
    fusion_engine = WeightedEvidenceFusion()
    correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)
    explainer = LocalFeatureExplainer(feature_names=getattr(classifier, "FEATURE_NAMES", []))

    stage_timings_ns: Dict[str, List[int]] = {
        "1_normalization": [],
        "2_isolation_forest": [],
        "3_baseline_profiler": [],
        "4_sequence_features": [],
        "5_graph_features": [],
        "6_48_feature_assembly": [],
        "7_classifier_inference": [],
        "8_evidence_fusion": [],
        "9_local_explainer": [],
        "10_incident_correlation": [],
        "11_pydantic_serialization": [],
    }

    alerts_generated = 0
    incidents_correlated = 0

    # Warm-up run (20 events)
    for raw in events[:20]:
        ev = NormalizerPipeline.normalize(raw, strict=True)
        if ev:
            _ = if_detector.predict(ev)
            _ = profiler.compute_deviation_score(ev)
            feats = extract_full_causal_features(
                event=ev, if_score=0.1, baseline_deviation=0.1,
                profiler=profiler, failed_auth_rate=0.0,
                graph_tracker=graph_tracker, sequence_tracker=sequence_tracker,
            )
            _ = classifier.predict(feats)

    # Active Profiling Run
    gc.collect()
    tracemalloc.start()
    total_start = time.perf_counter()

    for raw in events:
        # Stage 1: Normalization
        t0 = time.perf_counter_ns()
        ev = NormalizerPipeline.normalize(raw, strict=True)
        t1 = time.perf_counter_ns()
        stage_timings_ns["1_normalization"].append(t1 - t0)

        if not ev:
            continue

        # Stage 2: Isolation Forest Anomaly Scoring
        t0 = time.perf_counter_ns()
        if_score = if_detector.predict(ev)
        t1 = time.perf_counter_ns()
        stage_timings_ns["2_isolation_forest"].append(t1 - t0)

        # Stage 3: Baseline Profiler Deviation
        t0 = time.perf_counter_ns()
        base_dev = profiler.compute_deviation_score(ev)
        t1 = time.perf_counter_ns()
        stage_timings_ns["3_baseline_profiler"].append(t1 - t0)

        # Stage 4: Sequence Context Features
        failed_auth = 1.0 if (ev.status_code == 401 or str(ev.auth_result or "").strip().lower() == "failure") else 0.0
        t0 = time.perf_counter_ns()
        seq_feats = sequence_tracker.extract_features_single(ev, advance_state=True)
        t1 = time.perf_counter_ns()
        stage_timings_ns["4_sequence_features"].append(t1 - t0)

        # Stage 5: Temporal Graph Features
        t0 = time.perf_counter_ns()
        graph_feats = graph_tracker.extract_features_single(ev, advance_state=True)
        t1 = time.perf_counter_ns()
        stage_timings_ns["5_graph_features"].append(t1 - t0)

        # Stage 6: Full 48-feature Assembly
        t0 = time.perf_counter_ns()
        features = extract_full_causal_features(
            event=ev,
            if_score=if_score,
            baseline_deviation=base_dev,
            profiler=profiler,
            failed_auth_rate=failed_auth,
            graph_tracker=graph_tracker,
            sequence_tracker=sequence_tracker,
        )
        t1 = time.perf_counter_ns()
        stage_timings_ns["6_48_feature_assembly"].append(t1 - t0)

        # Stage 7: Calibrated Classifier Inference (Random Forest)
        t0 = time.perf_counter_ns()
        prediction = classifier.predict(features)
        t1 = time.perf_counter_ns()
        stage_timings_ns["7_classifier_inference"].append(t1 - t0)

        # Stage 8: Evidence Fusion
        t0 = time.perf_counter_ns()
        fusion_result = fusion_engine.fuse(
            event=ev,
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
            confidence_qualification=prediction.confidence_qualification,
        )
        t1 = time.perf_counter_ns()
        stage_timings_ns["8_evidence_fusion"].append(t1 - t0)

        # Stage 9: Local Explainer (if threat or anomaly)
        is_threat = (prediction.threat_type != "benign")
        is_anom = (if_score >= 0.70 or base_dev >= 0.70)
        local_explanations = {}
        if is_threat or is_anom:
            t0 = time.perf_counter_ns()
            local_explanations = explainer.explain(
                features,
                global_importances=prediction.feature_importances,
                entity_profile=profiler.profiles.get(ev.src_entity),
            )
            t1 = time.perf_counter_ns()
            stage_timings_ns["9_local_explainer"].append(t1 - t0)

        # Stage 10: Incident Correlation
        if is_threat and prediction.confidence >= 0.60:
            alerts_generated += 1
            alert_obj = Alert(
                event_id=ev.event_id,
                timestamp=ev.timestamp,
                threat_type=prediction.threat_type,
                severity=prediction.severity or "medium",
                confidence=round(prediction.confidence, 4),
                classifier_probability=round(prediction.confidence, 4),
                anomaly_score=round(if_score, 4),
                baseline_deviation=round(base_dev, 4),
                src_entity=ev.src_entity,
                dst_entity=ev.dst_entity,
                layer=ev.layer,
                fingerprint=ev.event_id,
            )
            t0 = time.perf_counter_ns()
            inc, is_new = correlator.correlate_alert(alert_obj, raw_event=ev)
            t1 = time.perf_counter_ns()
            stage_timings_ns["10_incident_correlation"].append(t1 - t0)
            incidents_correlated += 1

            # Stage 11: Pydantic serialization
            t0 = time.perf_counter_ns()
            _ = alert_obj.model_dump()
            _ = inc.model_dump()
            t1 = time.perf_counter_ns()
            stage_timings_ns["11_pydantic_serialization"].append(t1 - t0)

    total_time = time.perf_counter() - total_start
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Calculate summary statistics per stage
    stage_summaries = {}
    total_measured_ns = 0

    for stage_name, times_ns in stage_timings_ns.items():
        if times_ns:
            count = len(times_ns)
            total_stage_ns = sum(times_ns)
            total_measured_ns += total_stage_ns
            times_ms = [t / 1e6 for t in times_ns]
            sorted_ms = sorted(times_ms)
            p50 = sorted_ms[int(count * 0.50)]
            p95 = sorted_ms[int(count * 0.95)]
            mean_ms = (total_stage_ns / count) / 1e6

            stage_summaries[stage_name] = {
                "invocations": count,
                "total_time_ms": round(total_stage_ns / 1e6, 3),
                "mean_ms": round(mean_ms, 4),
                "p50_ms": round(p50, 4),
                "p95_ms": round(p95, 4),
            }
        else:
            stage_summaries[stage_name] = {
                "invocations": 0,
                "total_time_ms": 0.0,
                "mean_ms": 0.0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
            }

    # Add percentage of measured time
    for stage_name, s in stage_summaries.items():
        if total_measured_ns > 0:
            s["percent_of_pipeline"] = round((s["total_time_ms"] / (total_measured_ns / 1e6)) * 100, 2)
        else:
            s["percent_of_pipeline"] = 0.0

    print("\n--- Pipeline Profiling Breakdown ---")
    print(f"{'Stage Name':<32} | {'Calls':<6} | {'Mean (ms)':<10} | {'p50 (ms)':<10} | {'p95 (ms)':<10} | {'Total (ms)':<10} | {'Share (%)':<8}")
    print("-" * 105)
    for name, s in stage_summaries.items():
        print(f"{name:<32} | {s['invocations']:<6} | {s['mean_ms']:<10.4f} | {s['p50_ms']:<10.4f} | {s['p95_ms']:<10.4f} | {s['total_time_ms']:<10.2f} | {s['percent_of_pipeline']:<8.2f}%")
    print("-" * 105)
    print(f"Total Pipeline Elapsed Time: {total_time:.3f} s ({len(events)/total_time:.2f} eps)")
    print(f"Alerts: {alerts_generated} | Incidents: {incidents_correlated}")
    print(f"Peak Memory: {peak_mem / (1024 * 1024):.2f} MB")

    report = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "events_profiled": len(events),
            "alerts_generated": alerts_generated,
            "incidents_correlated": incidents_correlated,
            "total_elapsed_seconds": round(total_time, 4),
            "effective_throughput_eps": round(len(events) / total_time, 2),
            "peak_memory_mb": round(peak_mem / (1024 * 1024), 2),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "stages": stage_summaries,
    }

    out_file = PROJECT_ROOT / "data" / "models" / "pipeline_profiling_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Profiling report saved to {out_file}")
    return report


if __name__ == "__main__":
    stream = generate_profiling_stream(200)
    profile_pipeline_stages(stream)
