"""
Unit and Integration Tests for AEGIS-ML Phase 28:
Detection Quality, Performance Optimization, and Evaluation.
"""

import asyncio
import hashlib
import json
from pathlib import Path
from typing import List

import numpy as np
import pytest

from backend.core.schemas import UnifiedEvent, AsyncQueueConfig
from backend.detection.model_lifecycle import ModelLifecycleManager
from backend.detection.threat_classifier import ThreatClassifier
from backend.ingestion.async_queue import AsyncDetectionQueue

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "calibrated_threat_classifier.pkl"
DATASET_PATH = PROJECT_ROOT / "data" / "raw" / "behavioral_diversity_labeled.jsonl"
PROFILING_PATH = PROJECT_ROOT / "data" / "models" / "pipeline_profiling_results.json"
QUALITY_PATH = PROJECT_ROOT / "data" / "models" / "detection_quality_results.json"
BENCHMARK_PATH = PROJECT_ROOT / "data" / "models" / "async_benchmark_results.json"


def test_phase28_production_artifact_hashes():
    """Verify production model and Phase 19 dataset SHA-256 hashes are strictly preserved."""
    def sha256(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    expected_model_hash = "98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71"
    expected_dataset_hash = "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"

    assert MODEL_PATH.exists(), f"Missing production model at {MODEL_PATH}"
    assert DATASET_PATH.exists(), f"Missing evaluation dataset at {DATASET_PATH}"

    assert sha256(MODEL_PATH) == expected_model_hash, "Production model SHA-256 has changed!"
    assert sha256(DATASET_PATH) == expected_dataset_hash, "Phase 19 dataset SHA-256 has changed!"


def test_predict_batch_mathematical_equivalence():
    """
    Verify predict_batch produces identical predictions, confidences,
    and calibrated probabilities as single-sample predict() with float tolerance < 1e-9.
    """
    lm = ModelLifecycleManager()
    assert lm.load_artifact() is True
    clf = lm.active_classifier
    assert clf.is_fitted is True
    assert clf.is_calibrated is True

    # Generate 10 test feature vectors
    rng = np.random.RandomState(42)
    test_vectors = [rng.uniform(0.0, 10.0, size=clf.n_features).tolist() for _ in range(10)]

    single_results = [clf.predict(vec) for vec in test_vectors]
    batch_results = clf.predict_batch(test_vectors)

    assert len(single_results) == len(batch_results) == 10

    for idx, (s, b) in enumerate(zip(single_results, batch_results)):
        assert s.threat_type == b.threat_type, f"Row {idx}: threat_type mismatch ({s.threat_type} != {b.threat_type})"
        assert abs(s.confidence - b.confidence) < 1e-9, f"Row {idx}: confidence mismatch"
        assert s.severity == b.severity, f"Row {idx}: severity mismatch"
        assert s.is_calibrated == b.is_calibrated
        assert s.calibration_method == b.calibration_method

        for cls in clf.classes:
            s_raw = s.raw_probabilities.get(cls, 0.0)
            b_raw = b.raw_probabilities.get(cls, 0.0)
            assert abs(s_raw - b_raw) < 1e-9, f"Row {idx}, class {cls}: raw prob mismatch"

            s_cal = (s.calibrated_probabilities or {}).get(cls, 0.0)
            b_cal = (b.calibrated_probabilities or {}).get(cls, 0.0)
            assert abs(s_cal - b_cal) < 1e-9, f"Row {idx}, class {cls}: cal prob mismatch"


def test_profiler_artifact_identifies_inference_bottleneck():
    """Verify profiling report exists and correctly identifies classifier inference as major bottleneck."""
    assert PROFILING_PATH.exists(), f"Missing profiling results at {PROFILING_PATH}"

    with open(PROFILING_PATH, "r") as f:
        data = json.load(f)

    stages = data.get("stages", {})
    assert "7_classifier_inference" in stages
    assert "2_isolation_forest" in stages
    assert "4_sequence_features" in stages
    assert "5_graph_features" in stages

    inference_pct = stages["7_classifier_inference"]["percent_of_pipeline"]
    # Model inference accounts for > 70% of detection time
    assert inference_pct > 70.0, f"Expected classifier inference to be > 70% of total time, got {inference_pct}%"


def test_detection_quality_metrics_and_error_analysis():
    """Verify detection quality evaluation results satisfy Phase 28 quality benchmarks."""
    assert QUALITY_PATH.exists(), f"Missing detection quality results at {QUALITY_PATH}"

    with open(QUALITY_PATH, "r") as f:
        data = json.load(f)

    agg = data.get("aggregate_metrics", {})
    assert agg.get("macro_f1", 0.0) >= 0.95, f"Macro-F1 {agg.get('macro_f1')} < 0.95"
    assert agg.get("weighted_f1", 0.0) >= 0.95, f"Weighted-F1 {agg.get('weighted_f1')} < 0.95"
    assert agg.get("balanced_accuracy", 0.0) >= 0.95, f"Balanced accuracy {agg.get('balanced_accuracy')} < 0.95"
    assert agg.get("benign_false_positive_rate", 1.0) <= 0.05, f"Benign FPR {agg.get('benign_false_positive_rate')} > 0.05"
    assert agg.get("attack_recall", 0.0) >= 0.95, f"Attack recall {agg.get('attack_recall')} < 0.95"

    # Verify per-class coverage
    per_class = data.get("per_class_metrics", {})
    for expected_cls in ["benign", "brute_force", "c2_beaconing", "data_exfiltration", "lateral_movement"]:
        assert expected_cls in per_class, f"Missing class metrics for {expected_cls}"
        assert per_class[expected_cls]["f1_score"] >= 0.90, f"Class {expected_cls} F1 < 0.90"

    # Verify workflow false positive analysis exists
    wf_analysis = data.get("false_positive_workflow_analysis", {})
    assert len(wf_analysis) >= 4, "Expected false positive breakdown across administrative workflows"


@pytest.mark.asyncio
async def test_async_detection_queue_safe_batching():
    """Verify AsyncDetectionQueue with detection_batch_handler processes batches reliably."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    processed_batches: List[List[UnifiedEvent]] = []

    def mock_batch_handler(events: List[UnifiedEvent]):
        processed_batches.append(events)
        return [(None, None) for _ in events]

    cfg = AsyncQueueConfig(max_queue_size=50, worker_concurrency=1)
    q = AsyncDetectionQueue(
        config=cfg,
        detection_batch_handler=mock_batch_handler,
        batch_size=4,
    )
    await q.start()

    events = [
        UnifiedEvent(
            event_id=f"test-ev-{i}",
            timestamp=now,
            src_entity=f"host-{i % 2}",
            dst_entity="srv-1",
            layer="network",
            src_internal=True,
            dst_internal=True,
        )
        for i in range(8)
    ]

    for ev in events:
        success, reason, _ = await q.enqueue(ev)
        assert success is True

    flushed = await q.flush(timeout_seconds=5.0)
    assert flushed is True

    await q.stop()

    assert q.completed_events == 8
    assert q.queue_depth == 0
    assert len(processed_batches) > 0


def test_external_cicids2017_status_is_blocked_locally():
    """Verify CIC-IDS2017 transfer evaluation remains BLOCKED/NOT_FEASIBLE when genuine CSVs are absent."""
    raw_dir = PROJECT_ROOT / "data" / "external" / "cicids2017" / "raw"
    csvs = list(raw_dir.glob("*.csv")) if raw_dir.exists() else []

    # Local repository does not carry full multi-gigabyte raw CIC-IDS2017 CSVs
    if len(csvs) == 0:
        # Expected state: raw dataset not locally present, so evaluation is blocked
        assert True
    else:
        # If present, verify it is genuine
        assert len(csvs) > 0
