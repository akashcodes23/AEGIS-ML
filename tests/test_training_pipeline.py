import json
import pytest
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

from backend.core.schemas import UnifiedEvent
from backend.detection.model_trainer import (
    calculate_evaluation_metrics,
    train_pipeline,
    CANONICAL_CLASSES,
)


def test_calculate_evaluation_metrics():
    y_true = np.array(["benign", "benign", "brute_force", "lateral_movement", "benign"])
    y_pred = np.array(["benign", "brute_force", "brute_force", "lateral_movement", "benign"])
    y_proba = np.array([
        [0.9, 0.1, 0.0, 0.0, 0.0],
        [0.4, 0.6, 0.0, 0.0, 0.0],
        [0.1, 0.8, 0.1, 0.0, 0.0],
        [0.0, 0.1, 0.8, 0.0, 0.1],
        [0.95, 0.05, 0.0, 0.0, 0.0],
    ])

    metrics = calculate_evaluation_metrics(
        y_true=y_true,
        y_pred=y_pred,
        y_proba=y_proba,
        classes=CANONICAL_CLASSES,
        inference_latency_ms=1.5
    )

    assert "accuracy" in metrics
    assert "macro_f1" in metrics
    assert "weighted_f1" in metrics
    assert "false_positive_rate_benign" in metrics
    assert "per_class" in metrics
    assert "confusion_matrix" in metrics

    # 3 benign total: 2 correctly predicted as benign, 1 falsely predicted as brute_force
    # FPR on benign = 1 / 3 = 0.3333
    assert pytest.approx(metrics["false_positive_rate_benign"], 0.01) == (1.0 / 3.0)


def test_train_pipeline_end_to_end_synthetic(tmp_path):
    # Create small deterministic synthetic dataset file
    jsonl_path = tmp_path / "test_data.jsonl"
    events = []
    base_time = datetime(2026, 4, 1, 10, 0, 0)

    # 30 benign, 10 brute force, 10 lateral movement, 10 data exfiltration, 10 c2 beaconing
    classes_to_gen = [
        ("benign", 30),
        ("brute_force", 10),
        ("lateral_movement", 10),
        ("data_exfiltration", 10),
        ("c2_beaconing", 10),
    ]

    for label, count in classes_to_gen:
        for i in range(count):
            events.append({
                "timestamp": (base_time + timedelta(seconds=len(events))).isoformat(),
                "layer": "network",
                "src_entity": f"10.0.0.{10 + (i % 5)}",
                "dst_entity": f"10.0.0.{50 + (i % 5)}",
                "src_internal": True,
                "dst_internal": True if label != "data_exfiltration" else False,
                "bytes_sent": 500 if label == "benign" else 100000,
                "bytes_received": 1000 if label == "benign" else 100,
                "dst_port": 80 if label == "benign" else 4444,
                "duration_ms": 50,
                "connections_per_minute": 5.0 if label == "benign" else 120.0,
                "attack_type": label,
                "raw_label": label,
            })

    with open(jsonl_path, "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    out_dir = tmp_path / "models_out"

    report = train_pipeline(
        data_source=str(jsonl_path),
        output_dir=str(out_dir),
        random_seed=42
    )

    assert "test_metrics" in report
    assert "dummy_baseline_macro_f1" in report
    assert report["total_events"] == 70
    assert report["test_samples"] == 14  # 20% of 70
    assert (out_dir / "threat_classifier.pkl").exists()
    assert (out_dir / "eval_results.json").exists()

    # Verify JSON report is machine-readable
    with open(out_dir / "eval_results.json") as f:
        loaded_json = json.load(f)
    assert "accuracy" in loaded_json["test_metrics"]
    assert "macro_f1" in loaded_json["test_metrics"]
