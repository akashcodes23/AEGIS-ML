"""
AEGIS-ML External Benchmark Evaluation Framework
Module: backend.evaluation.external_benchmark

Provides a rigorous, reproducible evaluation pipeline for external intrusion datasets
(specifically CIC-IDS2017 flow-based CSV records) while maintaining complete isolation
from the synthetic evaluation pipeline.

Guarantees:
1. Operates on authorized local copies of external datasets only; never claims results if absent.
2. Distinguishes available network telemetry from unavailable endpoint telemetry.
3. Evaluates Baseline vs Causal Temporal/Relational features on identical partitions.
4. Generates comprehensive audit metrics: Macro-F1, Weighted-F1, Balanced Accuracy, Benign FPR,
   per-class precision/recall/F1/support, and confusion matrices.
"""

import os
import sys
import json
import time
import argparse
import logging
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
from sklearn.metrics import (
    precision_recall_fscore_support,
    balanced_accuracy_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

try:
    from backend.core.config import PROJECT_ROOT
    from backend.core.schemas import UnifiedEvent
    from backend.detection.model_trainer import (
        CANONICAL_CLASSES,
        DATASET_LABEL_MAP,
        calculate_failed_auth_rate,
        build_feature_matrix,
    )
    from backend.detection.baseline_profiler import BehavioralBaselineProfiler
    from backend.detection.isolation_forest import IsolationForestDetector
    from backend.detection.threat_classifier import ThreatClassifier
    from backend.detection.temporal_graph_extractor import (
        CausalTemporalGraphTracker,
        TEMPORAL_FEATURE_NAMES,
        RELATIONAL_GRAPH_FEATURE_NAMES,
    )
    from backend.ingestion.cicids_loader import load_cicids2017
except ModuleNotFoundError:
    from core.config import PROJECT_ROOT
    from core.schemas import UnifiedEvent
    from detection.model_trainer import (
        CANONICAL_CLASSES,
        DATASET_LABEL_MAP,
        calculate_failed_auth_rate,
        build_feature_matrix,
    )
    from detection.baseline_profiler import BehavioralBaselineProfiler
    from detection.isolation_forest import IsolationForestDetector
    from detection.threat_classifier import ThreatClassifier
    from detection.temporal_graph_extractor import (
        CausalTemporalGraphTracker,
        TEMPORAL_FEATURE_NAMES,
        RELATIONAL_GRAPH_FEATURE_NAMES,
    )
    from ingestion.cicids_loader import load_cicids2017

logger = logging.getLogger(__name__)


def evaluate_external_dataset(
    file_path: str,
    output_path: Optional[str] = None,
    max_rows: Optional[int] = 10000,
    random_seed: int = 42,
    deduplicate: bool = True,
) -> Dict[str, Any]:
    """
    Run evaluation on an external CIC-IDS2017 dataset file.
    
    If the file does not exist locally, returns a documented 'not_completed' status
    with reproduction instructions and exits safely without fabricating metrics.
    """
    path = Path(file_path)
    report_metadata: Dict[str, Any] = {
        "evaluation_name": "CIC-IDS2017 External Benchmark Evaluation",
        "timestamp": datetime.utcnow().isoformat(),
        "target_file": str(file_path),
        "random_seed": random_seed,
        "provenance": "External benchmark — University of New Brunswick (UNB), Canadian Institute for Cybersecurity (CIC).",
    }

    if not path.exists():
        msg = (
            f"External dataset file not found at: {file_path}. "
            "To evaluate on real-world CIC-IDS2017 traffic, download the dataset per instructions "
            "in docs/CICIDS2017_IMPORT.md and run: "
            f"python3 -m backend.evaluation.external_benchmark --data {file_path}"
        )
        logger.info(msg)
        result = {
            "metadata": report_metadata,
            "status": "not_completed",
            "reason": "Dataset file not present locally. Evaluation infrastructure ready.",
            "instructions": "See docs/CICIDS2017_IMPORT.md for download and placement instructions.",
            "metrics": None,
        }
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w") as f:
                json.dump(result, f, indent=2)
        return result

    # File exists — proceed with genuine ingestion
    logger.info(f"Loading external dataset from {file_path}...")
    events, stats = load_cicids2017(
        str(file_path),
        max_rows=max_rows,
        random_seed=random_seed,
        deduplicate=deduplicate,
    )

    if not events:
        result = {
            "metadata": report_metadata,
            "status": "failed",
            "reason": f"Loader returned 0 valid events. Stats: {stats}",
            "metrics": None,
        }
        return result

    labels = [e.attack_type for e in events]
    class_counts = Counter(labels)

    # Need at least 2 distinct classes to perform classification
    active_classes = [c for c in CANONICAL_CLASSES if class_counts.get(c, 0) > 0]
    if len(active_classes) < 2:
        result = {
            "metadata": report_metadata,
            "status": "insufficient_classes",
            "reason": f"Dataset file contains only {len(active_classes)} class ({active_classes}). Multi-class evaluation requires >= 2 classes.",
            "class_distribution": dict(class_counts),
            "stats": stats,
            "metrics": None,
        }
        return result

    # Disclose unavailable feature groups in network flow telemetry
    unavailable_features = [
        "process_name",
        "file_path",
        "endpoint_action",
        "parent_pid",
        "auth_result",
        "http_status_code",
    ]

    # Split: 80/20 train/test split
    indices = np.arange(len(events))
    try:
        tr_idx, te_idx = train_test_split(indices, test_size=0.20, random_state=random_seed, stratify=labels)
    except Exception:
        tr_idx, te_idx = train_test_split(indices, test_size=0.20, random_state=random_seed)

    tr_events = [events[i] for i in tr_idx]
    te_events = [events[i] for i in te_idx]
    y_tr = np.array([labels[i] for i in tr_idx])
    y_te = np.array([labels[i] for i in te_idx])

    # Fit baseline profiler and isolation forest strictly on train split
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(tr_events, benign_only=True)
    if_detector = IsolationForestDetector(random_state=random_seed)
    if_detector.fit(tr_events)

    fa_tr = calculate_failed_auth_rate(tr_events)
    fa_te = calculate_failed_auth_rate(te_events)

    X_tr_base = build_feature_matrix(tr_events, if_detector, profiler, fa_tr)
    X_te_base = build_feature_matrix(te_events, if_detector, profiler, fa_te)

    # Causal Temporal and Graph features
    tracker = CausalTemporalGraphTracker()
    tracker.fit_baseline_pairs(tr_events)

    t_feat_start = time.perf_counter()
    tr_tg = tracker.extract_sequence(tr_events)
    te_tg = tracker.extract_sequence(te_events)
    feat_gen_latency_ms = round(((time.perf_counter() - t_feat_start) / max(len(events), 1)) * 1000.0, 4)

    tr_ext = np.array([[f[k] for k in TEMPORAL_FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES] for f in tr_tg], dtype=np.float64)
    te_ext = np.array([[f[k] for k in TEMPORAL_FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES] for f in te_tg], dtype=np.float64)

    X_tr_full = np.hstack([X_tr_base, tr_ext])
    X_te_full = np.hstack([X_te_base, te_ext])

    eval_configs = {
        "A_baseline_network": {
            "label": "Baseline 15-Feature Network Telemetry",
            "features": ThreatClassifier.FEATURE_NAMES,
            "X_tr": X_tr_base,
            "X_te": X_te_base,
        },
        "B_temporal_relational_network": {
            "label": "Network Telemetry + Temporal & Relational Graph Features",
            "features": ThreatClassifier.FEATURE_NAMES + TEMPORAL_FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES,
            "X_tr": X_tr_full,
            "X_te": X_te_full,
        },
    }

    config_results = {}
    classes = CANONICAL_CLASSES
    bi = classes.index("benign")

    for cfg_id, cfg_info in eval_configs.items():
        X_tr = cfg_info["X_tr"]
        X_te = cfg_info["X_te"]
        f_names = cfg_info["features"]

        min_samples = min(Counter(y_tr).values()) if Counter(y_tr) else 1
        if min_samples >= 2:
            try:
                sm = SMOTE(random_state=random_seed, k_neighbors=min(5, min_samples - 1))
                X_tr_res, y_tr_res = sm.fit_resample(X_tr, y_tr)
            except Exception:
                X_tr_res, y_tr_res = X_tr, y_tr
        else:
            X_tr_res, y_tr_res = X_tr, y_tr

        clf = ThreatClassifier(random_state=random_seed, feature_names=f_names)
        clf.fit(X_tr_res, y_tr_res)

        t_inf_start = time.perf_counter()
        y_pred = clf.model.predict(X_te)
        inf_latency_ms = round(((time.perf_counter() - t_inf_start) / max(len(X_te), 1)) * 1000.0, 4)

        prec, rec, f1s, supp = precision_recall_fscore_support(y_te, y_pred, labels=classes, zero_division=0)
        per_class = {}
        for i, c in enumerate(classes):
            per_class[c] = {
                "precision": round(float(prec[i]), 4),
                "recall": round(float(rec[i]), 4),
                "f1": round(float(f1s[i]), 4),
                "support": int(supp[i]),
            }

        cm = confusion_matrix(y_te, y_pred, labels=classes)
        benign_total = int(sum(cm[bi]))
        benign_fp = int(sum(cm[bi, j] for j in range(len(classes)) if j != bi))
        benign_fpr = round(benign_fp / max(benign_total, 1), 4)

        config_results[cfg_id] = {
            "config_label": cfg_info["label"],
            "n_features": len(f_names),
            "macro_f1": round(float(f1_score(y_te, y_pred, average="macro", zero_division=0)), 4),
            "weighted_f1": round(float(f1_score(y_te, y_pred, average="weighted", zero_division=0)), 4),
            "balanced_accuracy": round(float(balanced_accuracy_score(y_te, y_pred)), 4),
            "benign_fpr": benign_fpr,
            "feature_generation_latency_ms": feat_gen_latency_ms if "temporal" in cfg_id else 0.0,
            "inference_latency_ms_per_event": inf_latency_ms,
            "per_class": per_class,
            "confusion_matrix": cm.tolist(),
        }

    full_report = {
        "metadata": report_metadata,
        "status": "completed",
        "dataset_stats": stats,
        "train_samples": len(tr_events),
        "test_samples": len(te_events),
        "class_distribution_train": dict(Counter(y_tr)),
        "class_distribution_test": dict(Counter(y_te)),
        "unavailable_feature_groups": unavailable_features,
        "configurations": config_results,
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(full_report, f, indent=2)
        logger.info(f"External evaluation report saved to {output_path}")

    return full_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS-ML External Dataset Benchmark")
    parser.add_argument(
        "--data",
        default="/Users/akashgpatil/major_project/AEGIS-ML/data/external/cicids2017/Monday-WorkingHours.pcap_ISCX.csv",
        help="Path to external dataset CSV file",
    )
    parser.add_argument(
        "--output",
        default=str(Path(PROJECT_ROOT) / "data" / "models" / "external_benchmark_results.json"),
        help="Path to write external evaluation results",
    )
    parser.add_argument("--max-rows", type=int, default=10000, help="Maximum rows to load")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    res = evaluate_external_dataset(
        file_path=args.data,
        output_path=args.output,
        max_rows=args.max_rows,
        random_seed=args.seed,
    )
    print("\nExternal Benchmark Run Status:", res.get("status"))
    if res.get("status") == "not_completed":
        print("Reason:", res.get("reason"))
        print("Instructions:", res.get("instructions"))
    elif res.get("status") == "completed":
        print("Configurations evaluated:", list(res["configurations"].keys()))
        for k, v in res["configurations"].items():
            print(f"  {v['config_label']}: Macro-F1 = {v['macro_f1']}, Bal-Acc = {v['balanced_accuracy']}, FPR = {v['benign_fpr']}")
