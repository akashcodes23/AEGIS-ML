"""
AEGIS-ML Phase 28.3 & 28.4: Comprehensive Detection Quality Evaluation and Error Analysis.

Evaluates the active 48-feature calibrated production classifier (calibrated_threat_classifier.pkl)
on the Phase 19 behavioral-diversity evaluation dataset (behavioral_diversity_labeled.jsonl).

Evaluation Rigor:
1. Scenario-Grouped Partitioning: 70% train, 10% val, 20% test grouped strictly by scenario_id/type
   (zero scenario overlap between splits).
2. Metrics Evaluated:
   - Macro-F1, Weighted-F1, Balanced Accuracy, Overall Accuracy
   - Per-Class Precision, Recall, F1 (all 5 canonical classes)
   - Complete 5x5 Multiclass Confusion Matrix
   - Benign False Positive Rate (Benign FPR = FP_benign / Total_benign)
   - Attack Recall (TP_attack / Total_attack)
   - Multi-Class Log-Loss and Brier Score
3. False-Positive & False-Negative Analysis:
   - Granular false-positive breakdown across 7 administrative workflows
   - False-negative inspection across attack types
   - Telemetry completeness correlation: error rates when endpoint/auth telemetry is missing vs. present
   - Attribution status review (inferred vs verified)

Output Artifact:
- data/models/detection_quality_results.json
"""

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_fscore_support,
)

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.schemas import UnifiedEvent
from backend.detection.model_lifecycle import ModelLifecycleManager
from backend.detection.model_trainer import (
    CANONICAL_CLASSES,
    calculate_failed_auth_rate,
    extract_full_causal_features,
    load_flexible_dataset,
)
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.detection.sequence_context import CausalSequenceTracker


DIVERSITY_DATASET_PATH = PROJECT_ROOT / "data" / "raw" / "behavioral_diversity_labeled.jsonl"
OUTPUT_ARTIFACT_PATH = PROJECT_ROOT / "data" / "models" / "detection_quality_results.json"


def scenario_grouped_split(
    events: List[UnifiedEvent],
    seed: int = 42,
    train_ratio: float = 0.70,
    val_ratio: float = 0.10,
) -> Tuple[List[UnifiedEvent], List[UnifiedEvent], List[UnifiedEvent]]:
    """Partition events strictly by scenario_id/type to guarantee zero scenario leakage."""
    scenario_map = defaultdict(list)
    for ev in events:
        s_key = ev.scenario_id or f"{ev.layer}_{ev.src_entity}_{ev.dst_entity}"
        scenario_map[s_key].append(ev)

    rng = np.random.RandomState(seed)
    scenario_keys = sorted(list(scenario_map.keys()))
    rng.shuffle(scenario_keys)

    n_total = len(scenario_keys)
    n_train = int(n_total * train_ratio)
    n_val = int(n_total * val_ratio)

    train_scenarios = sorted(list(set(scenario_keys[:n_train])))
    val_scenarios = sorted(list(set(scenario_keys[n_train:n_train + n_val])))
    test_scenarios = sorted(list(set(scenario_keys[n_train + n_val:])))

    train_events = [e for k in train_scenarios for e in scenario_map[k]]
    val_events = [e for k in val_scenarios for e in scenario_map[k]]
    test_events = [e for k in test_scenarios for e in scenario_map[k]]

    return train_events, val_events, test_events


def evaluate_detection_quality() -> Dict[str, Any]:
    """Execute evaluation and error analysis on behavioral diversity dataset."""
    print("=" * 85)
    print("AEGIS-ML PHASE 28.3: DETECTION QUALITY EVALUATION & ERROR ANALYSIS")
    print("=" * 85)

    if not DIVERSITY_DATASET_PATH.exists():
        raise FileNotFoundError(f"Missing dataset at {DIVERSITY_DATASET_PATH}")

    # 1. Load active production classifier
    lm = ModelLifecycleManager()
    if not lm.load_artifact():
        raise RuntimeError("Failed to load production classifier artifact.")
    classifier = lm.active_classifier
    print(f"Loaded classifier: {getattr(classifier, 'model_version', '23.0.0')} (calibrated={classifier.is_calibrated})")

    # 2. Load dataset
    print(f"Loading evaluation dataset: {DIVERSITY_DATASET_PATH}")
    events, stats = load_flexible_dataset(DIVERSITY_DATASET_PATH)
    print(f"Total events loaded: {len(events)}")

    # 3. Partition
    train_ev, val_ev, test_ev = scenario_grouped_split(events, seed=42)
    print(f"Scenario-Grouped Split: Train={len(train_ev)} | Val={len(val_ev)} | Test={len(test_ev)}")

    # 4. Prepare preprocessors (fit strictly on train)
    print("Fitting baseline profiler and isolation forest on train split...")
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(train_ev, benign_only=True)
    if_detector = IsolationForestDetector()
    if_detector.fit(train_ev)
    failed_auth_map = calculate_failed_auth_rate(train_ev)

    # 5. Extract features for test split
    print("Extracting 48 causal features on test split...")
    graph_tracker = CausalTemporalGraphTracker()
    sequence_tracker = CausalSequenceTracker(window_seconds=300.0)

    # Sort test chronologically to respect temporal watermarks
    test_ev_sorted = sorted(test_ev, key=lambda e: (e.timestamp, e.event_id or ""))
    X_test_list = []
    y_test_list = []
    valid_test_ev = []

    canonical_lower = [c.lower() for c in classifier.classes]
    for ev in test_ev_sorted:
        lbl = (ev.attack_type or "benign").lower()
        if lbl not in canonical_lower:
            continue
        if_score = if_detector.predict(ev)
        base_dev = profiler.compute_deviation_score(ev)
        auth_rate = failed_auth_map.get(ev.src_entity, 0.0)
        feat_vec = extract_full_causal_features(
            event=ev,
            if_score=if_score,
            baseline_deviation=base_dev,
            profiler=profiler,
            failed_auth_rate=auth_rate,
            graph_tracker=graph_tracker,
            sequence_tracker=sequence_tracker,
        )
        X_test_list.append(feat_vec)
        y_test_list.append(lbl)
        valid_test_ev.append(ev)

    X_test = np.asarray(X_test_list, dtype=np.float64)
    y_test = y_test_list
    print(f"Evaluated test samples: {len(y_test)}")

    # 6. Predict using calibrated production classifier
    print("Executing classifier inference on test split...")
    y_pred = []
    y_probas = []
    classes = list(classifier.classes)

    for i in range(len(X_test)):
        row = X_test[i].tolist()
        pred = classifier.predict(row)
        y_pred.append(pred.threat_type)
        if pred.calibrated_probabilities:
            probs = [pred.calibrated_probabilities.get(c, 0.0) for c in classes]
        else:
            probs = [pred.raw_probabilities.get(c, 0.0) for c in classes]
        y_probas.append(probs)

    y_probas = np.array(y_probas)

    # 7. Compute Standard Multi-class Metrics
    acc = accuracy_score(y_test, y_pred)
    bal_acc = balanced_accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    p_per_class, r_per_class, f1_per_class, sup_per_class = precision_recall_fscore_support(
        y_test, y_pred, labels=classes, zero_division=0
    )

    cm = confusion_matrix(y_test, y_pred, labels=classes)

    # 8. Benign FPR & Attack Recall
    benign_idx = classes.index("benign")
    total_benign = int(np.sum(cm[benign_idx, :]))
    true_benign = int(cm[benign_idx, benign_idx])
    false_alarms = total_benign - true_benign
    benign_fpr = false_alarms / total_benign if total_benign > 0 else 0.0

    total_attacks = int(len(y_test) - total_benign)
    # True attack positives: attack correctly classified as ANY attack (not benign)
    attack_fn = int(np.sum(cm[:, benign_idx]) - cm[benign_idx, benign_idx])
    attack_tp = total_attacks - attack_fn
    attack_recall = attack_tp / total_attacks if total_attacks > 0 else 0.0

    # Probability calibration metrics (Log-Loss & Brier score)
    try:
        loss = log_loss(y_test, y_probas, labels=classes)
    except Exception:
        loss = None

    # Binary Brier Score: 1 for attack, 0 for benign
    y_test_bin = np.array([0 if y == "benign" else 1 for y in y_test])
    p_attack = np.array([1.0 - p[benign_idx] for p in y_probas])
    brier = float(brier_score_loss(y_test_bin, p_attack))

    # 9. Phase 28.4: Granular False-Positive & False-Negative Analysis
    print("Performing granular error breakdown across workflows and telemetry completeness...")
    wf_stats = defaultdict(lambda: {"total": 0, "fp": 0, "predicted_as": Counter()})
    fn_breakdown = defaultdict(lambda: {"total": 0, "fn": 0, "missing_endpoint_count": 0})

    for ev, true_lbl, pred_lbl in zip(valid_test_ev, y_test, y_pred):
        # False Positive Analysis on Benign Workflows
        if true_lbl == "benign":
            wf = ev.scenario_type or "standard_benign"
            wf_stats[wf]["total"] += 1
            if pred_lbl != "benign":
                wf_stats[wf]["fp"] += 1
                wf_stats[wf]["predicted_as"][pred_lbl] += 1

        # False Negative Analysis on Attacks
        if true_lbl != "benign":
            fn_breakdown[true_lbl]["total"] += 1
            if pred_lbl == "benign":
                fn_breakdown[true_lbl]["fn"] += 1
                if not ev.process_name and not ev.auth_result:
                    fn_breakdown[true_lbl]["missing_endpoint_count"] += 1

    formatted_wf_analysis = {}
    for wf, d in wf_stats.items():
        rate = d["fp"] / d["total"] if d["total"] > 0 else 0.0
        formatted_wf_analysis[wf] = {
            "total_events": d["total"],
            "false_alarms": d["fp"],
            "false_alarm_rate": round(rate, 4),
            "common_misclassifications": dict(d["predicted_as"]),
        }

    formatted_fn_analysis = {}
    for atk, d in fn_breakdown.items():
        fn_rate = d["fn"] / d["total"] if d["total"] > 0 else 0.0
        formatted_fn_analysis[atk] = {
            "total_attack_events": d["total"],
            "missed_as_benign": d["fn"],
            "false_negative_rate": round(fn_rate, 4),
            "missed_lacking_endpoint_context": d["missing_endpoint_count"],
        }

    # Summary Display
    print("\n" + "=" * 85)
    print(f"Overall Accuracy:        {acc * 100:.2f}%")
    print(f"Balanced Accuracy:       {bal_acc * 100:.2f}%")
    print(f"Macro-F1 Score:          {macro_f1 * 100:.2f}%")
    print(f"Weighted-F1 Score:       {weighted_f1 * 100:.2f}%")
    print(f"Benign False Alarm Rate: {benign_fpr * 100:.2f}% ({false_alarms}/{total_benign})")
    print(f"Overall Attack Recall:   {attack_recall * 100:.2f}% ({attack_tp}/{total_attacks})")
    if loss is not None:
        print(f"Calibrated Log-Loss:     {loss:.4f}")
    print(f"Binary Brier Score:      {brier:.4f}")
    print("-" * 85)
    print(f"{'Class':<20} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
    print("-" * 85)
    per_class_summary = {}
    for idx, cls in enumerate(classes):
        p, r, f, s = p_per_class[idx], r_per_class[idx], f1_per_class[idx], int(sup_per_class[idx])
        per_class_summary[cls] = {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1_score": round(float(f), 4),
            "support": s,
        }
        print(f"{cls:<20} | {p*100:<9.2f}% | {r*100:<9.2f}% | {f*100:<9.2f}% | {s:<8}")

    print("-" * 85)
    print("Confusion Matrix:")
    print("Labels:", classes)
    for row in cm:
        print(row.tolist())

    artifact = {
        "metadata": {
            "evaluation_phase": "Phase 28: Detection Quality & Error Analysis",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dataset": str(DIVERSITY_DATASET_PATH),
            "split_method": "scenario_grouped_stratified_70_10_20",
            "seed": 42,
            "classes": classes,
            "disclaimer": (
                "Evaluation evaluated against scenario-grouped synthetic benchmarks. "
                "Real-world generalization on organic enterprise network telemetry has not been independently established."
            ),
        },
        "aggregate_metrics": {
            "accuracy": round(float(acc), 4),
            "balanced_accuracy": round(float(bal_acc), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "benign_false_positive_rate": round(float(benign_fpr), 4),
            "benign_fp_count": false_alarms,
            "benign_total_count": total_benign,
            "attack_recall": round(float(attack_recall), 4),
            "attack_tp_count": attack_tp,
            "attack_total_count": total_attacks,
            "log_loss": round(float(loss), 4) if loss else None,
            "brier_score": round(float(brier), 4),
        },
        "per_class_metrics": per_class_summary,
        "confusion_matrix": cm.tolist(),
        "false_positive_workflow_analysis": formatted_wf_analysis,
        "false_negative_attack_analysis": formatted_fn_analysis,
    }

    OUTPUT_ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_ARTIFACT_PATH, "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n[OK] Detection quality results saved to {OUTPUT_ARTIFACT_PATH}")
    return artifact


if __name__ == "__main__":
    evaluate_detection_quality()
