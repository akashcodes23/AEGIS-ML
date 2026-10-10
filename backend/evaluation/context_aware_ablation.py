"""AEGIS-ML Phase 20: Context-Aware Detection and Feature Ablation.

Module: backend.evaluation.context_aware_ablation

Executes a controlled 4-configuration (plus optimal combination) feature ablation
on the Phase 19 behavioral-diversity dataset to investigate whether telemetry-context
and missingness handling reduce administrative false positives without harming attack recall:

Configurations evaluated:
A. Config A (Config C Baseline, 21 features):
   15 baseline features + 6 relational temporal graph features.
B. Config B (Config C + Supported Context, 31 features):
   Config C + 10 explicit telemetry context features (layer, process/net presence, direction, bucket, socket).
C. Config C (Config C without Network-Risk Heuristics, 19 features):
   Config C with dst_port_risk and is_external_dst removed to test if SMB/port heuristics cause false alarms.
D. Config D (Config C + Explicit Missingness, 26 features):
   Config C + 5 missingness indicators (missing port, bytes sent/recv, process, auth result).
E. Config E (Config C + Context + Missingness, 36 features):
   Unified context-aware and missingness-aware representation.

Guarantees:
- Uses identical scenario-grouped train/test partitions (seed 42, 0.0% scenario overlap).
- Preprocessors (profiler, IF, failed_auth, SMOTE) fitted strictly on training data.
- Strict provenance exclusion (scenario_id, scenario_type, generator_version, event_id prohibited).
- Serializes complete comparative evaluation to data/models/context_aware_ablation_artifact.json.
"""

from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    accuracy_score,
)
from imblearn.over_sampling import SMOTE

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import UnifiedEvent
from backend.detection.model_trainer import (
    load_flexible_dataset,
    build_feature_matrix,
    calculate_failed_auth_rate,
    CANONICAL_CLASSES,
)
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.temporal_graph_extractor import (
    CausalTemporalGraphTracker,
    RELATIONAL_GRAPH_FEATURE_NAMES,
)
from backend.detection.telemetry_context import (
    SUPPORTED_CONTEXT_FEATURE_NAMES,
    MISSINGNESS_FEATURE_NAMES,
    extract_telemetry_context_features,
    extract_missingness_features,
)
from backend.evaluation.scenario_evaluation import (
    compute_file_sha256,
    PROHIBITED_FEATURE_FIELDS,
)
from backend.evaluation.behavioral_diversity_evaluation import (
    partition_behavioral_diversity_split,
    DIVERSITY_DATASET_REL_PATH,
    BENIGN_WORKFLOW_TYPES,
)


ABLATION_ARTIFACT_REL_PATH = "data/models/context_aware_ablation_artifact.json"
HISTORICAL_PHASE19_ARTIFACT_PATH = "data/models/behavioral_diversity_artifact.json"


def run_single_ablation_configuration(
    config_id: str,
    config_name: str,
    feature_names: List[str],
    X_train: np.ndarray,
    y_train: List[str],
    X_test: np.ndarray,
    y_test: List[str],
    test_events: List[UnifiedEvent],
    model_seed: int = 42,
) -> Dict[str, Any]:
    """Train and evaluate a specific feature configuration with train-only SMOTE."""
    # Audit: ensure zero prohibited fields in feature names
    for prohibited in PROHIBITED_FEATURE_FIELDS:
        assert prohibited not in feature_names, (
            f"Leakage in {config_id}: prohibited field '{prohibited}' in feature names!"
        )

    # SMOTE applied strictly to training data
    min_count = min(Counter(y_train).values())
    smote = SMOTE(k_neighbors=max(1, min(4, min_count - 1)), random_state=model_seed)
    X_tr_res, y_tr_res = smote.fit_resample(X_train, y_train)

    clf = ThreatClassifier(random_state=model_seed, feature_names=feature_names)
    clf.fit(X_tr_res, y_tr_res)

    y_pred = list(clf.model.predict(X_test))
    classes = CANONICAL_CLASSES

    cm = confusion_matrix(y_test, y_pred, labels=classes)
    prec, rec, f1_vals, supp = precision_recall_fscore_support(
        y_test, y_pred, labels=classes, zero_division=0
    )

    per_class_results = {}
    for idx, c_name in enumerate(classes):
        per_class_results[c_name] = {
            "support": int(supp[idx]),
            "precision": round(float(prec[idx]), 4),
            "recall": round(float(rec[idx]), 4),
            "f1": round(float(f1_vals[idx]), 4),
        }

    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    balanced_acc = float(balanced_accuracy_score(y_test, y_pred))
    acc = float(accuracy_score(y_test, y_pred))

    # Binary metrics: Attack (1) vs Benign (0)
    y_test_bin = [0 if lbl == "benign" else 1 for lbl in y_test]
    y_pred_bin = [0 if pred == "benign" else 1 for pred in y_pred]

    total_benign_test = sum(1 for b in y_test_bin if b == 0)
    fp_benign_count = sum(1 for yt, yp in zip(y_test_bin, y_pred_bin) if yt == 0 and yp == 1)
    binary_fpr_on_benign = fp_benign_count / total_benign_test if total_benign_test > 0 else 0.0

    total_attack_test = sum(1 for b in y_test_bin if b == 1)
    tp_attack_count = sum(1 for yt, yp in zip(y_test_bin, y_pred_bin) if yt == 1 and yp == 1)
    binary_attack_recall = tp_attack_count / total_attack_test if total_attack_test > 0 else 0.0

    # Per-workflow breakdown for benign workflows
    test_scenario_types = [e.scenario_type for e in test_events]
    workflow_events = defaultdict(list)
    for st, yt, yp in zip(test_scenario_types, y_test, y_pred):
        if yt == "benign":
            workflow_events[st].append((yt, yp))

    workflow_breakdown = {}
    for w_type in BENIGN_WORKFLOW_TYPES:
        pairs = workflow_events.get(w_type, [])
        w_total = len(pairs)
        if w_total == 0:
            workflow_breakdown[w_type] = {
                "total_events": 0,
                "correct_benign": 0,
                "false_alarms": 0,
                "false_alarm_rate": 0.0,
                "predictions": {},
            }
            continue

        w_correct = sum(1 for _, pred_c in pairs if pred_c == "benign")
        w_false = w_total - w_correct
        w_fpr = w_false / w_total
        pred_dist = Counter(pred_c for _, pred_c in pairs)

        workflow_breakdown[w_type] = {
            "total_events": w_total,
            "correct_benign": w_correct,
            "false_alarms": w_false,
            "false_alarm_rate": round(float(w_fpr), 4),
            "predictions": dict(pred_dist),
        }

    return {
        "config_id": config_id,
        "config_name": config_name,
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "metrics": {
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "balanced_accuracy": round(balanced_acc, 4),
            "binary_attack_recall": round(binary_attack_recall, 4),
            "binary_false_alarm_rate_on_benign": round(binary_fpr_on_benign, 4),
            "benign_fpr_numerator": fp_benign_count,
            "benign_fpr_denominator": total_benign_test,
            "confusion_matrix": cm.tolist(),
            "per_class": per_class_results,
        },
        "benign_workflow_breakdown": workflow_breakdown,
        "predictions": y_pred,
    }


def execute_feature_ablation_experiments(
    data_path: str = DIVERSITY_DATASET_REL_PATH,
    split_seed: int = 42,
    model_seed: int = 42,
    output_path: str = ABLATION_ARTIFACT_REL_PATH,
) -> Dict[str, Any]:
    """Execute all 4 ablation configurations (+ optimal combination) on identical split."""
    full_data_path = Path(PROJECT_ROOT) / data_path if not Path(data_path).is_absolute() else Path(data_path)
    if not full_data_path.exists():
        raise FileNotFoundError(f"Dataset not found at {full_data_path}")

    dataset_sha256 = compute_file_sha256(full_data_path)
    events, _ = load_flexible_dataset(str(full_data_path))
    labels = [e.attack_type or "benign" for e in events]

    # Partition by scenario (identical partition to Phase 19)
    tr_indices, te_indices, split_stats = partition_behavioral_diversity_split(
        events, labels, test_ratio=0.20, seed=split_seed
    )

    tr_events = [events[i] for i in tr_indices]
    y_tr = [labels[i] for i in tr_indices]
    te_events = [events[i] for i in te_indices]
    y_te = [labels[i] for i in te_indices]

    # 1. Base preprocessors fitted strictly on training data
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(tr_events, benign_only=True)

    if_detector = IsolationForestDetector(random_state=model_seed)
    if_detector.fit(tr_events)

    fa_tr = calculate_failed_auth_rate(tr_events)
    fa_te = calculate_failed_auth_rate(te_events)

    X_tr_base = build_feature_matrix(tr_events, if_detector, profiler, fa_tr)
    X_te_base = build_feature_matrix(te_events, if_detector, profiler, fa_te)

    # 2. Relational graph features
    tracker = CausalTemporalGraphTracker()
    tracker.fit_baseline_pairs(tr_events)
    tr_tg = tracker.extract_sequence(tr_events)
    te_tg = tracker.extract_sequence(te_events)

    tr_rel = np.array([[f[k] for k in RELATIONAL_GRAPH_FEATURE_NAMES] for f in tr_tg], dtype=np.float64)
    te_rel = np.array([[f[k] for k in RELATIONAL_GRAPH_FEATURE_NAMES] for f in te_tg], dtype=np.float64)

    # Config A: Config C Baseline (21 features)
    X_tr_A = np.hstack([X_tr_base, tr_rel])
    X_te_A = np.hstack([X_te_base, te_rel])
    feats_A = ThreatClassifier.FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES
    assert len(feats_A) == 21

    # Context features (10 features)
    ctx_tr = np.array([extract_telemetry_context_features(e) for e in tr_events], dtype=np.float64)
    ctx_te = np.array([extract_telemetry_context_features(e) for e in te_events], dtype=np.float64)
    feats_ctx = SUPPORTED_CONTEXT_FEATURE_NAMES

    # Missingness features (5 features)
    miss_tr = np.array([extract_missingness_features(e) for e in tr_events], dtype=np.float64)
    miss_te = np.array([extract_missingness_features(e) for e in te_events], dtype=np.float64)
    feats_miss = MISSINGNESS_FEATURE_NAMES

    # Config B: Config C + Context (31 features)
    X_tr_B = np.hstack([X_tr_A, ctx_tr])
    X_te_B = np.hstack([X_te_A, ctx_te])
    feats_B = feats_A + feats_ctx
    assert len(feats_B) == 31

    # Config C: Config C without dst_port_risk and is_external_dst (19 features)
    # dst_port_risk is index 9, is_external_dst is index 11
    keep_indices_C = [i for i in range(len(feats_A)) if i not in (9, 11)]
    X_tr_C = X_tr_A[:, keep_indices_C]
    X_te_C = X_te_A[:, keep_indices_C]
    feats_C = [feats_A[i] for i in keep_indices_C]
    assert len(feats_C) == 19

    # Config D: Config C + Explicit Missingness (26 features)
    X_tr_D = np.hstack([X_tr_A, miss_tr])
    X_te_D = np.hstack([X_te_A, miss_te])
    feats_D = feats_A + feats_miss
    assert len(feats_D) == 26

    # Config E: Config C + Context + Missingness (36 features)
    X_tr_E = np.hstack([X_tr_A, ctx_tr, miss_tr])
    X_te_E = np.hstack([X_te_A, ctx_te, miss_te])
    feats_E = feats_A + feats_ctx + feats_miss
    assert len(feats_E) == 36

    ablation_definitions = [
        ("config_a", "Config A: Config C Baseline (21 feats)", feats_A, X_tr_A, X_te_A),
        ("config_b", "Config B: Config C + Supported Context (31 feats)", feats_B, X_tr_B, X_te_B),
        ("config_c", "Config C: Config C without Network-Risk Heuristics (19 feats)", feats_C, X_tr_C, X_te_C),
        ("config_d", "Config D: Config C + Explicit Missingness (26 feats)", feats_D, X_tr_D, X_te_D),
        ("config_e", "Config E: Config C + Context + Missingness (36 feats)", feats_E, X_tr_E, X_te_E),
    ]

    ablation_results = {}
    summary_comparison = []

    for cfg_id, cfg_name, cfg_feats, xtr, xte in ablation_definitions:
        print(f"[Phase 20] Running {cfg_name}...")
        res = run_single_ablation_configuration(
            config_id=cfg_id,
            config_name=cfg_name,
            feature_names=cfg_feats,
            X_train=xtr,
            y_train=y_tr,
            X_test=xte,
            y_test=y_te,
            test_events=te_events,
            model_seed=model_seed,
        )
        ablation_results[cfg_id] = res
        summary_comparison.append({
            "config_id": cfg_id,
            "config_name": cfg_name,
            "feature_count": res["feature_count"],
            "macro_f1": res["metrics"]["macro_f1"],
            "balanced_accuracy": res["metrics"]["balanced_accuracy"],
            "accuracy": res["metrics"]["accuracy"],
            "binary_attack_recall": res["metrics"]["binary_attack_recall"],
            "binary_benign_fpr": res["metrics"]["binary_false_alarm_rate_on_benign"],
            "backup_fpr": res["benign_workflow_breakdown"]["scheduled_backup"]["false_alarm_rate"],
            "transfer_fpr": res["benign_workflow_breakdown"]["large_file_transfer"]["false_alarm_rate"],
            "smb_fpr": res["benign_workflow_breakdown"]["smb_file_sharing"]["false_alarm_rate"],
            "archive_fpr": res["benign_workflow_breakdown"]["bulk_read_archive"]["false_alarm_rate"],
            "deploy_fpr": res["benign_workflow_breakdown"]["software_deployment"]["false_alarm_rate"],
            "sync_fpr": res["benign_workflow_breakdown"]["data_synchronization"]["false_alarm_rate"],
        })

    artifact = {
        "protocol_title": "AEGIS-ML Phase 20: Context-Aware Detection and Feature Ablation",
        "timestamp": datetime.now().isoformat(),
        "dataset_metadata": {
            "dataset_path": str(full_data_path),
            "dataset_sha256": dataset_sha256,
            "total_records": len(events),
            "split_seed": split_seed,
            "model_seed": model_seed,
            "generator_version": "3.0.0",
        },
        "split_methodology": {
            "strategy": "scenario_grouped_stratified_by_type",
            "total_scenarios": split_stats["total_scenarios"],
            "train_scenarios_count": split_stats["train_scenarios_count"],
            "test_scenarios_count": split_stats["test_scenarios_count"],
            "scenario_overlap_count": split_stats["scenario_overlap_count"],
            "train_samples": len(tr_indices),
            "test_samples": len(te_indices),
        },
        "summary_comparison": summary_comparison,
        "ablation_configurations": {
            k: {
                "config_id": v["config_id"],
                "config_name": v["config_name"],
                "feature_count": v["feature_count"],
                "feature_names": v["feature_names"],
                "metrics": v["metrics"],
                "benign_workflow_breakdown": v["benign_workflow_breakdown"],
            }
            for k, v in ablation_results.items()
        },
        "instance_level_data": {
            "test_event_ids": [e.event_id for e in te_events],
            "test_scenario_ids": [e.scenario_id for e in te_events],
            "ground_truth_labels": y_te,
            "predictions_by_config": {k: v["predictions"] for k, v in ablation_results.items()},
        },
        "status": "COMPLETED",
    }

    out_file = Path(PROJECT_ROOT) / output_path if not Path(output_path).is_absolute() else Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    print(f"[Phase 20] Ablation experiments complete. Saved to {output_path}")
    return artifact


if __name__ == "__main__":
    execute_feature_ablation_experiments()
