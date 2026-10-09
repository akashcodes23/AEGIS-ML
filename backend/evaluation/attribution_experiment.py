"""
AEGIS-ML Phase 14: Attribution-Aware Model Experiment
Module: backend.evaluation.attribution_experiment

Evaluates Configuration C (15 baseline + 6 relational features) as the baseline
across multiple fixed seeds under strict leak-free conditions.
Audits attribution feature availability in the source dataset.
Reports experimental attribution-aware model configuration status (marked
as NOT_COMPLETED when genuine process-to-network telemetry is absent) and
provides the reproducible harness required to execute it once populated.
"""

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple
import random

import numpy as np
from sklearn.metrics import (
    f1_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
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
    TEMPORAL_FEATURE_NAMES,
    RELATIONAL_GRAPH_FEATURE_NAMES,
)


def get_event_fingerprint(e: UnifiedEvent) -> Tuple:
    return (
        e.layer, e.src_entity, e.dst_entity, e.src_port, e.dst_port,
        e.protocol, e.action, e.process_name, e.file_path,
        e.bytes_sent, e.bytes_received, e.auth_result,
        e.http_method, e.endpoint_path, e.status_code
    )


def audit_feature_availability(data_path: str) -> Dict[str, Any]:
    """Audit genuine availability and missingness of attribution features in dataset."""
    fields_to_check = [
        "socket_id", "host_id", "process_guid", "connection_direction",
        "process_start_time", "process_end_time", "pid", "parent_pid",
        "process_name", "user_account", "file_path", "parent_process"
    ]
    counts = {f: 0 for f in fields_to_check}
    total = 0

    with open(data_path, "r") as f:
        for line in f:
            total += 1
            record = json.loads(line)
            for f in fields_to_check:
                if record.get(f) is not None:
                    counts[f] += 1

    availability = {}
    for f, c in counts.items():
        availability[f] = {
            "populated_count": c,
            "total_count": total,
            "availability_pct": round((c / total) * 100, 2) if total else 0.0,
            "missingness_pct": round(((total - c) / total) * 100, 2) if total else 100.0,
            "status": "absent" if c == 0 else ("sparse" if c < total * 0.1 else "populated")
        }

    return {
        "dataset_path": str(data_path),
        "total_records": total,
        "features": availability,
        "dual_telemetry_viable": counts["socket_id"] > 0 and counts["process_guid"] > 0,
    }


def evaluate_baseline_config_c(
    events: List[UnifiedEvent],
    labels: List[str],
    seed: int = 42,
) -> Dict[str, Any]:
    """Train and evaluate Configuration C (21 features) on a group-aware holdout."""
    classes = CANONICAL_CLASSES

    # Fingerprint clustering
    fp_to_gid = {}
    event_groups = []
    for e in events:
        fp = get_event_fingerprint(e)
        if fp not in fp_to_gid:
            fp_to_gid[fp] = len(fp_to_gid)
        event_groups.append(fp_to_gid[fp])

    rng = random.Random(seed)
    class_to_groups = defaultdict(set)
    for gid, lbl in zip(event_groups, labels):
        class_to_groups[lbl].add(gid)

    train_gids = set()
    test_gids = set()
    for lbl, gids in class_to_groups.items():
        gid_list = sorted(list(gids))
        rng.shuffle(gid_list)
        n_test = max(1, int(len(gid_list) * 0.20))
        test_gids.update(gid_list[:n_test])
        train_gids.update(gid_list[n_test:])

    tr_indices = [i for i, gid in enumerate(event_groups) if gid in train_gids]
    te_indices = [i for i, gid in enumerate(event_groups) if gid in test_gids]

    tr_events = [events[i] for i in tr_indices]
    y_tr = [labels[i] for i in tr_indices]
    te_events = [events[i] for i in te_indices]
    y_te = [labels[i] for i in te_indices]

    # Preprocessing strictly inside train
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(tr_events, benign_only=True)
    iso_detector = IsolationForestDetector(contamination=0.08, random_state=seed)
    iso_detector.fit(tr_events)
    tr_failed_rates = calculate_failed_auth_rate(tr_events)
    te_failed_rates = calculate_failed_auth_rate(te_events)

    X_tr_base = build_feature_matrix(tr_events, iso_detector, profiler, tr_failed_rates)
    X_te_base = build_feature_matrix(te_events, iso_detector, profiler, te_failed_rates)

    # Relational features
    tracker = CausalTemporalGraphTracker()
    tracker.fit_baseline_pairs(tr_events)
    tr_tg = tracker.extract_sequence(tr_events)
    te_tg = tracker.extract_sequence(te_events)

    tr_rel_arr = np.array([[f[k] for k in RELATIONAL_GRAPH_FEATURE_NAMES] for f in tr_tg], dtype=np.float64)
    te_rel_arr = np.array([[f[k] for k in RELATIONAL_GRAPH_FEATURE_NAMES] for f in te_tg], dtype=np.float64)

    X_tr_c = np.hstack([X_tr_base, tr_rel_arr])
    X_te_c = np.hstack([X_te_base, te_rel_arr])
    feats_c = ThreatClassifier.FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES

    # SMOTE on train only
    min_count = min(Counter(y_tr).values())
    k_smote = max(1, min(4, min_count - 1))
    smote = SMOTE(k_neighbors=k_smote, random_state=seed)
    X_tr_res, y_tr_res = smote.fit_resample(X_tr_c, y_tr)

    clf = ThreatClassifier(random_state=seed, feature_names=feats_c)
    clf.fit(X_tr_res, y_tr_res)
    y_pred = list(clf.model.predict(X_te_c))

    cm = confusion_matrix(y_te, y_pred, labels=classes)
    prec, rec, f1, supp = precision_recall_fscore_support(y_te, y_pred, labels=classes, zero_division=0)
    per_class = {
        cls: {
            "precision": round(float(prec[i]), 4),
            "recall": round(float(rec[i]), 4),
            "f1": round(float(f1[i]), 4),
            "support": int(supp[i]),
        }
        for i, cls in enumerate(classes)
    }

    bi = classes.index("benign")
    total_test_samples = len(y_te)
    actual_benign = int(sum(cm[bi]))
    actual_non_benign = int(total_test_samples - actual_benign)
    benign_fp = int(sum(cm[i, bi] for i in range(len(classes)) if i != bi))
    benign_fn = int(sum(cm[bi, j] for j in range(len(classes)) if j != bi))

    multiclass_benign_fpr = round(benign_fp / max(actual_non_benign, 1), 6)
    benign_fnr = round(benign_fn / max(actual_benign, 1), 6)
    binary_false_alarm_rate_on_benign = round(benign_fn / max(actual_benign, 1), 6)

    # Error breakdown for lateral_movement (idx 2) and data_exfiltration (idx 3)
    lm_idx = classes.index("lateral_movement")
    lm_fp = int(sum(cm[i, lm_idx] for i in range(len(classes)) if i != lm_idx))
    lm_fn = int(sum(cm[lm_idx, j] for j in range(len(classes)) if j != lm_idx))

    de_idx = classes.index("data_exfiltration")
    de_fp = int(sum(cm[i, de_idx] for i in range(len(classes)) if i != de_idx))
    de_fn = int(sum(cm[de_idx, j] for j in range(len(classes)) if j != de_idx))

    return {
        "seed": seed,
        "macro_f1": round(float(f1_score(y_te, y_pred, average="macro", zero_division=0)), 4),
        "weighted_f1": round(float(f1_score(y_te, y_pred, average="weighted", zero_division=0)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_te, y_pred)), 4),
        "benign_fpr": multiclass_benign_fpr,
        "benign_fpr_denominator": actual_non_benign,
        "benign_fpr_numerator": benign_fp,
        "benign_false_positives": benign_fp,
        "benign_fnr": benign_fnr,
        "benign_fnr_denominator": actual_benign,
        "benign_fnr_numerator": benign_fn,
        "benign_false_negatives": benign_fn,
        "binary_false_alarm_rate_on_benign": binary_false_alarm_rate_on_benign,
        "lateral_movement_errors": {"false_positives": lm_fp, "false_negatives": lm_fn},
        "data_exfiltration_errors": {"false_positives": de_fp, "false_negatives": de_fn},
        "confusion_matrix": cm.tolist(),
        "per_class": per_class,
        "test_sample_count": len(y_te),
        "train_sample_count": len(y_tr),
    }


def run_attribution_aware_experiment(
    data_path: str = "data/raw/combined_labeled.jsonl",
    seeds: List[int] = [42, 1337, 2026],
) -> Dict[str, Any]:
    """Execute attribution experiment auditing availability, baseline C, and experimental status."""
    data_file = Path(PROJECT_ROOT) / data_path if not Path(data_path).is_absolute() else Path(data_path)
    audit = audit_feature_availability(str(data_file))

    events, _ = load_flexible_dataset(str(data_file))
    labels = [e.attack_type or "benign" for e in events]

    baseline_results = []
    for s in seeds:
        res = evaluate_baseline_config_c(events, labels, seed=s)
        baseline_results.append(res)

    # Compute mean metrics across seeds for Baseline C
    mean_macro_f1 = round(float(np.mean([r["macro_f1"] for r in baseline_results])), 4)
    mean_bal_acc = round(float(np.mean([r["balanced_accuracy"] for r in baseline_results])), 4)
    mean_benign_fpr = round(float(np.mean([r["benign_fpr"] for r in baseline_results])), 6)
    mean_benign_fnr = round(float(np.mean([r["benign_fnr"] for r in baseline_results])), 6)

    experiment_report = {
        "experiment_title": "AEGIS-ML Attribution-Aware Model Experiment",
        "timestamp": datetime.utcnow().isoformat(),
        "feature_availability_audit": audit,
        "baseline_configuration_c": {
            "description": "15 baseline features + 6 relational temporal-graph features",
            "feature_count": 21,
            "seeds_evaluated": seeds,
            "individual_seed_results": baseline_results,
            "aggregate_metrics": {
                "mean_macro_f1": mean_macro_f1,
                "mean_balanced_accuracy": mean_bal_acc,
                "mean_benign_fpr": mean_benign_fpr,
                "mean_benign_fnr": mean_benign_fnr,
            },
        },
        "experimental_configuration_status": {
            "status": "NOT_COMPLETED",
            "reason": (
                "Genuine process-to-network attribution fields (socket_id, process_guid, host_id) "
                "are 0.0% populated in the combined_labeled.jsonl source dataset. "
                "In accordance with Phase 14 Safety Rules 6 & 10, real telemetry will not be fabricated. "
                "No predictive improvement is claimed without comparable measured real data."
            ),
            "reproducible_setup_harness": {
                "required_schema_fields": [
                    "socket_id", "process_guid", "host_id", "pid", "process_start_time"
                ],
                "proposed_experimental_features": [
                    "has_verified_socket_binding (binary)",
                    "process_network_divergence_score (float)",
                    "cross_layer_co_occurrence_count (int)",
                ],
                "evaluation_protocol": (
                    "When dual-telemetry dataset is provided, evaluate identical group-aware holdout "
                    "with seeds [42, 1337, 2026], reporting delta against Configuration C baseline."
                ),
            },
        },
        "limitations": [
            "Source dataset combined_labeled.jsonl lacks host OS socket table and process GUID attribution.",
            "Synthetic correlation benchmarks validate software logic only, not real-world predictive ML generalization.",
        ],
    }

    out_file = Path(PROJECT_ROOT) / "data" / "models" / "attribution_experiment_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(experiment_report, f, indent=2)

    return experiment_report


if __name__ == "__main__":
    rep = run_attribution_aware_experiment()
    print("Attribution experiment completed!")
    print(f"Feature availability: {rep['feature_availability_audit']['dual_telemetry_viable']}")
    print(f"Baseline C Mean Macro-F1 across seeds: {rep['baseline_configuration_c']['aggregate_metrics']['mean_macro_f1']}")
    print(f"Experimental Status: {rep['experimental_configuration_status']['status']}")
