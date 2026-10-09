import json
import math
import time
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import label_binarize
import sklearn

from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

try:
    from core.schemas import UnifiedEvent
    from core.config import (
        PORT_RISK,
        MODEL_DIR,
        RF_CLASSIFIER_PATH,
        IF_NETWORK_PATH,
        IF_ENDPOINT_PATH,
        BASELINES_PATH,
        PROJECT_ROOT,
    )
    from detection.baseline_profiler import BehavioralBaselineProfiler
    from detection.isolation_forest import IsolationForestDetector
    from detection.threat_classifier import ThreatClassifier
except ModuleNotFoundError:
    from backend.core.schemas import UnifiedEvent
    from backend.core.config import (
        PORT_RISK,
        MODEL_DIR,
        RF_CLASSIFIER_PATH,
        IF_NETWORK_PATH,
        IF_ENDPOINT_PATH,
        BASELINES_PATH,
        PROJECT_ROOT,
    )
    from backend.detection.baseline_profiler import BehavioralBaselineProfiler
    from backend.detection.isolation_forest import IsolationForestDetector
    from backend.detection.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)

# Canonical MITRE-aligned threat classes
CANONICAL_CLASSES = ThreatClassifier.CLASSES

# Mapping of known third-party dataset labels to AEGIS canonical categories
DATASET_LABEL_MAP = {
    # Benign variations
    "benign": "benign",
    "normal": "benign",
    # Brute force
    "ftp-patator": "brute_force",
    "ssh-patator": "brute_force",
    "web attack \x96 brute force": "brute_force",
    "web attack - brute force": "brute_force",
    "web attack - xss": "brute_force",
    "web attack - sql injection": "brute_force",
    "brute force": "brute_force",
    # Lateral movement / reconnaissance
    "portscan": "lateral_movement",
    "infiltration": "lateral_movement",
    "lateral_movement": "lateral_movement",
    # Data exfiltration
    "heartbleed": "data_exfiltration",
    "data_exfiltration": "data_exfiltration",
    # Command & Control / DoS
    "bot": "c2_beaconing",
    "c2_beaconing": "c2_beaconing",
    "ddos": "c2_beaconing",
    "dos hulk": "c2_beaconing",
    "dos goldeneye": "c2_beaconing",
    "dos slowhttptest": "c2_beaconing",
    "dos slowloris": "c2_beaconing",
}


def load_flexible_dataset(
    file_path: str,
    max_rows: Optional[int] = None,
    random_seed: int = 42
) -> Tuple[List[UnifiedEvent], Dict[str, Any]]:
    """
    Load and preprocess events from CSV, JSON, or JSONL formats.
    
    Returns:
        events: List of validated UnifiedEvent instances.
        stats: Diagnostic statistics dictionary detailing loaded, transformed,
               rejected, and retained counts, along with unmapped labels.
    """
    path = Path(file_path)
    stats: Dict[str, Any] = {
        "file_path": str(file_path),
        "raw_records_read": 0,
        "valid_events_loaded": 0,
        "rejected_records": 0,
        "retained_events": 0,
        "unmapped_labels_encountered": {},
        "label_distribution": {},
        "synthetic_timestamps_assigned": 0,
    }

    if not path.exists():
        logger.warning(f"Dataset file not found: {file_path}")
        return [], stats

    raw_df: Optional[pd.DataFrame] = None

    try:
        if path.suffix.lower() == ".csv":
            raw_df = pd.read_csv(file_path, low_memory=False)
        elif path.suffix.lower() == ".jsonl":
            raw_df = pd.read_json(file_path, lines=True)
        else:
            try:
                raw_df = pd.read_json(file_path, lines=True)
            except Exception:
                raw_df = pd.read_json(file_path)
    except Exception as exc:
        logger.error(f"Pandas load failed on {file_path}: {exc}")
        # Fallback line-by-line JSON reader
        events_fallback: List[UnifiedEvent] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stats["raw_records_read"] += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = UnifiedEvent.model_validate_json(line)
                    events_fallback.append(ev)
                    stats["valid_events_loaded"] += 1
                except Exception:
                    stats["rejected_records"] += 1
        stats["retained_events"] = len(events_fallback)
        return events_fallback, stats

    if raw_df is None or raw_df.empty:
        return [], stats

    stats["raw_records_read"] = len(raw_df)

    # Standardize column headers
    raw_df.columns = [str(c).strip().lower() for c in raw_df.columns]

    # Column name normalization dictionary
    col_map = {
        "source ip": "src_ip",
        "destination ip": "dst_ip",
        "label": "raw_label",
        "attack_type": "attack_type",
        "src": "src_entity",
        "dst": "dst_entity",
        "timestamp": "timestamp",
        "time": "timestamp",
        "destination port": "dst_port",
        "protocol": "protocol",
        "total length of fwd packets": "bytes_sent",
        "total length of bwd packets": "bytes_received",
        "flow duration": "duration_ms",
    }
    raw_df = raw_df.rename(columns=lambda c: col_map.get(c, c))

    # Clean string labels
    label_col = "attack_type" if "attack_type" in raw_df.columns else ("raw_label" if "raw_label" in raw_df.columns else None)
    if label_col:
        raw_df[label_col] = raw_df[label_col].astype(str).str.strip()

    events: List[UnifiedEvent] = []
    base_synthetic_time = datetime(2026, 1, 1, 0, 0, 0)

    for idx, row in raw_df.iterrows():
        d = row.to_dict()

        # Extract & map label — must handle float NaN from pandas (NaN is truthy in Python)
        raw_attack = d.get("attack_type")
        raw_lbl = d.get("raw_label")
        _is_nan = lambda v: v is None or (isinstance(v, float) and math.isnan(v)) or str(v).strip().lower() in ("nan", "none", "null", "")
        if not _is_nan(raw_attack):
            source_label = str(raw_attack).strip()
        elif not _is_nan(raw_lbl):
            source_label = str(raw_lbl).strip()
        else:
            source_label = ""

        canonical_label: Optional[str] = None

        if source_label.lower() in DATASET_LABEL_MAP:
            canonical_label = DATASET_LABEL_MAP[source_label.lower()]
        elif source_label.lower() in CANONICAL_CLASSES:
            canonical_label = source_label.lower()
        elif source_label == "" or source_label.lower() in ("none", "nan", "null"):
            canonical_label = "benign"
        else:
            # Explicit unmapped label handling — do NOT silently cast to benign!
            stats["unmapped_labels_encountered"][source_label] = stats["unmapped_labels_encountered"].get(source_label, 0) + 1
            # Mark explicitly as unknown attack or drop
            stats["rejected_records"] += 1
            continue

        d["attack_type"] = canonical_label
        d["raw_label"] = source_label

        # Handle Timestamps
        raw_ts = d.get("timestamp")
        if raw_ts is None or pd.isna(raw_ts) or str(raw_ts).strip() in ("", "nan", "None"):
            # Assign deterministic sequential synthetic timestamp (1 second per row)
            d["timestamp"] = base_synthetic_time + timedelta(seconds=idx)
            stats["synthetic_timestamps_assigned"] += 1
        elif isinstance(raw_ts, str):
            try:
                d["timestamp"] = pd.to_datetime(raw_ts).to_pydatetime()
            except Exception:
                d["timestamp"] = base_synthetic_time + timedelta(seconds=idx)
                stats["synthetic_timestamps_assigned"] += 1
        elif isinstance(raw_ts, (int, float)):
            # Epoch millisecond or second
            try:
                d["timestamp"] = datetime.fromtimestamp(raw_ts if raw_ts < 1e11 else raw_ts / 1000.0)
            except Exception:
                d["timestamp"] = base_synthetic_time + timedelta(seconds=idx)
                stats["synthetic_timestamps_assigned"] += 1

        # Protocol mapping
        proto = d.get("protocol")
        if proto == 6 or proto == "6":
            d["protocol"] = "TCP"
        elif proto == 17 or proto == "17":
            d["protocol"] = "UDP"
        elif proto == 1 or proto == "1":
            d["protocol"] = "ICMP"
        elif proto is not None and not pd.isna(proto):
            d["protocol"] = str(proto).upper()

        # Duration units: flow duration in CICIDS is microseconds -> convert to ms
        dur = d.get("duration_ms")
        if dur is not None and not pd.isna(dur):
            try:
                val = float(dur)
                if val > 100000:  # clearly microseconds
                    d["duration_ms"] = max(0, int(val / 1000.0))
                else:
                    d["duration_ms"] = max(0, int(val))
            except (ValueError, TypeError):
                d["duration_ms"] = 0

        # Numeric sanitization: replace inf / nan
        for num_field in ["bytes_sent", "bytes_received", "dst_port", "src_port"]:
            val = d.get(num_field)
            if val is not None:
                try:
                    fval = float(val)
                    if math.isnan(fval) or math.isinf(fval):
                        d[num_field] = None
                    else:
                        d[num_field] = int(fval)
                except (ValueError, TypeError):
                    d[num_field] = None

        if "layer" not in d or not d["layer"]:
            d["layer"] = "network"

        if "src_entity" not in d or not d["src_entity"]:
            d["src_entity"] = d.get("src_ip") or "unknown_src"
        if "dst_entity" not in d or not d["dst_entity"]:
            d["dst_entity"] = d.get("dst_ip") or "unknown_dst"

        if "src_internal" not in d:
            d["src_internal"] = True
        if "dst_internal" not in d:
            d["dst_internal"] = True

        # Clean NaN/None for Pydantic
        clean_d = {k: v for k, v in d.items() if not (isinstance(v, float) and math.isnan(v))}

        try:
            event = UnifiedEvent(**clean_d)
            events.append(event)
            stats["valid_events_loaded"] += 1
            stats["label_distribution"][canonical_label] = stats["label_distribution"].get(canonical_label, 0) + 1
        except Exception:
            stats["rejected_records"] += 1

    # Deterministic sampling if max_rows specified
    if max_rows and len(events) > max_rows:
        rng = np.random.RandomState(random_seed)
        indices = rng.choice(len(events), size=max_rows, replace=False)
        events = [events[i] for i in indices]

    stats["retained_events"] = len(events)
    logger.info(
        f"Loaded {stats['retained_events']} events from {file_path} "
        f"(read: {stats['raw_records_read']}, rejected: {stats['rejected_records']})"
    )
    return events, stats


def calculate_failed_auth_rate(events: List[UnifiedEvent]) -> Dict[str, float]:
    """
    Calculate rolling count of 401s in last 60s for each event's src_entity,
    strictly respecting causal temporal ordering to prevent lookahead leakage.
    """
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    auth_failures: Dict[str, List[datetime]] = defaultdict(list)
    rates: Dict[str, float] = {}

    for event in sorted_events:
        src = event.src_entity
        current_time = event.timestamp

        if event.layer == "application" and event.status_code == 401:
            auth_failures[src].append(current_time)

        # Retain only timestamps within historical 60s window
        cutoff = current_time - timedelta(seconds=60)
        auth_failures[src] = [t for t in auth_failures[src] if t >= cutoff]

        rates[event.event_id] = float(len(auth_failures[src]))

    return rates


def extract_features(
    event: UnifiedEvent,
    if_score: float,
    baseline_deviation: float,
    profiler: BehavioralBaselineProfiler,
    failed_auth_rate: float,
    graph_new_connections: float = 0.0,
) -> List[float]:
    """
    Unified 15-feature extraction matching ThreatClassifier.FEATURE_NAMES exactly.
    Handles zero-division and missing values safely.
    """
    profile = profiler.profiles.get(event.src_entity)
    conn_freq = float(event.connections_per_minute or 0.0)

    # 1. bytes_sent_zscore
    bytes_sent_zscore = 0.0
    if profile and event.bytes_sent is not None and profile.get("std_bytes_sent", 0) > 0:
        bytes_sent_zscore = abs(event.bytes_sent - profile["avg_bytes_sent"]) / profile["std_bytes_sent"]
        bytes_sent_zscore = float(np.clip(bytes_sent_zscore, 0.0, 10.0))

    # 2. bytes_sent_log
    bytes_sent_val = max(0.0, float(event.bytes_sent or 0.0))
    bytes_sent_log = math.log1p(bytes_sent_val)

    # 3. bytes_ratio
    bytes_rx = max(0.0, float(event.bytes_received or 0.0))
    bytes_tx = max(0.0, float(event.bytes_sent or 0.0))
    bytes_ratio = math.log1p(bytes_tx) / math.log1p(bytes_rx + 1.0)

    # 4. conn_rate_zscore
    conn_rate_zscore = 0.0
    if profile and profile.get("avg_connections_per_min") is not None:
        avg_conn = float(profile.get("avg_connections_per_min", 0.0) or 0.0)
        conn_rate_zscore = min(max((conn_freq - avg_conn) / max(avg_conn, 1.0), -10.0), 10.0)

    # 5. dst_port_risk
    dst_port_risk = float(PORT_RISK.get(event.dst_port, 0.0) if event.dst_port else 0.0)

    # 6. is_new_destination
    is_new_destination = 1.0
    if profile and event.dst_entity in profile.get("typical_destinations", []):
        is_new_destination = 0.0

    # 7. is_external_dst
    is_external_dst = 0.0 if event.dst_internal else 1.0

    # 8. hour_of_day cyclical encoding
    hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
    hour_of_day_sin = math.sin(2 * math.pi * hour / 24.0)
    hour_of_day_cos = math.cos(2 * math.pi * hour / 24.0)

    # 9. cross_layer_match
    cross_layer_match = 0.0

    vector = [
        float(if_score),
        float(baseline_deviation),
        float(graph_new_connections),
        float(failed_auth_rate),
        float(conn_freq),
        float(bytes_sent_zscore),
        float(bytes_sent_log),
        float(bytes_ratio),
        float(conn_rate_zscore),
        float(dst_port_risk),
        float(is_new_destination),
        float(is_external_dst),
        float(hour_of_day_sin),
        float(hour_of_day_cos),
        float(cross_layer_match),
    ]

    # Validate vector
    assert len(vector) == ThreatClassifier.N_FEATURES, f"Vector length {len(vector)} != 15"
    return vector


def build_feature_matrix(
    events: List[UnifiedEvent],
    if_detector: IsolationForestDetector,
    profiler: BehavioralBaselineProfiler,
    failed_auth_rates: Dict[str, float]
) -> np.ndarray:
    """Build numeric feature matrix from events using fitted detector and profiler."""
    X = []
    for event in events:
        if_score = if_detector.predict(event)
        baseline_dev = profiler.compute_deviation_score(event)
        auth_rate = failed_auth_rates.get(event.event_id, 0.0)
        X.append(extract_features(event, if_score, baseline_dev, profiler, auth_rate))
    return np.asarray(X, dtype=np.float64)


def calculate_evaluation_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray],
    classes: List[str],
    inference_latency_ms: float = 0.0
) -> Dict[str, Any]:
    """
    Comprehensive, transparent evaluation metrics calculation without warning suppression.
    """
    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    precision_per_class, recall_per_class, f1_per_class, support_per_class = (
        precision_recall_fscore_support(y_true, y_pred, labels=classes, zero_division=0)
    )

    per_class_metrics = {}
    for i, cls_name in enumerate(classes):
        per_class_metrics[cls_name] = {
            "precision": float(precision_per_class[i]),
            "recall": float(recall_per_class[i]),
            "f1_score": float(f1_per_class[i]),
            "support": int(support_per_class[i]),
        }

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=classes)
    cm_dict = {
        row_cls: {col_cls: int(cm[i, j]) for j, col_cls in enumerate(classes)}
        for i, row_cls in enumerate(classes)
    }

    # False Positive Rate (FPR) on Benign class:
    # Definition: Benign traffic misclassified as attack / Total true benign samples
    fpr_benign = 0.0
    if "benign" in classes:
        benign_idx = classes.index("benign")
        benign_total = int(support_per_class[benign_idx])
        if benign_total > 0:
            false_positives = int(sum(cm[benign_idx, j] for j in range(len(classes)) if j != benign_idx))
            fpr_benign = float(false_positives / benign_total)

    # ROC-AUC (Multiclass OvR) if probabilities available
    roc_auc_val: Optional[float] = None
    if y_proba is not None and len(np.unique(y_true)) > 1:
        try:
            y_bin = label_binarize(y_true, classes=classes)
            if y_bin.shape[1] == y_proba.shape[1]:
                roc_auc_val = float(roc_auc_score(y_bin, y_proba, multi_class="ovr", average="macro"))
        except Exception:
            roc_auc_val = None

    return {
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "false_positive_rate_benign": fpr_benign,
        "fpr_definition": "Benign events misclassified as any attack / Total actual benign events",
        "roc_auc_macro_ovr": roc_auc_val,
        "inference_latency_ms": inference_latency_ms,
        "per_class": per_class_metrics,
        "confusion_matrix": cm_dict,
    }


def train_pipeline(
    data_source: Optional[str] = None,
    output_dir: Optional[str] = None,
    random_seed: int = 42
) -> Dict[str, Any]:
    """
    Execute reproducible, leak-free training and evaluation pipeline for AEGIS-ML.
    
    1. Loads dataset from specified source or default synthetic generator.
    2. Separates 80% train / 20% holdout test partitions BEFORE any fitting.
    3. Fits behavioral baselines and Isolation Forest strictly on train data.
    4. Evaluates Dummy baseline and candidate Random Forest models with CV.
    5. Evaluates selected model ONCE on the untouched holdout test partition.
    6. Persists models, metadata, and JSON evaluation report.
    """
    start_total = time.time()
    target_dir = Path(output_dir or MODEL_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)

    events: List[UnifiedEvent] = []

    # Source resolution
    if data_source:
        print(f"Loading configured dataset from {data_source}...")
        events, stats = load_flexible_dataset(data_source, random_seed=random_seed)
    else:
        # Check datasets directory first
        dataset_dir = PROJECT_ROOT / "datasets"
        if dataset_dir.exists() and list(dataset_dir.glob("*.csv")):
            print("Scanning real-world datasets in datasets/...")
            for csv_file in sorted(dataset_dir.glob("*.csv")):
                chunk, _ = load_flexible_dataset(str(csv_file), max_rows=2000, random_seed=random_seed)
                events.extend(chunk)
        else:
            default_path = PROJECT_ROOT / "data" / "raw" / "combined_labeled.jsonl"
            if not default_path.exists():
                print(f"Dataset not found at {default_path}. Generating synthetic scenario dataset...")
                from backend.data_generator.orchestrator import DataOrchestrator
                DataOrchestrator().training_mode(str(default_path))
            print(f"Loading dataset from {default_path}...")
            events, stats = load_flexible_dataset(str(default_path), random_seed=random_seed)

    print(f"Loaded a total of {len(events)} events for pipeline.")
    if not events:
        raise ValueError("No valid events could be loaded for training.")

    # Extract labels — prefer attack_type when populated; fall back to raw_label via DATASET_LABEL_MAP.
    # The synthetic dataset stores labels in raw_label (attack_type is None).
    unmapped_count = 0
    labels = []
    for e in events:
        if e.attack_type and e.attack_type in CANONICAL_CLASSES:
            labels.append(e.attack_type)
        elif e.raw_label:
            mapped = DATASET_LABEL_MAP.get(e.raw_label.strip().lower())
            if mapped and mapped in CANONICAL_CLASSES:
                labels.append(mapped)
            else:
                labels.append("benign")
                unmapped_count += 1
        else:
            labels.append("benign")
    if unmapped_count > 0:
        print(f"WARNING: {unmapped_count} events had unmapped labels — defaulted to 'benign'. Check DATASET_LABEL_MAP.")
    class_counts = Counter(labels)
    print(f"Class distribution before splitting: {dict(class_counts)}")

    # Check for rare classes (fewer than 2 instances cannot be stratified)
    can_stratify = all(c >= 2 for c in class_counts.values()) and len(class_counts) > 1
    if not can_stratify:
        print("WARNING: Rare classes with < 2 samples detected. Falling back to non-stratified split.")

    # 1. STRICT TRAIN/TEST SPLIT (80% train, 20% test)
    train_events, test_events, y_train, y_test = train_test_split(
        events,
        labels,
        test_size=0.20,
        stratify=labels if can_stratify else None,
        random_state=random_seed
    )
    print(f"Partition: {len(train_events)} Train events / {len(test_events)} Untouched Test events")
    print(f"Train class distribution: {dict(Counter(y_train))}")
    print(f"Test class distribution:  {dict(Counter(y_test))}")

    # 2. FIT PREPROCESSING & UNSUPERVISED DETECTORS STRICTLY ON TRAIN EVENTS
    print("\nFitting Behavioral Baseline Profiler on training set (benign only)...")
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(train_events, benign_only=True)
    profiler.save(str(target_dir / "entity_baselines.pkl"))
    print(f"Baselines built for {len(profiler.profiles)} entities.")

    print("Fitting Isolation Forest Detector on training set...")
    if_detector = IsolationForestDetector(random_state=random_seed)
    if_detector.fit(train_events)
    if_detector.save(
        net_path=str(target_dir / "isolation_forest_network.pkl"),
        end_path=str(target_dir / "isolation_forest_endpoint.pkl"),
    )
    print("Isolation Forest trained.")

    # 3. COMPUTE CAUSAL FAILED AUTH WINDOWS
    print("Computing causal failed-auth rates...")
    failed_auth_train = calculate_failed_auth_rate(train_events)
    failed_auth_test = calculate_failed_auth_rate(test_events)

    # 4. EXTRACT FEATURES
    print("Extracting feature matrices...")
    X_train = build_feature_matrix(train_events, if_detector, profiler, failed_auth_train)
    X_test = build_feature_matrix(test_events, if_detector, profiler, failed_auth_test)
    y_train_arr = np.array(y_train)
    y_test_arr = np.array(y_test)

    # 5. BASELINE BENCHMARK COMPARISON (Dummy Classifier)
    print("\n--- Evaluating Baseline Benchmark (Dummy Stratified Classifier) ---")
    dummy = DummyClassifier(strategy="stratified", random_state=random_seed)
    dummy.fit(X_train, y_train_arr)
    dummy_pred = dummy.predict(X_test)
    dummy_macro_f1 = f1_score(y_test_arr, dummy_pred, average="macro", zero_division=0)
    print(f"Dummy Classifier Macro F1: {dummy_macro_f1:.4f}")

    # 6. CANDIDATE MODEL EVALUATION WITH CROSS-VALIDATION
    print("\n--- Training Candidate Random Forest with Leak-Free CV ---")
    min_train_samples = min(Counter(y_train).values()) if len(Counter(y_train)) > 1 else 1
    n_splits = min(5, min_train_samples)

    candidate_rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        random_state=random_seed,
        class_weight="balanced"
    )

    cv_scores = []
    if n_splits > 1:
        # Check SMOTE feasibility within folds
        k_neighbors = min(5, max(1, min_train_samples - 1))
        try:
            smote = SMOTE(random_state=random_seed, k_neighbors=k_neighbors)
            pipeline = ImbPipeline([("smote", smote), ("clf", candidate_rf)])
            cv = StratifiedKFold(n_splits=n_splits)
            cv_scores = cross_val_score(pipeline, X_train, y_train_arr, cv=cv, scoring="f1_macro")
            print(f"Cross-Validation Macro F1 Scores across {n_splits} folds: {np.round(cv_scores, 4)}")
            print(f"Mean CV Macro F1: {np.mean(cv_scores):.4f} (std: {np.std(cv_scores):.4f})")
        except Exception as e:
            print(f"SMOTE CV skipped due to sample constraints ({e}); evaluating standard CV...")
            cv = StratifiedKFold(n_splits=n_splits)
            cv_scores = cross_val_score(candidate_rf, X_train, y_train_arr, cv=cv, scoring="f1_macro")
            print(f"Mean CV Macro F1: {np.mean(cv_scores):.4f}")

    # 7. FIT FINAL MODEL ON TRAINING SET
    print("\nFitting final Random Forest on training set...")
    # Apply SMOTE strictly to the training partition if appropriate
    if min_train_samples >= 2:
        try:
            smote = SMOTE(random_state=random_seed, k_neighbors=min(5, min_train_samples - 1))
            X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train_arr)
            print(f"Resampled training distribution: {dict(Counter(y_train_resampled))}")
        except Exception as e:
            print(f"SMOTE resampling skipped on train partition: {e}")
            X_train_resampled, y_train_resampled = X_train, y_train_arr
    else:
        X_train_resampled, y_train_resampled = X_train, y_train_arr

    classifier = ThreatClassifier(random_state=random_seed)
    classifier.fit(X_train_resampled, y_train_resampled)
    classifier_path = target_dir / "threat_classifier.pkl"
    classifier.save(str(classifier_path))

    # 8. EVALUATE ON UNTOUCHED TEST PARTITION
    print("\n" + "=" * 65)
    print("HOLDOUT TEST EVALUATION RESULTS (Evaluated ONCE on 20% unseen data)")
    print("=" * 65)

    t_inf_start = time.time()
    y_test_pred = classifier.model.predict(X_test)
    y_test_proba = classifier.model.predict_proba(X_test)
    inf_latency_ms = ((time.time() - t_inf_start) / max(len(X_test), 1)) * 1000.0

    eval_results = calculate_evaluation_metrics(
        y_true=y_test_arr,
        y_pred=y_test_pred,
        y_proba=y_test_proba,
        classes=classifier.CLASSES,
        inference_latency_ms=inf_latency_ms
    )

    print(f"Accuracy                 : {eval_results['accuracy']:.4f}")
    print(f"Balanced Accuracy        : {eval_results['balanced_accuracy']:.4f}")
    print(f"Macro F1 Score           : {eval_results['macro_f1']:.4f}")
    print(f"Weighted F1 Score        : {eval_results['weighted_f1']:.4f}")
    print(f"False Positive Rate (Benign): {eval_results['false_positive_rate_benign']:.4f}")
    print(f"Inference Latency        : {eval_results['inference_latency_ms']:.3f} ms / sample")
    print("\nPer-Class Classification Report:")
    print(classification_report(y_test_arr, y_test_pred, labels=classifier.CLASSES, zero_division=0))

    actual_header = "Actual \\ Pred"
    header = f"{actual_header:<22}" + "".join(f"{c[:10]:>12}" for c in classifier.CLASSES)
    print(header)
    for r_cls in classifier.CLASSES:
        row_str = f"{r_cls:<22}"
        for c_cls in classifier.CLASSES:
            val = eval_results["confusion_matrix"][r_cls][c_cls]
            row_str += f"{val:>12}"
        print(row_str)

    # 9. PERSIST MACHINE-READABLE JSON METRICS
    pipeline_report = {
        "timestamp": datetime.now().isoformat(),
        "random_seed": random_seed,
        "split_strategy": "80/20 train/test holdout" + (" (stratified)" if can_stratify else " (random)"),
        "total_events": len(events),
        "train_samples": len(train_events),
        "test_samples": len(test_events),
        "dummy_baseline_macro_f1": float(dummy_macro_f1),
        "cv_macro_f1_scores": [float(s) for s in cv_scores],
        "cv_macro_f1_mean": float(np.mean(cv_scores)) if len(cv_scores) > 0 else None,
        "test_metrics": eval_results,
        "dependencies": {
            "sklearn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
        "feature_names": ThreatClassifier.FEATURE_NAMES,
        "artifact_paths": {
            "threat_classifier": str(classifier_path),
            "isolation_forest_network": str(target_dir / "isolation_forest_network.pkl"),
            "isolation_forest_endpoint": str(target_dir / "isolation_forest_endpoint.pkl"),
            "entity_baselines": str(target_dir / "entity_baselines.pkl"),
        }
    }

    report_path = target_dir / "eval_results.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(pipeline_report, f, indent=2)
    print(f"\nMachine-readable metrics saved to {report_path}")

    return pipeline_report


def evaluate_pipeline(data_path: str, model_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate previously persisted models on an independent external dataset.
    """
    print(f"Loading external evaluation dataset from {data_path}...")
    events, stats = load_flexible_dataset(data_path)
    print(f"Loaded {len(events)} events for evaluation.")

    if not events:
        print("No valid events found for evaluation.")
        return {}

    mdir = Path(model_dir or MODEL_DIR)

    profiler = BehavioralBaselineProfiler()
    profiler.load(str(mdir / "entity_baselines.pkl"))

    if_detector = IsolationForestDetector()
    if_detector.load(
        net_path=str(mdir / "isolation_forest_network.pkl"),
        end_path=str(mdir / "isolation_forest_endpoint.pkl")
    )

    classifier = ThreatClassifier()
    loaded = classifier.load(str(mdir / "threat_classifier.pkl"))
    if not loaded:
        print(f"Classifier model could not be loaded from {mdir}. Please run train pipeline first.")
        return {}

    failed_auth_rates = calculate_failed_auth_rate(events)
    X = build_feature_matrix(events, if_detector, profiler, failed_auth_rates)
    # Same label extraction logic as train_pipeline — prefer attack_type then raw_label fallback
    extracted = []
    for e in events:
        if e.attack_type and e.attack_type in CANONICAL_CLASSES:
            extracted.append(e.attack_type)
        elif e.raw_label:
            mapped = DATASET_LABEL_MAP.get(e.raw_label.strip().lower())
            extracted.append(mapped if (mapped and mapped in CANONICAL_CLASSES) else "benign")
        else:
            extracted.append("benign")
    labels = np.array(extracted)

    t_start = time.time()
    y_pred = classifier.model.predict(X)
    y_proba = classifier.model.predict_proba(X)
    latency_ms = ((time.time() - t_start) / max(len(X), 1)) * 1000.0

    results = calculate_evaluation_metrics(
        y_true=labels,
        y_pred=y_pred,
        y_proba=y_proba,
        classes=classifier.CLASSES,
        inference_latency_ms=latency_ms
    )

    print("\n" + "=" * 65)
    print(f"EXTERNAL EVALUATION REPORT: {data_path}")
    print("=" * 65)
    print(f"Accuracy         : {results['accuracy']:.4f}")
    print(f"Balanced Accuracy: {results['balanced_accuracy']:.4f}")
    print(f"Macro F1         : {results['macro_f1']:.4f}")
    print(f"Weighted F1      : {results['weighted_f1']:.4f}")
    print(f"FPR (Benign)     : {results['false_positive_rate_benign']:.4f}")
    print("\nClassification Report:")
    print(classification_report(labels, y_pred, labels=classifier.CLASSES, zero_division=0))

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "train":
            src = sys.argv[2] if len(sys.argv) > 2 else None
            train_pipeline(data_source=src)
        elif cmd == "evaluate" and len(sys.argv) > 2:
            evaluate_pipeline(sys.argv[2])
        else:
            print("Usage: python -m backend.detection.model_trainer [train [data_path] | evaluate <data_path>]")
    else:
        train_pipeline()
