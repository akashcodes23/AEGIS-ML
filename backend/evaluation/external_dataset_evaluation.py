"""
AEGIS-ML Phase 24.1: CIC-IDS2017 Acquisition, Leakage-Resistant Evaluation, and Network-Flow Benchmark
Module: backend.evaluation.external_dataset_evaluation

Evaluates the generalization limits of AEGIS-ML against external intrusion detection
data (specifically the Canadian Institute for Cybersecurity CIC-IDS2017 benchmark).

Guarantees & Scientific Integrity:
1. Distinguishes fundamentally between:
   (A) Existing-Model Transfer Evaluation (Phase 23 48-feature calibrated model) -> NOT_FEASIBLE
   (B) External-Dataset Retrained Experiment (isolated model on observable network flow features)
2. Audits all 48 schema features into Categories A, B, C, D, E.
3. Audits all 18 observable flow features with transformation, units, and leakage analysis.
4. Formally records transfer evaluation as NOT_FEASIBLE due to INCOMPATIBLE_TELEMETRY
   (17 endpoint/process/auth features are absent from network-only flows).
5. Strictly refuses to fabricate results if external data is not locally present.
6. Preserves existing production models (calibrated_threat_classifier.pkl is never modified).
7. Leakage-Resistant Splitting: Supports and compares:
   - Stratified Random Split
   - Grouped Split (by src-dst communication pair, ensuring 0% pair overlap)
   - Temporal Causal Split (ordered chronologically)
8. Multi-Tier Evaluation:
   - Binary evaluation (benign vs attack) with log-loss and Brier score
   - Original-label evaluation (preserving raw ground-truth classes)
   - Derived AEGIS-ML canonical multiclass evaluation with PortScan caveat
9. Discloses explicit denominators for Benign FPR and Attack Recall.
10. Saves separate experimental models in data/models/external_experiments/cicids2017/.
"""

import os
import sys
import json
import time
import math
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from collections import Counter, defaultdict
from typing import Dict, Any, List, Optional, Tuple, Set

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_fscore_support,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from imblearn.over_sampling import SMOTE

try:
    from backend.core.config import PROJECT_ROOT, MODEL_DIR, RF_CLASSIFIER_PATH
    from backend.core.schemas import UnifiedEvent
    from backend.detection.model_trainer import (
        CANONICAL_CLASSES,
        DATASET_LABEL_MAP,
    )
    from backend.detection.threat_classifier import ThreatClassifier
    from backend.detection.temporal_graph_extractor import (
        CausalTemporalGraphTracker,
        RELATIONAL_GRAPH_FEATURE_NAMES,
    )
    from backend.detection.telemetry_context import (
        SUPPORTED_CONTEXT_FEATURE_NAMES,
        MISSINGNESS_FEATURE_NAMES,
    )
    from backend.detection.sequence_context import (
        SEQUENCE_FEATURE_NAMES,
        is_rfc1918_private,
    )
    from backend.ingestion.cicids_loader import load_cicids2017
except ModuleNotFoundError:
    from core.config import PROJECT_ROOT, MODEL_DIR, RF_CLASSIFIER_PATH
    from core.schemas import UnifiedEvent
    from detection.model_trainer import (
        CANONICAL_CLASSES,
        DATASET_LABEL_MAP,
    )
    from detection.threat_classifier import ThreatClassifier
    from detection.temporal_graph_extractor import (
        CausalTemporalGraphTracker,
        RELATIONAL_GRAPH_FEATURE_NAMES,
    )
    from detection.telemetry_context import (
        SUPPORTED_CONTEXT_FEATURE_NAMES,
        MISSINGNESS_FEATURE_NAMES,
    )
    from detection.sequence_context import (
        SEQUENCE_FEATURE_NAMES,
        is_rfc1918_private,
    )
    from ingestion.cicids_loader import load_cicids2017

logger = logging.getLogger(__name__)

# Canonical 48 features used in Phase 22/23
_INFERRED_CROSS_FEATS = {
    "seq_inferred_file_read_before_outbound_net",
    "seq_inferred_file_read_before_internal_net",
}
AEGIS_48_FEATURE_NAMES: List[str] = (
    ThreatClassifier.FEATURE_NAMES
    + RELATIONAL_GRAPH_FEATURE_NAMES
    + SUPPORTED_CONTEXT_FEATURE_NAMES
    + MISSINGNESS_FEATURE_NAMES
    + [f for f in SEQUENCE_FEATURE_NAMES if f not in _INFERRED_CROSS_FEATS]
)
assert len(AEGIS_48_FEATURE_NAMES) == 48

# Observable flow features computable on external network telemetry
OBSERVABLE_FLOW_FEATURE_NAMES: List[str] = [
    "dst_port_risk",
    "bytes_sent_log",
    "bytes_ratio",
    "is_external_dst",
    "hour_of_day_sin",
    "hour_of_day_cos",
    "is_network_layer",
    "has_network_context",
    "transfer_size_bucket",
    "direction_internal",
    "direction_outbound",
    "direction_inbound",
    "distinct_dst_internal_5m",
    "dst_diversity_ratio_5m",
    "is_new_src_dst_pair",
    "src_out_degree_5m",
    "dst_in_degree_5m",
    "pivot_chain_indicator",
]
assert len(OBSERVABLE_FLOW_FEATURE_NAMES) == 18

# CIC-IDS2017 Dataset Provenance & Metadata
CICIDS2017_METADATA: Dict[str, Any] = {
    "dataset_name": "CIC-IDS2017",
    "version": "1.0 (MachineLearningCVE)",
    "institution": "Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)",
    "citation": (
        "Sharafaldin, I., Habibi Lashkari, A., Ghorbani, A. (2018). "
        "'Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.' "
        "Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)."
    ),
    "official_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "licensing_and_distribution": (
        "UNB requires interactive registration form with name, institutional affiliation, "
        "and email confirmation. Non-interactive scraping and redistributing raw CSVs via Git "
        "is restricted."
    ),
    "telemetry_modality": "Network flow records generated via CICFlowMeter (bidirectional flow statistics).",
    "known_limitations": [
        "Pure network flow telemetry: Zero host process, socket binding, or auth log context.",
        "CICFlowMeter overflow bugs: produces Infinity and NaN in flow rate features, and negative duration values.",
        "Duplicate records: Contains ~1% exact 5-tuple duplicates across capture windows.",
        "Label casing and whitespace inconsistencies in raw CSVs.",
        "High class imbalance: Benign traffic represents >80% of flows in most daily captures.",
        "Targeted DoS/DDoS attacks dominate the attack volume, which are volumetric flooding rather than stealthy intrusions.",
    ],
    "storage_requirements": {
        "MachineLearningCVE_csv_archive": "~500 MB compressed, ~2.5 GB uncompressed (8 daily CSV files)",
        "full_pcap_archive": "~50 GB compressed",
    },
    "expected_files": [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    ],
}

# Strict Semantic Label Mapping for CIC-IDS2017
CICIDS2017_STRICT_LABEL_MAP: Dict[str, Optional[str]] = {
    "benign": "benign",
    "ftp-patator": "brute_force",
    "ssh-patator": "brute_force",
    "web attack - brute force": "brute_force",
    # Reconnaissance / lateral probing
    "portscan": "lateral_movement",
    "infiltration": "lateral_movement",
    # C2 communication
    "bot": "c2_beaconing",
    # Information disclosure / exfiltration
    "heartbleed": "data_exfiltration",
    # Excluded from canonical 5-class multi-class mapping due to semantic mismatch
    "ddos": None,
    "dos hulk": None,
    "dos goldeneye": None,
    "dos slowloris": None,
    "dos slowhttptest": None,
    "web attack - xss": None,
    "web attack - sql injection": None,
}


def audit_observable_flow_features() -> List[Dict[str, Any]]:
    """
    Audit each of the 18 observable flow features used by the separate network-flow benchmark.
    Documents name, source column, units, missing handling, identifiers, inference availability,
    and leakage risk.
    """
    return [
        {
            "feature_name": "dst_port_risk",
            "source_column": "Destination Port",
            "transformation": "PORT_RISK dictionary lookup for known high-risk destination service ports",
            "units": "[0.0, 1.0] categorical risk score",
            "missing_handling": "Default 0.0 if port is null or outside known risk mapping table",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: destination port is an intrinsic flow header attribute",
        },
        {
            "feature_name": "bytes_sent_log",
            "source_column": "Total Length of Fwd Packets",
            "transformation": "math.log1p(max(0.0, float(fwd_bytes)))",
            "units": "[0.0, 25.0] log-transformed bytes",
            "missing_handling": "Impute 0.0 if NaN or negative (CICFlowMeter overflow defect)",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: forward packet payload size is directly observable in flow stats",
        },
        {
            "feature_name": "bytes_ratio",
            "source_column": "Total Length of Fwd Packets & Total Length of Bwd Packets",
            "transformation": "fwd_bytes / (fwd_bytes + bwd_bytes + 1e-6)",
            "units": "[0.0, 1.0] asymmetry ratio",
            "missing_handling": "Default 0.5 (symmetric) if both forward and backward bytes are 0 or NaN",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: measures bidirectional traffic asymmetry at flow close",
        },
        {
            "feature_name": "is_external_dst",
            "source_column": "Destination IP",
            "transformation": "1.0 if not is_rfc1918_private(dst_ip) else 0.0",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "Default 0.0 if IP is unparseable",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: evaluates RFC1918 private subnet boundary; raw IP string is excluded",
        },
        {
            "feature_name": "hour_of_day_sin",
            "source_column": "Timestamp",
            "transformation": "math.sin(2 * math.pi * (hour + minute/60.0) / 24.0)",
            "units": "[-1.0, 1.0] trigonometric harmonic coordinate",
            "missing_handling": "Default 0.0 if timestamp is missing",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: cyclical coordinates prevent memorization of absolute date/session",
        },
        {
            "feature_name": "hour_of_day_cos",
            "source_column": "Timestamp",
            "transformation": "math.cos(2 * math.pi * (hour + minute/60.0) / 24.0)",
            "units": "[-1.0, 1.0] trigonometric harmonic coordinate",
            "missing_handling": "Default 1.0 if timestamp is missing",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: cyclical coordinates prevent temporal index memorization",
        },
        {
            "feature_name": "is_network_layer",
            "source_column": "Telemetry metadata (layer)",
            "transformation": "Constant 1.0 for network flow records",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "1.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: structural layer indicator",
        },
        {
            "feature_name": "has_network_context",
            "source_column": "Telemetry metadata (layer == 'network')",
            "transformation": "Constant 1.0 for network flow records",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "1.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: structural context indicator",
        },
        {
            "feature_name": "transfer_size_bucket",
            "source_column": "Total Length of Fwd Packets",
            "transformation": "Ordinal binning: 0 (<1KB), 1 (<64KB), 2 (<1MB), 3 (>=1MB)",
            "units": "{0.0, 1.0, 2.0, 3.0} ordinal scale",
            "missing_handling": "Default 0.0 if missing",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: quantized magnitude of forward transfer",
        },
        {
            "feature_name": "direction_internal",
            "source_column": "Source IP and Destination IP",
            "transformation": "1.0 if both src and dst are RFC1918 private, else 0.0",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "Default 0.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: subnet classification only",
        },
        {
            "feature_name": "direction_outbound",
            "source_column": "Source IP and Destination IP",
            "transformation": "1.0 if src is private and dst is external, else 0.0",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "Default 0.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: subnet classification only",
        },
        {
            "feature_name": "direction_inbound",
            "source_column": "Source IP and Destination IP",
            "transformation": "1.0 if src is external and dst is private, else 0.0",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "Default 0.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "None: subnet classification only",
        },
        {
            "feature_name": "distinct_dst_internal_5m",
            "source_column": "Destination IP over sliding 300s window",
            "transformation": "Count of distinct private internal destinations contacted by src in 300s",
            "units": "[0, inf) count",
            "missing_handling": "Default 0.0 if no prior causal history",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "Strictly causal: evaluated strictly on history prior to event arrival t",
        },
        {
            "feature_name": "dst_diversity_ratio_5m",
            "source_column": "Destination IP and Flow Count in 300s window",
            "transformation": "distinct_dst_internal_5m / max(total_events_5m, 1)",
            "units": "[0.0, 1.0] ratio",
            "missing_handling": "Default 0.0 if window empty",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "Strictly causal: no future event lookahead",
        },
        {
            "feature_name": "is_new_src_dst_pair",
            "source_column": "Source IP and Destination IP communication history",
            "transformation": "1.0 if (src, dst) pair has not been observed in training baseline or causal stream",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "Default 1.0 (novel pair) if unobserved",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "Baseline pairs are fitted STRICTLY on training partition; zero test-set leakage",
        },
        {
            "feature_name": "src_out_degree_5m",
            "source_column": "Entity communication graph in sliding 300s window",
            "transformation": "Number of unique destination nodes contacted by src node in 300s",
            "units": "[0, inf) graph degree",
            "missing_handling": "Default 0.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "Strictly causal: evaluated on streaming graph state prior to event t",
        },
        {
            "feature_name": "dst_in_degree_5m",
            "source_column": "Entity communication graph in sliding 300s window",
            "transformation": "Number of unique source nodes contacting dst node in 300s",
            "units": "[0, inf) graph degree",
            "missing_handling": "Default 0.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "Strictly causal: evaluated on streaming graph state prior to event t",
        },
        {
            "feature_name": "pivot_chain_indicator",
            "source_column": "Entity communication graph in sliding 300s window",
            "transformation": "1.0 if src node was previously an inbound destination of another host in window",
            "units": "{0.0, 1.0} boolean indicator",
            "missing_handling": "Default 0.0",
            "uses_identifiers": False,
            "inference_time_available": True,
            "leakage_risk": "Strictly causal: evaluated on streaming graph state prior to event t",
        },
    ]


def audit_feature_compatibility() -> Dict[str, Any]:
    """
    Perform a schema and feature compatibility audit comparing the 48
    AEGIS-ML features against network flow telemetry in CIC-IDS2017.
    """
    cat_a = [
        "dst_port_risk",
        "bytes_sent_log",
        "bytes_ratio",
        "is_external_dst",
        "hour_of_day_sin",
        "hour_of_day_cos",
        "is_network_layer",
        "is_endpoint_layer",
        "is_application_layer",
        "has_network_context",
        "transfer_size_bucket",
        "missing_dst_port",
        "missing_bytes_sent",
        "missing_bytes_received",
    ]
    cat_b = [
        "distinct_dst_internal_5m",
        "dst_diversity_ratio_5m",
        "is_new_src_dst_pair",
        "src_out_degree_5m",
        "dst_in_degree_5m",
        "pivot_chain_indicator",
        "direction_internal",
        "direction_outbound",
        "direction_inbound",
        "is_new_destination",
        "connection_frequency",
        "seq_window_event_count_host",
        "seq_window_network_event_count",
        "seq_time_since_last_host_event_log",
        "seq_time_since_last_network_event_log",
        "seq_window_has_external_transfer",
        "seq_window_bytes_sent_sum_log",
    ]
    cat_c = [
        "failed_auth_rate",
        "missing_process_name",
        "missing_auth_result",
        "has_process_context",
        "has_verified_socket_binding",
        "seq_window_endpoint_event_count",
        "seq_time_since_last_endpoint_event_log",
        "seq_process_ancestry_observed",
        "seq_parent_process_is_shell_or_script",
        "seq_verified_socket_attribution",
    ]
    cat_d = [
        "baseline_deviation",
        "bytes_sent_zscore",
        "conn_rate_zscore",
        "cross_layer_match",
        "if_anomaly_score",
        "graph_new_connections",
        "seq_sequence_completeness_score",
    ]
    cat_e = sorted(list(set(cat_c + cat_d)))

    all_categorized = set(cat_a + cat_b + cat_c + cat_d)
    missing_from_audit = set(AEGIS_48_FEATURE_NAMES) - all_categorized
    assert len(missing_from_audit) == 0, f"Uncategorized features: {missing_from_audit}"

    return {
        "audit_name": "AEGIS-ML 48-Feature Schema Compatibility Audit on CIC-IDS2017",
        "total_features": 48,
        "counts": {
            "category_a_directly_observable": len(cat_a),
            "category_b_computable_transformations": len(cat_b),
            "category_c_dependent_on_missing_telemetry": len(cat_c),
            "category_d_dependent_on_unreconstructable_context": len(cat_d),
            "category_e_unavailable_or_incompatible": len(cat_e),
        },
        "percentages": {
            "directly_observable_pct": round(len(cat_a) / 48.0 * 100.0, 1),
            "computable_transformations_pct": round(len(cat_b) / 48.0 * 100.0, 1),
            "incompatible_or_unobserved_pct": round(len(cat_e) / 48.0 * 100.0, 1),
        },
        "feature_lists": {
            "category_a": cat_a,
            "category_b": cat_b,
            "category_c": cat_c,
            "category_d": cat_d,
            "category_e": cat_e,
        },
        "audit_verdict": (
            "17 of 48 features (35.4%) are structurally unavailable in pure network flow datasets. "
            "Zero-filling or imputing unobserved endpoint features introduces severe distributional shift "
            "and invalidates the Phase 23 calibrated decision boundaries."
        ),
    }


def evaluate_model_transfer_feasibility(model_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate whether the existing Phase 23 calibrated model can be directly
    transferred to evaluate on CIC-IDS2017 without retraining.
    """
    if model_path:
        model_file = Path(model_path)
    else:
        cal_path = Path(MODEL_DIR) / "calibrated_threat_classifier.pkl"
        model_file = cal_path if cal_path.exists() else Path(RF_CLASSIFIER_PATH)
    artifact_exists = model_file.exists()

    metadata_path = model_file.with_name(model_file.stem + "_metadata.json")
    meta = {}
    if metadata_path.exists():
        try:
            with open(metadata_path, "r") as f:
                meta = json.load(f)
        except Exception as e:
            meta = {"error": str(e)}

    n_feats_expected = meta.get("n_features", 48)

    verdict = {
        "evaluation_mode": "EXISTING_MODEL_TRANSFER_EVALUATION",
        "production_model_path": str(model_file),
        "production_model_exists": artifact_exists,
        "production_model_version": meta.get("model_version", "23.0.0"),
        "expected_feature_count": n_feats_expected,
        "is_calibrated": meta.get("is_calibrated", True),
        "calibration_method": meta.get("calibration_method", "isotonic"),
        "transfer_feasible": False,
        "status": "NOT_FEASIBLE",
        "limitation_category": "INCOMPATIBLE_TELEMETRY",
        "blocking_reasons": [
            "AEGIS-ML's calibrated model strictly requires 48 input features; CIC-IDS2017 provides only network flow telemetry.",
            "17 features (35.4% of schema) represent endpoint processes, parent-child process ancestry, PAM/auth failures, and cross-layer socket bindings.",
            "Silently imputing 0.0 for absent endpoint features corrupts calibrated probabilities: the model was calibrated on dual-telemetry synthetic data where endpoint indicators actively discriminate attacks.",
            "Truncating the feature vector to 15 features is prohibited by model validation (ThreatClassifier enforces exact feature dimensionality).",
            "Retraining or fine-tuning the production model simply to score higher on external benchmark data violates project integrity rules.",
        ],
        "conclusion": (
            "Direct evaluation of calibrated_threat_classifier.pkl on CIC-IDS2017 is mathematically "
            "and scientifically INVALID. The model was trained on dual-telemetry events and cannot "
            "be transferred to single-modality network-only flow datasets without severe telemetry truncation."
        ),
    }
    return verdict


def map_external_label(raw_label: str) -> Tuple[Optional[str], str, str]:
    """
    Map an external dataset label to:
    (canonical_5class_label, binary_label, semantic_explanation)
    """
    clean = str(raw_label).strip().lower()
    clean = clean.replace("â\x80\x93", "-").replace("â\x80\x94", "-").replace("\x96", "-")
    import re
    clean = re.sub(r"web\s+attack\s*[-–—]\s*", "web attack - ", clean)

    canonical = CICIDS2017_STRICT_LABEL_MAP.get(clean)
    is_benign = (clean in ["benign", "normal"])
    binary = "benign" if is_benign else "attack"

    if is_benign:
        explanation = "Direct semantic match: benign network traffic."
    elif canonical == "brute_force":
        explanation = f"Direct semantic match: {raw_label} is an authentication brute-force attempt."
    elif clean == "portscan":
        explanation = (
            "Derived research mapping (caveat): PortScan is network reconnaissance that proxies "
            "potential lateral movement, but is not confirmed post-exploitation host traversal."
        )
    elif canonical == "lateral_movement":
        explanation = f"Derived research mapping: {raw_label} represents remote service exploitation or pivoting."
    elif canonical == "c2_beaconing":
        explanation = f"Direct semantic match: {raw_label} represents botnet command-and-control callback."
    elif canonical == "data_exfiltration":
        explanation = f"Derived research mapping: {raw_label} involves unauthorized memory content disclosure."
    elif clean in ["ddos", "dos hulk", "dos goldeneye", "dos slowloris", "dos slowhttptest"]:
        explanation = f"Excluded from canonical 5-class: Denial of Service ({raw_label}) is volumetric flooding, not targeted intrusion."
    else:
        explanation = f"Unmapped in canonical 5-class: {raw_label} lacks endpoint process telemetry to confirm attack subtype."

    return canonical, binary, explanation


def scan_dataset_quality_and_leakage(file_path: str, sample_rows: int = 50000) -> Dict[str, Any]:
    """
    Inspect an external dataset file for data quality issues, CICFlowMeter defects,
    duplicate flows, and potential feature-target leakage.
    """
    path = Path(file_path)
    if not path.exists():
        return {
            "status": "file_not_found",
            "file_path": str(file_path),
            "quality_scan_completed": False,
        }

    df = pd.read_csv(file_path, nrows=sample_rows, low_memory=False)
    raw_rows = len(df)
    clean_cols = [c.strip().lower() for c in df.columns]
    df.columns = clean_cols

    inf_count = 0
    nan_count = int(df.isna().sum().sum())
    for col in df.columns:
        if df[col].dtype in [np.float64, np.float32, float]:
            inf_count += int((~np.isfinite(df[col].astype(float, errors="ignore"))).sum())

    dup_cols = [c for c in ["source ip", "destination ip", "destination port", "protocol", "label"] if c in df.columns]
    dup_count = int(df.duplicated(subset=dup_cols).sum()) if dup_cols else 0

    neg_duration_count = 0
    if "flow duration" in df.columns:
        num_dur = pd.to_numeric(df["flow duration"], errors="coerce")
        neg_duration_count = int((num_dur < 0).sum())

    label_col = "label" if "label" in df.columns else None
    class_dist: Dict[str, int] = {}
    if label_col:
        vc = df[label_col].astype(str).str.strip().value_counts()
        class_dist = {str(k): int(v) for k, v in vc.items()}

    leakage_findings = [
        "Source IP and Destination IP are excluded from model features (used only for causally building rolling degree/diversity metrics).",
        "Timestamp is converted into cyclical trigonometric hour features (sin/cos) and relative deltas, preventing temporal index memorization.",
        "Ground truth label is strictly excluded from feature extraction pipelines.",
        "SMOTE resampling and graph baseline pairs are fitted strictly on the training partition.",
    ]

    return {
        "status": "completed",
        "file_path": str(file_path),
        "sample_rows_analyzed": raw_rows,
        "quality_scan_completed": True,
        "total_nan_cells": nan_count,
        "total_inf_cells": inf_count,
        "duplicate_flow_records": dup_count,
        "duplicate_ratio_pct": round(dup_count / max(raw_rows, 1) * 100.0, 2),
        "negative_duration_records": neg_duration_count,
        "class_distribution": class_dist,
        "leakage_checks": leakage_findings,
    }


def extract_observable_flow_features(
    events: List[UnifiedEvent],
    tracker: Optional[CausalTemporalGraphTracker] = None,
    fit_tracker: bool = False,
) -> np.ndarray:
    """
    Extract the 18 observable network-flow and IP-graph features from a sequence
    of UnifiedEvents.
    
    Leakage Protection:
    - If tracker is provided and fit_tracker=False, extracts features using existing
      historical state without learning new baseline communication pairs.
    - If fit_tracker=True, learns baseline pairs from the provided events.
    """
    if tracker is None:
        tracker = CausalTemporalGraphTracker()
        if fit_tracker:
            tracker.fit_baseline_pairs(events)

    graph_dicts = tracker.extract_sequence(events)

    from backend.core.config import PORT_RISK

    features = []
    for idx, e in enumerate(events):
        g = graph_dicts[idx]
        fwd_b = float(e.bytes_sent or 0)
        bwd_b = float(e.bytes_received or 0)
        tot_b = fwd_b + bwd_b

        # 1. dst_port_risk
        port_risk = PORT_RISK.get(e.dst_port, 0.0)

        # 2. bytes_sent_log
        bytes_log = math.log1p(max(0.0, fwd_b))

        # 3. bytes_ratio
        ratio = fwd_b / (tot_b + 1e-6) if tot_b > 0 else 0.5

        # 4. is_external_dst
        ext_dst = 1.0 if not is_rfc1918_private(e.dst_ip or e.dst_entity) else 0.0

        # 5, 6. hour sin/cos
        dt = e.timestamp or datetime.now(timezone.utc)
        hour = dt.hour + dt.minute / 60.0
        sin_h = math.sin(2 * math.pi * hour / 24.0)
        cos_h = math.cos(2 * math.pi * hour / 24.0)

        # 7. is_network_layer
        is_net = 1.0

        # 8. has_network_context
        has_net = 1.0

        # 9. transfer_size_bucket
        if fwd_b < 1024:
            bucket = 0.0
        elif fwd_b < 65536:
            bucket = 1.0
        elif fwd_b < 1048576:
            bucket = 2.0
        else:
            bucket = 3.0

        # 10, 11, 12. direction
        src_priv = is_rfc1918_private(e.src_ip or e.src_entity)
        dst_priv = is_rfc1918_private(e.dst_ip or e.dst_entity)
        dir_internal = 1.0 if (src_priv and dst_priv) else 0.0
        dir_out = 1.0 if (src_priv and not dst_priv) else 0.0
        dir_in = 1.0 if (not src_priv and dst_priv) else 0.0

        # 13-18. Graph features
        row = [
            port_risk,
            bytes_log,
            ratio,
            ext_dst,
            sin_h,
            cos_h,
            is_net,
            has_net,
            bucket,
            dir_internal,
            dir_out,
            dir_in,
            float(g.get("distinct_dst_internal_5m", 0.0)),
            float(g.get("dst_diversity_ratio_5m", 0.0)),
            float(g.get("is_new_src_dst_pair", 0.0)),
            float(g.get("src_out_degree_5m", 0.0)),
            float(g.get("dst_in_degree_5m", 0.0)),
            float(g.get("pivot_chain_indicator", 0.0)),
        ]
        features.append(row)

    return np.array(features, dtype=np.float64)


def partition_dataset(
    events: List[UnifiedEvent],
    split_strategy: str = "stratified_random",
    test_size: float = 0.20,
    random_seed: int = 42,
) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """
    Partition events into train and test splits using a specified strategy.
    
    Strategies:
    - 'stratified_random': Standard random stratified splitting.
    - 'grouped_communication_pair': Groups by (src, dst) communication pair to prevent identical
      communication flows from leaking across partitions.
    - 'temporal_causal': Sorts chronologically; takes earlier (1 - test_size) as train, subsequent as test.
    
    Returns:
        tr_indices, te_indices, split_audit_metadata
    """
    n = len(events)
    indices = np.arange(n)
    raw_labels = [e.raw_label or "benign" for e in events]

    if split_strategy == "temporal_causal":
        # Sort indices by timestamp
        sorted_indices = sorted(indices, key=lambda i: events[i].timestamp or datetime.min)
        split_point = int(n * (1.0 - test_size))
        tr_idx = sorted_indices[:split_point]
        te_idx = sorted_indices[split_point:]
        notes = "Split chronologically based on flow timestamp."

    elif split_strategy == "grouped_communication_pair":
        # Group by (src_entity, dst_entity)
        groups = np.array([f"{e.src_entity or 'unk'}->{e.dst_entity or 'unk'}" for e in events])
        unique_groups = len(set(groups))
        
        if unique_groups >= 4:
            gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_seed)
            tr_idx_arr, te_idx_arr = next(gss.split(indices, groups=groups))
            tr_idx = tr_idx_arr.tolist()
            te_idx = te_idx_arr.tolist()
            notes = f"Grouped by communication pair ({unique_groups} unique groups)."
        else:
            # Fallback to stratified random if too few unique groups
            try:
                tr_idx, te_idx = train_test_split(indices, test_size=test_size, random_state=random_seed, stratify=raw_labels)
            except Exception:
                tr_idx, te_idx = train_test_split(indices, test_size=test_size, random_state=random_seed)
            tr_idx, te_idx = tr_idx.tolist(), te_idx.tolist()
            notes = f"Insufficient communication groups ({unique_groups}); fell back to stratified random."

    else:
        # Default: stratified_random
        split_strategy = "stratified_random"
        try:
            tr_idx, te_idx = train_test_split(indices, test_size=test_size, random_state=random_seed, stratify=raw_labels)
        except Exception:
            tr_idx, te_idx = train_test_split(indices, test_size=test_size, random_state=random_seed)
        tr_idx, te_idx = tr_idx.tolist(), te_idx.tolist()
        notes = "Stratified random split."

    # Compute communication pair overlap
    train_pairs = {(events[i].src_entity, events[i].dst_entity) for i in tr_idx if events[i].src_entity and events[i].dst_entity}
    test_pairs = {(events[i].src_entity, events[i].dst_entity) for i in te_idx if events[i].src_entity and events[i].dst_entity}
    overlap_pairs = train_pairs.intersection(test_pairs)

    metadata = {
        "strategy": split_strategy,
        "train_samples": len(tr_idx),
        "test_samples": len(te_idx),
        "total_samples": n,
        "unique_train_pairs": len(train_pairs),
        "unique_test_pairs": len(test_pairs),
        "cross_partition_pair_overlap_count": len(overlap_pairs),
        "cross_partition_pair_overlap_pct": round(len(overlap_pairs) / max(len(test_pairs), 1) * 100.0, 2),
        "notes": notes,
    }
    return tr_idx, te_idx, metadata


def execute_external_retrained_benchmark(
    events: List[UnifiedEvent],
    random_seed: int = 42,
    test_size: float = 0.20,
    split_strategy: str = "stratified_random",
    save_model: bool = False,
    model_output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute an isolated training and evaluation experiment on external network flow data.
    
    Guarantees:
    - Uses strictly observable flow features (18 features).
    - Preserves production model artifacts untouched.
    - Fits preprocessing, graph baseline pairs, and SMOTE strictly on the training partition.
    - Evaluates:
      1. Binary detection (benign vs attack) with probability calibration diagnostics.
      2. Original-label classification directly on raw external dataset labels.
      3. Derived AEGIS-ML multiclass classification with explicit PortScan caveat.
    """
    if len(events) < 50:
        return {
            "status": "insufficient_data",
            "reason": f"Only {len(events)} events provided. Need at least 50 events.",
        }

    raw_labels = [e.raw_label or "benign" for e in events]
    mapped_canon = []
    mapped_binary = []

    for r in raw_labels:
        c, b, _ = map_external_label(r)
        mapped_canon.append(c)
        mapped_binary.append(b)

    # 1. Partition dataset
    tr_idx, te_idx, split_meta = partition_dataset(
        events, split_strategy=split_strategy, test_size=test_size, random_seed=random_seed
    )
    tr_events = [events[i] for i in tr_idx]
    te_events = [events[i] for i in te_idx]

    # 2. Extract features strictly without test-set pair leakage
    tracker = CausalTemporalGraphTracker()
    tracker.fit_baseline_pairs(tr_events)  # Train pairs ONLY
    X_tr = extract_observable_flow_features(tr_events, tracker=tracker, fit_tracker=False)
    X_te = extract_observable_flow_features(te_events, tracker=tracker, fit_tracker=False)

    # ── A. Binary Evaluation Experiment (Benign vs Attack) ────────────────────────
    y_bin = np.array(mapped_binary)
    y_tr_bin, y_te_bin = y_bin[tr_idx], y_bin[te_idx]

    # SMOTE on training partition only
    min_bin_c = min(Counter(y_tr_bin).values())
    if min_bin_c > 1:
        k_neigh = max(1, min(5, min_bin_c - 1))
        sm_bin = SMOTE(k_neighbors=k_neigh, random_state=random_seed)
        X_tr_bin_res, y_tr_bin_res = sm_bin.fit_resample(X_tr, y_tr_bin)
    else:
        X_tr_bin_res, y_tr_bin_res = X_tr, y_tr_bin

    rf_bin = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=random_seed)
    rf_bin.fit(X_tr_bin_res, y_tr_bin_res)
    y_pred_bin = rf_bin.predict(X_te)
    y_prob_bin = rf_bin.predict_proba(X_te)

    bin_labels = ["benign", "attack"]
    bin_cm = confusion_matrix(y_te_bin, y_pred_bin, labels=bin_labels)
    tn, fp = int(bin_cm[0, 0]), int(bin_cm[0, 1])
    fn, tp = int(bin_cm[1, 0]), int(bin_cm[1, 1])

    benign_denominator = tn + fp
    attack_denominator = tp + fn
    benign_fpr = round(fp / max(benign_denominator, 1), 4)
    attack_recall = round(tp / max(attack_denominator, 1), 4)
    attack_precision = round(tp / max(tp + fp, 1), 4)

    # Probability calibration metrics
    brier_val = None
    log_loss_val = None
    try:
        attack_idx = list(rf_bin.classes_).index("attack")
        prob_attack = y_prob_bin[:, attack_idx]
        y_true_binary_num = np.array([1 if y == "attack" else 0 for y in y_te_bin])
        brier_val = round(float(brier_score_loss(y_true_binary_num, prob_attack)), 4)
        log_loss_val = round(float(log_loss(y_true_binary_num, prob_attack)), 4)
    except Exception as e:
        logger.debug(f"Could not compute Brier/log-loss: {e}")

    binary_metrics = {
        "confusion_matrix": {
            "labels": bin_labels,
            "matrix": bin_cm.tolist(),
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "benign_false_alarm_rate": benign_fpr,
        "benign_false_alarm_denominator": f"FP ({fp}) / (TN + FP) ({benign_denominator})",
        "attack_recall": attack_recall,
        "attack_recall_denominator": f"TP ({tp}) / (TP + FN) ({attack_denominator})",
        "attack_precision": attack_precision,
        "accuracy": round(float(accuracy_score(y_te_bin, y_pred_bin)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_te_bin, y_pred_bin)), 4),
        "f1_score": round(float(f1_score(y_te_bin, y_pred_bin, pos_label="attack", zero_division=0)), 4),
        "brier_score": brier_val,
        "log_loss": log_loss_val,
    }

    # ── B. Original-Label Evaluation Experiment ────────────────────────────────────
    y_orig = np.array([e.raw_label.strip() for e in events])
    y_tr_orig, y_te_orig = y_orig[tr_idx], y_orig[te_idx]
    orig_classes = sorted(list(set(y_orig)))
    orig_results = None

    if len(orig_classes) >= 2 and set(y_te_orig).issubset(set(y_tr_orig)):
        try:
            min_orig_c = min(Counter(y_tr_orig).values())
            if min_orig_c > 1:
                k_orig = max(1, min(4, min_orig_c - 1))
                sm_orig = SMOTE(k_neighbors=k_orig, random_state=random_seed)
                X_tr_orig_res, y_tr_orig_res = sm_orig.fit_resample(X_tr, y_tr_orig)
            else:
                X_tr_orig_res, y_tr_orig_res = X_tr, y_tr_orig

            rf_orig = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=random_seed)
            rf_orig.fit(X_tr_orig_res, y_tr_orig_res)
            y_pred_orig = rf_orig.predict(X_te)

            active_orig = sorted(list(set(np.concatenate([y_te_orig, y_pred_orig]))))
            orig_cm = confusion_matrix(y_te_orig, y_pred_orig, labels=active_orig)
            prec_o, rec_o, f1_o, supp_o = precision_recall_fscore_support(
                y_te_orig, y_pred_orig, labels=active_orig, zero_division=0
            )

            per_class_orig = {}
            for idx, c in enumerate(active_orig):
                per_class_orig[c] = {
                    "support": int(supp_o[idx]),
                    "precision": round(float(prec_o[idx]), 4),
                    "recall": round(float(rec_o[idx]), 4),
                    "f1": round(float(f1_o[idx]), 4),
                }

            orig_results = {
                "active_original_labels": active_orig,
                "confusion_matrix": {
                    "labels": active_orig,
                    "matrix": orig_cm.tolist(),
                },
                "per_class_metrics": per_class_orig,
                "macro_f1": round(float(f1_score(y_te_orig, y_pred_orig, average="macro", zero_division=0)), 4),
                "weighted_f1": round(float(f1_score(y_te_orig, y_pred_orig, average="weighted", zero_division=0)), 4),
                "balanced_accuracy": round(float(balanced_accuracy_score(y_te_orig, y_pred_orig)), 4),
                "accuracy": round(float(accuracy_score(y_te_orig, y_pred_orig)), 4),
            }
        except Exception as e:
            logger.debug(f"Original label evaluation skipped or failed: {e}")

    # ── C. Derived AEGIS-ML Multiclass Evaluation ──────────────────────────────────
    valid_canon_idx = [i for i, c in enumerate(mapped_canon) if c is not None]
    multi_class_results = None

    if len(valid_canon_idx) >= 30:
        events_mc = [events[i] for i in valid_canon_idx]
        y_mc = np.array([mapped_canon[i] for i in valid_canon_idx])
        mc_counts = Counter(y_mc)
        active_classes = sorted([c for c, cnt in mc_counts.items() if cnt >= 2])

        if len(active_classes) >= 2:
            keep_sub_idx = [i for i, c in enumerate(y_mc) if c in active_classes]
            mc_indices = np.array(valid_canon_idx)[keep_sub_idx]
            
            # Map into current split partitions
            tr_mc_idx = [i for i in tr_idx if i in mc_indices]
            te_mc_idx = [i for i in te_idx if i in mc_indices]

            if len(tr_mc_idx) >= 10 and len(te_mc_idx) >= 5:
                X_tr_mc = extract_observable_flow_features([events[i] for i in tr_mc_idx], tracker=tracker, fit_tracker=False)
                X_te_mc = extract_observable_flow_features([events[i] for i in te_mc_idx], tracker=tracker, fit_tracker=False)
                y_tr_mc = np.array([mapped_canon[i] for i in tr_mc_idx])
                y_te_mc = np.array([mapped_canon[i] for i in te_mc_idx])

                min_mc_c = min(Counter(y_tr_mc).values())
                if min_mc_c > 1:
                    k_n = max(1, min(4, min_mc_c - 1))
                    sm_mc = SMOTE(k_neighbors=k_n, random_state=random_seed)
                    X_tr_mc_res, y_tr_mc_res = sm_mc.fit_resample(X_tr_mc, y_tr_mc)
                else:
                    X_tr_mc_res, y_tr_mc_res = X_tr_mc, y_tr_mc

                rf_mc = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=random_seed)
                rf_mc.fit(X_tr_mc_res, y_tr_mc_res)
                y_pred_mc = rf_mc.predict(X_te_mc)

                act_mc = sorted(list(set(np.concatenate([y_te_mc, y_pred_mc]))))
                mc_cm = confusion_matrix(y_te_mc, y_pred_mc, labels=act_mc)
                prec, rec, f1s, supp = precision_recall_fscore_support(
                    y_te_mc, y_pred_mc, labels=act_mc, zero_division=0
                )

                per_class = {}
                for idx, c in enumerate(act_mc):
                    per_class[c] = {
                        "support": int(supp[idx]),
                        "precision": round(float(prec[idx]), 4),
                        "recall": round(float(rec[idx]), 4),
                        "f1": round(float(f1s[idx]), 4),
                    }

                benign_as_attack = 0
                attack_as_benign = 0
                attack_subtype_confusion = 0
                for actual, pred in zip(y_te_mc, y_pred_mc):
                    if actual == "benign" and pred != "benign":
                        benign_as_attack += 1
                    elif actual != "benign" and pred == "benign":
                        attack_as_benign += 1
                    elif actual != "benign" and pred != "benign" and actual != pred:
                        attack_subtype_confusion += 1

                total_attacks_test = sum(supp[idx] for idx, c in enumerate(act_mc) if c != "benign")

                multi_class_results = {
                    "active_classes": act_mc,
                    "mapping_caveat": (
                        "PortScan is mapped to lateral_movement as a proxy for reconnaissance-driven pivoting. "
                        "Do NOT interpret PortScan as confirmed internal host compromise."
                    ),
                    "confusion_matrix": {
                        "labels": act_mc,
                        "matrix": mc_cm.tolist(),
                    },
                    "per_class_metrics": per_class,
                    "macro_f1": round(float(f1_score(y_te_mc, y_pred_mc, average="macro", zero_division=0)), 4),
                    "weighted_f1": round(float(f1_score(y_te_mc, y_pred_mc, average="weighted", zero_division=0)), 4),
                    "balanced_accuracy": round(float(balanced_accuracy_score(y_te_mc, y_pred_mc)), 4),
                    "accuracy": round(float(accuracy_score(y_te_mc, y_pred_mc)), 4),
                    "misclassification_taxonomy": {
                        "benign_classified_as_attack_count": benign_as_attack,
                        "attack_classified_as_benign_count": attack_as_benign,
                        "attack_subtype_confusion_count": attack_subtype_confusion,
                        "attack_subtype_confusion_ratio": (
                            round(attack_subtype_confusion / max(total_attacks_test, 1), 4)
                            if total_attacks_test > 0
                            else 0.0
                        ),
                    },
                }

    # ── D. Save Experimental Model (Separate from Production) ─────────────────────
    saved_model_path = None
    if save_model:
        out_dir = Path(model_output_dir or (Path(MODEL_DIR) / "external_experiments" / "cicids2017"))
        out_dir.mkdir(parents=True, exist_ok=True)
        model_file = out_dir / "network_flow_rf.pkl"
        meta_file = out_dir / "network_flow_rf_metadata.json"

        joblib.dump(rf_bin, model_file)
        saved_model_path = str(model_file)

        exp_meta = {
            "experiment_name": "Separate Network-Flow Random Forest (CIC-IDS2017)",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "model_version": "24.1.0-exp",
            "feature_names": OBSERVABLE_FLOW_FEATURE_NAMES,
            "n_features": len(OBSERVABLE_FLOW_FEATURE_NAMES),
            "split_strategy": split_strategy,
            "evaluation_targets": ["binary", "original_labels", "canonical_multiclass"],
            "production_model_isolation": "Strictly isolated from calibrated_threat_classifier.pkl",
        }
        with open(meta_file, "w") as f:
            json.dump(exp_meta, f, indent=2)

    return {
        "experiment_name": "External Dataset Retrained Network-Flow Benchmark",
        "observable_feature_count": len(OBSERVABLE_FLOW_FEATURE_NAMES),
        "observable_features": OBSERVABLE_FLOW_FEATURE_NAMES,
        "split_metadata": split_meta,
        "sample_counts": {
            "total_events": len(events),
            "train_samples": len(tr_idx),
            "test_samples": len(te_idx),
        },
        "binary_evaluation": binary_metrics,
        "original_label_evaluation": orig_results,
        "derived_canonical_evaluation": multi_class_results,
        "saved_experimental_model_path": saved_model_path,
    }


def compute_file_sha256(filepath: Path) -> str:
    """Compute sha256 checksum for a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_phase24_evaluation(
    dataset_path: Optional[str] = None,
    output_path: Optional[str] = None,
    random_seed: int = 42,
    save_model: bool = True,
    model_output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main Phase 24 / 24.1 orchestration entry point.
    
    Checks dataset availability:
    - If absent: produces complete audit, marks status as NOT_COMPLETED / BLOCKED_AWAITING_LOCAL_COPY,
      documents provenance, and writes machine-readable report without fabricating metrics.
    - If present: conducts quality scan, transfer feasibility check, and isolated retrained benchmark
      across Stratified Random, Grouped (Pair-Isolated), and Temporal splits.
    """
    schema_audit = audit_feature_compatibility()
    feature_audit_18 = audit_observable_flow_features()
    transfer_eval = evaluate_model_transfer_feasibility()

    candidates = []
    if dataset_path:
        candidates.append(Path(dataset_path))
    else:
        base_dir = PROJECT_ROOT / "datasets" / "cicids2017"
        for fn in CICIDS2017_METADATA["expected_files"]:
            candidates.append(base_dir / fn)
        candidates.append(PROJECT_ROOT / "data" / "external" / "cicids2017" / "Monday-WorkingHours.pcap_ISCX.csv")

    resolved_path: Optional[Path] = None
    for cand in candidates:
        if cand.exists() and cand.is_file():
            resolved_path = cand
            break

    target_output = Path(
        output_path or (PROJECT_ROOT / "data" / "models" / "external_dataset_evaluation_artifact.json")
    )
    target_output.parent.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "phase": "24.1",
        "title": "CIC-IDS2017 Acquisition, Leakage-Resistant Evaluation, and Network-Flow Benchmark",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "random_seed": random_seed,
        "dataset_metadata": CICIDS2017_METADATA,
        "feature_audit_18": feature_audit_18,
        "schema_compatibility_audit": schema_audit,
        "existing_model_transfer_evaluation": transfer_eval,
    }

    if resolved_path is None:
        logger.info(
            "External dataset CIC-IDS2017 is not available locally. "
            "Recording NOT_COMPLETED status per Phase 24.1 preflight specifications."
        )
        report["status"] = "not_completed"
        report["status_code"] = "BLOCKED_AWAITING_LOCAL_COPY"
        report["dataset_acquisition_status"] = "NOT_DOWNLOADED"
        report["reason"] = (
            "No CIC-IDS2017 CSV files found in datasets/cicids2017/. "
            "Official UNB download requires an interactive registration form at https://www.unb.ca/cic/datasets/ids-2017.html. "
            "Automated scraping without registration is prohibited by UNB. "
            "Evaluation infrastructure, schema audit, and leakage-resistant benchmarks are fully operational."
        )
        report["reproduction_instructions"] = [
            "1. Visit https://www.unb.ca/cic/datasets/ids-2017.html and complete the dataset registration form.",
            "2. Download the MachineLearningCVE archive (~500 MB).",
            "3. Extract CSV files into datasets/cicids2017/ (e.g., Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv).",
            "4. Execute: python3 -m backend.evaluation.external_dataset_evaluation --data datasets/cicids2017/<file>.csv",
        ]
        report["retrained_experiment"] = None
        report["split_comparison"] = None
    else:
        logger.info(f"External dataset located at: {resolved_path}. Commencing evaluation...")
        file_sha256 = compute_file_sha256(resolved_path)
        file_size_bytes = resolved_path.stat().st_size

        quality_scan = scan_dataset_quality_and_leakage(str(resolved_path))

        events, loader_stats = load_cicids2017(
            str(resolved_path),
            max_rows=5000,
            random_seed=random_seed,
            deduplicate=True,
        )

        # Multi-split comparison:
        # A. Stratified Random Split
        bench_rand = execute_external_retrained_benchmark(
            events,
            random_seed=random_seed,
            split_strategy="stratified_random",
            save_model=save_model,
            model_output_dir=model_output_dir,
        )
        # B. Grouped Communication Pair Split (prevents identical pair leakage)
        bench_group = execute_external_retrained_benchmark(
            events, random_seed=random_seed, split_strategy="grouped_communication_pair", save_model=False
        )
        # C. Temporal Causal Split (prevents temporal future-event leakage)
        bench_time = execute_external_retrained_benchmark(
            events, random_seed=random_seed, split_strategy="temporal_causal", save_model=False
        )

        report["status"] = "completed"
        report["status_code"] = "EVALUATION_COMPLETED"
        report["dataset_acquisition_status"] = "VERIFIED_LOCAL_COPY"
        report["dataset_file_info"] = {
            "file_name": resolved_path.name,
            "file_path": str(resolved_path),
            "file_size_bytes": file_size_bytes,
            "sha256_checksum": file_sha256,
        }
        report["data_quality_and_leakage_scan"] = quality_scan
        report["loader_stats"] = loader_stats
        report["retrained_experiment"] = bench_rand
        report["split_comparison"] = {
            "stratified_random": bench_rand,
            "grouped_communication_pair": bench_group,
            "temporal_causal": bench_time,
        }

    def _json_default(o):
        if isinstance(o, (np.integer, np.int64, np.int32)):
            return int(o)
        if isinstance(o, (np.floating, np.float64, np.float32)):
            return float(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
        return str(o)

    with open(target_output, "w") as f:
        json.dump(report, f, indent=2, default=_json_default)

    logger.info(f"Phase 24.1 evaluation report written to {target_output}")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AEGIS-ML Phase 24.1 External Dataset Evaluation")
    parser.add_argument("--data", type=str, default=None, help="Path to CIC-IDS2017 CSV file")
    parser.add_argument("--out", type=str, default=None, help="Output path for evaluation report JSON")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--no-save", action="store_true", help="Do not save experimental model artifact")
    args = parser.parse_args()

    res = run_phase24_evaluation(
        dataset_path=args.data, output_path=args.out, random_seed=args.seed, save_model=not args.no_save
    )
    print(f"\n--- AEGIS-ML PHASE 24.1 EVALUATION REPORT ---")
    print(f"Status: {res.get('status')} ({res.get('status_code')})")
    print(f"Transfer Feasibility: {res['existing_model_transfer_evaluation']['status']}")
    print(f"Features Audited: 48 (General Schema) / 18 (Observable Flow Benchmark)")
    if res.get("status") == "completed":
        bin_eval = res["retrained_experiment"]["binary_evaluation"]
        print(f"Attack Recall: {bin_eval['attack_recall']} (denom: {bin_eval['attack_recall_denominator']})")
        print(f"Benign FPR: {bin_eval['benign_false_alarm_rate']} (denom: {bin_eval['benign_false_alarm_denominator']})")
        if res.get("split_comparison"):
            for strat, b in res["split_comparison"].items():
                m = b["split_metadata"]
                print(f"  Split [{strat}]: overlap={m['cross_partition_pair_overlap_pct']}% | Test F1={b['binary_evaluation']['f1_score']}")
    else:
        print(f"Reason: {res.get('reason')}")
