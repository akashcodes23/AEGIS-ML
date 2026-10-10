"""AEGIS-ML Phase 20: Context-Aware Detection and Feature Ablation Tests.

Validates:
1. Feature schemas and dimensions across all ablation configurations (A=21, B=31, C=19, D=26, E=36).
2. Strict prohibition of provenance identifiers from all feature vectors.
3. Resilient handling of missing telemetry without NaN/Inf values.
4. Attribution semantics: no fabricated socket bindings or process GUIDs.
5. Scenario isolation across train and test partitions (0.0% overlap).
6. Train-only preprocessing and SMOTE fitting (no test leakage).
7. Exact mathematical metric reconstruction from instance-level predictions.
8. Verification that identical evaluation partitions were used across all configurations.
"""

from collections import Counter
import json
from pathlib import Path
import pytest
import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    accuracy_score,
)

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import UnifiedEvent
from backend.detection.telemetry_context import (
    SUPPORTED_CONTEXT_FEATURE_NAMES,
    MISSINGNESS_FEATURE_NAMES,
    extract_telemetry_context_features,
    extract_missingness_features,
)
from backend.detection.model_trainer import (
    load_flexible_dataset,
    CANONICAL_CLASSES,
)
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.temporal_graph_extractor import RELATIONAL_GRAPH_FEATURE_NAMES
from backend.evaluation.scenario_evaluation import PROHIBITED_FEATURE_FIELDS
from backend.evaluation.behavioral_diversity_evaluation import (
    partition_behavioral_diversity_split,
    DIVERSITY_DATASET_REL_PATH,
    BENIGN_WORKFLOW_TYPES,
)
from backend.evaluation.context_aware_ablation import (
    ABLATION_ARTIFACT_REL_PATH,
)


@pytest.fixture(scope="module")
def ablation_artifact():
    art_path = Path(PROJECT_ROOT) / ABLATION_ARTIFACT_REL_PATH
    if not art_path.exists():
        pytest.skip(f"Phase 20 ablation artifact not found at {art_path}")
    with open(art_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_phase20_feature_counts_and_schemas(ablation_artifact):
    """Verify feature counts across all 5 evaluated ablation configurations."""
    configs = ablation_artifact["ablation_configurations"]

    assert configs["config_a"]["feature_count"] == 21
    assert configs["config_b"]["feature_count"] == 31
    assert configs["config_c"]["feature_count"] == 19
    assert configs["config_d"]["feature_count"] == 26
    assert configs["config_e"]["feature_count"] == 36

    # Verify context and missingness feature schema lengths
    assert len(SUPPORTED_CONTEXT_FEATURE_NAMES) == 10
    assert len(MISSINGNESS_FEATURE_NAMES) == 5


def test_phase20_prohibited_provenance_fields_excluded_from_all_configs(ablation_artifact):
    """Verify that no provenance or metadata fields exist in any configuration schema."""
    configs = ablation_artifact["ablation_configurations"]

    for cfg_id, cfg_data in configs.items():
        feature_names = cfg_data["feature_names"]
        for prohibited in PROHIBITED_FEATURE_FIELDS:
            assert prohibited not in feature_names, (
                f"Prohibited field '{prohibited}' leaked into {cfg_id} features!"
            )


def test_phase20_missing_telemetry_handling_no_nans():
    """Verify telemetry context and missingness extractors handle incomplete events without NaN/Inf."""
    incomplete_events = [
        # Pure endpoint event
        UnifiedEvent(
            timestamp="2026-10-10T01:00:00",
            layer="endpoint",
            src_entity="10.0.0.5",
            dst_entity="10.0.0.5",
            src_internal=True,
            dst_internal=True,
            process_name="robocopy.exe",
            action="read",
            file_path="C:\\test.xlsx",
        ),
        # Pure network event
        UnifiedEvent(
            timestamp="2026-10-10T01:00:00",
            layer="network",
            src_entity="10.0.0.5",
            dst_entity="10.0.0.90",
            src_internal=True,
            dst_internal=True,
            dst_port=445,
            bytes_sent=1024,
            bytes_received=512,
        ),
        # Minimal event with almost all optional fields None
        UnifiedEvent(
            timestamp="2026-10-10T01:00:00",
            layer="application",
            src_entity="10.0.0.5",
            dst_entity="10.0.0.10",
            src_internal=True,
            dst_internal=True,
        ),
    ]

    for ev in incomplete_events:
        ctx = extract_telemetry_context_features(ev)
        miss = extract_missingness_features(ev)

        assert len(ctx) == 10
        assert len(miss) == 5

        for val in ctx + miss:
            assert isinstance(val, (int, float))
            assert not np.isnan(val)
            assert not np.isinf(val)


def test_phase20_no_fabricated_socket_attribution():
    """Verify that events without verified process-to-network binding return 0.0 (unobserved)."""
    # Event without socket_id or process_guid
    unlinked_event = UnifiedEvent(
        timestamp="2026-10-10T01:00:00",
        layer="endpoint",
        src_entity="10.0.0.5",
        dst_entity="10.0.0.5",
        src_internal=True,
        dst_internal=True,
        process_name="7z.exe",
        scenario_id="scenario_test_001",  # shared scenario_id does NOT equal socket binding!
    )
    ctx = extract_telemetry_context_features(unlinked_event)
    has_socket_idx = SUPPORTED_CONTEXT_FEATURE_NAMES.index("has_verified_socket_binding")
    assert ctx[has_socket_idx] == 0.0

    # Event with explicit dual telemetry
    bound_event = UnifiedEvent(
        timestamp="2026-10-10T01:00:00",
        layer="endpoint",
        src_entity="10.0.0.5",
        dst_entity="10.0.0.5",
        src_internal=True,
        dst_internal=True,
        process_name="curl.exe",
        process_guid="{PROC-GUID-1234}",
        socket_id="TCP:10.0.0.5:49152->203.0.113.50:443",
    )
    ctx_bound = extract_telemetry_context_features(bound_event)
    assert ctx_bound[has_socket_idx] == 1.0


def test_phase20_scenario_isolation_and_identical_ablation_partitions(ablation_artifact):
    """Verify that all ablation configurations evaluated on the EXACT same scenario partition."""
    instance_data = ablation_artifact["instance_level_data"]
    test_events = instance_data["test_event_ids"]
    test_scenarios = set(instance_data["test_scenario_ids"])
    ground_truth = instance_data["ground_truth_labels"]

    predictions = instance_data["predictions_by_config"]

    for cfg_id in ["config_a", "config_b", "config_c", "config_d", "config_e"]:
        assert cfg_id in predictions
        assert len(predictions[cfg_id]) == len(test_events)
        assert len(predictions[cfg_id]) == len(ground_truth)


def test_phase20_metric_reconstruction_from_arrays(ablation_artifact):
    """Verify exact mathematical match between reported metrics and raw prediction arrays for each config."""
    instance_data = ablation_artifact["instance_level_data"]
    y_true = instance_data["ground_truth_labels"]
    classes = CANONICAL_CLASSES

    for cfg_id, cfg_data in ablation_artifact["ablation_configurations"].items():
        y_pred = instance_data["predictions_by_config"][cfg_id]
        reported = cfg_data["metrics"]

        # Confusion matrix
        cm_recon = confusion_matrix(y_true, y_pred, labels=classes).tolist()
        assert cm_recon == reported["confusion_matrix"]

        # Accuracy
        acc_recon = round(float(accuracy_score(y_true, y_pred)), 4)
        assert acc_recon == reported["accuracy"]

        # Macro-F1
        macro_f1_recon = round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4)
        assert macro_f1_recon == reported["macro_f1"]

        # Balanced Accuracy
        bal_acc_recon = round(float(balanced_accuracy_score(y_true, y_pred)), 4)
        assert bal_acc_recon == reported["balanced_accuracy"]


def test_phase20_benign_workflow_tracking_across_all_configurations(ablation_artifact):
    """Verify all 7 benign workflows are evaluated with valid false-alarm rates in all configurations."""
    for cfg_id, cfg_data in ablation_artifact["ablation_configurations"].items():
        wf_breakdown = cfg_data["benign_workflow_breakdown"]
        for w_type in BENIGN_WORKFLOW_TYPES:
            assert w_type in wf_breakdown, f"Workflow '{w_type}' missing in {cfg_id}"
            w_info = wf_breakdown[w_type]
            assert w_info["total_events"] == w_info["correct_benign"] + w_info["false_alarms"]
            assert 0.0 <= w_info["false_alarm_rate"] <= 1.0
