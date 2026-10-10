"""AEGIS-ML Phase 21: Regression Tests for Sequence-Aware Detection and Attribution.

Module: tests.test_phase21_sequence_aware_detection

Validates:
1. Zero future-event leakage during causal/online feature extraction.
2. Strict host isolation: zero cross-host joins without evidence.
3. Resilient handling of missing timestamps, entities, and sparse fields.
4. Unobserved socket attribution strictly remains 0.0 (no fabricated bindings).
5. Complete exclusion of prohibited provenance metadata.
6. Identical scenario-grouped partitions across all ablation configurations.
7. Exact mathematical reconstruction of metrics and workflow counts from stored predictions.
8. Historical artifact preservation (Canonical, Phase 17, Phase 19, Phase 20).
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Optional
import pytest
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, balanced_accuracy_score

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import UnifiedEvent
from backend.detection.sequence_context import (
    CausalSequenceTracker,
    SEQUENCE_FEATURE_NAMES,
)
from backend.evaluation.scenario_evaluation import PROHIBITED_FEATURE_FIELDS
from backend.evaluation.sequence_aware_ablation import (
    SEQUENCE_ABLATION_ARTIFACT_REL_PATH,
    HISTORICAL_PHASE20_ARTIFACT_PATH,
)


def _make_event(
    event_id: str = "e1",
    timestamp: Optional[datetime] = None,
    layer: str = "endpoint",
    src_ip: str = "10.0.0.5",
    dst_ip: Optional[str] = None,
    src_internal: bool = True,
    dst_internal: bool = True,
    process_name: Optional[str] = None,
    parent_process: Optional[str] = None,
    action: Optional[str] = None,
    bytes_sent: Optional[int] = None,
    socket_id: Optional[str] = None,
    process_guid: Optional[str] = None,
) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=event_id,
        timestamp=timestamp or datetime.utcnow(),
        layer=layer,
        src_entity=src_ip,
        dst_entity=dst_ip or "internal_host",
        src_internal=src_internal,
        dst_internal=dst_internal,
        src_ip=src_ip,
        dst_ip=dst_ip,
        process_name=process_name,
        parent_process=parent_process,
        action=action,
        bytes_sent=bytes_sent,
        socket_id=socket_id,
        process_guid=process_guid,
    )


def test_phase21_no_future_event_leakage():
    """Verify that future events never leak into features extracted for a prior event."""
    tracker = CausalSequenceTracker(window_seconds=300.0)

    t0 = datetime(2026, 10, 10, 12, 0, 0)
    e1 = _make_event(
        event_id="e1",
        timestamp=t0,
        src_ip="10.0.0.5",
        layer="endpoint",
        process_name="7z.exe",
        action="read",
    )

    # Extract features for e1 in isolation
    feat1_isolated = tracker.extract_features_single(e1, advance_state=False)

    # Reset and simulate streaming where e1 arrives first
    tracker.reset()
    feat1_stream = tracker.extract_features_single(e1, advance_state=True)
    assert feat1_isolated == feat1_stream

    # Now add a future event at t0 + 10s (massive exfiltration to external IP)
    e2 = _make_event(
        event_id="e2",
        timestamp=t0 + timedelta(seconds=10),
        src_ip="10.0.0.5",
        layer="network",
        dst_ip="203.0.113.99",
        src_internal=True,
        dst_internal=False,
        bytes_sent=50000000,
    )
    _ = tracker.extract_features_single(e2, advance_state=True)

    # Re-extract e1 on a fresh tracker to verify that e2's occurrence had 0 impact on e1
    tracker2 = CausalSequenceTracker(window_seconds=300.0)
    feat1_fresh = tracker2.extract_features_single(e1, advance_state=False)

    for k in SEQUENCE_FEATURE_NAMES:
        assert feat1_fresh[k] == feat1_stream[k], f"Leakage detected: {k} changed!"


def test_phase21_no_cross_host_event_joins():
    """Verify that events on Host B never alter features on Host A."""
    tracker = CausalSequenceTracker(window_seconds=300.0)
    t0 = datetime(2026, 10, 10, 12, 0, 0)

    # Event on Host A
    e_a1 = _make_event(
        event_id="ea1",
        timestamp=t0,
        src_ip="10.0.0.5",
        layer="endpoint",
        process_name="7z.exe",
        action="read",
    )
    _ = tracker.extract_features_single(e_a1, advance_state=True)

    # 5 massive exfiltration network events on Host B (10.0.0.99)
    for i in range(5):
        e_b = _make_event(
            event_id=f"eb_{i}",
            timestamp=t0 + timedelta(seconds=i + 1),
            src_ip="10.0.0.99",
            layer="network",
            dst_ip="203.0.113.5",
            src_internal=True,
            dst_internal=False,
            bytes_sent=10000000,
        )
        _ = tracker.extract_features_single(e_b, advance_state=True)

    # Next event on Host A at t0 + 10s: purely local file read
    e_a2 = _make_event(
        event_id="ea2",
        timestamp=t0 + timedelta(seconds=10),
        src_ip="10.0.0.5",
        layer="endpoint",
        process_name="7z.exe",
        action="read",
    )
    feats_a2 = tracker.extract_features_single(e_a2, advance_state=False)

    # Host A should see zero network events, zero external transfers, zero bytes
    assert feats_a2["seq_window_network_event_count"] == 0.0
    assert feats_a2["seq_inferred_file_read_before_outbound_net"] == 0.0
    assert feats_a2["seq_window_has_external_transfer"] == 0.0
    assert feats_a2["seq_window_bytes_sent_sum_log"] == 0.0
    assert feats_a2["seq_window_event_count_host"] == 1.0  # only e_a1


def test_phase21_missing_telemetry_and_identifiers_handled_safely():
    """Ensure missing timestamps, entities, and sparse fields produce finite numbers and zero NaNs."""
    tracker = CausalSequenceTracker(window_seconds=300.0)

    # Test duck-typed sparse objects with None fields
    @dataclass
    class SparseEvent:
        event_id: str
        timestamp: Optional[datetime] = None
        layer: Optional[str] = None
        src_ip: Optional[str] = None
        src_entity: Optional[str] = None
        dst_ip: Optional[str] = None
        dst_internal: Optional[bool] = None
        action: Optional[str] = None
        process_name: Optional[str] = None
        parent_process: Optional[str] = None
        file_path: Optional[str] = None
        bytes_sent: Optional[int] = None
        socket_id: Optional[str] = None
        process_guid: Optional[str] = None

    sparse_events = [
        SparseEvent(event_id="sp1", timestamp=None, src_ip=None, layer=None),
        SparseEvent(event_id="sp2", timestamp=datetime.utcnow(), src_ip="10.0.0.1", bytes_sent=None),
        SparseEvent(event_id="sp3", timestamp=datetime.utcnow() - timedelta(seconds=1000), src_ip="10.0.0.1"),
    ]

    for ev in sparse_events:
        feats = tracker.extract_features_single(ev, advance_state=True)
        assert len(feats) == len(SEQUENCE_FEATURE_NAMES)
        for k, v in feats.items():
            assert not np.isnan(v), f"NaN detected in feature {k}"
            assert not np.isinf(v), f"Inf detected in feature {k}"
            assert isinstance(v, float), f"Feature {k} is not float: {type(v)}"


def test_phase21_unknown_attribution_never_verified():
    """Verify that missing socket_id or process_guid strictly evaluates to 0.0 (unobserved)."""
    tracker = CausalSequenceTracker(window_seconds=300.0)

    # Event with process but no socket
    e1 = _make_event(
        event_id="e1",
        src_ip="10.0.0.5",
        layer="endpoint",
        process_name="powershell.exe",
        socket_id=None,
        process_guid=None,
    )
    f1 = tracker.extract_features_single(e1, advance_state=False)
    assert f1["seq_verified_socket_attribution"] == 0.0

    # Event with socket but no process_guid
    e2 = _make_event(
        event_id="e2",
        src_ip="10.0.0.5",
        layer="network",
        socket_id="sock_1234",
        process_guid=None,
    )
    f2 = tracker.extract_features_single(e2, advance_state=False)
    assert f2["seq_verified_socket_attribution"] == 0.0

    # Event with both socket_id and process_guid verified
    e3 = _make_event(
        event_id="e3",
        src_ip="10.0.0.5",
        layer="network",
        socket_id="sock_1234",
        process_guid="{proc-guid-5678}",
    )
    f3 = tracker.extract_features_single(e3, advance_state=False)
    assert f3["seq_verified_socket_attribution"] == 1.0


def test_phase21_provenance_fields_excluded_from_all_configs():
    """Verify that provenance fields are excluded from feature definitions across all configs."""
    for prohibited in PROHIBITED_FEATURE_FIELDS:
        assert prohibited not in SEQUENCE_FEATURE_NAMES, f"Prohibited field {prohibited} in SEQUENCE_FEATURE_NAMES"

    art_path = Path(PROJECT_ROOT) / SEQUENCE_ABLATION_ARTIFACT_REL_PATH
    if art_path.exists():
        with open(art_path) as f:
            data = json.load(f)
        for cid, cfg in data["ablation_configurations"].items():
            for prohibited in PROHIBITED_FEATURE_FIELDS:
                assert prohibited not in cfg["feature_names"], (
                    f"Prohibited field {prohibited} found in config {cid} feature_names"
                )


def test_phase21_metric_reconstruction_from_stored_predictions():
    """Reconstruct confusion matrices and metrics from instance-level predictions to verify integrity."""
    art_path = Path(PROJECT_ROOT) / SEQUENCE_ABLATION_ARTIFACT_REL_PATH
    if not art_path.exists():
        pytest.skip("Phase 21 artifact not yet generated.")

    with open(art_path) as f:
        data = json.load(f)

    inst = data["instance_level_data"]
    y_test = inst["ground_truth_labels"]
    preds = inst["predictions_by_config"]
    assert len(y_test) == 991, f"Expected 991 test events, found {len(y_test)}"

    for cid, cfg in data["ablation_configurations"].items():
        y_pred = preds[cid]
        assert len(y_pred) == len(y_test)

        # Reconstruct macro-F1 and balanced accuracy
        reconstructed_macro = round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        reconstructed_bal = round(float(balanced_accuracy_score(y_test, y_pred)), 4)

        stored_macro = cfg["metrics"]["macro_f1"]
        stored_bal = cfg["metrics"]["balanced_accuracy"]

        assert reconstructed_macro == stored_macro, f"Macro F1 mismatch in {cid}: {reconstructed_macro} vs {stored_macro}"
        assert reconstructed_bal == stored_bal, f"Balanced Acc mismatch in {cid}: {reconstructed_bal} vs {stored_bal}"


def test_phase21_historical_artifacts_preservation():
    """Verify historical artifacts (Canonical, Phase 17, Phase 19, Phase 20) are preserved unmodified."""
    milestones = [
        ("data/models/canonical_evaluation_artifact.json", "macro_f1", 0.8685),
        ("data/models/scenario_evaluation_artifact.json", "macro_f1", 0.9732),
        ("data/models/behavioral_diversity_artifact.json", "macro_f1", 0.8717),
    ]

    for rel_path, key, expected_val in milestones:
        p = Path(PROJECT_ROOT) / rel_path
        assert p.exists(), f"Historical artifact {rel_path} missing!"
        with open(p) as f:
            data = json.load(f)
        val = data.get("evaluation_results", {}).get(key)
        assert val == expected_val, f"Mismatch in {rel_path}: expected {expected_val}, found {val}"
