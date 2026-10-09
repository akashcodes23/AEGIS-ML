"""AEGIS-ML Phase 14 Dual-Telemetry Validation & Canonical Artifact Tests.

Validates:
1. Canonical evaluation artifact mathematical consistency & reproducibility.
2. Dual-telemetry controlled correlation benchmark (10 scenarios).
3. Raw dataset attribution feature availability and missingness verification.
4. Investigation evidence quality: distinction between observed evidence and hypotheses.
"""

import json
import pytest
import numpy as np
from pathlib import Path

from backend.evaluation.canonical_artifact import (
    generate_canonical_artifact,
    verify_canonical_artifact_consistency,
    CANONICAL_CLASSES,
)
from backend.evaluation.dual_telemetry_benchmark import (
    evaluate_dual_telemetry_benchmark,
    build_scenario_fixtures,
)
from backend.core.schemas import Alert
from backend.correlation.incident_correlator import IncidentCorrelator


ARTIFACT_PATH = Path("data/models/canonical_evaluation_artifact.json")
RAW_DATA_PATH = Path("data/raw/combined_labeled.jsonl")


def test_canonical_artifact_file_exists_and_valid():
    """Verify the canonical evaluation artifact is generated and valid JSON."""
    if not ARTIFACT_PATH.exists():
        artifact = generate_canonical_artifact(output_path=str(ARTIFACT_PATH))
    else:
        with open(ARTIFACT_PATH, "r") as f:
            artifact = json.load(f)

    assert "metadata" in artifact
    assert "model_configuration" in artifact
    assert "evaluation_results" in artifact
    assert "instance_level_data" in artifact


def test_canonical_artifact_mathematical_consistency():
    """Verify that all reported metrics strictly derive from the prediction arrays."""
    with open(ARTIFACT_PATH, "r") as f:
        artifact = json.load(f)

    is_consistent, errors = verify_canonical_artifact_consistency(artifact)
    assert is_consistent, f"Canonical artifact mathematical inconsistency found: {errors}"


def test_canonical_artifact_exact_values():
    """Verify specific invariants of the canonical evaluation artifact."""
    with open(ARTIFACT_PATH, "r") as f:
        artifact = json.load(f)

    # Class order
    assert artifact["metadata"]["canonical_class_order"] == CANONICAL_CLASSES
    # Test set size
    assert artifact["metadata"]["test_samples"] == 1400
    assert len(artifact["instance_level_data"]["ground_truth_labels"]) == 1400
    assert len(artifact["instance_level_data"]["predicted_labels"]) == 1400
    assert len(artifact["instance_level_data"]["test_event_ids"]) == 1400

    # Metrics
    metrics = artifact["evaluation_results"]
    cm = np.array(metrics["confusion_matrix"])
    assert cm.shape == (5, 5)
    assert cm.sum() == 1400

    # Benign Rates (FPR = 0 / 990, FNR = 3 / 410)
    benign_total = cm[0].sum()
    benign_fn = benign_total - cm[0, 0]
    non_benign_total = cm.sum() - benign_total
    benign_fp = cm[:, 0].sum() - cm[0, 0]
    assert benign_total == 410
    assert benign_fn == 3
    assert non_benign_total == 990
    assert benign_fp == 0
    assert metrics["benign_fpr"] == 0.0
    assert abs(metrics["benign_fnr"] - (3 / 410)) < 1e-4
    assert abs(metrics["binary_false_alarm_rate_on_benign"] - (3 / 410)) < 1e-4

    # Lateral movement recall = 100%, precision = 40.94%
    lm_metrics = metrics["per_class"]["lateral_movement"]
    assert lm_metrics["support"] == 61
    assert lm_metrics["recall"] == 1.0
    assert abs(lm_metrics["precision"] - (61 / (61 + 88))) < 1e-4


def test_dual_telemetry_benchmark_all_scenarios_pass():
    """Verify all 10 controlled dual-telemetry regression scenarios pass."""
    report = evaluate_dual_telemetry_benchmark()
    meta = report["benchmark_metadata"]
    assert meta["total_scenarios"] == 10
    assert meta["passed_scenarios"] == 10
    assert meta["pass_rate_pct"] == 100.0
    for res in report["scenarios"]:
        assert res["passed"], f"Scenario {res['scenario_id']} failed: {res.get('failure_reasons')}"


def test_scenario_1_direct_socket_binding_evidence():
    """Verify that directly observed socket-to-PID binding produces observation claim."""
    scenarios = {s["scenario_id"]: s for s in build_scenario_fixtures()}
    sc = scenarios["SCENARIO_1_DIRECT_SOCKET_BINDING"]

    correlator = IncidentCorrelator(time_window_seconds=600)
    for ev in sc["events"]:
        alert = Alert(
            alert_id=f"ALT-{ev.event_id}",
            event_id=ev.event_id,
            created_at=ev.timestamp,
            timestamp=ev.timestamp,
            threat_type=ev.attack_type or "statistical_anomaly",
            severity="high" if ev.attack_type != "benign" else "low",
            confidence=0.85 if ev.attack_type != "benign" else 0.50,
            src_entity=ev.src_entity,
            dst_entity=ev.dst_entity,
            layer=ev.layer,
            raw_event=ev.model_dump(),
        )
        correlator.correlate_alert(alert, raw_event=ev)

    assert len(correlator.incidents) == 1
    inc = list(correlator.incidents.values())[0]
    assert "endpoint" in inc.layers_involved
    assert "network" in inc.layers_involved

    # Check relationship evidence
    bindings = [r for r in inc.relationship_evidence if r.get("relationship_type") == "direct_process_socket_binding"]
    assert len(bindings) >= 1
    assert bindings[0].get("claim_type") == "observation"
    assert len(bindings[0].get("missing_evidence", [])) == 0


def test_scenario_3_forbidden_socket_binding():
    """Verify temporal proximity alone does NOT falsely bind distinct process to socket."""
    scenarios = {s["scenario_id"]: s for s in build_scenario_fixtures()}
    sc = scenarios["SCENARIO_3_UNRELATED_NETWORK_SAME_HOST"]

    correlator = IncidentCorrelator(time_window_seconds=600)
    for ev in sc["events"]:
        alert = Alert(
            alert_id=f"ALT-{ev.event_id}",
            event_id=ev.event_id,
            created_at=ev.timestamp,
            timestamp=ev.timestamp,
            threat_type=ev.attack_type or "statistical_anomaly",
            severity="high" if ev.attack_type != "benign" else "low",
            confidence=0.85 if ev.attack_type != "benign" else 0.50,
            src_entity=ev.src_entity,
            dst_entity=ev.dst_entity,
            layer=ev.layer,
            raw_event=ev.model_dump(),
        )
        correlator.correlate_alert(alert, raw_event=ev)

    # Check that 7z.exe was not falsely bound to chrome's socket
    all_rels = []
    for inc in correlator.incidents.values():
        all_rels.extend(inc.relationship_evidence)

    for r in all_rels:
        assert not (
            r.get("relationship_type") == "direct_process_socket_binding"
            and "7z.exe" in r.get("uncertainty_notes", "")
        )


def test_scenario_5_pid_reuse_rejected():
    """Verify that events separated across process lifetimes reject process lineage match."""
    scenarios = {s["scenario_id"]: s for s in build_scenario_fixtures()}
    sc = scenarios["SCENARIO_5_PID_REUSE_DISAMBIGUATION"]

    correlator = IncidentCorrelator(time_window_seconds=3600)
    for ev in sc["events"]:
        alert = Alert(
            alert_id=f"ALT-{ev.event_id}",
            event_id=ev.event_id,
            created_at=ev.timestamp,
            timestamp=ev.timestamp,
            threat_type=ev.attack_type or "statistical_anomaly",
            severity="high" if ev.attack_type != "benign" else "low",
            confidence=0.85 if ev.attack_type != "benign" else 0.50,
            src_entity=ev.src_entity,
            dst_entity=ev.dst_entity,
            layer=ev.layer,
            raw_event=ev.model_dump(),
        )
        correlator.correlate_alert(alert, raw_event=ev)

    all_rels = []
    for inc in correlator.incidents.values():
        all_rels.extend(inc.relationship_evidence)

    # RULE_0_PROCESS_LINEAGE_MATCH must NOT have matched
    lineage_rels = [r for r in all_rels if r.get("correlation_rule") == "RULE_0_PROCESS_LINEAGE_MATCH"]
    assert len(lineage_rels) == 0


def test_scenario_6_cross_host_pid_isolation():
    """Verify that identical PIDs on different hosts are strictly isolated."""
    scenarios = {s["scenario_id"]: s for s in build_scenario_fixtures()}
    sc = scenarios["SCENARIO_6_IDENTICAL_PIDS_DIFFERENT_HOSTS"]

    correlator = IncidentCorrelator(time_window_seconds=600)
    for ev in sc["events"]:
        alert = Alert(
            alert_id=f"ALT-{ev.event_id}",
            event_id=ev.event_id,
            created_at=ev.timestamp,
            timestamp=ev.timestamp,
            threat_type=ev.attack_type or "statistical_anomaly",
            severity="high" if ev.attack_type != "benign" else "low",
            confidence=0.85 if ev.attack_type != "benign" else 0.50,
            src_entity=ev.src_entity,
            dst_entity=ev.dst_entity,
            layer=ev.layer,
            raw_event=ev.model_dump(),
        )
        correlator.correlate_alert(alert, raw_event=ev)

    assert len(correlator.incidents) == 2
    entities = {inc.primary_attacker for inc in correlator.incidents.values()}
    assert "10.0.0.51" in entities
    assert "10.0.0.52" in entities


def test_scenario_7_missing_evidence_flagged_as_hypothesis():
    """Verify that absent socket/GUID relationships are flagged as hypotheses with missing evidence."""
    scenarios = {s["scenario_id"]: s for s in build_scenario_fixtures()}
    sc = scenarios["SCENARIO_7_MISSING_GUID_AND_SOCKET"]

    correlator = IncidentCorrelator(time_window_seconds=600)
    for ev in sc["events"]:
        alert = Alert(
            alert_id=f"ALT-{ev.event_id}",
            event_id=ev.event_id,
            created_at=ev.timestamp,
            timestamp=ev.timestamp,
            threat_type=ev.attack_type or "statistical_anomaly",
            severity="high" if ev.attack_type != "benign" else "low",
            confidence=0.85 if ev.attack_type != "benign" else 0.50,
            src_entity=ev.src_entity,
            dst_entity=ev.dst_entity,
            layer=ev.layer,
            raw_event=ev.model_dump(),
        )
        correlator.correlate_alert(alert, raw_event=ev)

    assert len(correlator.incidents) == 1
    inc = list(correlator.incidents.values())[0]
    hypothesis_rels = [r for r in inc.relationship_evidence if r.get("claim_type") == "hypothesis"]
    assert len(hypothesis_rels) > 0
    assert "socket_to_pid_binding_absent" in hypothesis_rels[0].get("missing_evidence", [])


def test_source_dataset_feature_availability():
    """Audit source dataset to confirm attribution fields are truly absent, ensuring no fabrication."""
    if not RAW_DATA_PATH.exists():
        pytest.skip("Source dataset not present")

    total = 0
    counts = {
        "socket_id": 0,
        "host_id": 0,
        "process_guid": 0,
        "connection_direction": 0,
        "process_start_time": 0,
        "process_end_time": 0,
        "pid": 0,
        "parent_pid": 0,
    }

    with open(RAW_DATA_PATH, "r") as f:
        for line in f:
            total += 1
            obj = json.loads(line)
            for k in counts:
                if obj.get(k) is not None:
                    counts[k] += 1

    assert total == 7051
    # Every one of these fields must have 0% availability in the raw dataset
    for k, v in counts.items():
        assert v == 0, f"Field {k} unexpectedly populated ({v} times); check provenance!"
