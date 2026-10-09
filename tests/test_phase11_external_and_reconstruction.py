"""
Phase 11 Regression Tests: External Dataset Benchmark & Evidence-Driven Reconstruction
Tests external benchmark execution, unavailable feature group handling,
cross-layer exfiltration hypothesis demarcation, and evidence traceability.
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

from backend.core.schemas import Alert, UnifiedEvent, Incident
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.evaluation.external_benchmark import evaluate_external_dataset


def test_external_benchmark_missing_file_safe_status(tmp_path):
    """Verify that a non-existent external file returns 'not_completed' and does not fabricate metrics."""
    fake_path = tmp_path / "non_existent_cicids.csv"
    res = evaluate_external_dataset(str(fake_path))
    assert res["status"] == "not_completed"
    assert "not present locally" in res["reason"]
    assert res["metrics"] is None


def test_external_benchmark_synthetic_cicids_fixture(tmp_path):
    """
    Verify external benchmark pipeline end-to-end on a controlled CIC-IDS2017 fixture
    containing multi-class labels, Inf values, negative values, and flow durations.
    """
    fixture_rows = []
    base_time = datetime(2017, 7, 3, 9, 0, 0)
    # Generate multi-class flow records
    for i in range(120):
        # 60 benign, 30 brute force (FTP-Patator), 30 c2 (Bot)
        if i < 60:
            lbl = "BENIGN"
            src = f"192.168.10.{10 + (i % 5)}"
            dst = "192.168.10.1"
            dport = 80
            bytes_tx = 400 + i * 10
        elif i < 90:
            lbl = "FTP-Patator"
            src = "172.16.0.1"
            dst = "192.168.10.50"
            dport = 21
            bytes_tx = 1000 + i * 20
        else:
            lbl = "Bot"
            src = "192.168.10.99"
            dst = "203.0.113.5"
            dport = 8080
            bytes_tx = 64

        row = {
            " Source IP": src,
            " Destination IP": dst,
            " Destination Port": dport,
            " Source Port": 40000 + i,
            " Protocol": 6,
            " Total Length of Fwd Packets": float("inf") if i == 0 else bytes_tx,
            " Total Length of Bwd Packets": 200,
            " Flow Duration": -100 if i == 1 else 250000,
            " Timestamp": (base_time + timedelta(seconds=i * 2)).strftime("%d/%m/%Y %H:%M:%S"),
            " Label": lbl,
        }
        fixture_rows.append(row)

    csv_path = tmp_path / "cicids_fixture.csv"
    pd.DataFrame(fixture_rows).to_csv(csv_path, index=False)

    report = evaluate_external_dataset(
        file_path=str(csv_path),
        output_path=str(tmp_path / "output_report.json"),
        max_rows=500,
        random_seed=42,
    )

    assert report["status"] == "completed"
    assert "configurations" in report
    assert "A_baseline_network" in report["configurations"]
    assert "B_temporal_relational_network" in report["configurations"]

    # Verify unavailable feature groups are disclosed honestly
    assert "process_name" in report["unavailable_feature_groups"]
    assert "file_path" in report["unavailable_feature_groups"]

    cfg_a = report["configurations"]["A_baseline_network"]
    cfg_b = report["configurations"]["B_temporal_relational_network"]
    assert cfg_a["macro_f1"] > 0.0
    assert cfg_b["macro_f1"] > 0.0
    assert "confusion_matrix" in cfg_a
    assert "confusion_matrix" in cfg_b


def test_unrelated_endpoint_and_network_events_never_merged():
    """Verify that an endpoint file event on host A and network traffic on host B are never merged."""
    correlator = IncidentCorrelator(time_window_seconds=300)
    t0 = datetime(2026, 10, 9, 14, 0, 0)

    # Endpoint file read on Host A
    alert_ep = Alert(
        alert_id="ALT-EP-01",
        event_id="EV-EP-01",
        created_at=t0,
        layer="endpoint",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.85,
        src_entity="10.0.0.10",
        dst_entity="10.0.0.10",
        raw_event={"event_id": "EV-EP-01", "layer": "endpoint", "process_name": "7z.exe", "timestamp": t0},
    )
    inc_ep, is_new_ep = correlator.correlate_alert(alert_ep)

    # Completely unrelated network transfer on Host B at same time
    alert_net = Alert(
        alert_id="ALT-NET-01",
        event_id="EV-NET-01",
        created_at=t0 + timedelta(seconds=10),
        layer="network",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.90,
        src_entity="10.0.0.20",  # Different host
        dst_entity="203.0.113.99",
        raw_event={"event_id": "EV-NET-01", "layer": "network", "bytes_sent": 5000000, "timestamp": t0 + timedelta(seconds=10)},
    )
    inc_net, is_new_net = correlator.correlate_alert(alert_net)

    assert is_new_ep is True
    assert is_new_net is True
    assert inc_ep.incident_id != inc_net.incident_id, "Unrelated hosts must not be merged merely because they share a threat type"


def test_exfiltration_hypothesis_demarcation():
    """
    CRITICAL EVIDENCE DEMARCATION TEST:
    An endpoint file read followed by a network transfer on the same host must be tagged as an
    INFERRED HYPOTHESIS with explicit uncertainty notes, NOT as a proven physical fact.
    """
    correlator = IncidentCorrelator(time_window_seconds=300)
    t0 = datetime(2026, 10, 9, 14, 0, 0)

    # Step 1: Network connection establishing incident on Host A
    alert_net = Alert(
        alert_id="ALT-NET-01",
        event_id="EV-NET-01",
        created_at=t0,
        layer="network",
        threat_type="data_exfiltration",
        severity="medium",
        confidence=0.75,
        src_entity="10.0.0.30",
        dst_entity="198.51.100.4",
        raw_event={"event_id": "EV-NET-01", "layer": "network", "timestamp": t0},
    )
    inc, _ = correlator.correlate_alert(alert_net)

    # Step 2: Endpoint file read on Host A
    alert_ep = Alert(
        alert_id="ALT-EP-02",
        event_id="EV-EP-02",
        created_at=t0 + timedelta(seconds=15),
        layer="endpoint",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.88,
        src_entity="10.0.0.30",
        dst_entity="10.0.0.30",
        raw_event={"event_id": "EV-EP-02", "layer": "endpoint", "action": "read", "file_path": "/data/confidential.zip", "timestamp": t0 + timedelta(seconds=15)},
    )
    inc_updated, is_new = correlator.correlate_alert(alert_ep)

    assert is_new is False
    assert inc_updated.incident_id == inc.incident_id

    # Inspect the relationship evidence
    rel_entries = inc_updated.relationship_evidence
    assert len(rel_entries) >= 2

    ep_rel = [r for r in rel_entries if r["relationship_type"] == "cross_layer_co_occurrence"][0]
    assert ep_rel["claim_type"] == "hypothesis", "Exfiltration across layers must be tagged as a hypothesis"
    assert "uncertainty_notes" in ep_rel
    assert "exfiltration is an inferred hypothesis" in ep_rel["uncertainty_notes"].lower()
    assert "supporting_event_ids" in ep_rel
    assert "EV-EP-02" in ep_rel["supporting_event_ids"]
    assert ep_rel["timestamp"] is not None


def test_ambiguous_temporal_sequence_missing_evidence():
    """Verify that events with missing timestamps or unknown targets preserve uncertainty."""
    correlator = IncidentCorrelator(time_window_seconds=300)
    t0 = datetime(2026, 10, 9, 14, 0, 0)

    alert_missing = Alert(
        alert_id="ALT-MISSING-01",
        event_id="EV-MISSING-01",
        created_at=t0,
        layer="network",
        threat_type="brute_force",
        severity="medium",
        confidence=0.60,
        src_entity="10.0.0.55",
        dst_entity="unknown_dst",
        raw_event={"event_id": "EV-MISSING-01", "timestamp": None},
    )
    inc, _ = correlator.correlate_alert(alert_missing)

    assert inc.uncertainty_notes is not None
    assert len(inc.uncertainty_notes) > 0
    assert inc.relationship_evidence[0]["correlation_rule"] == "RULE_0_INITIAL_TRIGGER"
