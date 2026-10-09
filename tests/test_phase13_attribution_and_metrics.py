"""
Phase 13 Tests: Process-to-Network Attribution, Telemetry Schema, and Metric Consistency
Covers:
- Mathematical consistency of confusion matrices and classification metrics
- Backward-compatible UnifiedEvent telemetry schema extensions
- Handling of PID reuse, process GUIDs, socket IDs, and host identities
- Evidence-aware incident correlation distinguishing direct socket bindings from hypotheses
- Rejection of PID-based correlation across different hosts
"""

import pytest
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any

from backend.core.schemas import Alert, UnifiedEvent, Incident
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.detection.model_trainer import CANONICAL_CLASSES, calculate_evaluation_metrics


# ── PHASE A: MATHEMATICAL CONSISTENCY OF METRICS ──────────────────────────────

def test_confusion_matrix_and_metrics_mathematical_consistency():
    """
    Verify that TP, FP, FN, Support, Precision, Recall, F1, Balanced Accuracy,
    and Macro-F1 are mathematically consistent with the confusion matrix.
    """
    classes = CANONICAL_CLASSES
    # Realistic multi-class confusion matrix (rows=true, cols=pred)
    # ['benign', 'brute_force', 'lateral_movement', 'data_exfiltration', 'c2_beaconing']
    cm = np.array([
        [407,   2,   1,   0,   0],
        [  0, 498,   0,   0,   0],
        [  0,   0,  61,   0,   0],
        [  0,  33,  87, 239,   0],
        [  0,   0,   0,   0,  72],
    ])
    n_test = int(np.sum(cm))
    assert n_test == 1400

    per_class = {}
    f1s = []
    recalls = []

    for i, cls in enumerate(classes):
        tp = int(cm[i, i])
        fn = int(np.sum(cm[i, :])) - tp
        fp = int(np.sum(cm[:, i])) - tp
        supp = int(np.sum(cm[i, :]))

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / supp if supp > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        per_class[cls] = {"precision": prec, "recall": rec, "f1": f1, "support": supp}
        f1s.append(f1)
        recalls.append(rec)

    # 1. Total support sums exactly to N_test
    assert sum(p["support"] for p in per_class.values()) == n_test

    # 2. Lateral movement metrics check
    lat_metrics = per_class["lateral_movement"]
    assert lat_metrics["support"] == 61
    assert lat_metrics["recall"] == 1.0  # 61 / 61 = 100%
    assert round(lat_metrics["precision"], 4) == round(61 / (61 + 88), 4)  # 61 / 149 = 0.4094
    assert round(lat_metrics["f1"], 4) == round((2 * 0.4094 * 1.0) / (0.4094 + 1.0), 4)  # 0.5810

    # 3. Macro-F1 is unweighted arithmetic mean of per-class F1s
    macro_f1 = float(np.mean(f1s))
    assert round(macro_f1, 4) == 0.8685

    # 4. Balanced accuracy is unweighted arithmetic mean of per-class recalls
    bal_acc = float(np.mean(recalls))
    assert round(bal_acc, 4) == 0.9317


# ── PHASE B: TELEMETRY SCHEMA EXTENSIONS ──────────────────────────────────────

def test_unified_event_backward_compatibility():
    """Verify that existing events without new Phase 13 fields parse cleanly with None defaults."""
    t0 = datetime(2026, 10, 9, 12, 0, 0)
    old_event_dict = {
        "event_id": "legacy-ev-01",
        "timestamp": t0,
        "layer": "network",
        "src_entity": "10.0.0.5",
        "dst_entity": "10.0.0.99",
        "src_internal": True,
        "dst_internal": True,
        "dst_port": 445,
        "protocol": "TCP",
        "bytes_sent": 500,
    }
    event = UnifiedEvent(**old_event_dict)
    assert event.event_id == "legacy-ev-01"
    assert event.host_id is None
    assert event.process_guid is None
    assert event.process_start_time is None
    assert event.process_end_time is None
    assert event.connection_direction is None
    assert event.socket_id is None
    assert event.telemetry_source is None


def test_unified_event_complete_process_socket_identifiers():
    """Verify that events with complete process-to-network fields instantiate correctly."""
    t0 = datetime(2026, 10, 9, 12, 0, 0)
    pstart = t0 - timedelta(seconds=120)
    event = UnifiedEvent(
        event_id="proc-net-ev-01",
        timestamp=t0,
        layer="network",
        src_entity="10.0.0.15",
        dst_entity="198.51.100.22",
        src_internal=True,
        dst_internal=False,
        src_port=49210,
        dst_port=443,
        protocol="TCP",
        bytes_sent=15420,
        process_name="powershell.exe",
        pid=4128,
        parent_pid=1052,
        host_id="WORKSTATION-04",
        process_guid="{d7a2-4128-powershell}",
        process_start_time=pstart,
        connection_direction="outbound",
        socket_id="10.0.0.15:49210->198.51.100.22:443",
        telemetry_source="sysmon",
    )
    assert event.host_id == "WORKSTATION-04"
    assert event.process_guid == "{d7a2-4128-powershell}"
    assert event.process_start_time == pstart
    assert event.socket_id == "10.0.0.15:49210->198.51.100.22:443"
    assert event.connection_direction == "outbound"
    assert event.telemetry_source == "sysmon"


def test_process_id_reuse_disambiguation():
    """
    Verify that two events sharing the same PID on the same host but having
    different process_start_time or process_guid represent distinct process instances.
    """
    t1 = datetime(2026, 10, 9, 10, 0, 0)
    t2 = datetime(2026, 10, 9, 11, 0, 0)

    # Process A: started at 09:55
    ev1 = UnifiedEvent(
        event_id="ev-p1",
        timestamp=t1,
        layer="endpoint",
        src_entity="10.0.0.20",
        dst_entity="10.0.0.20",
        src_internal=True,
        dst_internal=True,
        host_id="HOST-A",
        pid=1234,
        process_name="cmd.exe",
        process_guid="{GUID-01}",
        process_start_time=datetime(2026, 10, 9, 9, 55, 0),
    )

    # Process B: started at 10:50 (reused PID 1234 after Process A exited)
    ev2 = UnifiedEvent(
        event_id="ev-p2",
        timestamp=t2,
        layer="endpoint",
        src_entity="10.0.0.20",
        dst_entity="10.0.0.20",
        src_internal=True,
        dst_internal=True,
        host_id="HOST-A",
        pid=1234,
        process_name="backup.exe",
        process_guid="{GUID-02}",
        process_start_time=datetime(2026, 10, 9, 10, 50, 0),
    )

    assert ev1.pid == ev2.pid
    assert ev1.process_guid != ev2.process_guid
    assert ev1.process_start_time != ev2.process_start_time


# ── PHASE C: EVIDENCE-AWARE CORRELATION REGRESSION ────────────────────────────

def test_exact_process_socket_attribution_verified():
    """
    Verify that an endpoint process event and an outbound network event sharing
    the exact socket_id and host_id are correlated as direct_process_socket_binding
    with claim_type='observation' and empty missing_evidence.
    """
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 14, 0, 0)
    socket_tuple = "10.0.0.12:51234->203.0.113.8:443"

    # Event 1: Endpoint process execution
    alert_proc = Alert(
        alert_id="ALT-PROC-01",
        event_id="EV-PROC-01",
        created_at=t0,
        layer="endpoint",
        threat_type="c2_beaconing",
        severity="high",
        confidence=0.88,
        src_entity="10.0.0.12",
        dst_entity="10.0.0.12",
        raw_event={
            "event_id": "EV-PROC-01",
            "host_id": "HOST-ALPHA",
            "process_name": "beacon.exe",
            "pid": 5012,
            "socket_id": socket_tuple,
            "layer": "endpoint",
        },
    )
    inc, is_new = correlator.correlate_alert(alert_proc)
    assert is_new is True

    # Event 2: Network connection 15 seconds later sharing the same host and socket_id
    alert_net = Alert(
        alert_id="ALT-NET-01",
        event_id="EV-NET-01",
        created_at=t0 + timedelta(seconds=15),
        layer="network",
        threat_type="c2_beaconing",
        severity="high",
        confidence=0.92,
        src_entity="10.0.0.12",
        dst_entity="203.0.113.8",
        raw_event={
            "event_id": "EV-NET-01",
            "host_id": "HOST-ALPHA",
            "socket_id": socket_tuple,
            "layer": "network",
        },
    )
    inc_updated, is_new_net = correlator.correlate_alert(alert_net)
    assert is_new_net is False
    assert inc_updated.incident_id == inc.incident_id

    # Check relationship evidence
    direct_rel = next(r for r in inc_updated.relationship_evidence if r["relationship_type"] == "direct_process_socket_binding")
    assert direct_rel["claim_type"] == "observation"
    assert direct_rel["correlation_rule"] == "RULE_0_DIRECT_PROCESS_SOCKET_BINDING"
    assert direct_rel["missing_evidence"] == []
    assert "Direct socket binding verified" in direct_rel["uncertainty_notes"]


def test_matching_pids_on_different_hosts_never_merged():
    """
    Verify that identical PIDs occurring on different hosts are recognized as
    host-local identifiers and are NEVER merged based on PID.
    """
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 14, 30, 0)

    # Host 1: PID 2048
    alert_host1 = Alert(
        alert_id="ALT-H1",
        event_id="EV-H1",
        created_at=t0,
        layer="endpoint",
        threat_type="brute_force",
        severity="medium",
        confidence=0.85,
        src_entity="10.0.0.10",
        dst_entity="10.0.0.10",
        raw_event={"event_id": "EV-H1", "host_id": "HOST-1", "pid": 2048, "process_name": "hydra.exe"},
    )

    # Host 2: PID 2048 (completely independent machine)
    alert_host2 = Alert(
        alert_id="ALT-H2",
        event_id="EV-H2",
        created_at=t0 + timedelta(seconds=5),
        layer="endpoint",
        threat_type="lateral_movement",
        severity="medium",
        confidence=0.85,
        src_entity="10.0.0.99",
        dst_entity="10.0.0.99",
        raw_event={"event_id": "EV-H2", "host_id": "HOST-2", "pid": 2048, "process_name": "cmd.exe"},
    )

    inc1, is_new1 = correlator.correlate_alert(alert_host1)
    inc2, is_new2 = correlator.correlate_alert(alert_host2)

    assert is_new1 is True
    assert is_new2 is True
    assert inc1.incident_id != inc2.incident_id


def test_pid_reuse_on_same_host_not_correlated():
    """
    Verify that when a process terminates and its PID is reused by an unrelated process
    (indicated by conflicting process_start_time or process_name), the correlator does
    not falsely merge them into the same process lineage.
    """
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 15, 0, 0)

    # Event 1: Attacker staging via cmd.exe PID 3000
    alert_attacker = Alert(
        alert_id="ALT-ATTACKER",
        event_id="EV-ATTACKER",
        created_at=t0,
        layer="endpoint",
        threat_type="lateral_movement",
        severity="high",
        confidence=0.90,
        src_entity="10.0.0.50",
        dst_entity="10.0.0.50",
        raw_event={
            "event_id": "EV-ATTACKER",
            "host_id": "HOST-50",
            "pid": 3000,
            "process_name": "cmd.exe",
            "process_start_time": t0 - timedelta(minutes=10),
        },
    )
    inc1, is_new1 = correlator.correlate_alert(alert_attacker)
    assert is_new1 is True

    # Event 2: Legitimate administrative maintenance reusing PID 3000 with different name and start time
    alert_benign = Alert(
        alert_id="ALT-BENIGN",
        event_id="EV-BENIGN",
        created_at=t0 + timedelta(seconds=30),
        layer="endpoint",
        threat_type="statistical_anomaly",
        severity="low",
        confidence=0.60,
        src_entity="10.0.0.50",
        dst_entity="10.0.0.50",
        raw_event={
            "event_id": "EV-BENIGN",
            "host_id": "HOST-50",
            "pid": 3000,
            "process_name": "trustedinstaller.exe",
            "process_start_time": t0 + timedelta(seconds=20),
        },
    )
    # Because PID 3000 was reused by a different process name and different start time,
    # it must NOT be correlated under RULE_0_PROCESS_LINEAGE_MATCH
    is_related, rule = correlator._is_behaviorally_related(inc1, alert_benign)
    assert rule != "RULE_0_PROCESS_LINEAGE_MATCH"


def test_concurrent_unrelated_processes_on_same_host():
    """
    Verify that when two different processes execute concurrently on the same host
    without socket bindings, an outbound connection is NOT arbitrarily assigned
    to the archiving process.
    """
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 15, 30, 0)

    # Process 1: 7z.exe local archiving
    alert_archive = Alert(
        alert_id="ALT-7Z",
        event_id="EV-7Z",
        created_at=t0,
        layer="endpoint",
        threat_type="data_exfiltration",
        severity="medium",
        confidence=0.75,
        src_entity="10.0.0.33",
        dst_entity="10.0.0.33",
        raw_event={
            "event_id": "EV-7Z",
            "host_id": "HOST-33",
            "process_name": "7z.exe",
            "pid": 1100,
            "action": "read",
        },
    )
    inc, _ = correlator.correlate_alert(alert_archive)

    # Process 2: chrome.exe network connection to internet
    alert_web = Alert(
        alert_id="ALT-WEB",
        event_id="EV-WEB",
        created_at=t0 + timedelta(seconds=10),
        layer="network",
        threat_type="data_exfiltration",
        severity="medium",
        confidence=0.75,
        src_entity="10.0.0.33",
        dst_entity="93.184.216.34",
        raw_event={
            "event_id": "EV-WEB",
            "host_id": "HOST-33",
            "process_name": "chrome.exe",
            "pid": 4500,
            "socket_id": "10.0.0.33:55123->93.184.216.34:443",
        },
    )
    inc_updated, _ = correlator.correlate_alert(alert_web)

    # Must NOT claim direct socket binding between 7z.exe and the web socket
    rel_entries = inc_updated.relationship_evidence
    socket_bindings = [r for r in rel_entries if r["relationship_type"] == "direct_process_socket_binding"]
    # If a socket binding was created, it must tie to chrome.exe, not 7z.exe
    for sb in socket_bindings:
        assert "7z.exe" not in sb["reason"]


def test_co_occurrence_without_socket_remains_hypothesis_with_missing_evidence():
    """
    Verify that when endpoint file reading co-occurs with outbound network traffic
    WITHOUT socket binding telemetry, it is strictly tagged as an inferred hypothesis
    with missing_evidence explicitly listed.
    """
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 16, 0, 0)

    # Outbound network transfer (no process telemetry)
    alert_net = Alert(
        alert_id="ALT-NET-NO-PID",
        event_id="EV-NET-NO-PID",
        created_at=t0,
        layer="network",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.90,
        src_entity="10.0.0.88",
        dst_entity="198.51.100.99",
        raw_event={"event_id": "EV-NET-NO-PID", "host_id": "HOST-88", "dst_port": 443},
    )
    inc, _ = correlator.correlate_alert(alert_net)

    # Endpoint file read (no socket telemetry)
    alert_read = Alert(
        alert_id="ALT-READ-NO-SOCK",
        event_id="EV-READ-NO-SOCK",
        created_at=t0 + timedelta(seconds=20),
        layer="endpoint",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.90,
        src_entity="10.0.0.88",
        dst_entity="10.0.0.88",
        raw_event={"event_id": "EV-READ-NO-SOCK", "host_id": "HOST-88", "process_name": "tar.exe", "pid": 9999},
    )
    inc_updated, _ = correlator.correlate_alert(alert_read)

    cross_layer_rel = next(r for r in inc_updated.relationship_evidence if r["relationship_type"] == "cross_layer_co_occurrence")
    assert cross_layer_rel["claim_type"] == "hypothesis"
    assert "socket_to_pid_binding_absent" in cross_layer_rel["missing_evidence"]
    assert "kernel_handle_lineage_unverified" in cross_layer_rel["missing_evidence"]
    assert "inferred hypothesis, not an established fact" in cross_layer_rel["uncertainty_notes"]
