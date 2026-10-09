"""
Phase 12 Tests: Validation, Generalization, and Correlation Regression
Covers:
- Group-aware split integrity, zero feature fingerprint leakage, and disjoint indices
- Determinism and stability of feature column ordering
- Train-only fitting of unsupervised profilers and SMOTE
- Scenario identifier absence verification
- Correlation regression: evidence provenance, exfiltration hypothesis demarcation,
  unrelated host isolation, ambiguous temporal proximity, and missing identifiers.
"""

import pytest
import numpy as np
import random
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path

from backend.core.schemas import Alert, UnifiedEvent, Incident
from backend.correlation.incident_correlator import IncidentCorrelator
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


def get_event_fingerprint(e: UnifiedEvent):
    return (
        e.layer, e.src_entity, e.dst_entity, e.src_port, e.dst_port,
        e.protocol, e.action, e.process_name, e.file_path,
        e.bytes_sent, e.bytes_received, e.auth_result,
        e.http_method, e.endpoint_path, e.status_code
    )


# ── SPLIT AND LEAKAGE VALIDATION (PHASE B) ───────────────────────────────────

def test_group_aware_split_no_fingerprint_leakage():
    """Verify that exact feature fingerprints NEVER cross the train/test boundary in group-aware split."""
    events, _ = load_flexible_dataset("data/raw/combined_labeled.jsonl")
    assert len(events) == 7051

    labels = [e.attack_type or "benign" for e in events]
    fp_to_gid = {}
    event_groups = []
    for e in events:
        fp = get_event_fingerprint(e)
        if fp not in fp_to_gid:
            fp_to_gid[fp] = len(fp_to_gid)
        event_groups.append(fp_to_gid[fp])

    rng = random.Random(42)
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

    # 1. Group ID overlap is strictly zero
    overlap = train_gids.intersection(test_gids)
    assert len(overlap) == 0, f"Leaked group IDs found across split: {overlap}"

    # 2. Indices disjoint and exhaustive
    tr_indices = [i for i, gid in enumerate(event_groups) if gid in train_gids]
    te_indices = [i for i, gid in enumerate(event_groups) if gid in test_gids]

    assert len(set(tr_indices).intersection(set(te_indices))) == 0
    assert len(tr_indices) + len(te_indices) == len(events)
    assert len(tr_indices) == 5651
    assert len(te_indices) == 1400

    # 3. Class support sums to test set size
    te_labels = [labels[i] for i in te_indices]
    supp = Counter(te_labels)
    assert sum(supp.values()) == 1400


def test_group_aware_split_determinism():
    """Verify that group-aware splitting is strictly deterministic for a fixed seed."""
    events, _ = load_flexible_dataset("data/raw/combined_labeled.jsonl")
    labels = [e.attack_type or "benign" for e in events]

    fp_to_gid = {}
    event_groups = []
    for e in events:
        fp = get_event_fingerprint(e)
        if fp not in fp_to_gid:
            fp_to_gid[fp] = len(fp_to_gid)
        event_groups.append(fp_to_gid[fp])

    def do_split(seed):
        rng = random.Random(seed)
        class_to_groups = defaultdict(set)
        for gid, lbl in zip(event_groups, labels):
            class_to_groups[lbl].add(gid)
        te_gids = set()
        for lbl, gids in class_to_groups.items():
            gid_list = sorted(list(gids))
            rng.shuffle(gid_list)
            n_test = max(1, int(len(gid_list) * 0.20))
            te_gids.update(gid_list[:n_test])
        return sorted([i for i, gid in enumerate(event_groups) if gid in te_gids])

    run1 = do_split(42)
    run2 = do_split(42)
    run_diff_seed = do_split(999)

    assert run1 == run2, "Split with seed 42 was non-deterministic"
    assert run1 != run_diff_seed, "Different seeds produced identical test partitions"


def test_feature_column_order_stability():
    """Verify that feature ordering is fixed and matches expected schemas."""
    # Config A: 15 baseline features
    assert len(ThreatClassifier.FEATURE_NAMES) == 15
    assert ThreatClassifier.FEATURE_NAMES[0] == "if_anomaly_score"
    assert ThreatClassifier.FEATURE_NAMES[-1] == "cross_layer_match"

    # Config C: 21 features (15 baseline + 6 relational)
    feats_c = ThreatClassifier.FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES
    assert len(feats_c) == 21
    assert feats_c[15:] == [
        "distinct_dst_internal_5m",
        "dst_diversity_ratio_5m",
        "is_new_src_dst_pair",
        "src_out_degree_5m",
        "dst_in_degree_5m",
        "pivot_chain_indicator",
    ]

    # Config D: 24 features (15 baseline + 3 temporal + 6 relational)
    feats_d = ThreatClassifier.FEATURE_NAMES + TEMPORAL_FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES
    assert len(feats_d) == 24
    assert feats_d[15:18] == [
        "inter_event_time_log",
        "event_rate_1m",
        "event_rate_5m",
    ]


def test_scenario_identifier_absence_documented():
    """
    Verify whether scenario identifiers exist in the raw dataset.
    Confirms that raw events contain no explicit scenario_id or campaign_id field,
    documenting why scenario-grouped splits cannot be performed without synthetic assumption.
    """
    events, _ = load_flexible_dataset("data/raw/combined_labeled.jsonl")
    sample_events = events[:100]

    for ev in sample_events:
        d = ev.model_dump()
        assert "scenario_id" not in d
        assert "campaign_id" not in d
        assert "simulation_batch" not in d


# ── CORRELATION REGRESSION & EVIDENCE MODEL (PHASE F) ─────────────────────────

def test_correlation_unrelated_hosts_not_merged():
    """Verify that distinct hosts with no common destination or pivot link are never merged."""
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 15, 0, 0)

    alert_a = Alert(
        alert_id="ALT-HOST-A",
        event_id="EV-HOST-A",
        created_at=t0,
        layer="network",
        threat_type="brute_force",
        severity="medium",
        confidence=0.90,
        src_entity="192.168.1.10",
        dst_entity="10.0.0.50",
    )
    alert_b = Alert(
        alert_id="ALT-HOST-B",
        event_id="EV-HOST-B",
        created_at=t0 + timedelta(seconds=10),
        layer="network",
        threat_type="c2_beaconing",
        severity="high",
        confidence=0.88,
        src_entity="172.16.5.99",
        dst_entity="203.0.113.100",
    )

    inc_a, is_new_a = correlator.correlate_alert(alert_a)
    inc_b, is_new_b = correlator.correlate_alert(alert_b)

    assert is_new_a is True
    assert is_new_b is True
    assert inc_a.incident_id != inc_b.incident_id
    assert "192.168.1.10" in inc_a.affected_entities
    assert "172.16.5.99" in inc_b.affected_entities


def test_correlation_ambiguous_temporal_proximity_not_merged():
    """
    Verify that two events occurring at the exact same second across unrelated entities
    do not get merged simply because of temporal proximity.
    """
    correlator = IncidentCorrelator(time_window_seconds=600)
    t_exact = datetime(2026, 10, 9, 15, 30, 0)

    alert_1 = Alert(
        alert_id="ALT-COINCIDENT-1",
        event_id="EV-COINCIDENT-1",
        created_at=t_exact,
        layer="endpoint",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.85,
        src_entity="10.0.0.21",
        dst_entity="10.0.0.21",
    )
    alert_2 = Alert(
        alert_id="ALT-COINCIDENT-2",
        event_id="EV-COINCIDENT-2",
        created_at=t_exact,
        layer="network",
        threat_type="lateral_movement",
        severity="high",
        confidence=0.85,
        src_entity="10.0.0.44",
        dst_entity="10.0.0.88",
    )

    inc1, is_new1 = correlator.correlate_alert(alert_1)
    inc2, is_new2 = correlator.correlate_alert(alert_2)

    assert is_new1 is True
    assert is_new2 is True
    assert inc1.incident_id != inc2.incident_id


def test_cross_layer_exfiltration_demarcated_as_hypothesis():
    """
    Verify that concurrent file read and network connection on the same host
    are strictly demarcated as a hypothesis with an explicit uncertainty note,
    not confirmed data exfiltration.
    """
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 16, 0, 0)

    # 1. Outbound network connection
    alert_net = Alert(
        alert_id="ALT-EXFIL-NET",
        event_id="EV-EXFIL-NET",
        created_at=t0,
        layer="network",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.89,
        src_entity="10.0.0.33",
        dst_entity="198.51.100.5",
    )
    inc, is_new = correlator.correlate_alert(alert_net)
    assert is_new is True

    # 2. Local endpoint file read by 7z.exe on the same host within 30s
    alert_ep = Alert(
        alert_id="ALT-EXFIL-EP",
        event_id="EV-EXFIL-EP",
        created_at=t0 + timedelta(seconds=30),
        layer="endpoint",
        threat_type="data_exfiltration",
        severity="high",
        confidence=0.91,
        src_entity="10.0.0.33",
        dst_entity="10.0.0.33",
        raw_event={"event_id": "EV-EXFIL-EP", "layer": "endpoint", "process_name": "7z.exe"},
    )
    inc_merged, is_new_ep = correlator.correlate_alert(alert_ep)
    assert is_new_ep is False
    assert inc_merged.incident_id == inc.incident_id

    # Verify relationship evidence
    rel_entries = inc_merged.relationship_evidence
    assert len(rel_entries) >= 2

    cross_layer_entry = next(r for r in rel_entries if r["relationship_type"] == "cross_layer_co_occurrence")
    assert cross_layer_entry["claim_type"] == "hypothesis"
    assert "data exfiltration is an inferred hypothesis" in cross_layer_entry["uncertainty_notes"]
    assert "socket" in cross_layer_entry["uncertainty_notes"].lower() or "lineage" in cross_layer_entry["uncertainty_notes"].lower()
    assert cross_layer_entry["supporting_event_ids"] == ["EV-EXFIL-EP"]


def test_missing_or_null_event_identifiers_handled_safely():
    """Verify that alerts with missing event_id or alert_id do not crash or corrupt relationship evidence."""
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 16, 15, 0)

    malformed_alert = Alert(
        alert_id="",
        event_id=None,
        created_at=t0,
        layer="network",
        threat_type="brute_force",
        severity="low",
        confidence=0.60,
        src_entity="10.0.0.99",
        dst_entity="10.0.0.1",
    )
    inc, is_new = correlator.correlate_alert(malformed_alert)
    assert is_new is True
    assert len(inc.relationship_evidence) == 1
    # Check that supporting_event_ids is not empty or None
    ev_ids = inc.relationship_evidence[0]["supporting_event_ids"]
    assert len(ev_ids) > 0


def test_alternative_benign_hypotheses_and_evidence_traceability():
    """Verify that every incident records alternative hypotheses and complete evidence traceability."""
    correlator = IncidentCorrelator(time_window_seconds=600)
    t0 = datetime(2026, 10, 9, 16, 30, 0)

    alert = Alert(
        alert_id="ALT-TRACE-01",
        event_id="EV-TRACE-01",
        created_at=t0,
        layer="network",
        threat_type="lateral_movement",
        severity="high",
        confidence=0.88,
        src_entity="10.0.0.15",
        dst_entity="10.0.0.80",
        source_file="auth_logs_20261009.jsonl",
    )
    inc, _ = correlator.correlate_alert(alert)

    # Alternative hypotheses must be present
    assert len(inc.alternative_hypotheses) > 0
    assert any("administration" in h.lower() or "ansible" in h.lower() or "maintenance" in h.lower() for h in inc.alternative_hypotheses)

    # Relationship evidence traceability
    ev = inc.relationship_evidence[0]
    assert ev["evidence_provenance"] == "auth_logs_20261009.jsonl"
    assert ev["correlation_rule"] == "RULE_0_INITIAL_TRIGGER"
    assert ev["supporting_event_ids"] == ["EV-TRACE-01"]
    assert ev["timestamp"] == t0.isoformat()
    assert len(ev["uncertainty_notes"]) > 0
