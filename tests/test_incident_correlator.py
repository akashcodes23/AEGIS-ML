"""
Automated Tests for AEGIS-ML Incident Correlation and Evidence Platform
Tests:
- Event correlation boundaries & sliding time windows
- Related and unrelated event sequences
- Missing timestamps and entity identifiers
- Duplicate event detection & fingerprinting
- Incident ID stability
- Evidence traceability to raw events
- Correct severity & priority calculation
- Observation vs Hypothesis timeline claim separation
- API response validation (incidents, FPR reporting, remediation)
"""

import pytest
from datetime import datetime, timedelta
import uuid

from backend.core.schemas import UnifiedEvent, Alert, Incident
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.explainability.explainer import LocalFeatureExplainer


@pytest.fixture
def correlator():
    return IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)


def create_mock_alert(
    event_id: str = "evt-1",
    threat_type: str = "brute_force",
    severity: str = "medium",
    src_entity: str = "185.220.101.45",
    dst_entity: str = "10.0.0.12",
    timestamp: datetime = None,
    layer: str = "network",
    confidence: float = 0.85,
    anomaly_score: float = 0.70
) -> Alert:
    ts = timestamp or datetime(2026, 10, 9, 12, 0, 0)
    return Alert(
        alert_id=str(uuid.uuid4()),
        event_id=event_id,
        created_at=ts,
        timestamp=ts,
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        classifier_probability=confidence,
        anomaly_score=anomaly_score,
        baseline_deviation=0.65,
        src_entity=src_entity,
        dst_entity=dst_entity,
        layer=layer,
        source_file="test_stream.pcap",
        is_synthetic=True,
    )


def create_mock_event(
    event_id: str = "evt-1",
    src_entity: str = "185.220.101.45",
    dst_entity: str = "10.0.0.12",
    timestamp: datetime = None,
    layer: str = "network",
    bytes_sent: int = 1500,
    dst_port: int = 445
) -> UnifiedEvent:
    ts = timestamp or datetime(2026, 10, 9, 12, 0, 0)
    return UnifiedEvent(
        event_id=event_id,
        timestamp=ts,
        layer=layer,
        src_entity=src_entity,
        dst_entity=dst_entity,
        src_internal=False,
        dst_internal=True,
        dst_port=dst_port,
        bytes_sent=bytes_sent,
    )


# ── 1. Event Correlation Boundaries & Time Windows ─────────────────────────────
def test_correlation_within_time_window(correlator):
    base_time = datetime(2026, 10, 9, 10, 0, 0)
    alert1 = create_mock_alert(event_id="e1", timestamp=base_time)
    inc1, is_new1 = correlator.correlate_alert(alert1)
    assert is_new1 is True

    # Alert 4 minutes later from same attacker within 10-minute window
    alert2 = create_mock_alert(event_id="e2", timestamp=base_time + timedelta(minutes=4))
    inc2, is_new2 = correlator.correlate_alert(alert2)
    assert is_new2 is False
    assert inc2.incident_id == inc1.incident_id
    assert len(inc2.alert_ids) == 2


def test_correlation_outside_time_window(correlator):
    base_time = datetime(2026, 10, 9, 10, 0, 0)
    alert1 = create_mock_alert(event_id="e1", timestamp=base_time)
    inc1, _ = correlator.correlate_alert(alert1)

    # Alert 25 minutes later exceeds the 10-minute window
    alert2 = create_mock_alert(event_id="e2", timestamp=base_time + timedelta(minutes=25))
    inc2, is_new2 = correlator.correlate_alert(alert2)
    assert is_new2 is True
    assert inc2.incident_id != inc1.incident_id


# ── 2. Related vs Unrelated Event Sequences ────────────────────────────────────
def test_lateral_movement_pivot_correlation(correlator):
    """Target of initial stage becomes source of next stage (Pivot)."""
    base_time = datetime(2026, 10, 9, 10, 0, 0)
    # Stage 1: External attacker exploits 10.0.0.12
    a1 = create_mock_alert(event_id="e1", src_entity="185.220.101.45", dst_entity="10.0.0.12", timestamp=base_time)
    inc1, _ = correlator.correlate_alert(a1)

    # Stage 2: Compromised 10.0.0.12 pivots laterally to 10.0.0.99
    a2 = create_mock_alert(
        event_id="e2", threat_type="lateral_movement", severity="high",
        src_entity="10.0.0.12", dst_entity="10.0.0.99",
        timestamp=base_time + timedelta(minutes=2)
    )
    inc2, is_new2 = correlator.correlate_alert(a2)
    assert is_new2 is False
    assert inc2.incident_id == inc1.incident_id
    assert "10.0.0.99" in inc2.affected_entities


def test_unrelated_events_not_grouped(correlator):
    """Completely independent entities within the same time window must NOT be grouped."""
    base_time = datetime(2026, 10, 9, 10, 0, 0)
    a1 = create_mock_alert(event_id="e1", src_entity="185.220.101.45", dst_entity="10.0.0.12", timestamp=base_time)
    inc1, is_new1 = correlator.correlate_alert(a1)

    # Completely different source and destination
    a2 = create_mock_alert(
        event_id="e2", threat_type="c2_beaconing",
        src_entity="192.168.1.50", dst_entity="203.0.113.88",
        timestamp=base_time + timedelta(minutes=1)
    )
    inc2, is_new2 = correlator.correlate_alert(a2)
    assert is_new2 is True
    assert inc1.incident_id != inc2.incident_id


# ── 3. Missing Timestamps and Identifiers ───────────────────────────────────────
def test_missing_timestamps_and_identifiers(correlator):
    a = Alert(
        event_id="",
        threat_type="statistical_anomaly",
        severity="low",
        confidence=0.5,
        src_entity="unknown",
        dst_entity="10.0.0.5",
        layer="network",
    )
    inc, is_new = correlator.correlate_alert(a)
    assert inc is not None
    assert inc.incident_id.startswith("INC-")
    assert inc.primary_target == "10.0.0.5"


# ── 4. Duplicate Event Detection ───────────────────────────────────────────────
def test_event_deduplication(correlator):
    ev1 = create_mock_event(event_id="dup-1")
    fp1 = correlator.compute_event_fingerprint(ev1)

    # First check: not duplicate
    assert correlator.is_duplicate(fp1, ev1.timestamp) is False
    # Second check within dedup window: is duplicate
    assert correlator.is_duplicate(fp1, ev1.timestamp + timedelta(seconds=10)) is True


# ── 5. Incident ID Stability ───────────────────────────────────────────────────
def test_incident_id_stability():
    c1 = IncidentCorrelator()
    c2 = IncidentCorrelator()
    ts = datetime(2026, 10, 9, 14, 30, 0)
    a1 = create_mock_alert(timestamp=ts, src_entity="185.220.101.45", dst_entity="10.0.0.12")
    a2 = create_mock_alert(timestamp=ts, src_entity="185.220.101.45", dst_entity="10.0.0.12")

    inc1, _ = c1.correlate_alert(a1)
    inc2, _ = c2.correlate_alert(a2)
    assert inc1.incident_id == inc2.incident_id


# ── 6. Evidence Traceability ───────────────────────────────────────────────────
def test_evidence_traceability(correlator):
    raw_ev = create_mock_event(event_id="trace-test-101", bytes_sent=99999)
    alert = create_mock_alert(event_id=raw_ev.event_id)
    alert.raw_event = raw_ev.model_dump()

    inc, _ = correlator.correlate_alert(alert, raw_event=raw_ev)
    assert alert.alert_id in inc.alert_ids
    assert len(inc.supporting_events) >= 1
    assert any(e.get("event_id") == "trace-test-101" for e in inc.supporting_events)
    assert any(e.get("bytes_sent") == 99999 for e in inc.supporting_events)


# ── 7. Correct Severity & Priority Calculation ─────────────────────────────────
def test_severity_and_priority_escalation(correlator):
    base_time = datetime(2026, 10, 9, 10, 0, 0)
    a1 = create_mock_alert(severity="medium", timestamp=base_time)
    inc, _ = correlator.correlate_alert(a1)
    initial_priority = inc.priority_score

    # Escalate with critical exfiltration alert
    a2 = create_mock_alert(
        severity="critical", threat_type="data_exfiltration",
        layer="application", timestamp=base_time + timedelta(minutes=2)
    )
    inc_updated, _ = correlator.correlate_alert(a2)
    assert inc_updated.severity == "critical"
    assert inc_updated.priority_score > initial_priority
    assert "application" in inc_updated.layers_involved


# ── 8. Separation of Observations vs Hypotheses ────────────────────────────────
def test_timeline_observation_vs_hypothesis_demarcation(correlator):
    alert = create_mock_alert(threat_type="data_exfiltration")
    raw_ev = create_mock_event(bytes_sent=1048576)
    inc, _ = correlator.correlate_alert(alert, raw_event=raw_ev)

    claims = [t.claim_type for t in inc.timeline]
    assert "observation" in claims
    assert "hypothesis" in claims

    obs = next(t for t in inc.timeline if t.claim_type == "observation")
    hyp = next(t for t in inc.timeline if t.claim_type == "hypothesis")

    # Observation contains factual telemetry
    assert "Observed" in obs.title or "Observed" in obs.description
    # Hypothesis contains model/inferential wording
    assert "Hypothesis" in hyp.title or "classified" in hyp.description


# ── 9. Local Feature Explainer ────────────────────────────────────────────────
def test_local_feature_explainer():
    from backend.detection.threat_classifier import ThreatClassifier
    feature_names = ThreatClassifier.FEATURE_NAMES
    explainer = LocalFeatureExplainer(feature_names=feature_names)

    # A feature vector with high anomaly scores and auth failures
    # Ordering matches ThreatClassifier.FEATURE_NAMES:
    # if_anomaly_score, baseline_deviation, graph_new_connections, failed_auth_rate,
    # connection_frequency, bytes_sent_zscore, bytes_sent_log, bytes_ratio,
    # conn_rate_zscore, dst_port_risk, is_new_destination, is_external_dst,
    # hour_of_day_sin, hour_of_day_cos, cross_layer_match
    features = [
        0.88,   # if_anomaly_score — very high
        0.90,   # baseline_deviation — very high
        0.50,   # graph_new_connections
        15.0,   # failed_auth_rate — high brute force signal
        80.0,   # connection_frequency — very high
        5.0,    # bytes_sent_zscore
        12.5,   # bytes_sent_log
        2.1,    # bytes_ratio
        8.0,    # conn_rate_zscore
        0.8,    # dst_port_risk — high risk port
        1.0,    # is_new_destination — new
        1.0,    # is_external_dst — external
        0.0,    # hour_of_day_sin
        1.0,    # hour_of_day_cos
        0.0,    # cross_layer_match
    ]
    assert len(features) == len(feature_names) == ThreatClassifier.N_FEATURES

    global_importances = {name: 1.0 / len(feature_names) for name in feature_names}
    global_importances["if_anomaly_score"] = 0.25  # High importance
    global_importances["failed_auth_rate"] = 0.20

    explanations = explainer.explain(features, global_importances)
    assert len(explanations) > 0
    # All returned keys must be valid feature names
    assert all(k in feature_names for k in explanations)
    # High anomaly score and auth rate should appear in explanations
    assert "if_anomaly_score" in explanations or "failed_auth_rate" in explanations


def test_explainer_feature_names_aligned():
    """Explainer output keys must be a subset of ThreatClassifier.FEATURE_NAMES."""
    from backend.detection.threat_classifier import ThreatClassifier
    feature_names = ThreatClassifier.FEATURE_NAMES
    explainer = LocalFeatureExplainer(feature_names=feature_names)
    features = [0.5] * len(feature_names)
    # Override some to create deviation
    features[0] = 0.95   # if_anomaly_score
    features[3] = 20.0   # failed_auth_rate
    result = explainer.explain(features, global_importances=None)
    canonical = set(ThreatClassifier.FEATURE_NAMES)
    for key in result:
        assert key in canonical, f"Explainer returned unknown feature key: {key}"


def test_duplicate_relationship_evidence_deduplication(correlator):
    """Verify that recurring alerts between the same entities and rule do not inflate relationship evidence."""
    base_time = datetime(2026, 10, 9, 10, 0, 0)
    a1 = create_mock_alert(
        event_id="evt-dup-1",
        src_entity="10.0.0.10",
        dst_entity="10.0.0.20",
        threat_type="brute_force",
        timestamp=base_time
    )
    inc, is_new = correlator.correlate_alert(a1)
    assert is_new is True
    initial_rel_count = len(inc.relationship_evidence)
    assert initial_rel_count >= 1

    # Correlate a second alert between the same entities on the same rule
    a2 = create_mock_alert(
        event_id="evt-dup-2",
        src_entity="10.0.0.10",
        dst_entity="10.0.0.20",
        threat_type="brute_force",
        timestamp=base_time + timedelta(seconds=30)
    )
    inc_updated, is_new2 = correlator.correlate_alert(a2)
    assert is_new2 is False
    assert inc_updated.incident_id == inc.incident_id
    # Relationship evidence should not have duplicated
    assert len(inc_updated.relationship_evidence) == initial_rel_count

    # The supporting_event_ids in the relationship should include both event IDs
    rel = inc_updated.relationship_evidence[0]
    assert "evt-dup-1" in rel["supporting_event_ids"]
    assert "evt-dup-2" in rel["supporting_event_ids"]

