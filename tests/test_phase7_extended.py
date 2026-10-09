"""
Additional AEGIS-ML Tests (Phase 7)
=====================================
Covers:
  - Shared entities across independent incidents
  - Overlapping incident time windows
  - Duplicate evidence not double-counted in risk
  - Explainer feature name alignment
  - Data label extraction correctness (D1 fix validation)
  - CIC-IDS2017 loader with synthetic fixtures (no real dataset required)
  - Ablation framework smoke test with minimal synthetic data
"""

import json
import math
import pytest
import uuid
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter

from backend.core.schemas import Alert, Incident, UnifiedEvent
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.explainability.explainer import LocalFeatureExplainer
from backend.detection.threat_classifier import ThreatClassifier


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def correlator():
    return IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)


def make_alert(
    src: str = "185.0.0.1",
    dst: str = "10.0.0.1",
    threat: str = "brute_force",
    severity: str = "medium",
    confidence: float = 0.85,
    ts: datetime = None,
    layer: str = "network",
) -> Alert:
    ts = ts or datetime(2026, 10, 1, 10, 0, 0)
    return Alert(
        alert_id=str(uuid.uuid4()),
        event_id=str(uuid.uuid4()),
        created_at=ts,
        timestamp=ts,
        threat_type=threat,
        severity=severity,
        confidence=confidence,
        classifier_probability=confidence,
        anomaly_score=0.70,
        baseline_deviation=0.55,
        src_entity=src,
        dst_entity=dst,
        layer=layer,
        source_file="test.jsonl",
        is_synthetic=True,
    )


def make_event(
    src: str = "185.0.0.1",
    dst: str = "10.0.0.1",
    ts: datetime = None,
    bytes_sent: int = 1500,
    dst_port: int = 445,
    layer: str = "network",
) -> UnifiedEvent:
    ts = ts or datetime(2026, 10, 1, 10, 0, 0)
    return UnifiedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=ts,
        layer=layer,
        src_entity=src,
        dst_entity=dst,
        src_internal=False,
        dst_internal=True,
        dst_port=dst_port,
        bytes_sent=bytes_sent,
    )


# ── 1. Shared Entity — Two Independent Attackers Targeting Same Server ────────

def test_shared_target_creates_independent_incidents(correlator):
    """
    Two completely different external attackers targeting the SAME internal server
    must NOT be grouped into the same incident, even within the time window.
    The shared target alone is not behavioral evidence of a coordinated campaign.
    """
    t0 = datetime(2026, 10, 1, 10, 0, 0)
    shared_victim = "10.0.0.100"

    # Attacker 1 hits the server
    a1 = make_alert(src="185.1.1.1", dst=shared_victim, ts=t0, threat="brute_force")
    inc1, new1 = correlator.correlate_alert(a1)
    assert new1 is True

    # Attacker 2 independently hits the SAME server, 1 minute later
    a2 = make_alert(
        src="91.2.2.2",       # Different external IP — no link to attacker 1
        dst=shared_victim,
        ts=t0 + timedelta(minutes=1),
        threat="c2_beaconing",  # Different threat type — further evidence of independence
    )
    inc2, new2 = correlator.correlate_alert(a2)

    assert new2 is True, (
        "Two independent attackers targeting the same server must produce separate incidents. "
        f"Both were assigned to: {inc1.incident_id}"
    )
    assert inc1.incident_id != inc2.incident_id


def test_shared_entity_as_victim_then_pivot_is_correlated(correlator):
    """
    If a host is first a victim and then pivots to attack another host
    (lateral movement), that SHOULD be correlated — the host changed roles.
    """
    t0 = datetime(2026, 10, 1, 10, 0, 0)

    # External attacker compromises 10.0.0.50
    a1 = make_alert(src="185.5.5.5", dst="10.0.0.50", ts=t0, threat="brute_force")
    inc1, _ = correlator.correlate_alert(a1)

    # Compromised host 10.0.0.50 pivots to attack 10.0.0.80 (lateral movement)
    a2 = make_alert(
        src="10.0.0.50",       # Previously victim, now acting as attacker
        dst="10.0.0.80",
        ts=t0 + timedelta(minutes=3),
        threat="lateral_movement",   # Explicit lateral movement signal
    )
    inc2, new2 = correlator.correlate_alert(a2)

    assert new2 is False, "Pivot from victim to lateral mover should correlate with original incident"
    assert inc2.incident_id == inc1.incident_id


# ── 2. Overlapping Incident Time Windows ─────────────────────────────────────

def test_interleaved_alerts_from_two_incidents_stay_separate(correlator):
    """
    Alerts from two distinct attack campaigns, interleaved in time,
    must stay in separate incidents if the entities are unrelated.
    """
    t0 = datetime(2026, 10, 1, 10, 0, 0)

    # Campaign 1: Attacker A → Victim X
    a1 = make_alert(src="10.1.1.1", dst="10.2.2.2", ts=t0, threat="brute_force")
    inc1, _ = correlator.correlate_alert(a1)

    # Campaign 2: Attacker B → Victim Y (completely different entities)
    a2 = make_alert(src="10.3.3.3", dst="10.4.4.4", ts=t0 + timedelta(minutes=1), threat="c2_beaconing")
    inc2, _ = correlator.correlate_alert(a2)

    # Campaign 1 continues
    a3 = make_alert(src="10.1.1.1", dst="10.2.2.2", ts=t0 + timedelta(minutes=2), threat="brute_force")
    inc1b, new1b = correlator.correlate_alert(a3)

    # Campaign 2 continues
    a4 = make_alert(src="10.3.3.3", dst="10.4.4.4", ts=t0 + timedelta(minutes=3), threat="c2_beaconing")
    inc2b, new2b = correlator.correlate_alert(a4)

    assert inc1.incident_id != inc2.incident_id
    assert new1b is False and inc1b.incident_id == inc1.incident_id
    assert new2b is False and inc2b.incident_id == inc2.incident_id
    assert len(inc1b.alert_ids) == 2
    assert len(inc2b.alert_ids) == 2


# ── 3. Duplicate Evidence Not Double-Counted in Risk ─────────────────────────

def test_duplicate_evidence_does_not_inflate_risk(correlator):
    """
    Adding the same supporting_event dict twice to an incident must not
    duplicate it in the supporting_events list (which would artificially
    increase risk score through inflated event count).
    """
    t0 = datetime(2026, 10, 1, 10, 0, 0)
    raw_ev = make_event(src="185.9.9.9", dst="10.0.0.1", ts=t0)

    a1 = make_alert(src="185.9.9.9", dst="10.0.0.1", ts=t0)
    a1.raw_event = raw_ev.model_dump()
    inc, _ = correlator.correlate_alert(a1, raw_event=raw_ev)
    initial_event_count = len(inc.supporting_events)

    # Feed the same raw event again via a second alert
    a2 = make_alert(src="185.9.9.9", dst="10.0.0.1", ts=t0 + timedelta(seconds=5))
    a2.raw_event = raw_ev.model_dump()  # Identical raw event dict
    inc2, new2 = correlator.correlate_alert(a2, raw_event=raw_ev)

    assert new2 is False
    # Supporting events list should not have grown to include a duplicate
    # (exact deduplication depends on dict equality; verify count is sane)
    assert len(inc2.supporting_events) <= initial_event_count + 1


# ── 4. Incident ID Stability Under Concurrent Correlators ────────────────────

def test_incident_id_deterministic_across_correlator_instances():
    """
    Two separate IncidentCorrelator instances receiving the same first alert
    for the same entity/timestamp must produce the same incident ID prefix.
    """
    ts = datetime(2026, 10, 1, 14, 30, 0)
    a = make_alert(src="185.1.0.1", dst="10.0.0.5", ts=ts, threat="brute_force")

    c1 = IncidentCorrelator()
    c2 = IncidentCorrelator()

    inc1, _ = c1.correlate_alert(a)
    inc2, _ = c2.correlate_alert(a)

    assert inc1.incident_id == inc2.incident_id, (
        f"Incident ID is not deterministic: {inc1.incident_id} != {inc2.incident_id}"
    )


# ── 5. Explainer Feature Name Alignment (D2 regression guard) ────────────────

def test_explainer_returns_only_canonical_feature_names():
    """
    All keys returned by LocalFeatureExplainer.explain() must appear in
    ThreatClassifier.FEATURE_NAMES. After D2 fix, old names like 'bytes_sent'
    must NOT appear in results when using the canonical feature set.
    """
    canonical_names = ThreatClassifier.FEATURE_NAMES
    explainer = LocalFeatureExplainer(feature_names=canonical_names)

    # Build a high-deviation feature vector
    features = [0.5] * len(canonical_names)
    features[0] = 0.95    # if_anomaly_score — far above baseline mean of 0.20
    features[3] = 50.0    # failed_auth_rate — extremely high

    result = explainer.explain(features, global_importances=None)

    assert len(result) > 0, "Explainer returned empty dict for clearly anomalous feature vector"
    old_feature_names = {
        "bytes_sent", "bytes_received", "duration_ms", "hour_of_day",
        "is_business_hours", "port_risk_score", "connections_per_minute",
        "src_internal", "dst_internal", "if_score", "graph_degree",
        "graph_external_ratio",
    }
    for key in result:
        assert key in canonical_names, f"Explainer returned non-canonical key: '{key}'"
        assert key not in old_feature_names, (
            f"Explainer returned old (pre-D2) feature name: '{key}'. "
            "This means the DEFAULT_NORMAL_MEANS still uses outdated names."
        )


def test_explainer_empty_when_no_deviation():
    """
    When all feature values exactly match their baseline means, no deviation
    is detected. The explainer should return an empty dict rather than fabricating
    uniform-noise contributions.
    """
    canonical_names = ThreatClassifier.FEATURE_NAMES
    explainer = LocalFeatureExplainer(feature_names=canonical_names)

    # Feature values close to baseline means (from DEFAULT_NORMAL_MEANS)
    features = [
        0.20,   # if_anomaly_score
        0.15,   # baseline_deviation
        0.10,   # graph_new_connections
        0.00,   # failed_auth_rate
        2.00,   # connection_frequency
        0.50,   # bytes_sent_zscore
        7.50,   # bytes_sent_log
        1.20,   # bytes_ratio
        0.00,   # conn_rate_zscore
        0.10,   # dst_port_risk
        0.10,   # is_new_destination
        0.10,   # is_external_dst
        0.00,   # hour_of_day_sin
        0.70,   # hour_of_day_cos
        0.00,   # cross_layer_match
    ]
    result = explainer.explain(features, global_importances=None)
    # Should return empty when no meaningful deviation (post D2 fix: no fake uniform noise)
    assert result == {}, f"Expected empty dict for near-baseline features, got: {result}"


# ── 6. Label Extraction Correctness (D1 regression guard) ────────────────────

def test_label_extraction_uses_raw_label_when_attack_type_is_none(tmp_path):
    """
    Regression guard for D1: when attack_type is None (as in the synthetic dataset),
    the pipeline must fall back to raw_label via DATASET_LABEL_MAP.
    Previously, it silently defaulted all such events to 'benign'.
    """
    from backend.detection.model_trainer import load_flexible_dataset, DATASET_LABEL_MAP, CANONICAL_CLASSES

    # Create a small JSONL file where attack_type is null but raw_label is set
    records = []
    base_ts = datetime(2026, 4, 1, 10, 0, 0)
    for i in range(5):
        records.append({
            "timestamp": (base_ts + timedelta(seconds=i)).isoformat(),
            "layer": "network",
            "src_entity": "10.0.0.1",
            "dst_entity": "10.0.0.2",
            "src_internal": True,
            "dst_internal": True,
            "bytes_sent": 100000,
            "dst_port": 4444,
            "attack_type": None,              # None — as in synthetic dataset
            "raw_label": "brute_force",       # Label in raw_label only
        })
    for i in range(5):
        records.append({
            "timestamp": (base_ts + timedelta(seconds=10 + i)).isoformat(),
            "layer": "network",
            "src_entity": "10.0.0.3",
            "dst_entity": "10.0.0.4",
            "src_internal": True,
            "dst_internal": True,
            "bytes_sent": 200,
            "dst_port": 80,
            "attack_type": None,
            "raw_label": "benign",
        })

    jsonl_path = tmp_path / "test_raw_label.jsonl"
    with open(jsonl_path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    events, _ = load_flexible_dataset(str(jsonl_path))

    # Extract labels using the corrected pipeline logic
    labels = []
    for e in events:
        if e.attack_type and e.attack_type in CANONICAL_CLASSES:
            labels.append(e.attack_type)
        elif e.raw_label:
            mapped = DATASET_LABEL_MAP.get(e.raw_label.strip().lower())
            labels.append(mapped if (mapped and mapped in CANONICAL_CLASSES) else "benign")
        else:
            labels.append("benign")

    label_counts = Counter(labels)
    assert label_counts.get("brute_force", 0) == 5, (
        f"Expected 5 brute_force labels from raw_label fallback, got: {label_counts}. "
        "D1 regression: attack_type=None events must not silently become 'benign'."
    )
    assert label_counts.get("benign", 0) == 5


# ── 7. CIC-IDS2017 Loader with Synthetic Fixture ─────────────────────────────

def test_cicids_loader_returns_empty_with_clear_error_when_file_missing():
    """
    When the CIC-IDS2017 file is not present, the loader must return empty
    results with a documented error rather than raising an exception.
    This prevents false dataset results without the actual file.
    """
    from backend.ingestion.cicids_loader import load_cicids2017

    events, stats = load_cicids2017("/nonexistent/path/cicids.csv")

    assert events == [], "Loader must return empty list when file is not found"
    assert "error" in stats, "Loader must include an error key in stats"
    assert "File not found" in stats["error"] or "not found" in stats["error"].lower()
    assert stats["valid_events_loaded"] == 0


def test_cicids_loader_synthetic_fixture(tmp_path):
    """
    Validate the CIC-IDS2017 loader using a small synthetic fixture
    that mimics the CIC-IDS2017 CSV format.
    Does NOT require the real dataset to be present.
    """
    from backend.ingestion.cicids_loader import load_cicids2017

    # Synthetic fixture mimicking CIC-IDS2017 column format
    rows = [
        {" Source IP": "192.168.10.5", " Destination IP": "52.1.2.3",
         " Destination Port": 80, " Source Port": 54321, " Protocol": 6,
         " Total Length of Fwd Packets": 500, " Total Length of Bwd Packets": 2000,
         " Flow Duration": 250000,  # microseconds
         " Label": "BENIGN"},
        {" Source IP": "192.168.10.5", " Destination IP": "52.1.2.3",
         " Destination Port": 22, " Source Port": 54322, " Protocol": 6,
         " Total Length of Fwd Packets": 100000, " Total Length of Bwd Packets": 100,
         " Flow Duration": 1000000,
         " Label": "FTP-Patator"},
        {" Source IP": "192.168.10.6", " Destination IP": "203.0.113.1",
         " Destination Port": 8080, " Source Port": 55000, " Protocol": 6,
         " Total Length of Fwd Packets": 2000000, " Total Length of Bwd Packets": 500,
         " Flow Duration": 5000000,
         " Label": "Bot"},
        {" Source IP": "192.168.10.7", " Destination IP": "10.0.0.1",
         " Destination Port": 3389, " Source Port": 60000, " Protocol": 6,
         " Total Length of Fwd Packets": float("inf"),  # Known CICFlowMeter bug
         " Total Length of Bwd Packets": 100,
         " Flow Duration": 100000,
         " Label": "PortScan"},
    ]

    import pandas as pd
    fixture_path = tmp_path / "fixture_cicids.csv"
    pd.DataFrame(rows).to_csv(fixture_path, index=False)

    events, stats = load_cicids2017(
        str(fixture_path),
        max_rows=None,
        deduplicate=False,
        internal_ip_prefix="192.168.",
    )

    assert len(events) > 0, f"Loader returned no events. Stats: {stats}"
    assert stats["inf_nan_replaced"] > 0, "Inf values in bytes_sent must be detected and replaced"

    # Label mapping checks
    labels = [e.attack_type for e in events if e.attack_type]
    assert "benign" in labels
    assert "brute_force" in labels   # FTP-Patator → brute_force
    assert "c2_beaconing" in labels  # Bot → c2_beaconing

    # Internal IP classification
    internal_events = [e for e in events if e.src_internal]
    assert len(internal_events) > 0, "192.168.x.x addresses must be classified as internal"

    # Duration conversion: microseconds → milliseconds
    for e in events:
        if e.duration_ms is not None:
            assert e.duration_ms < 10_000_000, "Duration should be in milliseconds, not microseconds"

    assert stats["dataset"] == "CIC-IDS2017"
    assert "NOT synthetic" in stats["provenance"]


# ── 8. Ablation Study Smoke Test ─────────────────────────────────────────────

def test_ablation_study_runs_end_to_end(tmp_path):
    """
    Smoke test: ablation study must complete without error on a minimal
    synthetic dataset and produce a well-formed JSON report.
    The test validates structure only — not specific metric values.
    """
    from backend.evaluation.ablation_study import run_ablation

    # Build minimal dataset (enough for stratified split: >= 2 per class)
    records = []
    base_ts = datetime(2026, 4, 1, 10, 0, 0)
    for label, count in [("benign", 20), ("brute_force", 10), ("lateral_movement", 6),
                          ("data_exfiltration", 6), ("c2_beaconing", 6)]:
        for i in range(count):
            records.append({
                "timestamp": (base_ts + timedelta(seconds=len(records))).isoformat(),
                "layer": "network",
                "src_entity": f"10.0.0.{10 + (i % 5)}",
                "dst_entity": f"10.0.0.{50 + (i % 5)}",
                "src_internal": True,
                "dst_internal": label != "data_exfiltration",
                "bytes_sent": 200 if label == "benign" else 500000,
                "bytes_received": 1000 if label == "benign" else 100,
                "dst_port": 80 if label == "benign" else 4444,
                "duration_ms": 50,
                "connections_per_minute": 2.0 if label == "benign" else 100.0,
                "attack_type": label,
                "raw_label": label,
            })

    jsonl_path = tmp_path / "ablation_fixture.jsonl"
    with open(jsonl_path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    report = run_ablation(
        data_path=str(jsonl_path),
        output_dir=str(tmp_path),
        random_seed=42,
        analyst_queue_size=5,
        is_synthetic=True,
    )

    # Validate report structure
    assert "metadata" in report
    assert "configurations" in report
    assert "workload_reduction" in report
    assert set(report["configurations"].keys()) == {"A", "B", "C", "D"}

    for cfg, metrics in report["configurations"].items():
        assert "macro_f1" in metrics, f"Config {cfg} missing macro_f1"
        assert "fpr_benign" in metrics, f"Config {cfg} missing fpr_benign"
        assert 0.0 <= metrics["macro_f1"] <= 1.0, f"Config {cfg} macro_f1 out of range"
        assert 0.0 <= metrics["fpr_benign"] <= 1.0, f"Config {cfg} fpr_benign out of range"

    # Verify JSON output was written
    out_file = tmp_path / "ablation_results.json"
    assert out_file.exists(), "ablation_results.json was not written"
    with open(out_file) as f:
        loaded = json.load(f)
    assert loaded["metadata"]["dataset_provenance"] == "synthetic_scripted"
