"""
Phase 10 Regression Tests: Temporal and Graph-Aware Threat Detection
Tests causal ordering, zero future lookahead, edge cases, stability, and API compatibility.
"""

import pytest
from datetime import datetime, timedelta
import numpy as np
import copy

from backend.core.schemas import UnifiedEvent
from backend.detection.temporal_graph_extractor import (
    CausalTemporalGraphTracker,
    TEMPORAL_FEATURE_NAMES,
    RELATIONAL_GRAPH_FEATURE_NAMES,
    ALL_EXTENDED_FEATURE_NAMES,
)
from backend.detection.threat_classifier import ThreatClassifier, ThreatPrediction


def make_dummy_event(
    event_id: str,
    timestamp: datetime,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_internal: bool = True,
    dst_internal: bool = True,
    layer: str = "network",
) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_entity=src,
        dst_entity=dst,
        src_internal=src_internal,
        dst_internal=dst_internal,
        layer=layer,
        src_port=49152,
        dst_port=445,
        protocol="TCP",
        bytes_sent=256,
        bytes_received=512,
        connections_per_minute=10.0,
        raw_label="benign",
    )


def test_causal_temporal_feature_calculation():
    """Verify inter-event interval and rolling burst rates are computed correctly."""
    t0 = datetime(2026, 10, 9, 10, 0, 0)
    e1 = make_dummy_event("e1", t0, src="10.0.0.1", dst="10.0.0.2")
    e2 = make_dummy_event("e2", t0 + timedelta(seconds=10), src="10.0.0.1", dst="10.0.0.3")

    tracker = CausalTemporalGraphTracker()
    f1 = tracker.extract_features_single(e1)
    f2 = tracker.extract_features_single(e2)

    # First event has default log interval ~ 6.0 and rate = 0 (before e1)
    assert f1["event_rate_1m"] == 0.0
    assert f1["event_rate_5m"] == 0.0

    # Second event 10s later sees e1 in 1m window and interval ~ log(1 + 10)
    assert f2["event_rate_1m"] == 1.0
    assert f2["event_rate_5m"] == 1.0
    assert np.isclose(f2["inter_event_time_log"], np.log1p(10.0), atol=1e-3)


def test_no_future_event_leakage():
    """
    CRITICAL CAUSALITY TEST:
    Event e1's features must be strictly identical whether future events e2, e3 exist or not.
    """
    t0 = datetime(2026, 10, 9, 10, 0, 0)
    e1 = make_dummy_event("e1", t0, src="10.0.0.10", dst="10.0.0.20")
    e2 = make_dummy_event("e2", t0 + timedelta(seconds=5), src="10.0.0.10", dst="10.0.0.21")
    e3 = make_dummy_event("e3", t0 + timedelta(seconds=15), src="10.0.0.10", dst="10.0.0.22")

    # Sequence with only e1
    tracker_single = CausalTemporalGraphTracker()
    feats_single = tracker_single.extract_sequence([e1])[0]

    # Sequence with e1 followed by future events
    tracker_multi = CausalTemporalGraphTracker()
    feats_multi = tracker_multi.extract_sequence([e1, e2, e3])[0]

    for k in ALL_EXTENDED_FEATURE_NAMES:
        assert feats_single[k] == feats_multi[k], f"Feature {k} leaked future event information!"


def test_stable_feature_ordering():
    """Verify feature ordering is deterministic and matches constant specifications."""
    assert TEMPORAL_FEATURE_NAMES == ["inter_event_time_log", "event_rate_1m", "event_rate_5m"]
    assert len(RELATIONAL_GRAPH_FEATURE_NAMES) == 6
    assert len(ALL_EXTENDED_FEATURE_NAMES) == 9

    tracker = CausalTemporalGraphTracker()
    e = make_dummy_event("e1", datetime(2026, 10, 9, 12, 0, 0))
    feats = tracker.extract_features_single(e)
    for name in ALL_EXTENDED_FEATURE_NAMES:
        assert name in feats
        assert isinstance(feats[name], float)


def test_missing_timestamps_safe():
    """Verify missing timestamps do not crash and produce safe default features."""
    e_no_time = make_dummy_event("e_no_time", timestamp=datetime.utcnow(), src="10.0.0.5", dst="10.0.0.6")
    e_no_time.timestamp = None

    tracker = CausalTemporalGraphTracker()
    feats = tracker.extract_features_single(e_no_time)
    assert feats["inter_event_time_log"] == 6.0
    assert feats["event_rate_1m"] == 0.0
    assert feats["is_new_src_dst_pair"] == 1.0


def test_unknown_and_unseen_entities():
    """Verify unknown and blank entity names are handled gracefully without KeyError."""
    e_blank = make_dummy_event("e_blank", datetime(2026, 10, 9, 10, 0, 0), src="", dst="")
    tracker = CausalTemporalGraphTracker()
    feats = tracker.extract_features_single(e_blank)
    assert feats["src_out_degree_5m"] == 0.0
    assert feats["dst_in_degree_5m"] == 0.0


def test_duplicate_events_handling():
    """Verify identical duplicate events increment counts monotonically without failure."""
    t0 = datetime(2026, 10, 9, 10, 0, 0)
    e1 = make_dummy_event("e1", t0, src="10.0.0.1", dst="10.0.0.2")
    e1_dup = make_dummy_event("e1_dup", t0 + timedelta(seconds=1), src="10.0.0.1", dst="10.0.0.2")

    tracker = CausalTemporalGraphTracker()
    feats1 = tracker.extract_features_single(e1)
    feats2 = tracker.extract_features_single(e1_dup)

    assert feats1["is_new_src_dst_pair"] == 1.0
    assert feats2["is_new_src_dst_pair"] == 0.0  # Already observed in e1!
    assert feats2["event_rate_1m"] == 1.0


def test_unseen_destinations_relational_flag():
    """Verify distinct internal destination count and pair novelty flag correctly track fan-out."""
    t0 = datetime(2026, 10, 9, 10, 0, 0)
    events = [
        make_dummy_event(f"e{i}", t0 + timedelta(seconds=i * 5), src="10.0.0.100", dst=f"10.0.0.{i}", dst_internal=True)
        for i in range(1, 6)
    ]

    tracker = CausalTemporalGraphTracker()
    seq_feats = tracker.extract_sequence(events)

    # Fifth event should see 4 previous distinct internal destinations in 5m
    assert seq_feats[4]["distinct_dst_internal_5m"] == 4.0
    assert seq_feats[4]["src_out_degree_5m"] == 4.0
    assert seq_feats[4]["is_new_src_dst_pair"] == 1.0  # (100 -> 5) is newly observed


def test_train_test_isolation():
    """Verify fit_baseline_pairs establishes known pairs without polluting rolling streaming state."""
    train_ev = [
        make_dummy_event("tr1", datetime(2026, 10, 9, 8, 0, 0), src="10.0.0.1", dst="10.0.0.2"),
        make_dummy_event("tr2", datetime(2026, 10, 9, 8, 5, 0), src="10.0.0.1", dst="10.0.0.3"),
    ]
    tracker = CausalTemporalGraphTracker()
    tracker.fit_baseline_pairs(train_ev)

    # Windows must be completely empty initially
    assert len(tracker.events_1m) == 0
    assert len(tracker.events_5m) == 0
    assert len(tracker.last_seen) == 0

    # Known pair from train should have is_new_src_dst_pair = 0.0
    test_ev = make_dummy_event("te1", datetime(2026, 10, 9, 12, 0, 0), src="10.0.0.1", dst="10.0.0.2")
    feats = tracker.extract_features_single(test_ev)
    assert feats["is_new_src_dst_pair"] == 0.0

    # Novel pair in test should have is_new_src_dst_pair = 1.0
    novel_ev = make_dummy_event("te2", datetime(2026, 10, 9, 12, 1, 0), src="10.0.0.1", dst="10.0.0.99")
    feats_novel = tracker.extract_features_single(novel_ev)
    assert feats_novel["is_new_src_dst_pair"] == 1.0


def test_reproducibility():
    """Verify two independent tracker instances on the same event sequence produce identical output."""
    t0 = datetime(2026, 10, 9, 10, 0, 0)
    events = [
        make_dummy_event(f"e{i}", t0 + timedelta(seconds=i * 12), src=f"10.0.0.{i%3}", dst=f"10.0.0.{i%5}")
        for i in range(20)
    ]

    tracker1 = CausalTemporalGraphTracker()
    tracker2 = CausalTemporalGraphTracker()

    feats1 = tracker1.extract_sequence(events)
    feats2 = tracker2.extract_sequence(events)

    for f1, f2 in zip(feats1, feats2):
        for k in ALL_EXTENDED_FEATURE_NAMES:
            assert f1[k] == f2[k]


def test_existing_api_compatibility():
    """Verify ThreatClassifier maintains full backward compatibility with default 15 features and extended sets."""
    clf_default = ThreatClassifier(random_state=42)
    assert clf_default.n_features == 15
    assert len(clf_default.feature_names) == 15

    # Fits and predicts on 15 features
    X_15 = np.random.RandomState(42).randn(10, 15)
    y = np.array(["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"] * 2)
    clf_default.fit(X_15, y)

    pred = clf_default.predict([0.1] * 15)
    assert isinstance(pred, ThreatPrediction)
    assert pred.threat_type in ThreatClassifier.CLASSES

    # Extended classifier with 24 features
    clf_extended = ThreatClassifier(random_state=42, feature_names=ThreatClassifier.FEATURE_NAMES + ALL_EXTENDED_FEATURE_NAMES)
    assert clf_extended.n_features == 24
    X_24 = np.random.RandomState(42).randn(10, 24)
    clf_extended.fit(X_24, y)
    pred_ext = clf_extended.predict([0.1] * 24)
    assert isinstance(pred_ext, ThreatPrediction)
    assert pred_ext.threat_type in ThreatClassifier.CLASSES
