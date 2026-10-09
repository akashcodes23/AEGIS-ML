import math
import pytest
from datetime import datetime, timedelta

from backend.core.schemas import UnifiedEvent
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.model_trainer import extract_features, calculate_failed_auth_rate


def test_extract_features_length_and_ordering():
    event = UnifiedEvent(
        timestamp=datetime(2026, 4, 1, 14, 30, 0),
        layer="network",
        src_entity="10.0.0.1",
        dst_entity="10.0.0.2",
        src_internal=True,
        dst_internal=False,
        bytes_sent=1024,
        bytes_received=2048,
        dst_port=445,
        connections_per_minute=25.0
    )

    profiler = BehavioralBaselineProfiler()
    profiler.profiles["10.0.0.1"] = {
        "typical_hours": [14],
        "avg_bytes_sent": 1000.0,
        "std_bytes_sent": 50.0,
        "typical_destinations": ["10.0.0.2"],
        "typical_processes": [],
        "avg_connections_per_min": 20.0,
        "is_service_account": False
    }

    features = extract_features(
        event=event,
        if_score=0.45,
        baseline_deviation=0.20,
        profiler=profiler,
        failed_auth_rate=2.0,
        graph_new_connections=1.0
    )

    # 1. Exact length
    assert len(features) == ThreatClassifier.N_FEATURES
    assert len(features) == 15

    # 2. Exact ordering verification
    assert features[0] == 0.45                 # if_anomaly_score
    assert features[1] == 0.20                 # baseline_deviation
    assert features[2] == 1.0                  # graph_new_connections
    assert features[3] == 2.0                  # failed_auth_rate
    assert features[4] == 25.0                 # connection_frequency
    # bytes_sent_zscore = abs(1024 - 1000) / 50 = 24 / 50 = 0.48
    assert pytest.approx(features[5], 0.01) == 0.48
    # bytes_sent_log = log1p(1024)
    assert pytest.approx(features[6], 0.01) == math.log1p(1024)
    # bytes_ratio = log1p(1024) / log1p(2048 + 1)
    expected_ratio = math.log1p(1024) / math.log1p(2049)
    assert pytest.approx(features[7], 0.01) == expected_ratio
    # dst_port_risk for 445 is 0.7
    assert features[9] == 0.7
    # is_new_destination: 10.0.0.2 is in typical_destinations -> 0.0
    assert features[10] == 0.0
    # is_external_dst: dst_internal is False -> 1.0
    assert features[11] == 1.0


def test_extract_features_safe_division_and_edge_cases():
    # Empty / zero values event
    event = UnifiedEvent(
        timestamp=datetime(2026, 4, 1, 0, 0, 0),
        layer="network",
        src_entity="unknown_src",
        dst_entity="unknown_dst",
        src_internal=True,
        dst_internal=True,
        bytes_sent=0,
        bytes_received=0,
    )

    empty_profiler = BehavioralBaselineProfiler()

    features = extract_features(
        event=event,
        if_score=0.0,
        baseline_deviation=0.5,
        profiler=empty_profiler,
        failed_auth_rate=0.0
    )

    assert len(features) == 15
    for val in features:
        assert not math.isnan(val)
        assert not math.isinf(val)


def test_calculate_failed_auth_rate_causal_ordering():
    t0 = datetime(2026, 4, 1, 10, 0, 0)
    events = [
        UnifiedEvent(
            event_id="ev1",
            timestamp=t0,
            layer="application",
            src_entity="attacker",
            dst_entity="auth_endpoint",
            src_internal=False,
            dst_internal=True,
            status_code=401
        ),
        UnifiedEvent(
            event_id="ev2",
            timestamp=t0 + timedelta(seconds=30),
            layer="application",
            src_entity="attacker",
            dst_entity="auth_endpoint",
            src_internal=False,
            dst_internal=True,
            status_code=401
        ),
        UnifiedEvent(
            event_id="ev3",
            timestamp=t0 + timedelta(seconds=70),
            layer="application",
            src_entity="attacker",
            dst_entity="auth_endpoint",
            src_internal=False,
            dst_internal=True,
            status_code=401
        ),
    ]

    rates = calculate_failed_auth_rate(events)
    # At t0: 1 failure
    assert rates["ev1"] == 1.0
    # At t0+30: 2 failures (ev1 and ev2)
    assert rates["ev2"] == 2.0
    # At t0+70: ev1 is older than 60s, so only ev2 and ev3 are in window -> 2 failures
    assert rates["ev3"] == 2.0
