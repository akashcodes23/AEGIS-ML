import pytest
import numpy as np
from datetime import datetime
from pathlib import Path

from backend.core.schemas import UnifiedEvent
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector


@pytest.fixture
def sample_events():
    events = []
    # 20 benign network events
    for i in range(20):
        events.append(UnifiedEvent(
            timestamp=datetime(2026, 4, 1, 9, i, 0),
            layer="network",
            src_entity="10.0.0.10",
            dst_entity="10.0.0.20",
            src_internal=True,
            dst_internal=True,
            bytes_sent=500 + i * 10,
            bytes_received=1000,
            dst_port=80,
            duration_ms=100,
            connections_per_minute=10.0,
            attack_type="benign",
            raw_label="benign"
        ))
    # 5 attack events
    for i in range(5):
        events.append(UnifiedEvent(
            timestamp=datetime(2026, 4, 1, 23, i, 0),
            layer="network",
            src_entity="10.0.0.10",
            dst_entity="192.168.1.100",
            src_internal=True,
            dst_internal=False,
            bytes_sent=10000000,
            bytes_received=50,
            dst_port=4444,
            attack_type="data_exfiltration",
            raw_label="malicious"
        ))
    return events


def test_baseline_profiler_benign_filtering(sample_events):
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(sample_events, benign_only=True)

    assert "10.0.0.10" in profiler.profiles
    profile = profiler.profiles["10.0.0.10"]

    # Typical destinations should NOT include the exfiltration target
    assert "10.0.0.20" in profile["typical_destinations"]
    assert "192.168.1.100" not in profile["typical_destinations"]
    # Average bytes sent should be around 500-700, not 10 million
    assert profile["avg_bytes_sent"] < 1000.0


def test_baseline_profiler_unseen_entity():
    profiler = BehavioralBaselineProfiler()
    event = UnifiedEvent(
        timestamp=datetime.now(),
        layer="network",
        src_entity="completely_unknown_ip",
        dst_entity="unknown_dst",
        src_internal=True,
        dst_internal=True
    )
    score = profiler.compute_deviation_score(event)
    assert score == 0.5  # Neutral default


def test_isolation_forest_detector_fit_predict_save_load(sample_events, tmp_path):
    net_path = str(tmp_path / "if_net.pkl")
    end_path = str(tmp_path / "if_end.pkl")

    detector = IsolationForestDetector(random_state=42)
    detector.fit(sample_events)

    # Anomaly scores on normal vs extreme event
    normal_event = sample_events[0]
    extreme_event = sample_events[-1]

    score_normal = detector.predict(normal_event)
    score_extreme = detector.predict(extreme_event)

    assert 0.0 <= score_normal <= 1.0
    assert 0.0 <= score_extreme <= 1.0
    # The extreme exfiltration event should score higher than the normal event
    assert score_extreme > score_normal

    # Verify state persistence (payload_mean, payload_std, port_freqs)
    orig_mean = detector.payload_mean
    orig_std = detector.payload_std
    detector.save(net_path=net_path, end_path=end_path)

    new_detector = IsolationForestDetector()
    success = new_detector.load(net_path=net_path, end_path=end_path)
    assert success is True
    assert pytest.approx(new_detector.payload_mean) == orig_mean
    assert pytest.approx(new_detector.payload_std) == orig_std

    # Reloaded detector gives identical score
    reload_score = new_detector.predict(extreme_event)
    assert pytest.approx(reload_score, 0.001) == score_extreme
