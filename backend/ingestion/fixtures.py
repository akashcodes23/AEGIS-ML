"""
Phase 26 End-to-End Integration and Replay Fixtures for AEGIS-ML.

Provides 12 deterministic, controlled synthetic telemetry fixtures representing:
1. Benign network activity
2. Brute-force authentication behavior
3. Lateral-movement-like behavior
4. Data-exfiltration-like behavior
5. C2-beaconing-like behavior
6. Missing host/process attribution
7. Malformed telemetry
8. Duplicate event IDs
9. Duplicate payload fingerprints
10. Out-of-order events
11. Late-arriving events
12. Contradictory or incomplete evidence

All fixtures are strictly deterministic, isolated, and documented.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any


@dataclass
class E2EFixtureScenario:
    """Specification of an integration test scenario fixture."""
    scenario_id: str
    scenario_name: str
    description: str
    events: List[Dict[str, Any]]
    expected_ingestion_statuses: List[str]
    expected_threat_type: Optional[str] = None
    expected_alert_created: Optional[bool] = None
    expected_incident_status: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


def get_e2e_fixtures(base_time: Optional[datetime] = None) -> Dict[str, E2EFixtureScenario]:
    """Generate all 12 deterministic scenarios anchored at base_time."""
    if base_time is None:
        base_time = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)

    t0 = base_time

    # 1. Benign Network Activity
    benign_events = [
        {
            "event_id": "benign-net-001",
            "timestamp": t0.isoformat(),
            "layer": "network",
            "src_ip": "10.0.1.25",
            "dst_ip": "10.0.1.10",
            "src_port": 51234,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes_sent": 850,
            "bytes_received": 4200,
            "action": "http_request",
        },
        {
            "event_id": "benign-net-002",
            "timestamp": (t0 + timedelta(seconds=2)).isoformat(),
            "layer": "network",
            "src_ip": "10.0.1.25",
            "dst_ip": "142.250.190.46",
            "src_port": 51235,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": 1420,
            "bytes_received": 8940,
            "action": "tls_connect",
        },
    ]

    # 2. Brute-Force Authentication Behavior
    brute_force_events = []
    for i in range(6):
        brute_force_events.append({
            "event_id": f"brute-force-{i+1:03d}",
            "timestamp": (t0 + timedelta(seconds=i * 2)).isoformat(),
            "layer": "application",
            "src_ip": "198.51.100.44",
            "dst_ip": "10.0.0.10",
            "http_method": "POST",
            "endpoint_path": "/api/v1/login",
            "status_code": 401,
            "auth_result": "failure",
            "user_account": f"admin_user_{i%2}",
            "bytes_sent": 320,
            "bytes_received": 140,
            "action": "auth_attempt",
        })

    # 3. Lateral-Movement-Like Behavior
    lateral_movement_events = [
        {
            "event_id": "lat-move-001",
            "timestamp": t0.isoformat(),
            "layer": "endpoint",
            "host_id": "HOST-CORP-WS1",
            "src_ip": "10.0.2.15",
            "process_name": "powershell.exe",
            "parent_process": "cmd.exe",
            "pid": 4120,
            "parent_pid": 2040,
            "user_account": "CORP\\Administrator",
            "action": "process_create",
        },
        {
            "event_id": "lat-move-002",
            "timestamp": (t0 + timedelta(seconds=5)).isoformat(),
            "layer": "network",
            "host_id": "HOST-CORP-WS1",
            "src_ip": "10.0.2.15",
            "dst_ip": "10.0.2.50",
            "src_port": 49822,
            "dst_port": 445,
            "protocol": "TCP",
            "bytes_sent": 24000,
            "bytes_received": 4800,
            "action": "smb_session_setup",
        },
    ]

    # 4. Data-Exfiltration-Like Behavior
    exfil_events = [
        {
            "event_id": "exfil-001",
            "timestamp": t0.isoformat(),
            "layer": "network",
            "host_id": "DB-INTERNAL-SRV",
            "src_ip": "10.0.5.20",
            "dst_ip": "203.0.113.88",
            "src_port": 42100,
            "dst_port": 8443,
            "protocol": "TCP",
            "bytes_sent": 65_000_000,
            "bytes_received": 12_000,
            "action": "bulk_data_transfer",
        }
    ]

    # 5. C2-Beaconing-Like Behavior
    c2_events = []
    for i in range(4):
        c2_events.append({
            "event_id": f"c2-beacon-{i+1:03d}",
            "timestamp": (t0 + timedelta(seconds=i * 30)).isoformat(),
            "layer": "network",
            "host_id": "WORKSTATION-09",
            "src_ip": "10.0.3.109",
            "dst_ip": "198.51.100.99",
            "src_port": 50120 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": 256,
            "bytes_received": 128,
            "action": "beacon_poll",
        })

    # 6. Missing Host/Process Attribution
    missing_attr_events = [
        {
            "event_id": "missing-attr-001",
            "timestamp": t0.isoformat(),
            "layer": "network",
            "src_ip": "172.16.10.8",
            "dst_ip": "10.0.0.1",
            "src_port": 39120,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes_sent": 512,
            "bytes_received": 2048,
            "action": "http_request",
            # host_id, process_name, pid explicitly omitted
        }
    ]

    # 7. Malformed Telemetry
    malformed_events = [
        {
            "event_id": "malformed-001",
            "timestamp": t0.isoformat(),
            "layer": "unsupported_layer_xyz",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
        },
        {
            "event_id": "malformed-002",
            "timestamp": t0.isoformat(),
            "layer": "network",
            "src_ip": "invalid-ip-string",
            "dst_ip": "10.0.0.2",
            "dst_port": 999_999,  # Port out of valid 0-65535 range
        },
    ]

    # 8. Duplicate Event IDs
    dup_id_events = [
        {
            "event_id": "dup-id-001",
            "timestamp": t0.isoformat(),
            "layer": "network",
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.1.20",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes_sent": 100,
            "action": "syn",
        },
        {
            "event_id": "dup-id-001",  # Identical ID
            "timestamp": (t0 + timedelta(seconds=1)).isoformat(),
            "layer": "network",
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.1.20",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes_sent": 200,
            "action": "ack",
        },
    ]

    # 9. Duplicate Payload Fingerprints
    dup_fp_events = [
        {
            "event_id": "dup-fp-A",
            "timestamp": t0.isoformat(),
            "layer": "network",
            "src_ip": "10.0.4.1",
            "dst_ip": "10.0.4.2",
            "src_port": 55000,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": 1200,
            "action": "tls_hello",
        },
        {
            "event_id": "dup-fp-B",  # Distinct ID but identical invariant payload from dual-tap
            "timestamp": t0.isoformat(),
            "layer": "network",
            "src_ip": "10.0.4.1",
            "dst_ip": "10.0.4.2",
            "src_port": 55000,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": 1200,
            "action": "tls_hello",
        },
    ]

    # 10. Out-of-Order Events
    out_of_order_events = [
        {
            "event_id": "ooo-001",
            "timestamp": t0.isoformat(),  # 10:00:00
            "layer": "network",
            "src_ip": "10.0.6.1",
            "dst_ip": "10.0.6.2",
            "action": "step_1",
        },
        {
            "event_id": "ooo-002",
            "timestamp": (t0 + timedelta(seconds=10)).isoformat(),  # 10:00:10 (advances watermark)
            "layer": "network",
            "src_ip": "10.0.6.1",
            "dst_ip": "10.0.6.2",
            "action": "step_3",
        },
        {
            "event_id": "ooo-003",
            "timestamp": (t0 + timedelta(seconds=5)).isoformat(),  # 10:00:05 (arrives out-of-order, within tolerance)
            "layer": "network",
            "src_ip": "10.0.6.1",
            "dst_ip": "10.0.6.2",
            "action": "step_2",
        },
    ]

    # 11. Late-Arriving Events
    late_events = [
        {
            "event_id": "late-001",
            "timestamp": t0.isoformat(),  # 10:00:00
            "layer": "network",
            "src_ip": "10.0.7.1",
            "dst_ip": "10.0.7.2",
            "action": "baseline_connect",
        },
        {
            "event_id": "late-002",
            "timestamp": (t0 + timedelta(minutes=15)).isoformat(),  # 10:15:00 (advances watermark)
            "layer": "network",
            "src_ip": "10.0.7.1",
            "dst_ip": "10.0.7.2",
            "action": "current_connect",
        },
        {
            "event_id": "late-003",
            "timestamp": (t0 + timedelta(minutes=1)).isoformat(),  # 10:01:00 (14 min behind watermark, exceeds 5m tolerance)
            "layer": "network",
            "src_ip": "10.0.7.1",
            "dst_ip": "10.0.7.2",
            "action": "lagged_connect",
        },
    ]

    # 12. Contradictory or Incomplete Evidence
    contradictory_events = [
        {
            "event_id": "incomplete-001",
            "timestamp": t0.isoformat(),
            "layer": "network",
            "src_ip": "10.0.8.1",
            "dst_ip": "10.0.8.2",
            "action": "sparse_flow",
            # missing dst_port, bytes_sent, bytes_received, protocol
        },
        {
            "event_id": "contradictory-002",
            "timestamp": (t0 + timedelta(seconds=1)).isoformat(),
            "layer": "endpoint",
            "src_entity": "host-alpha",
            "dst_entity": "host-beta",
            "action": "cross_claim",
            "process_name": None,
            "pid": None,
            "socket_id": None,
        },
    ]

    scenarios = {
        "benign_network": E2EFixtureScenario(
            scenario_id="FIXTURE-01",
            scenario_name="Benign Network Activity",
            description="Normal DNS and TLS outbound communications with baseline volumes.",
            events=benign_events,
            expected_ingestion_statuses=["accepted", "accepted"],
            expected_threat_type="benign",
            expected_alert_created=False,
        ),
        "brute_force": E2EFixtureScenario(
            scenario_id="FIXTURE-02",
            scenario_name="Brute-Force Authentication Behavior",
            description="Series of failed HTTP 401 logins targeting web authentication interface.",
            events=brute_force_events,
            expected_ingestion_statuses=["accepted"] * len(brute_force_events),
            expected_threat_type="brute_force",
            expected_alert_created=True,
            expected_incident_status="open",
        ),
        "lateral_movement": E2EFixtureScenario(
            scenario_id="FIXTURE-03",
            scenario_name="Lateral Movement Activity",
            description="Endpoint administrative tool execution followed by SMB connection.",
            events=lateral_movement_events,
            expected_ingestion_statuses=["accepted", "accepted"],
            expected_threat_type="lateral_movement",
            expected_alert_created=True,
            metadata={"cross_layer": True},
        ),
        "data_exfiltration": E2EFixtureScenario(
            scenario_id="FIXTURE-04",
            scenario_name="Data Exfiltration Behavior",
            description="Abnormally high outbound volume transfer to external IP destination.",
            events=exfil_events,
            expected_ingestion_statuses=["accepted"],
            expected_threat_type="data_exfiltration",
            expected_alert_created=True,
        ),
        "c2_beaconing": E2EFixtureScenario(
            scenario_id="FIXTURE-05",
            scenario_name="C2 Beaconing Behavior",
            description="Fixed-cadence low-volume polls to external destination.",
            events=c2_events,
            expected_ingestion_statuses=["accepted"] * len(c2_events),
            expected_threat_type="c2_beaconing",
            expected_alert_created=True,
        ),
        "missing_attribution": E2EFixtureScenario(
            scenario_id="FIXTURE-06",
            scenario_name="Missing Host/Process Attribution",
            description="Pure network telemetry without host_id or process attribution.",
            events=missing_attr_events,
            expected_ingestion_statuses=["accepted"],
            metadata={"verified_binding_expected": False},
        ),
        "malformed_telemetry": E2EFixtureScenario(
            scenario_id="FIXTURE-07",
            scenario_name="Malformed Telemetry",
            description="Payloads with invalid layers and invalid port boundaries.",
            events=malformed_events,
            expected_ingestion_statuses=["rejected", "rejected"],
            expected_alert_created=False,
        ),
        "duplicate_event_ids": E2EFixtureScenario(
            scenario_id="FIXTURE-08",
            scenario_name="Duplicate Event IDs",
            description="Identical event_id submitted consecutively.",
            events=dup_id_events,
            expected_ingestion_statuses=["accepted", "duplicate"],
        ),
        "duplicate_payload_fingerprints": E2EFixtureScenario(
            scenario_id="FIXTURE-09",
            scenario_name="Duplicate Payload Fingerprints",
            description="Identical event payload characteristics with distinct event IDs.",
            events=dup_fp_events,
            expected_ingestion_statuses=["accepted", "duplicate"],
        ),
        "out_of_order_events": E2EFixtureScenario(
            scenario_id="FIXTURE-10",
            scenario_name="Out-of-Order Events",
            description="Events arriving non-chronologically within tolerance window.",
            events=out_of_order_events,
            expected_ingestion_statuses=["accepted", "accepted", "accepted"],
            metadata={"watermark_preserved": True},
        ),
        "late_arriving_events": E2EFixtureScenario(
            scenario_id="FIXTURE-11",
            scenario_name="Late-Arriving Events",
            description="Event timestamp significantly older than high-watermark.",
            events=late_events,
            expected_ingestion_statuses=["accepted", "accepted", "accepted"],
            metadata={"last_event_is_late": True},
        ),
        "contradictory_evidence": E2EFixtureScenario(
            scenario_id="FIXTURE-12",
            scenario_name="Contradictory or Incomplete Evidence",
            description="Sparse and incomplete telemetry attributes preserving None missingness.",
            events=contradictory_events,
            expected_ingestion_statuses=["accepted", "accepted"],
            metadata={"missingness_encoded": True},
        ),
    }

    return scenarios
