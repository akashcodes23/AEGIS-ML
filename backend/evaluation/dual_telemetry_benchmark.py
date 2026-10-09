"""
AEGIS-ML Dual-Telemetry Controlled Correlation Benchmark
Module: backend.evaluation.dual_telemetry_benchmark

Evaluates the IncidentCorrelator across 10 controlled regression fixtures
modeling dual-telemetry scenarios (process-to-socket attribution, PID reuse,
cross-host PID collision, missing evidence, and legitimate backup activity).

NOTE: These results measure software correlation logic correctness on
controlled synthetic fixtures. They do not represent real-world detection accuracy.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from pathlib import Path

from backend.core.config import PROJECT_ROOT
from backend.core.schemas import Alert, UnifiedEvent, Incident
from backend.correlation.incident_correlator import IncidentCorrelator


def build_scenario_fixtures() -> List[Dict[str, Any]]:
    """Build the 10 controlled dual-telemetry regression scenarios."""
    scenarios = []
    base_t = datetime(2026, 10, 9, 10, 0, 0)

    # ── Scenario 1: Directly Observed Process-to-Socket Association ──────────
    t1 = base_t
    sock_1 = "10.0.0.10:49152->203.0.113.5:443"
    s1_events = [
        UnifiedEvent(
            event_id="S1-EV-01",
            timestamp=t1,
            layer="endpoint",
            src_entity="10.0.0.10",
            dst_entity="10.0.0.10",
            src_internal=True,
            dst_internal=True,
            host_id="WORKSTATION-10",
            process_name="beacon.exe",
            pid=4012,
            process_guid="{S1-GUID-01}",
            socket_id=sock_1,
            attack_type="c2_beaconing",
        ),
        UnifiedEvent(
            event_id="S1-EV-02",
            timestamp=t1 + timedelta(seconds=10),
            layer="network",
            src_entity="10.0.0.10",
            dst_entity="203.0.113.5",
            src_internal=True,
            dst_internal=False,
            host_id="WORKSTATION-10",
            src_port=49152,
            dst_port=443,
            protocol="TCP",
            bytes_sent=1200,
            socket_id=sock_1,
            attack_type="c2_beaconing",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_1_DIRECT_SOCKET_BINDING",
        "description": "Endpoint process and network flow share verified socket_id on same host.",
        "events": s1_events,
        "expected_incident_count": 1,
        "expected_relationship_type": "direct_process_socket_binding",
        "expected_claim_type": "observation",
        "must_have_empty_missing_evidence": True,
    })

    # ── Scenario 2: File Access with No Network Connection ───────────────────
    t2 = base_t + timedelta(minutes=15)
    s2_events = [
        UnifiedEvent(
            event_id="S2-EV-01",
            timestamp=t2,
            layer="endpoint",
            src_entity="10.0.0.15",
            dst_entity="10.0.0.15",
            src_internal=True,
            dst_internal=True,
            host_id="WORKSTATION-15",
            process_name="notepad.exe",
            pid=2100,
            file_path="C:\\Users\\alice\\notes.txt",
            action="read",
            attack_type="benign",
        )
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_2_FILE_ACCESS_NO_NETWORK",
        "description": "Isolated file read without network socket; must not infer exfiltration.",
        "events": s2_events,
        "expected_incident_count": 1,
        "expected_relationship_type": "observed_telemetry",
        "expected_claim_type": "observation",
        "must_not_contain_relationship": "cross_layer_co_occurrence",
    })

    # ── Scenario 3: Unrelated Network Activity on the Same Host ──────────────
    t3 = base_t + timedelta(minutes=30)
    s3_events = [
        # Process A: 7z archiving local confidential files (no socket)
        UnifiedEvent(
            event_id="S3-EV-01",
            timestamp=t3,
            layer="endpoint",
            src_entity="10.0.0.22",
            dst_entity="10.0.0.22",
            src_internal=True,
            dst_internal=True,
            host_id="SERVER-22",
            process_name="7z.exe",
            pid=3300,
            file_path="D:\\FinData\\export.zip",
            action="read",
            attack_type="data_exfiltration",
        ),
        # Process B: chrome browsing external intranet site with distinct socket and PID
        UnifiedEvent(
            event_id="S3-EV-02",
            timestamp=t3 + timedelta(seconds=12),
            layer="network",
            src_entity="10.0.0.22",
            dst_entity="198.51.100.99",
            src_internal=True,
            dst_internal=False,
            host_id="SERVER-22",
            process_name="chrome.exe",
            pid=8800,
            socket_id="10.0.0.22:52111->198.51.100.99:443",
            attack_type="data_exfiltration",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_3_UNRELATED_NETWORK_SAME_HOST",
        "description": "Concurrent archiving (PID 3300) and web browsing (PID 8800); must not attribute web socket to 7z.",
        "events": s3_events,
        "expected_incident_count": 1,
        "forbidden_process_socket_binding": ("7z.exe", "10.0.0.22:52111->198.51.100.99:443"),
    })

    # ── Scenario 4: Multiple Concurrent Processes ────────────────────────────
    t4 = base_t + timedelta(minutes=45)
    s4_events = [
        # Process 1: Attacker discovery
        UnifiedEvent(
            event_id="S4-EV-01",
            timestamp=t4,
            layer="endpoint",
            src_entity="10.0.0.30",
            dst_entity="10.0.0.30",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-30",
            process_name="net.exe",
            pid=5110,
            action="exec",
            attack_type="lateral_movement",
        ),
        # Process 2: Developer node.js
        UnifiedEvent(
            event_id="S4-EV-02",
            timestamp=t4 + timedelta(seconds=5),
            layer="endpoint",
            src_entity="10.0.0.30",
            dst_entity="10.0.0.30",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-30",
            process_name="node.exe",
            pid=6220,
            action="exec",
            attack_type="benign",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_4_MULTIPLE_CONCURRENT_PROCESSES",
        "description": "Multiple distinct processes executing simultaneously on same host.",
        "events": s4_events,
        "expected_incident_count": 1,
    })

    # ── Scenario 5: PID Reuse with Process Lifetime Information ──────────────
    t5 = base_t + timedelta(hours=1)
    s5_events = [
        # Process 1: malicious payload starting at 10:55, pid 1234
        UnifiedEvent(
            event_id="S5-EV-01",
            timestamp=t5,
            layer="endpoint",
            src_entity="10.0.0.40",
            dst_entity="10.0.0.40",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-40",
            process_name="mimikatz.exe",
            pid=1234,
            process_start_time=t5 - timedelta(minutes=5),
            attack_type="lateral_movement",
        ),
        # Process 2: benign maintenance reusing pid 1234 starting at 11:05
        UnifiedEvent(
            event_id="S5-EV-02",
            timestamp=t5 + timedelta(minutes=10),
            layer="endpoint",
            src_entity="10.0.0.40",
            dst_entity="10.0.0.40",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-40",
            process_name="trustedinstaller.exe",
            pid=1234,
            process_start_time=t5 + timedelta(minutes=8),
            attack_type="benign",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_5_PID_REUSE_DISAMBIGUATION",
        "description": "PID 1234 reused by different process instance; must reject process lineage match.",
        "events": s5_events,
        "expected_incident_count": 1,
        "must_not_match_rule": "RULE_0_PROCESS_LINEAGE_MATCH",
    })

    # ── Scenario 6: Identical PIDs on Different Hosts ────────────────────────
    t6 = base_t + timedelta(hours=1, minutes=20)
    s6_events = [
        UnifiedEvent(
            event_id="S6-EV-01",
            timestamp=t6,
            layer="endpoint",
            src_entity="10.0.0.51",
            dst_entity="10.0.0.51",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-51",
            process_name="powershell.exe",
            pid=2048,
            attack_type="brute_force",
        ),
        UnifiedEvent(
            event_id="S6-EV-02",
            timestamp=t6 + timedelta(seconds=20),
            layer="endpoint",
            src_entity="10.0.0.52",
            dst_entity="10.0.0.52",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-52",
            process_name="powershell.exe",
            pid=2048,
            attack_type="lateral_movement",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_6_IDENTICAL_PIDS_DIFFERENT_HOSTS",
        "description": "Matching PID 2048 on two separate machines; must remain separate incidents.",
        "events": s6_events,
        "expected_incident_count": 2,
    })

    # ── Scenario 7: Missing Process GUID or Socket Identifiers ───────────────
    t7 = base_t + timedelta(hours=1, minutes=40)
    s7_events = [
        UnifiedEvent(
            event_id="S7-EV-01",
            timestamp=t7,
            layer="endpoint",
            src_entity="10.0.0.60",
            dst_entity="10.0.0.60",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-60",
            process_name="curl.exe",
            pid=7711,
            action="read",
            attack_type="data_exfiltration",
        ),
        UnifiedEvent(
            event_id="S7-EV-02",
            timestamp=t7 + timedelta(seconds=15),
            layer="network",
            src_entity="10.0.0.60",
            dst_entity="198.51.100.77",
            src_internal=True,
            dst_internal=False,
            host_id="HOST-60",
            dst_port=80,
            bytes_sent=8000,
            attack_type="data_exfiltration",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_7_MISSING_GUID_AND_SOCKET",
        "description": "Missing socket binding; must be tagged as hypothesis with missing_evidence.",
        "events": s7_events,
        "expected_incident_count": 1,
        "expected_relationship_type": "cross_layer_co_occurrence",
        "expected_claim_type": "hypothesis",
        "required_missing_evidence": ["socket_to_pid_binding_absent", "kernel_handle_lineage_unverified"],
    })

    # ── Scenario 8: Out-of-Order Events ──────────────────────────────────────
    t8 = base_t + timedelta(hours=2)
    sock_8 = "10.0.0.70:49999->203.0.113.88:443"
    s8_events = [
        # Network packet arrives first (timestamp t + 10s)
        UnifiedEvent(
            event_id="S8-EV-02",
            timestamp=t8 + timedelta(seconds=10),
            layer="network",
            src_entity="10.0.0.70",
            dst_entity="203.0.113.88",
            src_internal=True,
            dst_internal=False,
            host_id="HOST-70",
            socket_id=sock_8,
            dst_port=443,
            attack_type="c2_beaconing",
        ),
        # Endpoint process create arrives second (timestamp t)
        UnifiedEvent(
            event_id="S8-EV-01",
            timestamp=t8,
            layer="endpoint",
            src_entity="10.0.0.70",
            dst_entity="10.0.0.70",
            src_internal=True,
            dst_internal=True,
            host_id="HOST-70",
            process_name="implant.exe",
            pid=9100,
            socket_id=sock_8,
            attack_type="c2_beaconing",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_8_OUT_OF_ORDER_EVENTS",
        "description": "Network connection processed before process launch; monotonically correlates.",
        "events": s8_events,
        "expected_incident_count": 1,
        "expected_relationship_type": "direct_process_socket_binding",
    })

    # ── Scenario 9: Ambiguous Timestamps ─────────────────────────────────────
    t9 = base_t + timedelta(hours=2, minutes=20)
    s9_events = [
        UnifiedEvent(
            event_id="S9-EV-01",
            timestamp=t9,
            layer="network",
            src_entity="10.0.0.81",
            dst_entity="10.0.0.1",
            src_internal=True,
            dst_internal=True,
            dst_port=22,
            attack_type="brute_force",
        ),
        UnifiedEvent(
            event_id="S9-EV-02",
            timestamp=t9,
            layer="network",
            src_entity="10.0.0.82",
            dst_entity="10.0.0.2",
            src_internal=True,
            dst_internal=True,
            dst_port=445,
            attack_type="lateral_movement",
        ),
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_9_AMBIGUOUS_TIMESTAMPS",
        "description": "Coincident timestamp across distinct entities; must stay in separate incidents.",
        "events": s9_events,
        "expected_incident_count": 2,
    })

    # ── Scenario 10: Legitimate Compression and Backup Activity ──────────────
    t10 = base_t + timedelta(hours=2, minutes=40)
    s10_events = [
        UnifiedEvent(
            event_id="S10-EV-01",
            timestamp=t10,
            layer="endpoint",
            src_entity="10.0.0.95",
            dst_entity="10.0.0.95",
            src_internal=True,
            dst_internal=True,
            host_id="BACKUP-SRV",
            process_name="robocopy.exe",
            pid=1020,
            file_path="E:\\Backups\\Q3.tar.gz",
            action="read",
            attack_type="benign",
        )
    ]
    scenarios.append({
        "scenario_id": "SCENARIO_10_LEGITIMATE_BACKUP",
        "description": "Authorized robocopy backup archiving; must record alternative benign explanation.",
        "events": s10_events,
        "expected_incident_count": 1,
        "must_contain_alternative_hypothesis": True,
    })

    return scenarios


def evaluate_dual_telemetry_benchmark() -> Dict[str, Any]:
    """Execute the 10 dual-telemetry scenarios and evaluate correlation correctness."""
    scenarios = build_scenario_fixtures()
    results = []

    passed_scenarios = 0

    for sc in scenarios:
        correlator = IncidentCorrelator(time_window_seconds=600)
        scenario_id = sc["scenario_id"]
        events = sc["events"]

        incidents_created = []
        for ev in events:
            # Construct minimal alert
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
            inc, is_new = correlator.correlate_alert(alert, raw_event=ev)
            if is_new and inc not in incidents_created:
                incidents_created.append(inc)

        total_incidents = len(correlator.incidents)
        passed = True
        failure_reasons = []

        # Check incident count
        if "expected_incident_count" in sc and total_incidents != sc["expected_incident_count"]:
            passed = False
            failure_reasons.append(f"Expected {sc['expected_incident_count']} incidents, got {total_incidents}")

        # Check relationship type
        all_rels = []
        for inc in correlator.incidents.values():
            all_rels.extend(inc.relationship_evidence)

        if "expected_relationship_type" in sc:
            has_rel = any(r["relationship_type"] == sc["expected_relationship_type"] for r in all_rels)
            if not has_rel:
                passed = False
                failure_reasons.append(f"Missing expected relationship_type: {sc['expected_relationship_type']}")

        if "expected_claim_type" in sc:
            matching = [r for r in all_rels if r.get("claim_type") == sc["expected_claim_type"]]
            if not matching:
                passed = False
                failure_reasons.append(f"Missing expected claim_type: {sc['expected_claim_type']}")

        if sc.get("must_have_empty_missing_evidence"):
            for r in all_rels:
                if r["relationship_type"] == "direct_process_socket_binding" and r.get("missing_evidence") != []:
                    passed = False
                    failure_reasons.append("Direct socket binding had non-empty missing_evidence")

        if "required_missing_evidence" in sc:
            for req in sc["required_missing_evidence"]:
                found_me = any(req in r.get("missing_evidence", []) for r in all_rels)
                if not found_me:
                    passed = False
                    failure_reasons.append(f"Missing required missing_evidence entry: {req}")

        if sc.get("must_not_contain_relationship"):
            forbidden = sc["must_not_contain_relationship"]
            if any(r["relationship_type"] == forbidden for r in all_rels):
                passed = False
                failure_reasons.append(f"Contained forbidden relationship: {forbidden}")

        if "forbidden_process_socket_binding" in sc:
            proc, sock = sc["forbidden_process_socket_binding"]
            for r in all_rels:
                if r["relationship_type"] == "direct_process_socket_binding" and proc in r.get("reason", ""):
                    passed = False
                    failure_reasons.append(f"Falsely bound socket to {proc}")

        if "must_not_match_rule" in sc:
            for inc in correlator.incidents.values():
                if sc["must_not_match_rule"] in inc.matched_rules:
                    passed = False
                    failure_reasons.append(f"Falsely matched rule: {sc['must_not_match_rule']}")

        if sc.get("must_contain_alternative_hypothesis"):
            for inc in correlator.incidents.values():
                if not inc.alternative_hypotheses:
                    passed = False
                    failure_reasons.append("Incident missing alternative hypotheses")

        if passed:
            passed_scenarios += 1

        results.append({
            "scenario_id": scenario_id,
            "description": sc["description"],
            "events_evaluated": len(events),
            "incidents_created": total_incidents,
            "passed": passed,
            "failure_reasons": failure_reasons,
        })

    report = {
        "benchmark_metadata": {
            "name": "AEGIS-ML Dual-Telemetry Controlled Correlation Benchmark",
            "benchmark_type": "Synthetic software-validation fixture evaluation",
            "total_scenarios": len(scenarios),
            "passed_scenarios": passed_scenarios,
            "pass_rate_pct": round((passed_scenarios / len(scenarios)) * 100, 2),
            "disclaimer": "Measures correlation engine software correctness on controlled synthetic fixtures. Does not represent real-world detection accuracy.",
        },
        "scenarios": results,
    }

    out_file = Path(PROJECT_ROOT) / "data" / "models" / "dual_telemetry_benchmark_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    rep = evaluate_dual_telemetry_benchmark()
    meta = rep["benchmark_metadata"]
    print(f"\n{meta['name']}")
    print(f"Passed: {meta['passed_scenarios']} / {meta['total_scenarios']} ({meta['pass_rate_pct']}%)")
    for s in rep["scenarios"]:
        status = "PASSED" if s["passed"] else f"FAILED: {s['failure_reasons']}"
        print(f"  [{s['scenario_id']}]: {status}")
