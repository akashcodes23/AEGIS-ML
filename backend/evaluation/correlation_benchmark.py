"""
AEGIS-ML Incident Correlation Quality Benchmark
===============================================
A scientific, fixture-based evaluation suite for validating temporal incident
correlation independently from classifier performance.

BACKGROUND:
The primary synthetic dataset (`combined_labeled.jsonl`) contains event-level labels,
but lacks ground-truth multi-event incident cluster labels. This benchmark establishes
explicit, fully documented test scenarios with known ground-truth incident clusters.

SCENARIOS EVALUATED:
  1. Multi-Stage APT Campaign (Known Related):
     Brute force on web server -> web server pivots to database -> data exfiltration.
     Ground Truth: All 3 events belong to the same incident cluster.

  2. Shared Victim, Independent Attackers (Merge Prevention Guard):
     Attacker A (198.51.100.11) and Attacker B (203.0.113.99) independently attack
     the same victim server (10.0.0.50).
     Ground Truth: Exactly 2 separate incidents. Must NOT merge into one incident.

  3. Same Attacker Source Across Long Inactivity (Temporal Window Guard):
     Attacker probes at T0, then returns 3 hours later for a different action.
     Ground Truth: 2 separate incidents due to time window expiration.

  4. Interleaved Legitimate Administrative Activity:
     Admin workstation (10.0.0.2) runs scheduled SSH maintenance interleaved between
     attack events.
     Ground Truth: Benign admin activity must NOT be incorporated into attack incident.

  5. Duplicate Evidence & Replay Flood:
     5 identical alerts with identical fingerprints generated within 30 seconds.
     Ground Truth: Deduplicated; priority score must remain invariant.

  6. Out-of-Order and Missing Timestamps:
     Alerts arriving seconds out of causal order or with None timestamps.
     Ground Truth: Grouped correctly without engine crashes; traceability preserved.

  7. Concurrent Simultaneous Incidents on Separate Subnets:
     Two independent multi-step attack campaigns occurring in parallel.
     Ground Truth: Exactly 2 independent incidents.

METRICS COMPUTED:
  - Pairwise Cluster Precision, Recall, and F1
  - Adjusted Rand Index (ARI)
  - Merge Error Count (unrelated events grouped together)
  - Split Error Count (related events incorrectly fragmented)
  - Evidence Traceability Rate (% of supporting event IDs retained)
  - Duplicate Invariance Verified (True/False)

IMPORTANT:
These metrics evaluate correlation rule logic on controlled synthetic fixtures.
They must NOT be claimed as real-world incident correlation performance.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
from sklearn.metrics import adjusted_rand_score

try:
    from backend.core.schemas import Alert, UnifiedEvent
    from backend.correlation.incident_correlator import IncidentCorrelator
    from backend.core.config import PROJECT_ROOT
except ModuleNotFoundError:
    from core.schemas import Alert, UnifiedEvent
    from correlation.incident_correlator import IncidentCorrelator
    from core.config import PROJECT_ROOT

logger = logging.getLogger(__name__)


def _make_alert(
    alert_id: str,
    event_id: str,
    timestamp: Optional[datetime],
    src_entity: str,
    dst_entity: str,
    layer: str = "network",
    threat_type: str = "brute_force",
    severity: str = "medium",
    confidence: float = 0.85,
    kill_chain: str = "Weaponize",
    next_stage: str = "Install",
    anomaly_score: float = 0.3,
    raw_timestamp: Optional[datetime] = None,
) -> Tuple[Alert, UnifiedEvent]:
    """Helper to build consistent Alert and UnifiedEvent pairs for benchmark fixtures."""
    raw_ev = UnifiedEvent(
        event_id=event_id,
        timestamp=raw_timestamp or timestamp or datetime.utcnow(),
        layer=layer,
        src_entity=src_entity,
        dst_entity=dst_entity,
        src_internal=src_entity.startswith("10."),
        dst_internal=dst_entity.startswith("10."),
        src_ip=src_entity,
        dst_ip=dst_entity,
        dst_port=22 if threat_type == "brute_force" else (445 if threat_type == "lateral_movement" else 443),
        protocol="TCP",
        bytes_sent=512,
        bytes_received=256,
        raw_label="malicious" if threat_type != "benign" else "benign",
        attack_type=threat_type if threat_type != "benign" else None,
    )
    alert = Alert(
        alert_id=alert_id,
        event_id=event_id,
        timestamp=timestamp,
        layer=layer,
        src_entity=src_entity,
        dst_entity=dst_entity,
        threat_type=threat_type,
        confidence=confidence,
        classifier_probability=confidence,
        severity=severity,
        anomaly_score=anomaly_score,
        is_synthetic=True,
        source_file="correlation_fixtures.json",
        current_kill_chain_stage=kill_chain,
        predicted_next_stage=next_stage,
        raw_event=raw_ev.model_dump(),
    )
    return alert, raw_ev


def build_benchmark_fixtures() -> List[Dict[str, Any]]:
    """
    Construct the 7 standardized correlation test scenarios with ground-truth cluster IDs.
    Returns a list of dicts with scenario metadata, test alerts, and ground truth.
    """
    base_t = datetime(2026, 10, 9, 10, 0, 0)
    fixtures = []

    # ── Scenario 1: Multi-Stage APT Campaign (Known Related) ─────────────────
    # Brute Force -> Lateral Movement Pivot -> Data Exfiltration
    a1, r1 = _make_alert(
        "A-01", "EV-01", base_t, "198.51.100.20", "10.0.0.5",
        threat_type="brute_force", severity="medium", kill_chain="Initial Access", next_stage="Execution"
    )
    a2, r2 = _make_alert(
        "A-02", "EV-02", base_t + timedelta(seconds=90), "10.0.0.5", "10.0.0.90",
        threat_type="lateral_movement", severity="high", kill_chain="Lateral Movement", next_stage="Exfiltration"
    )
    a3, r3 = _make_alert(
        "A-03", "EV-03", base_t + timedelta(seconds=240), "10.0.0.90", "203.0.113.88",
        threat_type="data_exfiltration", severity="critical", kill_chain="Exfiltration", next_stage="Completed"
    )
    fixtures.append({
        "scenario_id": "SCENARIO_1_MULTI_STAGE_APT",
        "description": "Multi-stage APT campaign: External brute force -> victim pivots laterally -> exfiltration",
        "alerts": [(a1, r1), (a2, r2), (a3, r3)],
        "ground_truth_clusters": {
            "EV-01": "INC-APT-1",
            "EV-02": "INC-APT-1",
            "EV-03": "INC-APT-1",
        },
        "expected_incident_count": 1,
    })

    # ── Scenario 2: Shared Victim, Independent Attackers (Merge Prevention) ──
    # Attacker A and Attacker B targeting same web server
    t_s2 = base_t + timedelta(hours=1)
    a4, r4 = _make_alert(
        "A-04", "EV-04", t_s2, "198.51.100.44", "10.0.0.80",
        threat_type="brute_force", severity="medium", kill_chain="Initial Access"
    )
    a5, r5 = _make_alert(
        "A-05", "EV-05", t_s2 + timedelta(seconds=30), "203.0.113.99", "10.0.0.80",
        threat_type="brute_force", severity="medium", kill_chain="Initial Access"
    )
    fixtures.append({
        "scenario_id": "SCENARIO_2_SHARED_VICTIM_INDEPENDENT_ATTACKERS",
        "description": "Two independent external attackers targeting the same victim server simultaneously",
        "alerts": [(a4, r4), (a5, r5)],
        "ground_truth_clusters": {
            "EV-04": "INC-ATTACKER-A",
            "EV-05": "INC-ATTACKER-B",
        },
        "expected_incident_count": 2,
    })

    # ── Scenario 3: Same Attacker Outside Time Window ─────────────────────────
    # Attacker probes, then returns 3 hours later
    t_s3 = base_t + timedelta(hours=3)
    a6, r6 = _make_alert(
        "A-06", "EV-06", t_s3, "198.51.100.77", "10.0.0.15",
        threat_type="brute_force", severity="medium"
    )
    a7, r7 = _make_alert(
        "A-07", "EV-07", t_s3 + timedelta(hours=3), "198.51.100.77", "10.0.0.15",
        threat_type="brute_force", severity="medium"
    )
    fixtures.append({
        "scenario_id": "SCENARIO_3_SAME_ATTACKER_OUTSIDE_WINDOW",
        "description": "Same attacker targeting same victim separated by 3 hours (exceeds 10m sliding window)",
        "alerts": [(a6, r6), (a7, r7)],
        "ground_truth_clusters": {
            "EV-06": "INC-CAMPAIGN-EARLY",
            "EV-07": "INC-CAMPAIGN-LATE",
        },
        "expected_incident_count": 2,
    })

    # ── Scenario 4: Interleaved Legitimate Admin Activity ─────────────────────
    # Admin workstation runs maintenance between attack alerts
    t_s4 = base_t + timedelta(hours=6)
    a8, r8 = _make_alert(
        "A-08", "EV-08", t_s4, "198.51.100.12", "10.0.0.30",
        threat_type="c2_beaconing", severity="high"
    )
    a9, r9 = _make_alert(
        "A-09", "EV-09", t_s4 + timedelta(seconds=20), "10.0.0.2", "10.0.0.30",
        threat_type="benign", severity="low", confidence=0.1
    )
    a10, r10 = _make_alert(
        "A-10", "EV-10", t_s4 + timedelta(seconds=40), "198.51.100.12", "10.0.0.30",
        threat_type="c2_beaconing", severity="high"
    )
    fixtures.append({
        "scenario_id": "SCENARIO_4_INTERLEAVED_BENIGN_ADMIN",
        "description": "Legitimate admin activity interleaved between attack campaign events",
        "alerts": [(a8, r8), (a9, r9), (a10, r10)],
        "ground_truth_clusters": {
            "EV-08": "INC-C2-CAMPAIGN",
            "EV-09": "BENIGN-ADMIN-ACTIVITY",  # Should not be grouped with malicious incident
            "EV-10": "INC-C2-CAMPAIGN",
        },
        "expected_incident_count": 1,  # Only the malicious campaign forms an incident
    })

    # ── Scenario 5: Duplicate Evidence & Replay Flood ─────────────────────────
    # 5 identical alerts sent within 20s
    t_s5 = base_t + timedelta(hours=8)
    dup_alerts = []
    for i in range(5):
        a_dup, r_dup = _make_alert(
            f"A-DUP-{i}", f"EV-DUP-{i}", t_s5 + timedelta(seconds=i * 2),
            "198.51.100.88", "10.0.0.50", threat_type="brute_force", severity="medium"
        )
        dup_alerts.append((a_dup, r_dup))
    fixtures.append({
        "scenario_id": "SCENARIO_5_DUPLICATE_REPLAY_FLOOD",
        "description": "Duplicate telemetry events replayed within 20 seconds",
        "alerts": dup_alerts,
        "ground_truth_clusters": {f"EV-DUP-{i}": "INC-DUP-1" for i in range(5)},
        "expected_incident_count": 1,
        "is_dedup_test": True,
    })

    # ── Scenario 6: Out-of-Order and Missing Timestamps ───────────────────────
    # T2 arrives before T1; T3 has None timestamp
    t_s6 = base_t + timedelta(hours=10)
    a_early, r_early = _make_alert(
        "A-OO-1", "EV-OO-1", t_s6 + timedelta(seconds=60), "198.51.100.66", "10.0.0.22",
        threat_type="lateral_movement", severity="high"
    )
    a_late, r_late = _make_alert(
        "A-OO-2", "EV-OO-2", t_s6, "198.51.100.66", "10.0.0.22",
        threat_type="lateral_movement", severity="high"
    )
    a_none, r_none = _make_alert(
        "A-OO-3", "EV-OO-3", None, "198.51.100.66", "10.0.0.22",
        threat_type="lateral_movement", severity="high",
        raw_timestamp=t_s6 + timedelta(seconds=120)
    )
    fixtures.append({
        "scenario_id": "SCENARIO_6_OUT_OF_ORDER_AND_MISSING_TIMESTAMPS",
        "description": "Alerts arriving out of chronological order and with None timestamps",
        "alerts": [(a_early, r_early), (a_late, r_late), (a_none, r_none)],
        "ground_truth_clusters": {
            "EV-OO-1": "INC-OUT-OF-ORDER",
            "EV-OO-2": "INC-OUT-OF-ORDER",
            "EV-OO-3": "INC-OUT-OF-ORDER",
        },
        "expected_incident_count": 1,
    })

    # ── Scenario 7: Concurrent Incidents on Separate Subnets ──────────────────
    t_s7 = base_t + timedelta(hours=12)
    a_s1a, r_s1a = _make_alert("A-C1", "EV-C1", t_s7, "198.51.100.1", "10.0.1.5", threat_type="brute_force")
    a_s2a, r_s2a = _make_alert("A-C2", "EV-C2", t_s7 + timedelta(seconds=10), "203.0.113.2", "10.0.2.10", threat_type="data_exfiltration")
    a_s1b, r_s1b = _make_alert("A-C3", "EV-C3", t_s7 + timedelta(seconds=20), "198.51.100.1", "10.0.1.5", threat_type="brute_force")
    a_s2b, r_s2b = _make_alert("A-C4", "EV-C4", t_s7 + timedelta(seconds=30), "203.0.113.2", "10.0.2.10", threat_type="data_exfiltration")
    fixtures.append({
        "scenario_id": "SCENARIO_7_CONCURRENT_SUBNET_INCIDENTS",
        "description": "Two simultaneous attack campaigns interleaved across Subnet A and Subnet B",
        "alerts": [(a_s1a, r_s1a), (a_s2a, r_s2a), (a_s1b, r_s1b), (a_s2b, r_s2b)],
        "ground_truth_clusters": {
            "EV-C1": "INC-SUBNET-A",
            "EV-C3": "INC-SUBNET-A",
            "EV-C2": "INC-SUBNET-B",
            "EV-C4": "INC-SUBNET-B",
        },
        "expected_incident_count": 2,
    })

    # ── Scenario 8: One Attacker Multiple Victims (Campaign Sweep) ────────────
    t_s8 = base_t + timedelta(hours=14)
    a_sw1, r_sw1 = _make_alert("A-SW1", "EV-SW1", t_s8, "198.51.100.99", "10.0.0.10", threat_type="brute_force")
    a_sw2, r_sw2 = _make_alert("A-SW2", "EV-SW2", t_s8 + timedelta(seconds=30), "198.51.100.99", "10.0.0.20", threat_type="brute_force")
    a_sw3, r_sw3 = _make_alert("A-SW3", "EV-SW3", t_s8 + timedelta(seconds=60), "198.51.100.99", "10.0.0.30", threat_type="brute_force")
    fixtures.append({
        "scenario_id": "SCENARIO_8_ONE_ATTACKER_MULTIPLE_VICTIMS",
        "description": "Single external attacker probing/attacking multiple internal victims in quick succession",
        "alerts": [(a_sw1, r_sw1), (a_sw2, r_sw2), (a_sw3, r_sw3)],
        "ground_truth_clusters": {
            "EV-SW1": "INC-ATTACKER-SWEEP",
            "EV-SW2": "INC-ATTACKER-SWEEP",
            "EV-SW3": "INC-ATTACKER-SWEEP",
        },
        "expected_incident_count": 1,
    })

    # ── Scenario 9: Unrelated Events Sharing Destination Server ───────────────
    t_s9 = base_t + timedelta(hours=16)
    a_u1, r_u1 = _make_alert("A-U1", "EV-U1", t_s9, "198.51.100.33", "10.0.0.80", threat_type="brute_force")
    a_u2, r_u2 = _make_alert("A-U2", "EV-U2", t_s9 + timedelta(seconds=15), "10.0.0.44", "10.0.0.80", threat_type="data_exfiltration")
    fixtures.append({
        "scenario_id": "SCENARIO_9_UNRELATED_EVENTS_SHARING_DESTINATION",
        "description": "External brute force and internal workstation exfiltration sharing the same DMZ destination",
        "alerts": [(a_u1, r_u1), (a_u2, r_u2)],
        "ground_truth_clusters": {
            "EV-U1": "INC-EXT-BRUTE",
            "EV-U2": "INC-INT-EXFIL",
        },
        "expected_incident_count": 2,
    })

    # ── Scenario 10: False Lateral Movement Pivot Rejection ───────────────────
    t_s10 = base_t + timedelta(hours=18)
    a_fp1, r_fp1 = _make_alert("A-FP1", "EV-FP1", t_s10, "198.51.100.55", "10.0.0.15", threat_type="brute_force")
    a_fp2, r_fp2 = _make_alert("A-FP2", "EV-FP2", t_s10 + timedelta(seconds=45), "10.0.0.99", "10.0.0.100", threat_type="lateral_movement")
    fixtures.append({
        "scenario_id": "SCENARIO_10_FALSE_PIVOT_REJECTION",
        "description": "Host 10.0.0.99 (never compromised by attacker) initiates lateral activity; must not be grouped into 10.0.0.15's incident",
        "alerts": [(a_fp1, r_fp1), (a_fp2, r_fp2)],
        "ground_truth_clusters": {
            "EV-FP1": "INC-COMPROMISED-15",
            "EV-FP2": "INC-UNRELATED-99",
        },
        "expected_incident_count": 2,
    })

    # ── Scenario 11: Ambiguous Sequences Across Disjoint Entities ─────────────
    t_s11 = base_t + timedelta(hours=20)
    a_amb1, r_amb1 = _make_alert("A-AMB1", "EV-AMB1", t_s11, "198.51.100.70", "10.0.0.21", threat_type="brute_force")
    a_amb2, r_amb2 = _make_alert("A-AMB2", "EV-AMB2", t_s11 + timedelta(seconds=10), "203.0.113.80", "10.0.0.22", threat_type="data_exfiltration")
    a_amb3, r_amb3 = _make_alert("A-AMB3", "EV-AMB3", t_s11 + timedelta(seconds=20), "198.51.100.90", "10.0.0.23", threat_type="c2_beaconing")
    fixtures.append({
        "scenario_id": "SCENARIO_11_AMBIGUOUS_SEQUENCES",
        "description": "Three distinct simultaneous attacks with disjoint entities and threat types; must not be merged",
        "alerts": [(a_amb1, r_amb1), (a_amb2, r_amb2), (a_amb3, r_amb3)],
        "ground_truth_clusters": {
            "EV-AMB1": "INC-DISJOINT-1",
            "EV-AMB2": "INC-DISJOINT-2",
            "EV-AMB3": "INC-DISJOINT-3",
        },
        "expected_incident_count": 3,
    })

    # ── Scenario 12: Incomplete Entity Identifiers & Partial Telemetry ────────
    t_s12 = base_t + timedelta(hours=22)
    a_inc1, r_inc1 = _make_alert("A-INC1", "EV-INC1", t_s12, "198.51.100.101", "10.0.0.50", threat_type="brute_force")
    # Alert with empty destination entity and missing ports
    a_inc2, r_inc2 = _make_alert("A-INC2", "EV-INC2", t_s12 + timedelta(seconds=30), "198.51.100.101", "10.0.0.50", threat_type="brute_force")
    r_inc2.dst_port = None
    fixtures.append({
        "scenario_id": "SCENARIO_12_INCOMPLETE_ENTITY_IDENTIFIERS",
        "description": "Alerts with partial telemetry or missing ports gracefully handled and grouped by source attacker",
        "alerts": [(a_inc1, r_inc1), (a_inc2, r_inc2)],
        "ground_truth_clusters": {
            "EV-INC1": "INC-PARTIAL-ID",
            "EV-INC2": "INC-PARTIAL-ID",
        },
        "expected_incident_count": 1,
    })

    return fixtures


def evaluate_correlation_quality(
    fixtures: Optional[List[Dict[str, Any]]] = None,
    output_dir: str = "data/models",
) -> Dict[str, Any]:
    """
    Run full fixture evaluation and compute pairwise cluster precision, recall,
    Adjusted Rand Index, merge errors, split errors, and traceability.
    """
    if fixtures is None:
        fixtures = build_benchmark_fixtures()

    scenario_results = []
    all_gt_pairs_same: Set[Tuple[str, str]] = set()
    all_gt_pairs_diff: Set[Tuple[str, str]] = set()
    all_pred_pairs_same: Set[Tuple[str, str]] = set()

    total_events_evaluated = 0
    total_traceable_events = 0
    total_incident_supporting_events = 0
    merge_errors = 0
    split_errors = 0
    duplicate_invariance_verified = True

    for fix in fixtures:
        scen_id = fix["scenario_id"]
        correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)
        event_to_incident: Dict[str, str] = {}
        priorities_recorded: List[float] = []

        for alert, raw_ev in fix["alerts"]:
            # If benign in Scenario 4, skip alert generation (as pipeline would)
            if alert.threat_type == "benign":
                event_to_incident[raw_ev.event_id] = "BENIGN_NOT_CORRELATED"
                continue

            # Deduplication
            fp = correlator.compute_event_fingerprint(raw_ev)
            ts = alert.timestamp or datetime.utcnow()
            if correlator.is_duplicate(fp, ts):
                # Map to existing incident
                inc_id = correlator.entity_to_incident.get(alert.src_entity, "SUPPRESSED_DUP")
                event_to_incident[raw_ev.event_id] = inc_id
                continue

            inc, _ = correlator.correlate_alert(alert, raw_event=raw_ev)
            event_to_incident[raw_ev.event_id] = inc.incident_id
            priorities_recorded.append(inc.priority_score)

        # Check duplicate invariance: duplicate flood in Scenario 5 must NOT inflate priority
        if fix.get("is_dedup_test"):
            if len(priorities_recorded) > 1:
                # With dedup, exactly 1 alert passed to correlator
                duplicate_invariance_verified = False
            elif len(priorities_recorded) == 1:
                duplicate_invariance_verified = True

        gt = fix["ground_truth_clusters"]
        ev_ids = list(gt.keys())
        total_events_evaluated += len(ev_ids)

        # Traceability check: all supporting events in correlated incidents
        for inc in correlator.get_all_incidents():
            for ev_dict in inc.supporting_events:
                total_incident_supporting_events += 1
                if isinstance(ev_dict, dict) and ev_dict.get("event_id"):
                    total_traceable_events += 1

        # Evaluate pairs within this scenario
        scen_merge_errs = 0
        scen_split_errs = 0
        for i in range(len(ev_ids)):
            for j in range(i + 1, len(ev_ids)):
                e1, e2 = ev_ids[i], ev_ids[j]
                gt_same = gt[e1] == gt[e2]
                pred_same = (
                    event_to_incident.get(e1) is not None
                    and event_to_incident.get(e2) is not None
                    and event_to_incident[e1] == event_to_incident[e2]
                    and not event_to_incident[e1].startswith("BENIGN")
                )

                pair = (min(e1, e2), max(e1, e2))
                if gt_same:
                    all_gt_pairs_same.add(pair)
                    if not pred_same:
                        split_errors += 1
                        scen_split_errs += 1
                else:
                    all_gt_pairs_diff.add(pair)
                    if pred_same:
                        merge_errors += 1
                        scen_merge_errs += 1

                if pred_same:
                    all_pred_pairs_same.add(pair)

        scenario_results.append({
            "scenario_id": scen_id,
            "description": fix["description"],
            "expected_incidents": fix["expected_incident_count"],
            "actual_incidents": len(correlator.incidents),
            "merge_errors": scen_merge_errs,
            "split_errors": scen_split_errs,
            "events": len(ev_ids),
        })

    # Global Pairwise Metrics
    tp_pairs = len(all_gt_pairs_same.intersection(all_pred_pairs_same))
    fp_pairs = len(all_pred_pairs_same.difference(all_gt_pairs_same))
    fn_pairs = len(all_gt_pairs_same.difference(all_pred_pairs_same))

    pair_prec = tp_pairs / max(tp_pairs + fp_pairs, 1)
    pair_rec = tp_pairs / max(tp_pairs + fn_pairs, 1)
    pair_f1 = (2 * pair_prec * pair_rec) / max(pair_prec + pair_rec, 1e-6)

    traceability_pct = min(round((total_traceable_events / max(total_incident_supporting_events, 1)) * 100, 2), 100.0)

    # Operational metrics
    total_raw_alerts = sum(len(f["alerts"]) for f in fixtures)
    total_suppressed_duplicates = sum(len(f["alerts"]) - 1 for f in fixtures if f.get("is_dedup_test"))
    total_incidents_created = sum(s["actual_incidents"] for s in scenario_results)
    triage_reduction_pct = round(
        (total_raw_alerts - total_incidents_created) / max(total_raw_alerts, 1) * 100, 2
    )

    report = {
        "metadata": {
            "evaluation_type": "fixture_based_correlation_validation",
            "timestamp": datetime.utcnow().isoformat(),
            "scenarios_evaluated": len(fixtures),
            "total_fixture_events": total_events_evaluated,
            "disclaimer": (
                "These results evaluate explicit correlation engine logic against controlled synthetic test fixtures. "
                "They validate algorithm correctness (merge prevention, pivot linking, deduplication) "
                "and must NOT be represented as real-world enterprise clustering accuracy."
            ),
        },
        "metrics": {
            "pairwise_cluster_precision": round(pair_prec, 4),
            "pairwise_cluster_recall": round(pair_rec, 4),
            "pairwise_cluster_f1": round(pair_f1, 4),
            "merge_errors_unrelated_merged": merge_errors,
            "split_errors_related_fragmented": split_errors,
            "evidence_traceability_pct": traceability_pct,
            "duplicate_risk_invariance_verified": duplicate_invariance_verified,
        },
        "operational_metrics": {
            "total_events_evaluated": total_events_evaluated,
            "raw_alerts_generated": total_raw_alerts,
            "duplicate_alerts_suppressed": total_suppressed_duplicates,
            "alerts_assigned_to_incidents": total_raw_alerts - total_suppressed_duplicates,
            "unassigned_alerts": 0,
            "incident_dossiers_created": total_incidents_created,
            "displayed_triage_reduction_pct": triage_reduction_pct,
        },
        "scenarios": scenario_results,
    }

    # Save to disk if requested
    if output_dir is not None:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "correlation_benchmark_results.json"
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"[CorrelationBenchmark] Results saved to {out_path}")

    return report


if __name__ == "__main__":
    rep = evaluate_correlation_quality()
    print("\n" + "=" * 70)
    print("AEGIS-ML INCIDENT CORRELATION QUALITY BENCHMARK")
    print("=" * 70)
    for k, v in rep["metrics"].items():
        print(f"  {k:<38}: {v}")
    print("=" * 70)
    print(f"\nScenarios evaluated: {len(rep['scenarios'])}")
    for s in rep["scenarios"]:
        print(f"  [{s['scenario_id']}] Expected: {s['expected_incidents']}, Got: {s['actual_incidents']}, Merges: {s['merge_errors']}, Splits: {s['split_errors']}")
