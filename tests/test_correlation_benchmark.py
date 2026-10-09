"""
Tests for AEGIS-ML Correlation Quality Benchmark (Phase 8)
=========================================================
Validates:
  - Scenario fixture construction
  - Execution of correlation benchmark
  - Zero merge errors on independent attackers with shared victims
  - Complete evidence traceability
  - Invariance under duplicate alert replay flood
"""

import pytest
from backend.evaluation.correlation_benchmark import (
    build_benchmark_fixtures,
    evaluate_correlation_quality,
)


def test_build_benchmark_fixtures():
    fixtures = build_benchmark_fixtures()
    assert len(fixtures) == 12
    scenario_ids = [f["scenario_id"] for f in fixtures]
    assert "SCENARIO_1_MULTI_STAGE_APT" in scenario_ids
    assert "SCENARIO_2_SHARED_VICTIM_INDEPENDENT_ATTACKERS" in scenario_ids
    assert "SCENARIO_5_DUPLICATE_REPLAY_FLOOD" in scenario_ids
    assert "SCENARIO_6_OUT_OF_ORDER_AND_MISSING_TIMESTAMPS" in scenario_ids
    assert "SCENARIO_8_ONE_ATTACKER_MULTIPLE_VICTIMS" in scenario_ids
    assert "SCENARIO_9_UNRELATED_EVENTS_SHARING_DESTINATION" in scenario_ids
    assert "SCENARIO_10_FALSE_PIVOT_REJECTION" in scenario_ids


def test_evaluate_correlation_quality_end_to_end():
    report = evaluate_correlation_quality()
    metrics = report["metrics"]
    op_metrics = report.get("operational_metrics", {})

    # No unrelated events erroneously merged
    assert metrics["merge_errors_unrelated_merged"] == 0
    # No related events fragmented
    assert metrics["split_errors_related_fragmented"] == 0
    # Perfect pairwise precision and recall on controlled fixtures
    assert metrics["pairwise_cluster_precision"] == 1.0
    assert metrics["pairwise_cluster_recall"] == 1.0
    # Traceability 100%
    assert metrics["evidence_traceability_pct"] == 100.0
    # Duplicate invariance verified
    assert metrics["duplicate_risk_invariance_verified"] is True
    # Operational metrics populated
    assert op_metrics.get("raw_alerts_generated", 0) > 0


def test_independent_attackers_never_merged():
    """Verify specifically that two attackers on the same victim produce 2 incidents."""
    fixtures = build_benchmark_fixtures()
    s2 = next(f for f in fixtures if f["scenario_id"] == "SCENARIO_2_SHARED_VICTIM_INDEPENDENT_ATTACKERS")
    report = evaluate_correlation_quality(fixtures=[s2], output_dir=None)
    scen_res = report["scenarios"][0]
    assert scen_res["expected_incidents"] == 2
    assert scen_res["actual_incidents"] == 2
    assert scen_res["merge_errors"] == 0


def test_unrelated_events_sharing_destination_never_merged():
    """Verify that external brute force and internal exfiltration sharing destination remain separate."""
    fixtures = build_benchmark_fixtures()
    s9 = next(f for f in fixtures if f["scenario_id"] == "SCENARIO_9_UNRELATED_EVENTS_SHARING_DESTINATION")
    report = evaluate_correlation_quality(fixtures=[s9], output_dir=None)
    scen_res = report["scenarios"][0]
    assert scen_res["expected_incidents"] == 2
    assert scen_res["actual_incidents"] == 2
    assert scen_res["merge_errors"] == 0


def test_one_attacker_multiple_victims_grouped():
    """Verify that an attacker sweeping multiple hosts is grouped into a single campaign."""
    fixtures = build_benchmark_fixtures()
    s8 = next(f for f in fixtures if f["scenario_id"] == "SCENARIO_8_ONE_ATTACKER_MULTIPLE_VICTIMS")
    report = evaluate_correlation_quality(fixtures=[s8], output_dir=None)
    scen_res = report["scenarios"][0]
    assert scen_res["expected_incidents"] == 1
    assert scen_res["actual_incidents"] == 1
    assert scen_res["split_errors"] == 0


def test_false_pivot_rejection():
    """Verify that activity from an uninvolved host is not attributed as a pivot."""
    fixtures = build_benchmark_fixtures()
    s10 = next(f for f in fixtures if f["scenario_id"] == "SCENARIO_10_FALSE_PIVOT_REJECTION")
    report = evaluate_correlation_quality(fixtures=[s10], output_dir=None)
    scen_res = report["scenarios"][0]
    assert scen_res["expected_incidents"] == 2
    assert scen_res["actual_incidents"] == 2
    assert scen_res["merge_errors"] == 0
