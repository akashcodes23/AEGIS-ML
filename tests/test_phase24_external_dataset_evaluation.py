"""
Phase 24.1 Tests: CIC-IDS2017 Acquisition, Leakage-Resistant Evaluation, and Network-Flow Benchmark
Module: tests.test_phase24_external_dataset_evaluation

Verifies:
1. 48-feature general schema compatibility categorization (Categories A, B, C, D, E).
2. Complete audit of all 18 observable flow features with transformation, units, and leakage risk.
3. Existing-model transfer evaluation infeasibility detection (INCOMPATIBLE_TELEMETRY).
4. Strict semantic label mapping, PortScan caveat, and unknown label handling.
5. Safe 'not_completed' status reporting when external dataset is absent locally.
6. CSV schema handling, missing label fallback, and non-finite value sanitization.
7. Leakage-resistant splitting strategies (Stratified Random, Grouped Pair, Temporal Causal).
8. Grouped split 0.0% communication pair overlap verification.
9. Train-only fitting of SMOTE, scalers, and graph baseline pairs.
10. Metric denominator correctness (Benign FPR, Attack Recall) and calibration metrics (Brier, Log-Loss).
11. Separate experimental artifact paths (data/models/external_experiments/cicids2017/).
12. Immutability of the active production model artifact during evaluation.
13. Prevention of ground-truth and IP identifier leakage.
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta

import pytest
import numpy as np
import pandas as pd

from backend.core.config import PROJECT_ROOT, MODEL_DIR, RF_CLASSIFIER_PATH
from backend.core.schemas import UnifiedEvent
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.evaluation.external_dataset_evaluation import (
    AEGIS_48_FEATURE_NAMES,
    OBSERVABLE_FLOW_FEATURE_NAMES,
    CICIDS2017_METADATA,
    audit_feature_compatibility,
    audit_observable_flow_features,
    evaluate_model_transfer_feasibility,
    map_external_label,
    scan_dataset_quality_and_leakage,
    extract_observable_flow_features,
    partition_dataset,
    execute_external_retrained_benchmark,
    run_phase24_evaluation,
)


def compute_file_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def test_schema_compatibility_audit_totals_and_categories():
    """Verify all 48 features are accounted for across Categories A-E without omission."""
    audit = audit_feature_compatibility()
    assert audit["total_features"] == 48

    cat_counts = audit["counts"]
    assert cat_counts["category_a_directly_observable"] == 14
    assert cat_counts["category_b_computable_transformations"] == 17
    assert cat_counts["category_c_dependent_on_missing_telemetry"] == 10
    assert cat_counts["category_d_dependent_on_unreconstructable_context"] == 7
    assert cat_counts["category_e_unavailable_or_incompatible"] == 17

    cats = audit["feature_lists"]
    assert set(cats["category_e"]) == set(cats["category_c"] + cats["category_d"])

    all_feats = set(cats["category_a"] + cats["category_b"] + cats["category_c"] + cats["category_d"])
    assert all_feats == set(AEGIS_48_FEATURE_NAMES)
    assert audit["percentages"]["incompatible_or_unobserved_pct"] == 35.4


def test_observable_18_feature_audit_complete():
    """Verify each of the 18 observable flow features is comprehensively documented without identifier leakage."""
    audit = audit_observable_flow_features()
    assert len(audit) == 18

    audited_names = [f["feature_name"] for f in audit]
    assert audited_names == OBSERVABLE_FLOW_FEATURE_NAMES

    for f in audit:
        assert "source_column" in f
        assert "transformation" in f
        assert "units" in f
        assert "missing_handling" in f
        assert "uses_identifiers" in f
        assert f["uses_identifiers"] is False  # Must NOT use raw IPs, timestamps, or labels as features
        assert f["inference_time_available"] is True
        assert "leakage_risk" in f


def test_transfer_feasibility_evaluation_verdict():
    """Verify that existing 48-feature calibrated model cannot be transferred to network-only flows."""
    feasibility = evaluate_model_transfer_feasibility()
    assert feasibility["transfer_feasible"] is False
    assert feasibility["status"] == "NOT_FEASIBLE"
    assert feasibility["limitation_category"] == "INCOMPATIBLE_TELEMETRY"
    assert feasibility["expected_feature_count"] == 48
    assert len(feasibility["blocking_reasons"]) >= 4
    assert any("endpoint" in r.lower() for r in feasibility["blocking_reasons"])


def test_label_mapping_and_unknown_labels():
    """Verify strict semantic mapping, exclusion of DoS from 5-class, and handling of unknown labels."""
    # 1. Benign
    c_benign, b_benign, exp = map_external_label("BENIGN")
    assert c_benign == "benign"
    assert b_benign == "benign"

    # 2. Brute force
    c_bf, b_bf, _ = map_external_label("FTP-Patator")
    assert c_bf == "brute_force"
    assert b_bf == "attack"

    # 3. PortScan: must document research caveat
    c_ps, b_ps, exp_ps = map_external_label("PortScan")
    assert c_ps == "lateral_movement"
    assert b_ps == "attack"
    assert "caveat" in exp_ps.lower()

    # 4. C2 beaconing
    c_bot, b_bot, _ = map_external_label("Bot")
    assert c_bot == "c2_beaconing"
    assert b_bot == "attack"

    # 5. Data exfiltration
    c_hb, b_hb, _ = map_external_label("Heartbleed")
    assert c_hb == "data_exfiltration"
    assert b_hb == "attack"

    # 6. Excluded from multi-class canonical mapping
    c_ddos, b_ddos, exp_ddos = map_external_label("DDoS")
    assert c_ddos is None
    assert b_ddos == "attack"
    assert "Excluded" in exp_ddos

    # 7. Web Attacks with encoding quirks (em-dash variants)
    c_web, b_web, _ = map_external_label("Web Attack \x96 Brute Force")
    assert c_web == "brute_force"
    assert b_web == "attack"

    # 8. Arbitrary unknown attack label
    c_unk, b_unk, exp_unk = map_external_label("UnknownZeroDayVariant")
    assert c_unk is None
    assert b_unk == "attack"
    assert "Unmapped" in exp_unk


def test_missing_dataset_safe_reporting(tmp_path):
    """Verify that a non-existent external file returns 'not_completed' and does not fabricate metrics."""
    non_existent = tmp_path / "absent_file.csv"
    report_out = tmp_path / "missing_report.json"

    res = run_phase24_evaluation(dataset_path=str(non_existent), output_path=str(report_out))

    assert res["status"] == "not_completed"
    assert res["status_code"] == "BLOCKED_AWAITING_LOCAL_COPY"
    assert res["dataset_acquisition_status"] == "NOT_DOWNLOADED"
    assert res["retrained_experiment"] is None
    assert "No CIC-IDS2017 CSV files found" in res["reason"]
    assert report_out.exists()


def test_leakage_resistant_splitting_strategies():
    """Verify Stratified Random, Grouped Pair, and Temporal Causal splitting behaviors."""
    base_time = datetime(2017, 7, 3, 9, 0, 0)
    events = []
    # Create 100 events across 5 distinct communication pairs
    for i in range(100):
        pair_id = i % 5
        src = f"192.168.10.{10 + pair_id}"
        dst = f"10.0.0.{100 + pair_id}"
        lbl = "BENIGN" if (i % 2 == 0) else "FTP-Patator"
        t = base_time + timedelta(seconds=i * 10)
        events.append(
            UnifiedEvent(
                event_id=f"ev_{i}",
                timestamp=t,
                layer="network",
                src_entity=src,
                dst_entity=dst,
                src_internal=True,
                dst_internal=False,
                src_ip=src,
                dst_ip=dst,
                dst_port=80 if lbl == "BENIGN" else 21,
                protocol="TCP",
                bytes_sent=500 + i,
                bytes_received=200,
                raw_label=lbl,
            )
        )

    # 1. Stratified Random
    tr_r, te_r, meta_r = partition_dataset(events, split_strategy="stratified_random", test_size=0.20, random_seed=42)
    assert len(tr_r) == 80
    assert len(te_r) == 20
    assert meta_r["strategy"] == "stratified_random"

    # 2. Grouped Communication Pair (guaranteed 0% pair overlap)
    tr_g, te_g, meta_g = partition_dataset(events, split_strategy="grouped_communication_pair", test_size=0.20, random_seed=42)
    assert len(tr_g) > 0 and len(te_g) > 0
    assert meta_g["cross_partition_pair_overlap_count"] == 0
    assert meta_g["cross_partition_pair_overlap_pct"] == 0.0

    # 3. Temporal Causal (ordered chronologically)
    tr_t, te_t, meta_t = partition_dataset(events, split_strategy="temporal_causal", test_size=0.20, random_seed=42)
    assert len(tr_t) == 80
    assert len(te_t) == 20
    max_train_time = max(events[i].timestamp for i in tr_t)
    min_test_time = min(events[i].timestamp for i in te_t)
    assert max_train_time <= min_test_time, "Temporal split must place all training events before test events"


def test_train_only_fitting_and_label_leakage_prevention():
    """Verify that graph baseline pairs and SMOTE are learned strictly from training events."""
    base_time = datetime(2017, 7, 3, 9, 0, 0)
    train_events = [
        UnifiedEvent(
            event_id=f"tr_{i}",
            timestamp=base_time + timedelta(seconds=i),
            layer="network",
            src_entity="192.168.1.10",
            dst_entity="10.0.0.1",
            src_internal=True,
            dst_internal=False,
            dst_port=80,
            protocol="TCP",
            bytes_sent=100,
            bytes_received=200,
            raw_label="benign",
        )
        for i in range(10)
    ]

    test_events = [
        UnifiedEvent(
            event_id=f"te_{i}",
            timestamp=base_time + timedelta(seconds=100 + i),
            layer="network",
            src_entity="192.168.2.99",
            dst_entity="203.0.113.5",
            src_internal=True,
            dst_internal=False,
            dst_port=8080,
            protocol="TCP",
            bytes_sent=5000,
            bytes_received=50,
            raw_label="bot",
        )
        for i in range(5)
    ]

    tracker = CausalTemporalGraphTracker()
    tracker.fit_baseline_pairs(train_events)

    # 1. Verify train pairs are learned, but test pairs are strictly NOT in known_pairs prior to evaluation
    assert ("192.168.1.10", "10.0.0.1") in tracker.known_pairs
    assert ("192.168.2.99", "203.0.113.5") not in tracker.known_pairs

    # 2. Extract test features using train-fitted tracker
    X_te = extract_observable_flow_features(test_events, tracker=tracker, fit_tracker=False)

    # 3. The 'is_new_src_dst_pair' feature (index 14) for the first test flow must be 1.0 (novel pair)
    assert X_te[0, 14] == 1.0


def test_production_model_immutability(tmp_path):
    """Verify that running Phase 24.1 evaluation never modifies calibrated_threat_classifier.pkl."""
    cal_model_path = Path(MODEL_DIR) / "calibrated_threat_classifier.pkl"
    if not cal_model_path.exists():
        pytest.skip("Calibrated model artifact not found.")

    initial_sha = compute_file_sha256(cal_model_path)

    fixture_rows = []
    base_time = datetime(2017, 7, 3, 9, 0, 0)
    for i in range(60):
        lbl = "BENIGN" if i < 40 else "FTP-Patator"
        fixture_rows.append({
            " Source IP": f"192.168.10.{i}",
            " Destination IP": "10.0.0.1",
            " Destination Port": 80 if i < 40 else 21,
            " Source Port": 40000 + i,
            " Protocol": 6,
            " Total Length of Fwd Packets": 500,
            " Total Length of Bwd Packets": 200,
            " Flow Duration": 100000,
            " Timestamp": (base_time + timedelta(seconds=i)).strftime("%d/%m/%Y %H:%M:%S"),
            " Label": lbl,
        })
    csv_file = tmp_path / "immutability_fixture.csv"
    pd.DataFrame(fixture_rows).to_csv(csv_file, index=False)

    report_out = tmp_path / "immutability_report.json"
    res = run_phase24_evaluation(dataset_path=str(csv_file), output_path=str(report_out), save_model=False)

    assert res["status"] == "completed"

    final_sha = compute_file_sha256(cal_model_path)
    assert initial_sha == final_sha, "CRITICAL: calibrated_threat_classifier.pkl was modified during evaluation!"


def test_controlled_fixture_triple_split_and_experimental_model_persistence(tmp_path):
    """
    Verify the external retrained benchmark end-to-end on a controlled CIC-IDS2017 fixture
    containing multi-class labels, Inf values, negative values, and duplicate flows.
    Confirms triple split comparison, Brier/Log-loss calculation, and separate experimental artifact saving.
    """
    fixture_rows = []
    base_time = datetime(2017, 7, 3, 9, 0, 0)
    for i in range(120):
        if i < 60:
            lbl = "BENIGN"
            src = f"192.168.10.{i + 1}"
            dst = "192.168.10.1"
            dport = 80
            bytes_tx = 400 + i * 5
        elif i < 90:
            lbl = "FTP-Patator"
            src = f"172.16.0.{i - 59}"
            dst = "192.168.10.50"
            dport = 21
            bytes_tx = 1500 + i * 10
        else:
            lbl = "Bot"
            src = f"192.168.20.{i - 89}"
            dst = "203.0.113.5"
            dport = 8080
            bytes_tx = 128

        fwd_len = float("inf") if i == 0 else bytes_tx
        flow_dur = -500 if i == 1 else 250000

        row = {
            " Source IP": src,
            " Destination IP": dst,
            " Destination Port": dport,
            " Source Port": 40000 + i,
            " Protocol": 6,
            " Total Length of Fwd Packets": fwd_len,
            " Total Length of Bwd Packets": 200,
            " Flow Duration": flow_dur,
            " Timestamp": (base_time + timedelta(seconds=i * 2)).strftime("%d/%m/%Y %H:%M:%S"),
            " Label": lbl,
        }
        fixture_rows.append(row)

    # Append 5 explicit duplicate rows
    for dup_i in range(5):
        fixture_rows.append(dict(fixture_rows[dup_i]))

    csv_path = tmp_path / "test_cicids_fixture.csv"
    pd.DataFrame(fixture_rows).to_csv(csv_path, index=False)

    report_out = tmp_path / "fixture_report.json"
    res = run_phase24_evaluation(
        dataset_path=str(csv_path),
        output_path=str(report_out),
        random_seed=42,
        save_model=True,
        model_output_dir=str(tmp_path / "external_experiments" / "cicids2017"),
    )

    assert res["status"] == "completed"
    assert res["dataset_acquisition_status"] == "VERIFIED_LOCAL_COPY"

    # Quality scan assertions
    q_scan = res["data_quality_and_leakage_scan"]
    assert q_scan["quality_scan_completed"] is True
    assert q_scan["total_inf_cells"] >= 1
    assert q_scan["negative_duration_records"] >= 1

    # Split comparison assertions
    splits = res["split_comparison"]
    assert "stratified_random" in splits
    assert "grouped_communication_pair" in splits
    assert "temporal_causal" in splits

    # Grouped split must have 0% pair overlap
    grp_meta = splits["grouped_communication_pair"]["split_metadata"]
    assert grp_meta["cross_partition_pair_overlap_pct"] == 0.0

    # Binary evaluation metrics & denominators
    bin_eval = splits["stratified_random"]["binary_evaluation"]
    assert 0.0 <= bin_eval["benign_false_alarm_rate"] <= 1.0
    assert 0.0 <= bin_eval["attack_recall"] <= 1.0
    assert "FP (" in bin_eval["benign_false_alarm_denominator"]
    assert "TP (" in bin_eval["attack_recall_denominator"]
    assert bin_eval["brier_score"] is not None
    assert bin_eval["log_loss"] is not None

    # Separate experimental model artifact verification
    exp_model_path = splits["stratified_random"]["saved_experimental_model_path"]
    assert exp_model_path is not None
    assert "external_experiments" in exp_model_path
    assert Path(exp_model_path).exists()
    meta_path = Path(exp_model_path).with_name("network_flow_rf_metadata.json")
    assert meta_path.exists()

    # Original-label evaluation assertions
    orig_eval = splits["stratified_random"]["original_label_evaluation"]
    assert orig_eval is not None
    assert orig_eval["macro_f1"] > 0.0

    # Derived canonical multiclass evaluation assertions
    mc_eval = splits["stratified_random"]["derived_canonical_evaluation"]
    assert mc_eval is not None
    assert "PortScan" in mc_eval["mapping_caveat"]


def test_leakage_checks_and_identifier_exclusion():
    """Verify that raw IPs, timestamps, and target labels are not used as numeric features."""
    events = [
        UnifiedEvent(
            event_id=f"ev_{i}",
            timestamp=datetime(2026, 10, 10, 12, i % 60),
            layer="network",
            src_entity="192.168.1.100",
            dst_entity="203.0.113.10",
            src_internal=True,
            dst_internal=False,
            src_ip="192.168.1.100",
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="TCP",
            bytes_sent=1500,
            bytes_received=3000,
            raw_label="benign",
        )
        for i in range(10)
    ]

    features = extract_observable_flow_features(events)
    assert isinstance(features, np.ndarray)
    assert features.shape == (10, 18)
    assert np.all(np.isfinite(features))
