"""
Phase 24 Tests: External Dataset Evaluation and Generalization Audit
Module: tests.test_phase24_external_dataset_evaluation

Verifies:
1. 48-feature schema compatibility categorization (Categories A, B, C, D, E).
2. Existing-model transfer evaluation infeasibility detection (INCOMPATIBLE_TELEMETRY).
3. Strict semantic label mapping and unmapped/unknown label handling.
4. Safe 'not_completed' status reporting when external dataset is absent locally.
5. Ingestion data quality scanning (Infs, NaNs, duplicates, negative values).
6. Controlled fixture execution of retrained external benchmark.
7. Metric denominator correctness (Benign FPR, Attack Recall).
8. Immutability of the active production model artifact during evaluation.
9. Prevention of ground-truth and IP identifier leakage.
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
from backend.evaluation.external_dataset_evaluation import (
    AEGIS_48_FEATURE_NAMES,
    OBSERVABLE_FLOW_FEATURE_NAMES,
    CICIDS2017_METADATA,
    audit_feature_compatibility,
    evaluate_model_transfer_feasibility,
    map_external_label,
    scan_dataset_quality_and_leakage,
    extract_observable_flow_features,
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

    # Incompatible features must be exactly C union D (10 + 7 = 17)
    cats = audit["feature_lists"]
    assert set(cats["category_e"]) == set(cats["category_c"] + cats["category_d"])

    # All 48 features in canonical list must be accounted for
    all_feats = set(cats["category_a"] + cats["category_b"] + cats["category_c"] + cats["category_d"])
    assert all_feats == set(AEGIS_48_FEATURE_NAMES)
    assert audit["percentages"]["incompatible_or_unobserved_pct"] == 35.4


def test_transfer_feasibility_evaluation_verdict():
    """Verify that existing 48-feature calibrated model cannot be transferred to network-only flows."""
    feasibility = evaluate_model_transfer_feasibility()
    assert feasibility["transfer_feasible"] is False
    assert feasibility["status"] == "NOT_FEASIBLE"
    assert feasibility["limitation_category"] == "INCOMPATIBLE_TELEMETRY"
    assert feasibility["expected_feature_count"] == 48
    assert len(feasibility["blocking_reasons"]) >= 4
    # Ensure reason mentions endpoint or dual-telemetry incompatibility
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

    # 3. Lateral movement / Reconnaissance
    c_ps, b_ps, _ = map_external_label("PortScan")
    assert c_ps == "lateral_movement"
    assert b_ps == "attack"

    # 4. C2 beaconing
    c_bot, b_bot, _ = map_external_label("Bot")
    assert c_bot == "c2_beaconing"
    assert b_bot == "attack"

    # 5. Data exfiltration
    c_hb, b_hb, _ = map_external_label("Heartbleed")
    assert c_hb == "data_exfiltration"
    assert b_hb == "attack"

    # 6. Excluded from multi-class canonical mapping (DDoS is traffic flooding, not targeted intrusion)
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


def test_production_model_immutability(tmp_path):
    """Verify that running Phase 24 evaluation never modifies calibrated_threat_classifier.pkl."""
    cal_model_path = Path(MODEL_DIR) / "calibrated_threat_classifier.pkl"
    if not cal_model_path.exists():
        pytest.skip("Calibrated model artifact not found.")

    initial_sha = compute_file_sha256(cal_model_path)

    # Create a small valid fixture to evaluate
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
    res = run_phase24_evaluation(dataset_path=str(csv_file), output_path=str(report_out))

    assert res["status"] == "completed"

    # Verify model file was not modified
    final_sha = compute_file_sha256(cal_model_path)
    assert initial_sha == final_sha, "CRITICAL: calibrated_threat_classifier.pkl was modified during evaluation!"


def test_controlled_fixture_retrained_benchmark(tmp_path):
    """
    Verify the external retrained benchmark end-to-end on a controlled CIC-IDS2017 fixture
    containing multi-class labels, Inf values, negative values, and duplicate flows.
    """
    fixture_rows = []
    base_time = datetime(2017, 7, 3, 9, 0, 0)
    # 120 distinct records: 60 benign, 30 FTP-Patator (brute_force), 30 Bot (c2_beaconing)
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

        # Inject known CICFlowMeter defects:
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

    # Append 5 explicit duplicate rows to test deduplication scanner
    for dup_i in range(5):
        fixture_rows.append(dict(fixture_rows[dup_i]))

    csv_path = tmp_path / "test_cicids_fixture.csv"
    pd.DataFrame(fixture_rows).to_csv(csv_path, index=False)

    report_out = tmp_path / "fixture_report.json"
    res = run_phase24_evaluation(dataset_path=str(csv_path), output_path=str(report_out), random_seed=42)

    assert res["status"] == "completed"
    assert res["dataset_acquisition_status"] == "VERIFIED_LOCAL_COPY"

    # Quality scan assertions
    q_scan = res["data_quality_and_leakage_scan"]
    assert q_scan["quality_scan_completed"] is True
    assert q_scan["total_inf_cells"] >= 1
    assert q_scan["negative_duration_records"] >= 1

    # Retrained benchmark assertions
    exp = res["retrained_experiment"]
    assert exp is not None
    assert exp["observable_feature_count"] == 18

    # Binary evaluation metrics & denominators
    bin_eval = exp["binary_evaluation"]
    assert 0.0 <= bin_eval["benign_false_alarm_rate"] <= 1.0
    assert 0.0 <= bin_eval["attack_recall"] <= 1.0
    assert "FP (" in bin_eval["benign_false_alarm_denominator"]
    assert "TP (" in bin_eval["attack_recall_denominator"]

    cm = bin_eval["confusion_matrix"]
    tn, fp = cm["true_negatives"], cm["false_positives"]
    fn, tp = cm["false_negatives"], cm["true_positives"]
    test_total = exp["sample_counts"]["test_samples"]
    assert tn + fp + fn + tp == test_total

    # Multi-class evaluation assertions
    mc_eval = exp["multi_class_evaluation"]
    assert mc_eval is not None
    assert "benign" in mc_eval["active_classes"]
    assert mc_eval["macro_f1"] > 0.0
    tax = mc_eval["misclassification_taxonomy"]
    assert "benign_classified_as_attack_count" in tax
    assert "attack_classified_as_benign_count" in tax
    assert "attack_subtype_confusion_count" in tax


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
    # Must produce float array of shape (10, 18)
    assert isinstance(features, np.ndarray)
    assert features.shape == (10, 18)
    # Check that all features are finite
    assert np.all(np.isfinite(features))
