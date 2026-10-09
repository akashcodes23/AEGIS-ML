import json
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

from backend.core.schemas import UnifiedEvent
from backend.detection.model_trainer import load_flexible_dataset


@pytest.fixture
def temp_dataset_files(tmp_path):
    # 1. Create a sample CSV with CICIDS-style headers and whitespace in labels
    csv_file = tmp_path / "sample_cicids.csv"
    csv_content = (
        " Destination Port , Total Length of Fwd Packets , Total Length of Bwd Packets , Flow Duration , Label \n"
        " 80 , 500 , 1200 , 150000 , BENIGN \n"
        " 445 , 128 , 256 , 50000 ,  PortScan \n"
        " 21 , 64 , 128 , 30000 , FTP-Patator \n"
        " 8080 , 200 , 400 , 20000 , Bot \n"
        " 443 , 1000000 , 500 , 40000 , Infiltration \n"
        " 9999 , 100 , 200 , 10000 , Unknown_Zero_Day_Attack \n"
    )
    csv_file.write_text(csv_content)

    # 2. Create a sample JSONL file
    jsonl_file = tmp_path / "sample_events.jsonl"
    events_data = [
        {
            "timestamp": "2026-04-01T12:00:00",
            "layer": "network",
            "src_entity": "10.0.0.1",
            "dst_entity": "10.0.0.2",
            "src_internal": True,
            "dst_internal": True,
            "attack_type": "benign",
            "bytes_sent": 100,
            "bytes_received": 200,
        },
        {
            "timestamp": "2026-04-01T12:00:01",
            "layer": "network",
            "src_entity": "10.0.0.5",
            "dst_entity": "10.0.0.6",
            "src_internal": True,
            "dst_internal": True,
            "attack_type": "brute_force",
            "bytes_sent": 500,
            "bytes_received": 100,
        },
    ]
    with open(jsonl_file, "w") as f:
        for ev in events_data:
            f.write(json.dumps(ev) + "\n")

    return {"csv": str(csv_file), "jsonl": str(jsonl_file)}


def test_load_flexible_dataset_csv_normalization(temp_dataset_files):
    events, stats = load_flexible_dataset(temp_dataset_files["csv"])

    assert stats["raw_records_read"] == 6
    # 5 known mapped labels, 1 unknown zero-day
    assert stats["retained_events"] == 5
    assert "Unknown_Zero_Day_Attack" in stats["unmapped_labels_encountered"]
    assert stats["unmapped_labels_encountered"]["Unknown_Zero_Day_Attack"] == 1

    labels = [e.attack_type for e in events]
    assert "benign" in labels
    assert "lateral_movement" in labels  # PortScan mapped
    assert "brute_force" in labels       # FTP-Patator mapped
    assert "c2_beaconing" in labels      # Bot mapped
    assert "lateral_movement" in labels or "data_exfiltration" in labels

    # Ensure unknown label was NOT automatically cast to benign
    assert "Unknown_Zero_Day_Attack" not in labels


def test_load_flexible_dataset_jsonl(temp_dataset_files):
    events, stats = load_flexible_dataset(temp_dataset_files["jsonl"])

    assert len(events) == 2
    assert stats["retained_events"] == 2
    assert events[0].attack_type == "benign"
    assert events[1].attack_type == "brute_force"


def test_load_flexible_dataset_missing_and_invalid_values(tmp_path):
    bad_csv = tmp_path / "bad_values.csv"
    bad_content = (
        "Destination Port,Total Length of Fwd Packets,Total Length of Bwd Packets,Flow Duration,Label\n"
        "80,Infinity,NaN,-500,BENIGN\n"
        "8080,100,200,1000,BENIGN\n"
    )
    bad_csv.write_text(bad_content)

    events, stats = load_flexible_dataset(str(bad_csv))
    assert len(events) == 2
    # Verify Infinity and NaN were sanitized without crashing
    assert events[0].bytes_sent is None
    assert events[0].bytes_received is None
    assert events[0].duration_ms == 0
