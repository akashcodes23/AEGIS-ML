"""
AEGIS-ML CIC-IDS2017 Dataset Loader
=====================================
Loads and normalizes the CIC-IDS2017 intrusion detection benchmark dataset
into AEGIS-ML UnifiedEvent format.

DATASET PROVENANCE:
  CIC-IDS2017 is a publicly available benchmark dataset produced by the
  Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick.
  Reference: Sharafaldin, I., Habibi Lashkari, A., Ghorbani, A. (2018).
             "Toward Generating a New Intrusion Detection Dataset and Intrusion
             Traffic Characterization." ICISSP 2018.
  URL: https://www.unb.ca/cic/datasets/ids-2017.html

IMPORTANT LIMITATIONS:
  - This loader operates on a LOCAL authorized copy ONLY.
  - Do NOT download CIC-IDS2017 automatically or commit it to the repository.
  - The CIC-IDS2017 dataset has known quality issues: duplicate rows, Inf values,
    NaN flows, and label inconsistencies. This loader handles all documented issues.
  - Class mapping is approximate. See DATASET_LABEL_MAP in model_trainer.py for
    the canonical mapping decisions and their rationale.
  - If the dataset file is not available, the loader returns empty results
    with a documented error. Do NOT claim real-dataset results without the file.
  - CIC-IDS2017 results MUST be reported separately from synthetic dataset results.

KNOWN ISSUES IN CIC-IDS2017 (documented):
  - 'Infinity' and NaN values appear in several flow-feature columns.
  - Duplicate rows exist (same flow, same timestamp) — use dedup=True.
  - The 'Label' column contains inconsistent casing and whitespace.
  - Timestamp format varies across daily CSV files.
  - Flow Duration is in microseconds (convert to milliseconds).
  - Some feature columns have negative values due to overflow bugs in CICFlowMeter.

COLUMN MAPPING (CIC-IDS2017 → UnifiedEvent):
  Source IP             → src_ip / src_entity
  Destination IP        → dst_ip / dst_entity
  Destination Port      → dst_port
  Protocol              → protocol (6=TCP, 17=UDP, 0=unspecified)
  Total Length of Fwd Packets → bytes_sent
  Total Length of Bwd Packets → bytes_received
  Flow Duration         → duration_ms (÷1000 from microseconds)
  Label                 → raw_label → DATASET_LABEL_MAP → attack_type

USAGE:
  from backend.ingestion.cicids_loader import load_cicids2017

  events, stats = load_cicids2017("/path/to/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv")
  print(stats)

IMPORT PROCEDURE:
  See docs/CICIDS2017_IMPORT.md for full instructions.
"""

import logging
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

try:
    from backend.core.schemas import UnifiedEvent
    from backend.detection.model_trainer import DATASET_LABEL_MAP, CANONICAL_CLASSES
except ModuleNotFoundError:
    from core.schemas import UnifiedEvent
    from detection.model_trainer import DATASET_LABEL_MAP, CANONICAL_CLASSES


# CIC-IDS2017 column mapping to UnifiedEvent field names
_CICIDS_COLUMN_MAP: Dict[str, str] = {
    " source ip": "src_ip",
    "source ip": "src_ip",
    " destination ip": "dst_ip",
    "destination ip": "dst_ip",
    " destination port": "dst_port",
    "destination port": "dst_port",
    " source port": "src_port",
    "source port": "src_port",
    " protocol": "protocol",
    "protocol": "protocol",
    " total length of fwd packets": "bytes_sent",
    "total length of fwd packets": "bytes_sent",
    " total length of bwd packets": "bytes_received",
    "total length of bwd packets": "bytes_received",
    " flow duration": "duration_ms",
    "flow duration": "duration_ms",
    " label": "raw_label",
    "label": "raw_label",
    " timestamp": "timestamp",
    "timestamp": "timestamp",
    " flow bytes/s": "_flow_bytes_s",   # used for validation only
    "flow bytes/s": "_flow_bytes_s",
    " flow packets/s": "_flow_pkts_s",  # used for validation only
    "flow packets/s": "_flow_pkts_s",
}

# Internal known-Inf/NaN columns in CICFlowMeter output
_KNOWN_INF_COLUMNS = [
    "flow bytes/s", " flow bytes/s",
    "flow packets/s", " flow packets/s",
]


def load_cicids2017(
    file_path: str,
    max_rows: Optional[int] = None,
    random_seed: int = 42,
    deduplicate: bool = True,
    internal_ip_prefix: str = "192.168.",
) -> Tuple[List[UnifiedEvent], Dict[str, Any]]:
    """
    Load a single CIC-IDS2017 CSV file into AEGIS-ML UnifiedEvent format.

    Parameters
    ----------
    file_path : str
        Absolute path to a CIC-IDS2017 CSV file (e.g., Monday-WorkingHours.pcap_ISCX.csv).
        The dataset must be obtained from https://www.unb.ca/cic/datasets/ids-2017.html
        and placed locally. This function does NOT download the file.

    max_rows : int, optional
        Maximum number of rows to load (after filtering). Uses deterministic sampling.

    random_seed : int
        Random seed for reproducible sampling.

    deduplicate : bool
        Remove exact-duplicate rows (same 5-tuple + label). Recommended: True.
        CIC-IDS2017 contains ~1% duplicate flows.

    internal_ip_prefix : str
        IP prefix used to classify IPs as internal. CIC-IDS2017 uses 192.168.x.x.

    Returns
    -------
    events : List[UnifiedEvent]
        List of validated, normalized events.

    stats : Dict[str, Any]
        Diagnostic statistics including:
        - raw_records_read: total rows in file
        - duplicates_removed: rows dropped by deduplication
        - inf_nan_replaced: cells replaced due to Inf/NaN
        - rejected_records: rows failing validation
        - valid_events_loaded: successfully parsed events
        - label_distribution: {canonical_label: count}
        - unmapped_labels: {original_label: count} for labels not in DATASET_LABEL_MAP
        - synthetic_timestamps_assigned: rows that got fallback timestamps
        - LIMITATION: "CIC-IDS2017 synthetic/scripted dataset" always noted
    """
    stats: Dict[str, Any] = {
        "file_path": str(file_path),
        "dataset": "CIC-IDS2017",
        "provenance": "External benchmark — University of New Brunswick, CIC. NOT synthetic.",
        "raw_records_read": 0,
        "duplicates_removed": 0,
        "inf_nan_replaced": 0,
        "rejected_records": 0,
        "valid_events_loaded": 0,
        "retained_events": 0,
        "label_distribution": {},
        "unmapped_labels": {},
        "synthetic_timestamps_assigned": 0,
        "limitations": [
            "CIC-IDS2017 has known CICFlowMeter bugs producing Inf/negative values.",
            "Duplicate flows present (~1%); removed when deduplicate=True.",
            "Label casing inconsistencies normalized to lowercase.",
            "Timestamp availability varies by daily file; fallback synthetic timestamps assigned.",
            "Results from this dataset MUST NOT be mixed with synthetic dataset results.",
        ],
    }

    path = Path(file_path)
    if not path.exists():
        logger.error(
            f"CIC-IDS2017 file not found: {file_path}\n"
            "To obtain the dataset, see docs/CICIDS2017_IMPORT.md.\n"
            "Do NOT claim real-dataset results without this file."
        )
        stats["error"] = "File not found — see docs/CICIDS2017_IMPORT.md"
        return [], stats

    # ── 1. Load raw CSV ────────────────────────────────────────────────────────
    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        logger.error(f"Failed to read CIC-IDS2017 CSV: {e}")
        stats["error"] = str(e)
        return [], stats

    stats["raw_records_read"] = len(df)
    logger.info(f"[CIC-IDS2017] Loaded {len(df)} rows from {file_path}")

    # ── 2. Normalize column names ─────────────────────────────────────────────
    df.columns = [str(c).strip().lower() for c in df.columns]
    df = df.rename(columns=lambda c: _CICIDS_COLUMN_MAP.get(c, c))

    # ── 3. Replace Inf/NaN in known-problematic columns ──────────────────────
    inf_count = 0
    for col in df.columns:
        if df[col].dtype in [np.float64, np.float32, float]:
            mask = ~np.isfinite(df[col].astype(float, errors='ignore'))
            n_bad = int(mask.sum())
            if n_bad > 0:
                df.loc[mask, col] = np.nan
                inf_count += n_bad
    stats["inf_nan_replaced"] = inf_count

    # ── 4. Deduplicate ────────────────────────────────────────────────────────
    if deduplicate:
        dedup_cols = [c for c in ["src_ip", "dst_ip", "dst_port", "protocol", "raw_label"] if c in df.columns]
        before = len(df)
        df = df.drop_duplicates(subset=dedup_cols, keep="first")
        stats["duplicates_removed"] = before - len(df)
        logger.info(f"[CIC-IDS2017] Deduplication removed {stats['duplicates_removed']} rows")

    # ── 5. Normalize labels ───────────────────────────────────────────────────
    if "raw_label" not in df.columns:
        logger.warning("[CIC-IDS2017] No 'Label' column found — all events treated as benign")
        df["raw_label"] = "benign"

    df["raw_label"] = df["raw_label"].astype(str).str.strip().str.lower()

    # Normalize em-dash variants in CIC-IDS2017 'Web Attack' labels
    # The dataset contains encoding variants: \x96, â€", â€" (all em-dash variants)
    import re
    def _normalize_web_attack(label: str) -> str:
        # Normalize any em-dash, en-dash, hyphen, or common encoding artifact to ASCII hyphen
        cleaned = label.replace("â\x80\x93", "-").replace("â\x80\x94", "-").replace("\x96", "-")
        return re.sub(r"web\s+attack\s*[-–—]\s*", "web attack - ", cleaned)
    df["raw_label"] = df["raw_label"].apply(_normalize_web_attack)


    # ── 6. Protocol normalization ─────────────────────────────────────────────
    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].map(
            lambda p: {6: "TCP", 17: "UDP", 0: "ICMP", 1: "ICMP"}.get(p, str(p).upper() if pd.notna(p) else "TCP")
        )

    # ── 7. Duration: microseconds → milliseconds ──────────────────────────────
    if "duration_ms" in df.columns:
        df["duration_ms"] = (
            df["duration_ms"]
            .apply(lambda x: max(0, int(float(x) / 1000.0)) if pd.notna(x) and np.isfinite(float(x) if isinstance(x, (int, float)) else 0) else 0)
        )

    # ── 8. Numeric sanitization ───────────────────────────────────────────────
    for num_col in ["bytes_sent", "bytes_received", "dst_port", "src_port"]:
        if num_col in df.columns:
            df[num_col] = pd.to_numeric(df[num_col], errors="coerce")
            df.loc[df[num_col] < 0, num_col] = np.nan  # Negative values = CICFlowMeter bug
            df[num_col] = df[num_col].apply(
                lambda x: int(x) if pd.notna(x) and np.isfinite(x) else None
            )

    # ── 9. Build UnifiedEvent instances ───────────────────────────────────────
    base_time = datetime(2017, 7, 3, 8, 0, 0)  # Approximate CIC-IDS2017 Monday start
    events: List[UnifiedEvent] = []

    for idx, row in df.iterrows():
        d = row.to_dict()

        # Label mapping
        source_label = str(d.get("raw_label", "")).strip()
        canonical: Optional[str] = None
        if source_label in DATASET_LABEL_MAP:
            canonical = DATASET_LABEL_MAP[source_label]
        elif source_label in CANONICAL_CLASSES:
            canonical = source_label
        elif source_label in ("", "none", "nan", "null"):
            canonical = "benign"
        else:
            stats["unmapped_labels"][source_label] = stats["unmapped_labels"].get(source_label, 0) + 1
            stats["rejected_records"] += 1
            continue

        d["attack_type"] = canonical
        d["raw_label"] = source_label

        # Timestamp handling
        raw_ts = d.get("timestamp")
        if raw_ts is None or (isinstance(raw_ts, float) and math.isnan(raw_ts)):
            d["timestamp"] = base_time + timedelta(seconds=idx)
            stats["synthetic_timestamps_assigned"] += 1
        elif isinstance(raw_ts, str):
            try:
                d["timestamp"] = pd.to_datetime(raw_ts, dayfirst=True).to_pydatetime()
            except Exception:
                d["timestamp"] = base_time + timedelta(seconds=idx)
                stats["synthetic_timestamps_assigned"] += 1

        # Entity resolution
        src_ip = str(d.get("src_ip", "") or "").strip()
        dst_ip = str(d.get("dst_ip", "") or "").strip()
        d["src_entity"] = src_ip if src_ip and src_ip != "nan" else "unknown_src"
        d["dst_entity"] = dst_ip if dst_ip and dst_ip != "nan" else "unknown_dst"
        d["src_internal"] = src_ip.startswith(internal_ip_prefix) if src_ip else False
        d["dst_internal"] = dst_ip.startswith(internal_ip_prefix) if dst_ip else False

        if "layer" not in d or not d.get("layer"):
            d["layer"] = "network"

        # Clean NaN values
        clean_d = {k: v for k, v in d.items() if not (isinstance(v, float) and math.isnan(v))}

        try:
            event = UnifiedEvent(**clean_d)
            events.append(event)
            stats["valid_events_loaded"] += 1
            stats["label_distribution"][canonical] = stats["label_distribution"].get(canonical, 0) + 1
        except Exception as e:
            stats["rejected_records"] += 1
            logger.debug(f"[CIC-IDS2017] Row {idx} rejected: {e}")

    # ── 10. Deterministic sampling ────────────────────────────────────────────
    if max_rows and len(events) > max_rows:
        rng = np.random.RandomState(random_seed)
        indices = rng.choice(len(events), size=max_rows, replace=False)
        events = [events[i] for i in sorted(indices)]

    stats["retained_events"] = len(events)
    logger.info(
        f"[CIC-IDS2017] Retained {len(events)} events | "
        f"rejected: {stats['rejected_records']} | "
        f"label_dist: {stats['label_distribution']}"
    )
    return events, stats
