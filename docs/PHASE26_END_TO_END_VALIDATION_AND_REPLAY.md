# AEGIS-ML Phase 26: End-to-End Detection Validation and Deterministic Event Replay

## Executive Summary

Phase 26 establishes complete end-to-end detection pipeline validation, a deterministic event replay engine, rigorous evidence integrity guarantees, and repeatable performance benchmarking for AEGIS-ML. This builds upon the streaming ingestion and telemetry normalization foundations introduced in Phase 25 and hardened in Phase 25.1.

All 25 new Phase 26 test cases pass (`pytest tests/test_phase26_e2e_replay.py`), all 37 Phase 25/25.1 tests pass, and the complete 276-test repository suite passes with 0 failures (`276 passed, 13 warnings`). The frontend production build completes with zero errors (`npm --prefix frontend run build`). The calibrated production model artifact hash and Phase 19 behavioral-diversity dataset hash are strictly verified and unchanged.

---

## 1. Pipeline Execution Contract & Architecture

The AEGIS-ML real-time detection pipeline operates over seven sequential stages:

```
[ Raw Ingestion Telemetry ]
           │
           ▼
1. Event Normalization & Validation (NormalizerPipeline)
   ├── Strict timestamp normalization to timezone-aware UTC
   ├── IP/Port validation, CIDR categorization (internal/external)
   ├── Bounded deduplication (Tier 1: Event ID, Tier 2: Payload Fingerprint)
   └── Monotonic watermark tracking with clock skew & late arrival detection
           │
           ▼
2. Provenance Tagging & Missing Telemetry Preservation
   ├── Observed fields vs. Derived fields vs. Unavailable telemetry
   └── Explicit `missing_fields` preservation (no silent zero or false coercion)
           │
           ▼
3. Causal Feature Extraction (extract_full_causal_features)
   ├── 48 deterministic features strictly aligned with FEATURE_NAMES schema
   ├── Graph Tracker: dynamic degree, cross-layer pivot chains, entity diversity
   └── Sequence Tracker: host-isolated rolling window, inter-arrival log-deltas
           │
           ▼
4. Calibrated Multi-Class Classifier Inference (ThreatClassifier)
   ├── 48-feature Random Forest ensemble (calibrated_threat_classifier.pkl)
   ├── Isotonic probability calibration preserving $\sum p_i = 1.0$
   └── Confidence qualification (very_high, high, medium, low, uncalibrated)
           │
           ▼
5. Evidence Fusion Engine (EvidenceFusionEngine)
   ├── Mathematical fusion: $R = 1 - \prod (1 - s_i)$
   └── Independent anomaly detection (Isolation Forest) + baseline deviation
           │
           ▼
6. Alert Generation & MITRE Mapping
   ├── MITRE ATT&CK technique mapping & unified Kill Chain stage
   ├── Local feature attribution explanations
   └── Populated strongly-typed `incident_id` reference
           │
           ▼
7. Incident Correlation (IncidentCorrelator)
   ├── Host boundary preservation & cross-layer graph clustering
   ├── Deduplication isolation (duplicates never inflate incident evidence)
   └── Structured incident timeline and threat state progression
```

### Key Contract Guarantees Verified:
- **Feature Ordering & Count**: Exactly 48 features extracted in identical order as defined in `ThreatClassifier.FEATURE_NAMES`.
- **Probability Semantics**: Model output calibrated probabilities sum to $1.0 \pm 10^{-4}$ across all 5 classes (`benign`, `brute_force`, `lateral_movement`, `data_exfiltration`, `c2_beaconing`).
- **Strong Typing**: `Alert.incident_id` is populated with the correlated incident identifier (`INC-...`) whenever an alert is associated with an incident.

---

## 2. Event and Evidence Semantics

To prevent false confidence and unsupported attribution, telemetry and detection artifacts maintain strict semantic boundaries:

1. **Observed Telemetry**:
   - Explicitly present in the raw event payload (e.g., `src_ip`, `dst_port`, `bytes_sent`, `process_name`). Recorded in `event.provenance["observed_fields"]`.
2. **Derived Metrics**:
   - Mathematically derived from observed values through documented formulas (e.g., `hour_of_day`, `bytes_ratio`, `is_business_hours`). Recorded in `event.provenance["derived_fields"]`.
3. **Unavailable / Missing Telemetry**:
   - Fields that were omitted in raw telemetry are cataloged in `event.missing_fields` and `event.provenance["unavailable_telemetry"]`. Missing numerical features are assigned negative sentinel indicator flags (`missing_dst_port=1.0`, `missing_bytes_sent=1.0`, etc.) in the 48-feature schema rather than silently masquerading as 0 bytes or benign traffic.
4. **Attribution Status**:
   - If socket binding or process ancestry cannot be verified from raw telemetry, attribution status remains `"unverified"`. Inferred associations are logged as hypotheses, never presented as verified forensic facts.
5. **Duplicate Invariance**:
   - Duplicate events are captured at Tier 1 (exact `event_id`) or Tier 2 (payload fingerprint within `dedup_window_seconds`). Rejected duplicates never advance the causal sequence tracker, never advance the high watermark, and never inflate incident evidence counts or timeline entries.

---

## 3. Deterministic Event Replay Facility

The replay facility (`backend/ingestion/replay.py`) provides isolated, reproducible event playback for historical debugging, regression verification, and attack simulation.

### Architecture & Isolation
- Replay executes inside an isolated instance of `StreamingIngestionManager` with dedicated, isolated sequence and graph trackers.
- Replay **never** alters live streaming ingestion buffers, live watermarks, or active production incidents.
- Administrative authentication is enforced via the `X-AEGIS-Admin-Key` header (`POST /api/ingest/replay`).

### Replay Configuration (`ReplayConfig`)
- `mode`: Replay mode (`"chronological"` or `"as_recorded"`).
- `seed`: Fixed PRNG seed (default `42`) guaranteeing bit-level deterministic ordering across runs.
- `jitter_max_seconds`: Max simulated latency jitter applied to ingestion arrival times.
- `out_of_order_probability`: Probability of transposing adjacent events to test out-of-order resilience.
- `duplicate_injection_rate`: Controlled rate of synthetic duplicate packet injection.
- `trigger_detection`: Flag controlling whether ML classification and incident correlation are triggered per replayed event.

### API Endpoint
```http
POST /api/ingest/replay
Header: X-AEGIS-Admin-Key: <ADMIN_SECRET_KEY>
Content-Type: application/json

{
  "events": [ ... ],
  "mode": "chronological",
  "jitter_max_seconds": 0.5,
  "out_of_order_probability": 0.1,
  "duplicate_injection_rate": 0.05,
  "trigger_detection": true,
  "seed": 42
}
```

---

## 4. End-to-End Integration Test Scenarios (12 Fixtures)

The test fixture module (`backend/ingestion/fixtures.py`) provides 12 deterministic scenarios:

| # | Scenario | Telemetry Characteristics | Expected Ingestion | Expected Detection / Incident |
|---|---|---|---|---|
| 1 | Benign Network Activity | Standard intranet HTTP GET traffic (`TCP:80`, normal byte ratios) | Accepted | No threat alert; clean baseline |
| 2 | Brute-Force Authentication | 6 rapid HTTP POST login failures (`401 Unauthorized`) | Accepted | Alert generated; incident created (`INC-...`) |
| 3 | Lateral Movement | Multi-hop SMB/RPC (`TCP:445`) across internal hosts with shell context | Accepted | Cross-layer alert; incident created |
| 4 | Data Exfiltration | Massive outbound data transfer (`TCP:443`, 25MB+) to external IP | Accepted | Alert generated; exfiltration incident created |
| 5 | C2 Beaconing | Periodic heartbeat connections with invariant payload size | Accepted | Alert generated; beaconing incident created |
| 6 | Missing Attribution | Network flows lacking process GUID and socket bindings | Accepted | Attribution flagged `"unverified"`; missing fields tracked |
| 7 | Malformed Telemetry | Invalid IP format, non-numeric ports, malformed timestamp | Rejected (`validation_error`) | Rejected before feature extraction |
| 8 | Duplicate Event IDs | Two identical events ingested with identical `event_id` | 1 accepted, 1 duplicate (`duplicate_event_id`) | Incident not inflated; 1 timeline entry |
| 9 | Duplicate Payload Fingerprints | Dual-tap capture: distinct IDs with identical invariant payload & timestamp | 1 accepted, 1 duplicate (`duplicate_payload_fingerprint`) | Incident not inflated |
| 10 | Out-of-Order Events | Event timestamped 5s prior arriving after advanced watermark | Accepted (within tolerance) | Watermark does not regress backwards |
| 11 | Late-Arriving Events | Event timestamped 15 min prior arriving well past late tolerance | Accepted (`is_late_arriving=True`) | Does not advance monotonic sequence state |
| 12 | Contradictory Evidence | Contradictory layer declarations and conflicting socket IDs | Ingested with missing/conflicting markers | Evidence fusion isolates contradictory claims |

---

## 5. Performance Benchmark Results

The benchmark module (`backend/evaluation/streaming_benchmark.py`) measures throughput, latency distribution (p50/p95), duplicate rejection, and memory consumption across two operational tiers:

### Benchmark Environment
- **Platform**: Darwin (macOS) / Apple Silicon
- **Runtime**: Python 3.10.12, PyTorch CPU, Scikit-Learn 1.6.1
- **Model**: Calibrated Random Forest (48 causal features)
- **Artifact**: `data/models/streaming_benchmark_results.json`

### Benchmark Measurements

```
====================================================================================================
AEGIS-ML STREAMING INGESTION & DETECTION BENCHMARK REPORT
====================================================================================================
Timestamp: 2026-10-11T04:42:04.996071Z
Config: dedup_window=60.0s, late_tolerance=300.0s, seed=42

[1] Profile: INGESTION ONLY (Normalization + Validation + Dedup + Tracking)
----------------------------------------------------------------------------------------------------
  Batch Size: 200 events
    - Total Elapsed:        0.0205 s
    - Throughput:           9766.1 events/sec
    - Latency (Median):     0.096 ms
    - Latency (p95):        0.134 ms
    - Status Counts:        Accepted=190, Duplicate=10, Rejected=0, Late=0
    - Peak Memory:          0.28 MB

  Batch Size: 1000 events
    - Total Elapsed:        0.0939 s
    - Throughput:           10651.9 events/sec
    - Latency (Median):     0.090 ms
    - Latency (p95):        0.116 ms
    - Status Counts:        Accepted=950, Duplicate=50, Rejected=0, Late=0
    - Peak Memory:          0.41 MB

[2] Profile: DETECTION ENABLED (Ingestion + 48-Feature Extraction + ML Inference + Fusion + Correlation)
----------------------------------------------------------------------------------------------------
  Batch Size: 200 events
    - Total Elapsed:        9.7615 s
    - Throughput:           20.5 events/sec
    - Latency (Median):     53.047 ms
    - Latency (p95):        62.486 ms
    - Alerts Generated:     0 (benign stream test)
    - Incidents Created:    0
    - Peak Memory:          5.34 MB
====================================================================================================
```

### Interpretation & Architectural Takeaways
1. **Ingestion Layer Scale**: Ingestion-only throughput exceeds **10,600 events/second** with sub-millisecond p95 latency (< 0.14 ms). Normalization, IP CIDR evaluation, bounded LRU deduplication, and watermarking introduce negligible overhead.
2. **Detection Tier**: Synchronous end-to-end execution (48-feature causal graph tracking + sequence window computation + 100-tree Random Forest inference + local explainer + fusion) processes **~20.5 events/second** synchronously per worker core (~53 ms median latency).
3. **Production Recommendation**: Real-world high-throughput deployments should decouple ingestion and ML detection via an asynchronous event bus or worker queue (e.g., Redis/Kafka/Celery), allowing the ingestion layer to absorb 10k+ events/sec bursts while horizontal inference workers process detection asynchronously.

---

## 6. Regression and Security Verification

| Component | Expected Verification | Actual Result | Status |
|---|---|---|---|
| Production Model Hash | `98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71` | `98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71` | Verified Unchanged |
| 48-Feature Schema | Exact order of 48 features matching `FEATURE_NAMES` | Verified by `test_pipeline_contract_48_feature_ordering_and_completeness` | Verified Unchanged |
| Phase 19 Dataset Hash | `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352` | `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352` | Verified Unchanged |
| Replay Endpoint Authorization | Administrative key check via `_require_admin_authorization` | Tested in `test_replay_api_endpoint_authenticated` | Verified Protected |
| Deduplication Bounding | Fixed LRU capacity (`max_seen_ids=10000`) preventing memory leaks | Tested in `test_audit4_dedup_capacity_lru_enforcement` | Verified Bounded |
| Full Test Suite | All repository tests pass | 276 passed, 0 failed, 13 warnings | Verified Clean |
| Frontend Build | Zero-error Vite bundle build | Built cleanly in 248ms | Verified Clean |

---

## 7. Known Limitations and Future Work

1. **Local Benchmark Caveat**:
   - The reported benchmark figures (10,650 eps ingestion-only; 20.5 eps synchronous ML detection) reflect local measurements on a single developer machine. Distributed performance will vary based on network I/O, database persistence, and CPU core allocation.
2. **Synchronous Inference vs. Streaming Queues**:
   - When `trigger_detection=True` is supplied to `/api/ingest/event`, the endpoint blocks on feature extraction and model inference. In high-volume production environments, this should be executed asynchronously via a worker pool.
3. **Explainer Feature Subset Warning**:
   - `LocalFeatureExplainer` currently focuses on core tabular features (15 base features). For the 48-feature schema, explanation fallbacks log a debug warning for unrecognized extended graph/sequence features. An explainer expansion is planned for a future phase.
