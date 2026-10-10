# Phase 23.1: Inference Integrity and Security Audit Report

## 1. Executive Summary

Phase 23.1 conducted a comprehensive code-level, mathematical, and architectural audit of AEGIS-ML's calibrated inference pipeline, feature parity between offline evaluation and live serving, legacy input handling, invalid numerical coercion, and model artifact lifecycle endpoint security.

The audit verified that:
1. **Online/Offline Feature Parity**: Bit-for-bit numerical parity ($0.0$ difference) exists between the 48-dimensional feature vectors produced by the offline evaluation pipeline (`_build_feature_matrix_48`) and the online production serving extractor (`extract_full_causal_features`).
2. **Defect in Legacy 15-Feature Coercion**: The previous Phase 23 implementation automatically zero-padded legacy 15-dimensional inputs with 33 zeros when evaluating against the 48-feature model. This was identified as semantically and statistically invalid (e.g. setting missing indicators to 0.0 falsely implies observed presence; setting `is_new_src_dst_pair` to 0.0 implies a whitelisted destination). Zero-padding was removed and replaced with explicit `ValueError` rejection, while preserving a clean legacy evaluation path for models natively trained on 15 features.
3. **Defect in Invalid Input Coercion**: The previous use of `np.nan_to_num(..., nan=0.0, posinf=1e5, neginf=-1e5)` silently transformed corrupted or infinite features into apparently valid predictions. This was corrected: `ThreatClassifier.validate_features` now strictly rejects NaN, $+Inf$, and $-Inf$ with explicit `ValueError`, which FastAPI `/api/detect` maps to `HTTP 422 Unprocessable Entity`.
4. **Lifecycle Endpoint Security**: Model lifecycle endpoints (`/api/model/validate`, `/api/model/reload`) were hardened against path traversal attacks by validating sandbox constraints prior to checking file existence, restricting allowed extensions to `.pkl` and `.joblib`, verifying cryptographic SHA-256 hashes against companion metadata, enforcing rollback retention on failed activations, and requiring `X-AEGIS-Admin-Key` header authentication when `AEGIS_ADMIN_KEY` is configured.

---

## 2. Online / Offline Feature Parity Audit

### 2.1 Feature Name and Index Alignment

The exact sequence of the 48 causal features was cross-checked across:
- Offline definition: `PHASE22_BASELINE_FEATURE_NAMES` in `backend/evaluation/false_positive_calibration.py`.
- Online extractor: `extract_full_causal_features` in `backend/detection/model_trainer.py`.

| Dimension Range | Feature Category | Features Count | Offline Source | Online Serving Source | Parity Status |
|---|---|---|---|---|---|
| `[0:15]` | Base Telemetry & Baseline | 15 | `ThreatClassifier.FEATURE_NAMES` | `extract_features(...)` | **Exact (100%)** |
| `[15:21]` | Relational Graph | 6 | `RELATIONAL_GRAPH_FEATURE_NAMES` | `graph_tracker.extract_features_single(...)` | **Exact (100%)** |
| `[21:31]` | Telemetry Context | 10 | `SUPPORTED_CONTEXT_FEATURE_NAMES` | `extract_telemetry_context_features(...)` | **Exact (100%)** |
| `[31:36]` | Missingness Indicators | 5 | `MISSINGNESS_FEATURE_NAMES` | `extract_missingness_features(...)` | **Exact (100%)** |
| `[36:48]` | Causal Sequence (Host-scoped) | 12 | `SEQUENCE_FEATURE_NAMES` (excl. 2 inferred) | `sequence_tracker.extract_features_single(...)` | **Exact (100%)** |

### 2.2 Numerical Verification Results

An end-to-end verification script evaluated the first 50 events from `data/raw/behavioral_diversity_labeled.jsonl` through both the offline extraction pipeline (`_build_feature_matrix_48`) and the online single-event extraction pipeline (`extract_full_causal_features`).
- **Maximum absolute difference**: **`0.0`** across all 50 events and 48 dimensions.
- **Proof Level**: **Proven exact parity**.

### 2.3 Causal State and Host Isolation

- **Host Partitioning**: In `CausalSequenceTracker`, historical events are stored in a `defaultdict(list)` strictly keyed by `src_entity`. Verified that events on `host_alpha` never increment event counters or sequence histories on `host_beta`.
- **Causal Ordering**: Features for event $e_t$ at timestamp $t$ are computed using state strictly before $t$. State advancement occurs only after feature extraction.
- **Reset Behavior**: `reset()` clears sliding-window event queues (`events_1m`, `events_5m`, `host_history`) without corrupting static baseline pairs learned during training (`known_pairs`).

---

## 3. Legacy 15-Feature Inputs: Decision and Architecture

### 3.1 Defect Analysis

In Phase 23, `ThreatClassifier.validate_features` padded 15-dimensional inputs with 33 zeros to prevent length mismatch exceptions on the 48-feature model.
This was semantically incorrect for the following reasons:
1. `is_new_src_dst_pair`: In the 48-feature schema, $0.0$ signifies that the source-destination pair was seen in baseline training. Padding with zero asserts that an unobserved destination is benign and trusted.
2. `has_endpoint_telemetry` and `has_network_telemetry`: $0.0$ denotes that telemetry is completely absent.
3. `m_port`, `m_bytes_sent`, `m_process`: Binary indicators where $1.0$ indicates missingness. Zero-padding sets them to $0.0$, falsely asserting that telemetry was observed.
4. `seq_window_event_count_host`: Sets host event count to $0.0$, erasing actual host activity.

### 3.2 Implemented Policy

- **Strict Mismatch Rejection on 48-Feature Model**:
  If a caller supplies 15 features to a 48-feature model, `ThreatClassifier.validate_features` raises:
  `ValueError: Feature vector length mismatch: expected 48 features, got 15. Silent zero-padding or truncation is semantically invalid. Provide all 48 ordered features matching model feature schema.`
- **Native Legacy Execution Path**:
  When a legacy 15-feature model artifact (`threat_classifier.pkl`) is loaded, `self.n_features == 15`. It natively accepts and predicts 15-dimensional vectors without error and without zero-padding.
- **Transparency**:
  Uncalibrated legacy predictions explicitly report `is_calibrated=False`, `calibrated_probabilities=None`, and `confidence_qualification="Uncalibrated tree-vote consensus fraction; does not represent calibrated probability."`

---

## 4. Invalid Numerical Inputs (NaN, Inf, Coercion)

### 4.1 Defect Analysis

`ThreatClassifier.validate_features` previously executed:
`np.nan_to_num(arr, nan=0.0, posinf=1e5, neginf=-1e5)`
This allowed corrupted telemetry or math errors (e.g. division by zero, float overflow) to be converted into finite numbers, causing the model to output a confident prediction for corrupted input.

### 4.2 Corrections Made

1. **Non-Finite Value Rejection**:
   `validate_features()` now inspects `np.all(np.isfinite(arr))`. If any NaN, $+Inf$, or $-Inf$ is present, it immediately raises:
   `ValueError: Feature vector contains non-finite values (NaN or Inf). Invalid numerical inputs cannot be silently coerced into valid predictions.`
2. **Explicit Missingness Support**:
   Genuinely missing telemetry fields are supported through explicit schema indicators in `MISSINGNESS_FEATURE_NAMES` ($1.0$ for missing, $0.0$ for observed), preserving statistical validity without NaNs.
3. **HTTP 422 Mapping**:
   `/api/detect` catches `ValueError` and responds with `HTTP 422 Unprocessable Entity` (`{"detail": "Invalid feature inputs: ..."}`), preventing silent acceptance of malformed data.
4. **Probability Bounds and Sum Verification**:
   Both raw ensemble probabilities and calibrated posterior probabilities are checked:
   - All elements must be finite and within $[0.0, 1.0]$.
   - Elements must sum to $1.0 \pm 1e-4$. Violations raise an explicit `ValueError`.

---

## 5. Model Artifact and Endpoint Security

### 5.1 Vulnerabilities Audited & Safeguards Implemented

| Security Concern | Potential Vulnerability | Implemented Safeguard | Verification Test |
|---|---|---|---|
| **Path Traversal** | API client specifies `../../etc/passwd` or `/etc/shadow` | `_is_safe_path()` checks sandbox bounds **before** `p.exists()` check; directory separators (`/`, `\`, `..`) are rejected at parameter level; error messages do not leak local paths. | `test_audit_path_traversal_blocked_in_lifecycle_manager` |
| **Arbitrary Code Execution via Deserialization** | Untrusted binary passed to `joblib.load()` | Artifacts must reside within `data/models/`; file extension restricted strictly to `.pkl` or `.joblib`. | `test_audit_unsupported_extensions_rejected` |
| **Tampered / Corrupted Artifacts** | Artifact modified on disk | SHA-256 checksum is computed on load and cross-validated against companion `<name>_metadata.json`. Mismatch rejects activation. | `test_audit_companion_metadata_checksum_mismatch_rejected` |
| **Failed Reload Breaking Service** | Corrupted artifact replaces running model | `load_artifact()` validates candidate in dry-run first; on failure, `self.active_classifier` retains previous model. | `test_audit_failed_activation_preserves_active_model` |
| **Unauthorized Hot-Reload** | Unauthenticated callers trigger model reloads | `/api/model/reload` checks `X-AEGIS-Admin-Key` header against `AEGIS_ADMIN_KEY` environment variable. | `test_audit_api_reload_requires_admin_key_when_configured` |
| **Calibrated Misrepresentation** | Uncalibrated model reported as calibrated | If artifact has `is_calibrated=False` or lacks valid calibrator, `is_calibrated` is strictly `False` and `calibrated_probabilities` is `None`. | `test_phase23_uncalibrated_model_never_misrepresented` |

---

## 6. Test Suites and Execution Results

1. **Phase 23.1 Integrity Suite** (`tests/test_phase23_1_inference_integrity.py`):
   - **17 / 17 PASSED** (Execution time: 2.05s).
2. **Phase 23 Serving Suite** (`tests/test_phase23_calibrated_inference.py`):
   - **20 / 20 PASSED** (Execution time: 1.88s).
3. **Phase 20, 21, 22 Regression Suites**:
   - **32 / 32 PASSED** (Execution time: 1.45s).
4. **Threat Classifier Core Suite** (`tests/test_threat_classifier.py`):
   - **4 / 4 PASSED** (Execution time: 0.15s).

---

## 7. Remaining Limitations and Assumptions

1. **Synthetic Evaluation Disclaimer**: Calibrated posterior probabilities were fitted on synthetic scenario distributions. Real-world enterprise network telemetry contains unpredictable software configurations and adversarial evasion that may degrade calibration quality.
2. **Local Admin Key Security**: If `AEGIS_ADMIN_KEY` is not set in production environments, `/api/model/reload` logs a warning. For multi-tenant or internet-exposed deployments, `AEGIS_ADMIN_KEY` must always be configured.
3. **In-Memory Tracker State**: In streaming mode, `CausalSequenceTracker` maintains sliding-window host history in memory. In multi-worker deployments, sticky sessions or shared state stores (e.g. Redis) would be required to maintain state across disparate worker processes.
