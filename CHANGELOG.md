# Changelog

All notable changes to the AEGIS-ML project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.0.0-rc.1] - 2026-10-11

### Release Candidate 1 Overview
This release marks the completion of the 30-phase architectural development, hardening, and validation cycle of AEGIS-ML. v1.0.0-rc.1 provides a verified, leak-free, multi-layered cyber threat detection and incident correlation engine.

### Detection and Feature Engineering
- **Production 48-Feature Causal Schema:** Implemented an immutable 48-dimensional causal feature vector combining 15 base behavioral/telemetry features, 6 relational graph context features, 10 telemetry context features, 5 explicit missingness indicators, and 12 host sequence features.
- **Isotonic Probability Calibration:** Fitted isotonic calibration mapping raw Random Forest ensemble scores to well-calibrated posterior probabilities $\hat{P}(Y=c|X)$ without test-set leakage.
- **Multi-Source Evidence Fusion:** Integrated unsupervised anomaly scoring (Isolation Forest), per-entity deviation profilers, and supervised threat probabilities into a single weighted severity rating.
- **MITRE ATT&CK Kill-Chain Mapping:** Automatically attaches kill-chain stages (Weaponize, Delivery, Install, Command & Control, Exfiltrate) to alerts.
- **Deterministic Incident Correlation:** Correlates alerts sharing common victim hosts, attack pivots, or credentials within sliding time windows into strongly-typed incidents.

### Streaming Ingestion
- **Event Normalizer Pipeline:** Enforces schema validation, monotonic UTC timestamp normalization, network IP/port bounds, and protocol parsing across network, endpoint, and application layers.
- **Dual-Key LRU Deduplication:** Implemented high-capacity LRU caching (up to 100,000 entries) preventing duplicate processing based on `event_id` and payload SHA-256 fingerprints.
- **Late Event & Clock Skew Detection:** Automatically detects and annotates clock skew ($>60\text{s}$ into future) and late-arriving events ($>300\text{s}$ past high watermark).
- **Batch Ingestion Support:** Added `/api/ingest/batch` endpoint handling up to 500 events per request with partial batch failure tolerance.

### Async Processing and Reliability
- **Bounded Async Detection Queue:** Implemented in-memory `asyncio.Queue` with configurable worker concurrency and queue depth (`AEGIS_QUEUE_MAX_SIZE`).
- **Host-Partitioned Concurrency:** Utilized per-host partition locks ensuring out-of-order worker dequeues never corrupt per-host temporal state or sequence features.
- **Backpressure Enforcement:** Added configurable backpressure policies (`REJECT` via HTTP 429 and `BLOCK` with timeout).
- **Error Classification & Retry Engine:** Differentiates transient errors (retried with exponential backoff) from permanent errors (routed directly to dead-letter queue).
- **Exact Queue Accounting:** Reconciles 100% of submitted events against mutually exclusive terminal categories (`completed`, `failed_dead_letter`, `duplicate`, `rejected`, `queued`, `processing`), achieving **0 unexplained event loss** across sustained load tiers.

### Security and Authorization
- **Fail-Closed Administrative Security:** Endpoints (`/api/model/reload`, `/api/ingest/reset`, `/api/ingest/replay`, `/api/ingest/queue/dead-letter`) strictly fail-closed with HTTP 503 when `AEGIS_ADMIN_KEY` is unconfigured in staging/production.
- **Dual-Header Authentication Parity:** Supports both `X-AEGIS-Admin-Key` and `Authorization: Bearer <key>` headers with rejection of conflicting or invalid tokens.
- **Artifact Path Traversal Immunity:** Filename sanitization strictly prevents directory traversal attacks across artifact endpoints.
- **Dead-Letter Payload Sanitization:** Sensitive credentials, authorization tokens, and private keys are recursively redacted before persistence into dead-letter queues.

### Evaluation and Reproducibility
- **Scenario-Grouped Partitioning:** Enforced `StratifiedGroupKFold` by `scenario_id` ensuring 0 train/test scenario overlap across all 116 behavioral scenarios.
- **Bit-Level Reproducibility Audit:** Verified exact reproduction of test metrics: 99.45% accuracy, 99.09% macro-F1, 0.15% benign FPR, and cell-by-cell confusion matrix reconstruction.
- **Immutable Artifact Hashing:** Verified production model SHA-256 (`98e926ed...`) and Phase 19 dataset SHA-256 (`1a8967f3...`).
- **Sustained Load Validation:** Tested across 100, 250, 500, and 1,000 event workloads with bounded memory growth ($<150\text{ MB}$ heap) and stable operating points.

### Testing and Documentation
- **324 Passing Backend Tests:** 100% test pass rate across unit, integration, security, and regression test suites.
- **Comprehensive Documentation Suite:**
  - `docs/ARCHITECTURE.md`: Complete system architecture and sequence specifications.
  - `docs/MODEL_CARD.md`: Model card detailing features, methodology, metrics, and failure modes.
  - `docs/DEMO_GUIDE.md`: Step-by-step operator guide for local execution and verification.
  - `docs/PHASE30_FINAL_VALIDATION_AND_RELEASE_READINESS.md`: Complete audit and validation report.

### Known Limitations
- **In-Memory Queue Volatility:** The async queue is in-memory; unhandled process crashes lose pending queue contents without an external durable broker.
- **Synthetic Benchmark Generalization:** Performance figures reflect scenario-grouped synthetic benchmarks; out-of-distribution real-world traffic requires continuous baseline updates.
- **CIC-IDS2017 Status:** Evaluation against public CIC-IDS2017 releases remains strictly BLOCKED due to absent endpoint context and incompatible schemas.
- **Observational Only:** The system generates intelligence, detections, and alerts; it does not deploy kernel-level EDR drivers or automated firewall rule modifications.
