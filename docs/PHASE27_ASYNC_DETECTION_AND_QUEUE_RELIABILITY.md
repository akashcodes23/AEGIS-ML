# AEGIS-ML Phase 27: Asynchronous Detection Pipeline and Queue Reliability

## Executive Summary

Phase 27 introduces a high-throughput, bounded asynchronous detection worker pipeline and queue reliability architecture for AEGIS-ML. In Phase 26, streaming benchmarking revealed that synchronous end-to-end ML detection (feature extraction across 48 causal features, Random Forest inference, Isolation Forest deviation, and incident correlation) on the HTTP thread limited throughput to ~20.5 events/second per core.

Phase 27 decouples ingestion from heavy ML detection by introducing an in-memory, bounded worker pipeline (`AsyncDetectionQueue`). This achieves:
- **Ingestion Enqueue Speedup**: **~270x improvement** in ingestion throughput (**> 6,600 events/second** on local benchmarks vs. 24.5 events/second synchronous).
- **Sub-Millisecond Ingestion Latency**: Median ingestion response time reduced to **0.15 ms** (down from ~40.5 ms).
- **Host-Partitioned Concurrency**: Strict sequential ordering within host partitions, preventing race conditions on temporal sequence buffers and graph degree trackers while enabling concurrent multi-host scaling.
- **Resilient Failure Handling**: Classification of transient vs. permanent faults, exponential backoff retries, and bounded dead-letter queueing.
- **Incident Idempotency**: Completed event tracking prevents retried tasks from duplicating alerts or inflating incident evidence.

All 18 new Phase 27 reliability tests pass (`pytest tests/test_phase27_async_queue.py`), all 80 Phase 25-27 streaming tests pass, and all 294 repository tests pass (`294 passed, 13 warnings`). The production model artifact and Phase 19 dataset SHA-256 hashes remain strictly verified and unchanged.

---

## 1. Architecture and Event Lifecycle

```
[ Incoming Telemetry Event ]
            │
            ▼
1. Validation & Normalization (NormalizerPipeline)
   ├── Timestamp normalization to timezone-aware UTC
   ├── IP/Port validation, CIDR categorization
   └── Schema enforcement (rejects malformed telemetry before queue)
            │
            ▼
2. Streaming Deduplication (StreamingIngestionManager)
   ├── Tier 1: Exact Event ID deduplication
   └── Tier 2: Invariant payload fingerprint within dedup_window
            │
            ▼
3. Timing & Monotonic Watermark Tracking
   ├── Clock skew calculation
   └── Late-arrival tagging (does not regress watermark)
            │
            ▼
4. Ingestion Choice Point
   ├── Synchronous Path: (trigger_detection=True, async_detection=False)
   │     └── Executes ML inference on HTTP thread (legacy / deterministic replay)
   │
   └── Asynchronous Path: (async_detection=True or ?async=true)
         │
         ▼
5. Bounded In-Memory Queue (AsyncDetectionQueue)
   ├── Enqueue with position & enqueued_at timestamp
   ├── Immediate HTTP Response: { status: "accepted", processing_state: "queued" }
   └── Backpressure Enforcement: REJECT (immediate 429/rejection) or BLOCK_TIMEOUT
         │
         ▼
6. Background Worker Pool (worker_concurrency=2)
   ├── Host-Partition Concurrency Lock: acquires per-host mutex (host_id / src_entity)
   ├── Idempotency Check: verifies event has not already been completed
   └── ThreadPoolExecutor Offload: runs 48-feature extraction & RF prediction off event loop
         │
         ▼
7. Outcome Handling
   ├── Success ──> Alert & Incident Correlator ──> processing_state: "completed"
   ├── Transient Error ──> Exponential Backoff ──> processing_state: "retry_pending"
   └── Permanent Error / Retry Exhaustion ──> Dead Letter Queue ──> processing_state: "failed"
```

---

## 2. Queue Contract and Delivery Guarantees

### Explicit Event Lifecycle States (`EventProcessingState`)

| State | Definition | Guarantee |
|---|---|---|
| `accepted` | Event validated and accepted into process memory | Held in process memory; detection not yet started |
| `queued` | Event enqueued onto bounded worker queue | Waiting in memory buffer for worker pickup |
| `processing` | Worker has dequeued item and acquired host lock | Offloaded to thread pool for feature extraction & ML inference |
| `completed` | Detection and incident correlation completed | Alert generated if threat; incident graph updated |
| `duplicate` | Identified as duplicate event_id or payload fingerprint | Dropped; never sent to worker or incident correlator |
| `rejected` | Validation error, malformed data, or queue saturation | Dropped before queue; reason documented |
| `retry_pending` | Transient error encountered; waiting for backoff | Will be retried after exponential delay |
| `failed` | Permanent error or retry limit exhausted | Terminal failure recorded in dead-letter queue |

### CRITICAL GUARANTEE: In-Memory Volatility (Non-Durable)

> [!WARNING]
> The default queue is an **in-memory volatile queue**. Acceptance into this queue guarantees that the event has been validated, normalized, and accepted into volatile server process memory.
> **It does NOT guarantee durability across process crashes, server restarts, or abrupt container terminations.**
> Events currently in the queue or in-flight when the process exits will be lost unless backed by a durable external queue (such as Redis or Kafka).

---

## 3. Backpressure Policy & Saturation Handling

Queue capacity is strictly bounded (`max_queue_size: int = 1000` by default) to prevent unbounded memory consumption. When the queue reaches capacity, behavior is governed by `QueueBackpressurePolicy`:

1. **`REJECT` (Default)**:
   - Non-blocking. Immediately rejects the incoming event with `status="rejected"`, `reason="queue_full"`, and `processing_state="failed"`.
   - Protects server responsiveness and CPU availability under burst loads.
2. **`BLOCK_TIMEOUT`**:
   - Blocks caller up to `timeout_seconds: float = 0.5`.
   - If worker capacity frees a slot within the window, the event is enqueued (`queued`).
   - If timeout elapses without capacity, rejects with `status="rejected"`, `reason="queue_saturated"`.

---

## 4. Host Partitioning & Ordering Preservation

In cybersecurity threat detection, sequence trackers (rolling windows, inter-arrival deltas) and temporal graph trackers (dynamic degrees, pivot paths) are stateful and order-dependent.

- **Concurreny Hazard**: If two worker threads process consecutive events for the same host concurrently, sequence buffers suffer race conditions, and out-of-order execution could corrupt causal timing features.
- **Solution — Per-Host Serialization**:
  `AsyncDetectionQueue` dynamically acquires a host partition lock (`self._host_locks[partition_key]`, where `partition_key = event.host_id or event.src_entity`) prior to executing feature extraction.
- **Guarantees**:
  - Events for the same host are guaranteed to execute strictly sequentially in arrival order.
  - Events for distinct hosts execute concurrently across the thread pool without blocking each other.

---

## 5. Failure Classification, Retries, and Idempotency

### Error Classification
1. **Transient Faults (`TransientDetectionError`)**:
   - Temporary resource contention, lock timeouts, or network hiccups.
   - Eligible for retry up to `max_retries: int = 3`.
   - Backoff: `delay = min(retry_backoff_base_seconds * (retry_backoff_multiplier ** (attempts - 1)), 2.0s)`.
2. **Permanent Faults (`PermanentDetectionError`)**:
   - Corrupt payload data, feature vector shape mismatch, unhandled type exceptions.
   - Not retryable. Bypasses retry loop and routes immediately to dead-letter queue with `state="failed"`.

### Incident Idempotency
- If an event is retried or delivered multiple times, it must not inflate incident evidence.
- `AsyncDetectionQueue` maintains a bounded LRU cache of `completed_event_ids` (capacity 10,000).
- If an event with an already-completed `event_id` is dequeued, it transitions directly to `completed` without re-executing detection or creating duplicate incident timeline entries.

---

## 6. Observability Metrics & Endpoints

Real-time queue health and latency percentiles are exposed via:
- `GET /api/ingest/queue/metrics`: Returns `QueueMetrics`.
- `GET /api/ingest/stats`: Includes `queue_metrics` in unified ingestion statistics.
- `GET /api/ingest/queue/dead-letter`: Administrative inspection of failed items (protected by `X-AEGIS-Admin-Key`).

### Exposed Metric Fields:
- `queue_depth`: Current items waiting in memory.
- `queue_capacity`: Maximum queue size.
- `accepted_events`, `queued_events`, `processing_events`, `completed_events`, `failed_events`.
- `retry_count`, `duplicate_count`, `rejected_count`, `dead_letter_count`.
- `queue_wait_time_ms`: Sliding window percentiles (`p50`, `p95`, `mean`) of time spent in queue before worker pickup.
- `processing_time_ms`: Sliding window percentiles (`p50`, `p95`, `mean`) of time spent executing feature extraction + inference.
- `end_to_end_latency_ms`: Total latency from initial enqueue to completion.
- `worker_health`: `"healthy"`, `"degraded"`, or `"stopped"`.
- `is_durable`: Explicitly reported as `false`.

---

## 7. Performance Benchmark Results

Benchmarked using `backend/evaluation/async_benchmark.py`:
- **Platform**: Darwin (macOS) / Apple Silicon, Python 3.10.12
- **Artifact**: `data/models/async_benchmark_results.json`

### Benchmark Measurements

```
==========================================================================================
AEGIS-ML PHASE 27: SYNCHRONOUS VS. ASYNCHRONOUS PIPELINE BENCHMARK
==========================================================================================

Workload: 100 events
  [Synchronous Pipeline]
    - Ingestion Throughput:               24.50 events/sec
    - Ingestion Median Latency:           40.782 ms
    - Total Elapsed Time:                 4.0813 s
  [Asynchronous Pipeline (2 workers)]
    - Ingestion Throughput (Enqueue):     6,722.01 events/sec  (Speedup: 274.4x)
    - Ingestion Median Latency:           0.145 ms
    - Completed Detection Throughput:     21.38 events/sec
    - Worker Detection Processing (p50):  93.128 ms
    - Total End-to-End Latency (p50):     2,434.818 ms

Workload: 250 events
  [Synchronous Pipeline]
    - Ingestion Throughput:               24.42 events/sec
    - Ingestion Median Latency:           40.509 ms
    - Total Elapsed Time:                 10.2386 s
  [Asynchronous Pipeline (2 workers)]
    - Ingestion Throughput (Enqueue):     6,589.52 events/sec  (Speedup: 269.8x)
    - Ingestion Median Latency:           0.150 ms
    - Completed Detection Throughput:     21.40 events/sec
    - Worker Detection Processing (p50):  92.764 ms
    - Total End-to-End Latency (p50):     5,911.330 ms
==========================================================================================
```

### Analysis
1. **API Responsiveness**: Asynchronous ingestion delivers a **~270x improvement** in ingestion throughput (> 6,500 eps vs ~24.5 eps synchronous), returning in **0.15 ms** instead of blocking the client for 40+ ms.
2. **Detection Throughput**: Completed detection throughput remains bounded by the CPU cost of the 48-feature causal extraction and 100-tree Random Forest ensemble (~21.4 eps with 2 worker threads).
3. **Queue Decoupling**: Large ingestion bursts can be absorbed smoothly without HTTP request timeouts or caller starvation.

---

## 8. Regression and Security Verification

| Component | Target / Standard | Observed Verification | Result |
|---|---|---|---|
| Production Classifier Hash | `98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71` | `98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71` | Strict Match |
| Phase 19 Dataset Hash | `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352` | `1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352` | Strict Match |
| Backward Compatibility | Existing `/api/ingest/event` & `/api/ingest/batch` API contracts | All 80 Phase 25-27 tests pass; 294 total suite pass | 100% Compatible |
| Dead Letter Protection | Administrative key check (`X-AEGIS-Admin-Key`) on dead-letter queue | Unauthorized calls return 401 | Protected |
| Frontend Production Build | Zero errors in Vite client build | Built cleanly in 248ms | Verified Clean |

---

## 9. Known Limitations

1. **Non-Durable Queue Recovery**:
   - Because the queue is in-memory, an unhandled process termination or kill signal before workers finish draining will drop uncompleted events.
2. **Single-Node Scaling**:
   - The thread pool executor scales across available local CPU cores. Scaling beyond a single server instance requires migrating to an external distributed broker (e.g., Redis Streams / Kafka) with shared worker consumers.
3. **End-to-End Latency Under High Saturation**:
   - In deep queues (e.g. 1000 items), items at the back of the queue experience wait times proportional to queue depth divided by detection throughput (~45 seconds at 22 eps).
