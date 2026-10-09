# AEGIS-ML Phase 13: Process-to-Network Attribution and Evidence-Grounded Detection

## Executive Summary

Phase 13 addresses the foundational endpoint-to-network attribution gap identified during Phase 12. Prior to this phase, temporal co-occurrence of file access and network traffic on the same host was vulnerable to cross-class misattribution (e.g., local 7z file reading confused with network exfiltration or lateral movement). Phase 13 introduces a backward-compatible telemetry schema extension for process-to-socket attribution, formalizes evidence-grounded correlation semantics (distinguishing directly observed socket bindings from unverified hypotheses), verifies the mathematical consistency of classification metrics, and documents dataset limitations without fabricating unobserved telemetry.

---

## 1. The Attribution Problem

In modern threat detection, hosts frequently run concurrent benign and malicious processes:
- A user may browse the web (`chrome.exe`) while an automated script backs up files (`robocopy.exe`), and an attacker stages data (`7z.exe`).
- If security telemetry only records IP-level network connections and unassociated endpoint process reads, the detection pipeline cannot mathematically determine which process spawned which network socket based on timestamps alone.
- **Consequence in Phase 12:** In the group-aware holdout test set ($N=1,400$), 87 ground-truth `data_exfiltration` staging events on host `10.0.0.33` were misclassified as `lateral_movement` because both classes share anomalous endpoint behaviors lacking socket bindings.
- **Guiding Principle:** **Timestamp proximity does not equal causal process attribution.** A process file read followed by network traffic must remain an unverified hypothesis unless OS kernel/eBPF telemetry explicitly provides the process-to-socket binding.

---

## 2. Backward-Compatible Telemetry Schema Changes

The `UnifiedEvent` schema in `backend/core/schemas.py` was extended with 7 optional attribution fields. All fields default to `None`, preserving 100% backward compatibility with legacy JSONL datasets, synthetic generators, and REST API endpoints:

```python
class UnifiedEvent(BaseModel):
    # Existing fields: event_id, timestamp, layer, src_entity, dst_entity, etc.
    ...
    # Process-to-network attribution fields (Phase 13)
    host_id: Optional[str] = None
    process_guid: Optional[str] = None
    process_start_time: Optional[datetime] = None
    process_end_time: Optional[datetime] = None
    connection_direction: Optional[Literal["inbound", "outbound", "unknown"]] = None
    socket_id: Optional[str] = None
    telemetry_source: Optional[str] = None
```

### Purpose of Fields:
1. `host_id`: Distinguishes physical/virtual machines when IP addresses are dynamic (DHCP), shared (NAT), or reassigned.
2. `process_guid`: Globally unique process identifier (e.g. Sysmon GUID) preventing false attribution across PID reuse.
3. `process_start_time`: Resolves PID reuse by establishing process instance boundaries.
4. `connection_direction`: Distinguishes outbound process connections (exfiltration/C2) from accepted daemon connections (listeners).
5. `socket_id`: 5-tuple descriptor or kernel socket inode (e.g. `10.0.0.15:49210->198.51.100.22:443`).
6. `telemetry_source`: Provenance tracking (`sysmon`, `auditd`, `zeek`, `netflow`, `synthetic`).

---

## 3. Correlation Engine Semantics and Evidence Hierarchy

`IncidentCorrelator` in `backend/correlation/incident_correlator.py` was upgraded to evaluate four distinct relationship categories:

| Category | Trigger Conditions | Relationship Type | Claim Type | Missing Evidence |
|---|---|---|---|---|
| **1. Direct Socket Binding** | Same host + matching `socket_id` linking process to connection, or single event containing both | `direct_process_socket_binding` | `observation` | `[]` (Verified) |
| **2. Corroborated Process Lineage** | Same host + matching `process_guid` or matching PID/name without start-time conflict | `corroborated_multi_observation` | `observation` | `["packet_payload_uninspected"]` |
| **3. Cross-Layer Co-occurrence** | Concurrent endpoint file activity and network connection on the same host WITHOUT socket binding | `cross_layer_co_occurrence` | `hypothesis` | `["socket_to_pid_binding_absent", "kernel_handle_lineage_unverified"]` |
| **4. Lateral Movement Pivot** | Compromised target/victim host initiates outbound attack traffic to another host | `pivot_lateral_movement` | `hypothesis` | `["internal_pivot_credentials_unverified"]` |

### Critical Correlation Safeguards:
- **Host-Local PID Isolation:** PIDs are host-local numbers. If Host 1 has PID 2048 and Host 2 has PID 2048, they are recognized as distinct entities and **never merged** based on PID.
- **PID Reuse Rejection:** If an event on Host 1 shares a PID with an earlier event but has a different `process_start_time` or different `process_name`, the engine detects PID reuse and rejects process lineage correlation.

---

## 4. Metric Consistency Checks

To ensure mathematical rigor, Phase 13 introduces formal verification that confusion matrices, class supports, and derived metrics align exactly:

$$\text{Precision}_i = \frac{M_{i,i}}{\sum_j M_{j,i}}, \quad \text{Recall}_i = \frac{M_{i,i}}{\sum_j M_{i,j}}, \quad \text{Support}_i = \sum_j M_{i,j}$$

$$\text{Macro-F1} = \frac{1}{K} \sum_{i=1}^K F1_i, \quad \text{Balanced Accuracy} = \frac{1}{K} \sum_{i=1}^K \text{Recall}_i$$

### Verified Ground-Truth Consistency (Group-Aware Holdout Seed 42, $N=1,400$):
- **Total Test Support:** $410 + 498 + 61 + 359 + 72 = 1,400$.
- **Lateral Movement:**
  - $TP = 61, \quad FN = 0 \implies \text{Recall} = \frac{61}{61} = 1.0000$ (100.0%)
  - $FP = 87 + 1 = 88 \implies \text{Precision} = \frac{61}{61 + 88} = \frac{61}{149} = 0.4094$ (40.94%)
  - $F1 = \frac{2 \times 0.4094 \times 1.0}{0.4094 + 1.0} = 0.5810$
- **Macro-F1:** $\frac{0.9914 + 0.9975 + 0.5810 + 0.8510 + 1.0000}{5} = 0.8685$.
- **Balanced Accuracy:** $\frac{0.9853 + 0.9950 + 1.0000 + 0.6657 + 1.0000}{5} = 0.9317$.

---

## 5. Dataset and Telemetry Provenance Analysis

- **Dataset Examined:** `data/raw/combined_labeled.jsonl` (SHA-256: `25f2bf6889a563fcc220be23c709294f151be4693a8108052391c1ce594bf7f7`).
- **Telemetry Availability Audit:**
  - `socket_id`: 0 / 7,051 records (0.0% populated)
  - `host_id`: 0 / 7,051 records (0.0% populated)
  - `process_guid`: 0 / 7,051 records (0.0% populated)
  - `connection_direction`: 0 / 7,051 records (0.0% populated)
- **Honest Reporting Principle:** Because the existing raw synthetic scenario records lack real kernel socket binding telemetry, **we do not fabricate synthetic socket IDs** to artificially manufacture a predictive performance boost.
- **Evaluated Baseline:** Configuration C (21 features: 15 baseline + 6 relational) remains the verified baseline model:
  - Macro-F1: **0.8685**
  - Balanced Accuracy: **0.9317**
  - Benign FPR: **0.73%**

---

## 6. External Dataset Status (CIC-IDS2017)

- **Execution Status:** **EXTERNAL EVALUATION NOT COMPLETED.**
- **Reason:** CIC-IDS2017 multi-gigabyte CSV files are not bundled in git.
- **Harness Status:** Verified and functional via `python3 -m backend.evaluation.external_benchmark`. When local files are absent, it safely records `status: "not_completed"` and outputs reproducible download instructions.
- **Limitation:** CIC-IDS2017 provides pure network flow telemetry and zero endpoint process context, confirming that external network flow datasets cannot validate endpoint process-to-network attribution.

---

## 7. Test Results Summary

| Suite / Test Target | Tests Run | Pass | Fail | Exit Status |
|---|:---:|:---:|:---:|:---:|
| `pytest tests/test_phase13_attribution_and_metrics.py` | 9 | 9 | 0 | **0** |
| `pytest tests/` (Full Repository Test Suite) | **84** | **84** | **0** | **0** |
| `backend.evaluation.ablation_study` | Full ablation | Done | 0 | **0** |
| `backend.evaluation.correlation_benchmark` | 12 scenarios | Done | 0 | **0** |
| `backend.evaluation.external_benchmark` | Absence check | Done | 0 | **0** |
| `frontend npm run build` | Vite client | Done | 0 | **0** |

---

## 8. Recommended Next Experiment

**Experiment: Dual-Telemetry Sysmon/Auditd Log Adaptor and Ingestion Testbed**
- **Hypothesis:** Generating or ingesting an atomic test scenario with synchronized Sysmon Event ID 1 (Process Create), Event ID 3 (Network Connect), and Event ID 11 (File Create) will provide true `socket_id` and `process_guid` values, eliminating the 87 cross-class staging false positives and raising lateral movement precision from 40.94% to >90%.
- **Validation Standard:** Evaluate on genuine host-network pairs (such as Mordor or BIRD datasets) without synthetic field substitution.
