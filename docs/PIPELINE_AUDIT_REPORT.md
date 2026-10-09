# AEGIS-ML Pipeline Audit & Trustworthy Investigation Architecture

This document records the Phase 1 audit findings and architectural blueprint for upgrading AEGIS-ML into an evidence-driven, trustworthy network threat investigation platform.

## 1. Audit Findings Across Pipeline Flow

### 1. Event Flow Through Trained Models
- **Status:** Partially verified with limitations.
- **Details:** Events in `dataset_worker` are passed to `IsolationForestDetector.predict(event)` and `BehavioralBaselineProfiler.compute_deviation_score(event)`, then fed into `ThreatClassifier.predict(features)`. However:
  - `failed_auth_rate` was hardcoded to `0.0`.
  - The raw `event.event_id` was discarded and replaced with synthetic sequence counters `f"{stem}-{counter}"`.
  - Underlying network flow attributes (ports, flags, payload bytes, process identifiers) were omitted from the resulting alert payloads, breaking forensic traceability.

### 2. Origin of Threat Types
- **Status:** Derived from Random Forest model predictions, with unhandled anomalies.
- **Details:** When the Random Forest predicts an attack category (`brute_force`, `lateral_movement`, `data_exfiltration`, `c2_beaconing`), that label is used. However, pure statistical anomalies from the Isolation Forest (high `if_score`) were either suppressed if predicted as `benign` or coerced into an arbitrary threat type. Pure anomalies should be explicitly labeled as `statistical_anomaly`.

### 3. Confidence vs Anomaly Score vs Incident Risk
- **Status:** Misleading conflation identified.
- **Details:**
  - For supervised alerts, `confidence` was Random Forest tree consensus ratio, not calibrated posterior probability.
  - For anomaly alerts, the continuous Isolation Forest outlier score `if_score` was assigned directly to `confidence`.
  - The dashboard rendered these as `XX% Confidence`, implying certainty of attack to analysts.
  - **Resolution:** Decouple `classifier_probability`, `anomaly_score`, `baseline_deviation`, and composite `incident_risk`. State clearly that tree vote agreement represents classifier consensus, not ground-truth certainty.

### 4. Feature Explanations
- **Status:** Identified as static global metrics, not event explanations.
- **Details:** `feature_importances` returned the global Random Forest Mean Decrease in Impurity (Gini) values computed at training time. Every single event received identical feature percentages regardless of its actual values.
- **Resolution:** Implement local feature deviation attribution that compares the observed feature vector against baseline normal distributions and weights by model importance.

### 5. False-Positive Rate Reporting
- **Status:** Invalid metric identified (`0.0%`).
- **Details:** The live streaming stats broadcast hardcoded `false_positive_rate: 0.0`. In unlabelled streaming traffic, true ground-truth labels are absent, making real-time FPR computation scientifically invalid.
- **Resolution:** Set `false_positive_rate` to `null` (`None`) in streaming mode and render `N/A` on the UI. Only compute FPR when benchmark evaluations with ground-truth labels are explicitly executed.

### 6. Network Graph Relationships
- **Status:** Naive pairwise links with hardcoded frequencies.
- **Details:** Edges were generated from the last 150 alerts with hardcoded `frequency: 1`. They did not track flow frequencies, directional volumes, or historical knowledge graph states.
- **Resolution:** Aggregate actual network connections, summarize traffic counts, and link entities across correlated incidents.

### 7. Entity Identifiers and Timestamp Preservation
- **Status:** Partial preservation.
- **Details:** Timestamps were preserved as ISO strings. However, original event IDs were lost and raw event fields were not attached to alerts.
- **Resolution:** Preserve raw `event_id`, attach source dataset provenance, and embed raw event records for deep investigation.

### 8. Duplicate Event Handling
- **Status:** Vulnerable to duplicates.
- **Details:** Duplicate or replayed events produced duplicate alerts.
- **Resolution:** Implement deterministic SHA-256 event fingerprinting and a deduplication cache within the correlation engine.

### 9. State Synchronization of Counters
- **Status:** `total_incidents` was disconnected from backend reality.
- **Details:** `total_incidents` reported 0 because no incident correlation engine was running.
- **Resolution:** Integrate `IncidentCorrelator` into the FastAPI lifecycle, maintaining real-time correlated incident collections and WebSocket event streaming.

### 10. Synthetic Data vs Real Network Telemetry
- **Status:** Lack of dataset provenance.
- **Details:** Synthetic data (`combined_labeled.jsonl`) and real PCAP captures (`Wednesday-workingHours.pcap_ISCX.csv`) were displayed identically without distinction.
- **Resolution:** Tag datasets and events with `is_synthetic: bool` and display provenance indicators (`Synthetic Benchmark` vs `Real Traffic Capture`) in the UI.

---

## 2. Target Architecture & Implementation Plan

```
[ Dataset / Ingestion Stream ]
             │
             ▼
   [ Event Fingerprinting & Deduplication ]
             │
             ├──► [ Feature Extraction + Local Deviation Computation ]
             ├──► [ Isolation Forest (anomaly_score) ]
             ├──► [ Behavioral Profiler (baseline_dev) ]
             └──► [ Threat Classifier (tree consensus proba) ]
                          │
                          ▼
            [ Weighted Evidence Fusion ]
                          │
                          ▼
         [ Incremental Incident Correlator ]
            - Sliding Time Window (e.g. 10m)
            - Entity & Host Session Graph
            - Kill Chain Progression
            - Timeline Builder (Observation vs Hypothesis)
            - Alternative Benign Explanations
            - Traceability to Raw Events
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
   [ REST API / State ]       [ WebSocket Stream ]
   - /api/incidents           - new_incident
   - /api/incident/{id}       - incident_update
   - /api/stats/summary       - stats_update (FPR = N/A)
             │                         │
             └────────────┬────────────┘
                          ▼
              [ React / Vite Frontend ]
   - Dashboard: FPR as "N/A", Dataset Provenance Badge
   - AlertFeed: Real-time telemetry
   - IncidentCard: Multi-tab investigation (Timeline,
     Observations vs Hypotheses, Local Explanations,
     Underlying Raw Events, Remediation Playbook)
```
