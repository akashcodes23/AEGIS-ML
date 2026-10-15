# AEGIS-ML Stage 8: Frontend Truthfulness, Investigation UX & Release Verification

**Document Status:** Release Verification Record  
**Target Repository:** `~/major_project/AEGIS-ML`  
**Base Branch:** `feat/stage7-frontend-integration`  
**Active Release Branch:** `feat/stage8-release-readiness`  
**Evaluation Standard:** Pre-registered empirical validation protocol v1.0.0 (`docs/evaluation.md`)

---

## 1. Executive Summary & Audit Findings

During Stage 8 release preparation, a comprehensive audit across all frontend components, data adapters, and routing layers was conducted. Key findings and resolutions include:

1. **Dashboard Status Contradiction Resolved:**
   - *Previous Defect:* When telemetry analysis completed, the dashboard unconditionally displayed `"Analysis finished. Your network looks secure."` even when anomalies were flagged and critical incidents were active.
   - *Resolution:* Analysis completion (data pipeline status) has been decoupled from security posture. When anomalies exist, the banner explicitly states `"Analysis Ingestion Finished — Active Findings ({count} Anomalies Flagged)"` with warning iconography and counts of correlated incidents.
2. **Operational Counter Source Transparency:**
   - Every KPI stat card now exposes its scope, sliding window, and authoritative backend or evaluation artifact data source.
3. **Evidence & Score Semantics:**
   - Replaced misleading `"100% Traceability"` claims with exact counts distinguishing **Observed Telemetry** (verified packet/host events) from **Inferred Hypotheses** (heuristic correlator cluster claims).
   - Replaced magic fallback numbers for priority scores (such as 92) with explicit heuristic rules and documented mathematical formula breakdown.
   - Distinct labels for Platt/isotonic **Calibrated Confidence** vs. raw uncalibrated Random Forest tree agreement.
4. **Entity Graph Usability & Investigation UX:**
   - Added interactive **Node Inspector Panel** displaying entity identity, compromise state, kill-chain depth, inbound/outbound degrees, and clickable connected neighbors.
   - Added **Neighborhood Focus** dimming all unrelated elements to 12% opacity when inspecting an entity.
   - Added Zoom in (`+`), Zoom out (`-`), Fit (`⊡`), and 1x Reset (`◎`) camera controls.
   - Added verified attribute filters for Entity Types (`All`, `IP`, `Process`, `User`) and Link Provenance (`All`, `Anomalous`, `Observed`, `Inferred`).
   - Added edge provenance visual and semantic distinction (solid line = observed telemetry, dashed purple = inferred hypothesis, dashed red = anomaly).
   - Added graceful empty state when no nodes are active.
5. **Model Assurance Integrity:**
   - Verified exact numerical parity between displayed values in `ModelAssuranceView.jsx` and canonical evaluation artifact `docs/evaluation/results.json`.
   - Missing or malformed metric values are safely formatted as `"Unavailable"` rather than fabricating reassuring default zeroes.
   - CIC-IDS2017 external benchmark remains documented as blocked due to verified 35.4% feature schema discrepancy.

---

## 2. Data-Source Mapping for Dashboard Counters

| Display Label | Display Value / Unit | Scope & Time Window | Authoritative Data Source | Mathematical / Empirical Basis |
| :--- | :--- | :--- | :--- | :--- |
| **Network Pulse** | `stats.events_per_second` (eps) | 5-second sliding window | Backend WebSocket / Live Telemetry Stream | Moving average of event ingress rate |
| **Events Processed** | `stats.total_events` | Total events evaluated in active session | Log Ingest Pipeline | Monotonically increasing raw packet/event count |
| **Correlated Incidents** | `stats.total_incidents` or `incidents.length` | Session attack clusters | `incident_correlator.py` | Graph-based clustering of multi-stage alert chains |
| **Validation FPR** | `0.11%` (or live `stats.false_positive_rate`) | Offline held-out benign test partition ($N=4,900$) | `docs/evaluation/results.json` | Empirical False Positive Rate on pure benign traffic |

---

## 3. Metric Definitions & Score Provenance

### Priority Score ($10.0$ to $99.0$)
- **Source:** `backend/correlation/incident_correlator.py`
- **Formula:**
  $$\text{Priority Score} = \text{round}\Big(\min\big(99.0, \max(10.0, \text{base\_sev} + \text{layer\_bonus} + \text{count\_bonus} + \text{confidence\_factor})\big), 1\Big)$$
- **Components:**
  - $\text{base\_sev} \in \{20.0 \text{ (Low)}, 45.0 \text{ (Medium)}, 75.0 \text{ (High)}, 95.0 \text{ (Critical)}\}$
  - $\text{layer\_bonus} = \min(10.0 \times \text{num\_unique\_layers}, 20.0)$
  - $\text{count\_bonus} = \min(2.0 \times \text{event\_count}, 15.0)$
  - $\text{confidence\_factor} = 10.0 \times \text{max\_prob}$
- **Epistemic Type:** Rule-based composite triage heuristic (not a calibrated probability).

### Model Consensus / Confidence ($0.0$ to $1.0$)
- **Calibrated Confidence:** When `is_calibrated === true`, represents empirical isotonic regression posterior probability ($P(Y=1 \mid X)$).
- **Uncalibrated Model Score:** When `is_calibrated === false`, represents raw Random Forest tree vote fraction (heuristic model agreement).
- **Anomaly Score:** Unsupervised Isolation Forest score representing outlier deviation from standard baseline distribution.

---

## 4. Observed vs. Inferred Evidence Semantics

To prevent epistemic conflation during incident investigation:

1. **Observed Telemetry:**
   - Direct network flows, authentication logs, or process execution records present in raw data.
   - Rendered with solid links, green `[OBSERVED TELEMETRY]` badges, and verified timestamps.
2. **Inferred Hypotheses:**
   - Multi-hop lateral movement connections, C2 beaconing correlations, or MITRE kill-chain progression steps derived by heuristic rules.
   - Rendered with dashed purple links, purple `[INFERRED HYPOTHESIS]` badges, and explicit rule annotations (e.g. `RULE: lateral_pivot`).
3. **Missing / Unrecorded Evidence:**
   - Links in the provenance chain where underlying telemetry was not captured.
   - Rendered as dashed gaps with amber `[NOT RECORDED]` annotations.

---

## 5. Entity Graph UX Enhancements

- **Direct Camera Controls:** Interactive toolbar with Zoom In (`+`), Zoom Out (`-`), Fit to View (`⊡`), and 1x Scale (`◎`).
- **Neighborhood Focus:** Tapping any entity isolates that node and its 1-hop connected neighbors while dimming unrelated elements to 12% opacity.
- **Node Inspector Drawer:** Displays entity IP/process name, degree centrality (inbound and outbound edges), kill-chain stage depth, compromise status, and interactive clickable neighbor buttons for smooth pivoting.
- **Verified Attribute Filters:**
  - Node Types: `ALL`, `IP`, `PROCESS`, `USER`
  - Link Provenance: `ALL`, `ANOMALOUS`, `OBSERVED`, `INFERRED`
- **Graceful Empty State:** Clean card providing guidance and a one-click button to load verification scenarios when no data is buffered.

---

## 6. Automated Test Suites & Exact Results

### Frontend Test Suite (`node --test frontend/src/**/*.test.js`)
- **Total Tests:** 82 passing, 0 failing
- **Duration:** 134.7ms
- **New Tests Added (`frontend/src/utils/truthfulness.test.js`):**
  - `Truthfulness: Dashboard analysis banner logic distinguishes analysis completion from security posture` (Pass)
  - `Truthfulness: Priority Score reflects documented mathematical formula without magic numbers` (Pass)
  - `Truthfulness: Evidence chain distinguishes observed facts, model-level explanations, and missing gaps` (Pass)
  - `Truthfulness: Graph attribute filters correctly isolate entity types and edge provenance` (Pass)
  - `Truthfulness: Model Assurance values remain strictly identical to results.json with uncertainty intervals` (Pass)

### Frontend Linter (`npm --prefix frontend run lint`)
- **Status:** Clean (0 errors, 0 warnings across all files)

### Frontend Production Build (`npm --prefix frontend run build`)
- **Status:** Clean Vite build in 291ms
- **Main Shell Bundle:** `dist/assets/index-C4h-T1nN.js` (258.43 kB minified, 76.68 kB gzipped)
- **Reports & Assurance Route:** `dist/assets/Reports-CI91YWaF.js` (51.41 kB minified, 11.44 kB gzipped)

### Backend Regression Tests (`pytest`)
- **Status:** 25 passed in 1.66s
  - `tests/test_evaluation_integrity_stage6.py` (9 passed)
  - `tests/test_threat_classifier.py` (4 passed)
  - `tests/test_incident_correlator.py` (12 passed)

---

## 7. Changed Files

- `frontend/src/components/Dashboard/Dashboard.jsx`: Decoupled analysis completion from security posture; enhanced StatCard with scope and data-source provenance.
- `frontend/src/components/Dashboard/IncidentCard.jsx`: Replaced magic fallback numbers with documented formula; explicit calibrated confidence vs consensus labeling; honest observed/inferred counts; documented local timezone.
- `frontend/src/components/Common/EvidenceTrail.jsx`: Added explicit counts of observed, inferred, and missing links; explicit status pill badges.
- `frontend/src/components/Graph/AttackGraph.jsx`: Added neighborhood focus, zoom in/out, attribute filters, edge provenance legend, and Node Inspector panel.
- `frontend/src/utils/truthfulness.test.js`: Added comprehensive truthfulness, metric semantics, and graph filter test suite.
- `docs/STAGE8_FRONTEND_TRUTHFULNESS_AND_UX.md`: This release and verification document.

---

## 8. Deployment Verification Status

- **GitHub Repository:** `https://github.com/akashcodes23/AEGIS-ML`
- **Release Branch:** `feat/stage8-release-readiness`
- **Remote Vercel URL:** `https://aegis-89ppwj7x5-akshs-projects-e1fdd364.vercel.app`
- **Deployment Status Note:** The Vercel URL was tested. It is deployed and responds, but currently has **Vercel Authentication (Deployment Protection)** enabled, requiring a Vercel team sign-in for external visitors. Disabling Deployment Protection in Vercel Project Settings will immediately allow public reviewer access.
