# AEGIS-ML — STAGE 9: Release Validation, Evidence Integrity & Production Deployment Readiness

**Date**: 2026-10-15  
**Branch**: `feat/stage9-release-validation`  
**Base Commit**: `09c5494fbe51140b2705fdec68495905288d04de`  

---

## 1. Executive Summary

Stage 9 executes comprehensive release validation, evidence integrity hardening, graph investigation usability refinements, and production deployment readiness audits across the AEGIS-ML platform.

Key achievements:
- **Evidence Integrity & Non-Inflation**: Implemented bidirectional deduplication of relationship evidence in both the backend correlator (`IncidentCorrelator._update_incident`) and frontend incident card (`IncidentCard.jsx`), preventing duplicate events from artificially inflating relationship counts.
- **Evidence Semantics**: Clarified evidence traceability definitions ($100\%$ of supporting event IDs preserved across 12 correlation benchmark attack scenarios), documented local timezones, and strictly demarcated factual telemetry from inferred hypotheses and missing evidence.
- **Graph UX & Resilience**: Added keyboard navigation (`+`/`-`/`F`/`R`/`Esc`), visible keyboard hints, empty/malformed record defensive filtering, and neighborhood focus dimming in `AttackGraph.jsx`.
- **Deployment & Security Hygiene**: Audited CORS regex configuration, verified constant-time admin authorization (`hmac.compare_digest`), confirmed no secrets in frontend source, and documented external Vercel Deployment Protection status.
- **Verification Suite**: 90 frontend unit tests passing, 0 ESLint errors/warnings, clean production Vite build, 45 targeted backend tests passing, and 346 full backend tests passing.

---

## 2. Baseline and Integrity Audit

### 2.1 Git Status & Branch Lineage
- **Initial Working Tree**: Clean working directory on `feat/stage8-release-readiness` pointing to commit `09c5494fbe51140b2705fdec68495905288d04de`.
- **Active Feature Branch**: Created `feat/stage9-release-validation` off Stage 8 HEAD.
- **Preservation**: The frozen 48-feature classifier schema, model weights, evaluation artifacts (`docs/evaluation/results.json`), and thresholds were strictly preserved unchanged.

### 2.2 Files Modified and Created
1. `backend/correlation/incident_correlator.py`: Deduplicated relationship evidence updates between identical entities and relationship types.
2. `tests/test_incident_correlator.py`: Added `test_duplicate_relationship_evidence_deduplication` unit test.
3. `frontend/src/components/Dashboard/IncidentCard.jsx`: Deduplicated relationship evidence via `useMemo` at the top level, preventing conditional hook calls and UI count inflation.
4. `frontend/src/components/Graph/AttackGraph.jsx`: Added malformed node/edge guards in Cytoscape batch ingestion, keyboard event handler (`onKeyDown`), and keyboard shortcut hints.
5. `frontend/src/components/Reports/ModelAssuranceView.jsx`: Documented the exact numerator, denominator, and benchmark scope for evidence traceability ($100\%$).
6. `frontend/src/utils/releaseValidation.test.js`: Added 8 release validation test cases.
7. `docs/DEMO_GUIDE.md`: Updated with the reproducible 10-step technical demonstration walkthrough.
8. `docs/STAGE9_RELEASE_VALIDATION.md`: Created this verification report.

---

## 3. Evidence Semantics & Provenance Audit

| Field | Source | Meaning | Range / Units | Calibrated? | Observed vs. Inferred |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `calibrated_confidence` | `CalibratedClassifierCV` (isotonic regression on validation split) | Posterior probability $P(\text{Malicious} \mid x)$ | $[0.0, 1.0]$ | **Yes** | Inferred model probability |
| `confidence` / `classifier_probability` | Raw Random Forest ensemble | Fraction of decision trees voting for predicted threat class | $[0.0, 1.0]$ | **No** (uncalibrated) | Inferred ensemble consensus |
| `anomaly_score` | Isolation Forest (`IsolationForestProfiler`) | Normalized decision function offset from nominal baseline | $[0.0, 1.0]$ | **No** (heuristic) | Observed baseline deviation |
| `priority_score` | `IncidentCorrelator._calculate_priority_and_risk` | Heuristic composite triage priority: $\min(99, \text{base} + \text{layer} + \text{count} + \text{conf})$ | $[0.0, 99.0]$ | **No** (heuristic triage index) | Operational synthesis |
| `evidence_traceability_pct` | `backend/evaluation/correlation_benchmark.py` | Ratio: $(\text{preserved supporting event IDs} / \text{total supporting events}) \times 100$ | $[0.0, 100.0]\%$ | N/A | Observed benchmark metric (12 scenarios) |
| `relationship_evidence` | `IncidentCorrelator` | Entity linkage claims with explicit `claim_type`: observation vs hypothesis | Count | N/A | **Demarcated**: `OBSERVED TELEMETRY` vs `INFERRED HYPOTHESIS` |

### Key Fix: Relationship Deduplication
- **Problem**: When multiple alerts between the same entities on the same rule arrived sequentially, `_update_incident` appended duplicate dictionaries to `relationship_evidence`, inflating relationship counts.
- **Fix**: The correlator now locates any existing relationship entry matching `(source_entity, target_entity, relationship_type)`:
  - Appends new event IDs to `supporting_event_ids` without duplicates.
  - Updates the observation `timestamp` to `max(existing, new)`.
  - Merges `missing_evidence` sets.
  - Preserves the relationship count at its true topological cardinality.
- **Frontend Safe Handling**: `IncidentCard.jsx` incorporates a top-level `useMemo` that filters out null or duplicate records before computing relationship counts and badges.

---

## 4. Entity Graph Investigation UX

1. **Defensive Cytoscape Ingestion**:
   - Skips null nodes or nodes missing `id`.
   - Skips orphaned edges whose `source` or `target` node does not exist in the graph, preventing uncaught Cytoscape crashes during streaming updates.
2. **Keyboard Accessibility**:
   - Focused graph canvas responds to:
     - `+` / `=`: Zoom In
     - `-` / `_`: Zoom Out
     - `F` / `0`: Fit-to-View
     - `R`: Reset Zoom (1.0x)
     - `Escape`: Clear Selection and dismiss inspector
   - Accessible hints rendered with styled `<kbd>` badges in the edge legend bar.
3. **Neighborhood Focus**:
   - Selecting any node dims non-adjacent nodes and edges to 12% opacity (`.faded`).
   - Connected neighbors illuminate with cyan halos (`.highlighted-neighbor`).
   - Floating **Node Inspector** provides one-click neighbor focus buttons.
4. **Attribute Filtering**:
   - Node type filters: `ALL`, `IP`, `PROCESS`, `USER`.
   - Edge provenance filters: `ALL`, `ANOMALOUS`, `OBSERVED`, `INFERRED`.

---

## 5. Security & Production Configuration Audit

### 5.1 API Configuration & Localhost Hygiene
- **Frontend Configuration (`frontend/src/config/api.js`)**:
  - `getApiBaseUrl()` inspects `VITE_API_BASE_URL`.
  - In production builds (`import.meta.env.PROD`) or on non-localhost hostnames, it falls back to `DEFAULT_PRODUCTION_API_URL` (`https://aegis-ml-api.onrender.com`).
  - `getWsUrl()` promotes `ws://` to `wss://` over HTTPS external origins and routes to `wss://aegis-ml-api.onrender.com/ws/live`.
  - Endpoint path deduplication prevents duplicate `/api/api/` prefixes.
  - No secrets, API keys, or credentials are present in frontend source code or bundles.

### 5.2 Backend Administrative Security (`backend/api/main.py`)
- **Protected Endpoints**:
  - `/api/ingest/queue/dead-letter`
  - `/api/ingest/reset`
  - `/api/ingest/replay`
  - `/api/model/reload`
- **Authentication**: Requires `X-AEGIS-Admin-Key` or `Authorization: Bearer <key>`.
- **Timing Defense**: Validates admin token using `hmac.compare_digest` in constant time.
- **CORS Configuration**: Restricts origins via `CORS_ORIGIN_REGEX` (`^https://.*\.vercel\.app$`) with explicit whitelist fallback.

---

## 6. Automated Release Test Results

### 6.1 Frontend Unit Tests (Node.js Test Runner)
```bash
node --test frontend/src/**/*.test.js
```
```text
ℹ tests 90
ℹ suites 3
ℹ pass 90
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 144.81ms
```

### 6.2 Frontend Lint & Build
```bash
npm --prefix frontend run lint
✔ 0 errors, 0 warnings

npm --prefix frontend run build
✓ built in 287ms (all production chunks generated cleanly to frontend/dist)
```

### 6.3 Backend Targeted Release Tests
```bash
PYTHONPATH=. pytest tests/test_evaluation_integrity_stage6.py tests/test_threat_classifier.py tests/test_incident_correlator.py tests/test_api_endpoints.py tests/test_production_deployment.py
```
```text
======================== 45 passed, 5 warnings in 2.58s ========================
```

### 6.4 Full Backend Test Suite
```bash
PYTHONPATH=. pytest tests/
```
```text
================= 346 passed, 17 warnings in 131.20s (0:02:11) =================
```

---

## 7. Deployment Verification Status & Known Limitations

1. **Vercel Deployment Protection**:
   - Preview URL: `https://aegis-89ppwj7x5-akshs-projects-e1fdd364.vercel.app`
   - **Verification Finding**: The deployment is live and healthy on Vercel edge infrastructure, but returns HTTP 401 with **Vercel Authentication (Deployment Protection)** enabled by the project team settings.
   - **Public Access Configuration**: To make this preview accessible to unauthenticated reviewers, the repository owner can either:
     1. In Vercel Project Settings → *Deployment Protection*, disable *Vercel Authentication* for Preview Deployments.
     2. Or generate a Protection Bypass Token (`x-vercel-protection-bypass`) for reviewer URLs.
2. **External Benchmark (CIC-IDS2017)**:
   - Status remains honestly `BLOCKED_AWAITING_LOCAL_COPY`.
   - The platform will not display estimated external figures until a compatible ground-truth dataset copy is processed.
3. **Supervised Zero-Day Blindness**:
   - Leave-one-attack-type-out stress tests confirm high escape rates (up to 100% for Exfiltration) when evaluated purely on supervised classifiers. This limitation is mitigated architecturally via anomaly profiling and temporal correlation, but remains an inherent property of supervised detection.

---

## 8. Reproducibility Commands

```bash
# 1. Run all frontend tests (90 tests)
node --test frontend/src/**/*.test.js

# 2. Run frontend linter
npm --prefix frontend run lint

# 3. Build frontend production assets
npm --prefix frontend run build

# 4. Run targeted backend release tests (45 tests)
PYTHONPATH=. pytest tests/test_evaluation_integrity_stage6.py tests/test_threat_classifier.py tests/test_incident_correlator.py tests/test_api_endpoints.py tests/test_production_deployment.py
```
