<div align="center">

# 🛡️ AEGIS-ML

### Multi-Layer Cyber Threat Detection & Incident Correlation Engine

**Release Candidate 1 (`v1.0.0-rc.1`)**

An asynchronous cyber defense platform that ingests heterogeneous security telemetry, extracts an immutable 48-dimensional causal feature contract, fuses supervised threat classification with unsupervised anomaly detection, and correlates multi-stage attacks along the **MITRE ATT&CK** kill chain into actionable incident dossiers.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-Dashboard-646CFF?logo=vite&logoColor=white)](https://vitejs.dev)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-RF%20%2B%20IF-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org)
[![Tests](https://img.shields.io/badge/tests-336%20passing-brightgreen)](tests/)
[![Release](https://img.shields.io/badge/release-v1.0.0--rc.1-blue)](CHANGELOG.md)

[Quick Start](#-quick-start) · [Architecture](#-architecture-overview) · [Detection & Correlation](#-detection--correlation-pipeline) · [SOC Views](#-soc-analyst-views) · [API Endpoints](#-api--security-endpoints) · [Evaluation](#-evaluation-methodology--results) · [Honest Scope & Limitations](#-known-limitations--honest-scope)

</div>

---

## 📌 Project Status & Empirical Disclosure

**Current Stage: Release Candidate 1 (`v1.0.0-rc.1`)**  
AEGIS-ML features an end-to-end detection, probability calibration, and incident correlation pipeline verified across **336 passing automated tests**.

> [!IMPORTANT]
> **Synthetic Demo Data Disclosure:**  
> The default preloaded dataset (`behavioral_diversity_labeled.jsonl`) consists of scenario-grouped synthetic telemetry for demonstration and algorithm validation. Synthetic results validate rule correctness, merge prevention, and model calibration; **they do not establish real-world enterprise detection accuracy**. Evaluation against public CIC-IDS2017 releases remains strictly **BLOCKED** due to missing endpoint execution context and schema incompatibilities.

---

## 🌐 Problem Statement

Enterprise Security Operations Centers (SOCs) face two fundamental failure modes:
1. **Single-Signal Blind Spots:** Network-only signatures fail to detect host privilege escalation, while host-only EDR tools miss lateral traversal across subnets and external C2 tunneling.
2. **Alert Fatigue & Disconnection:** Independent alert streams inundate analysts with disconnected notifications, obscuring multi-stage campaigns.

AEGIS-ML addresses this by unifying **network flows, endpoint process executions, and application authentication logs** into a normalized stream, scoring each event across four independent models, and correlating alerts into unified incident timelines mapped to the **MITRE ATT&CK** kill chain.

---

## ⚡ Core Capabilities

- **Unified Telemetry Ingestion:** Enforces monotonic UTC timestamps and schema normalization across network, endpoint, and application domains.
- **Immutable 48-Feature Causal Assembly:** Extracts 48 backward-looking features combining behavioral baselines, relational graph topology, missingness flags, and per-host sequence transitions with zero forward temporal leakage.
- **Calibrated Multi-Model Inference:**
  - *Supervised Classification:* Balanced Random Forest classifying 5 canonical threat categories.
  - *Isotonic Probability Calibration:* Re-maps ensemble outputs into empirically calibrated posterior probabilities $\hat{P}(Y=c|X)$ (`calibrated_confidence`).
  - *Unsupervised Anomaly Detection:* Isolation Forest detecting out-of-profile zero-day outliers.
  - *Behavioral Deviation Profiling:* Z-score entity deviation for hosts and service accounts.
- **Incident Correlator:** Aggregates alerts sharing victim entities, pivot credentials, or infrastructure within rolling time windows into strongly-typed `Incident` clusters.
- **Fail-Closed Administrative Security:** Sensitive endpoints (`/api/model/reload`, `/api/ingest/reset`) enforce `AEGIS_ADMIN_KEY` authentication.
- **Spatial SOC Interface:** React 19 + Cytoscape + Three.js application with "Depth is Data" spatial tokens, WebSocket streaming (`/ws/live`), and mobile-responsive navigation.

---

## 🏗️ Architecture Overview

```mermaid
flowchart TD
    subgraph Ingestion ["1. Ingestion & In-Memory Queue"]
        Raw[Raw Telemetry JSON/JSONL] --> Norm[Normalizer & LRU Deduplicator]
        Norm --> Queue[Bounded Async Queue<br/>Host-Partitioned Locks]
    end

    subgraph Featurization ["2. Causal Featurization"]
        Queue --> StateTrack[Host Sequence & Graph Tracker]
        StateTrack --> Feat[48-Dimensional Causal Feature Vector]
    end

    subgraph Inference ["3. Multi-Model Detection"]
        Feat --> IF[Isolation Forest<br/>Unsupervised Anomaly]
        Feat --> Drift[Entity Profiler<br/>Z-Score Drift]
        Feat --> RF[Threat Classifier<br/>Balanced Random Forest]
        RF --> Calib[Isotonic Calibrator<br/>Calibrated Confidence]
    end

    subgraph Fusion ["4. Evidence Fusion & Incident Correlation"]
        IF & Drift & Calib --> Fuse[Weighted Evidence Fusion]
        Fuse --> Correlate[Incident Correlator & MITRE ATT&CK Mapping]
        Correlate --> API[FastAPI REST & WebSocket Server]
    end

    subgraph SOC ["5. Presentation Layer"]
        API -->|WebSocket /ws/live| UI[React 19 Spatial Dashboard :5173]
    end
```

---

## 🔬 Detection & Correlation Pipeline

### 1. 48-Dimensional Causal Feature Schema (`PHASE22_BASELINE_FEATURE_NAMES`)
- **Base Behavioral & Telemetry (15):** Byte volumes, packet ratios, connection duration, port risk scores, failed auth rates, protocol encodings, entity deviation score, Isolation Forest baseline.
- **Relational Graph Topology (6):** Source out-degree, destination in-degree, bipartite ratio, multi-hop indicator, graph density, clustering coefficient.
- **Context & Privilege Flags (10):** Layer indicators, privilege flags, service account flags, business hours indicator, cross-subnet routing flag.
- **Explicit Missingness Indicators (5):** Binary indicators for missing parent process, missing user ID, missing payload hash, missing port, missing session token.
- **Host Sequence Transitions (12):** Rolling event rates, burst ratio, sequence transitions (auth $\rightarrow$ exec $\rightarrow$ network egress), time-delta variances.

### 2. Threat Taxonomy & MITRE ATT&CK Mapping
| Canonical Class | Description | Kill-Chain Stage |
|---|---|---|
| `benign` | Authorized enterprise traffic, normal workloads | N/A |
| `brute_force` | Credential stuffing, password spraying, repeated auth failures | Weaponize / Delivery |
| `lateral_movement` | Internal reconnaissance, PsExec execution, SMB credential reuse | Install |
| `c2_beaconing` | Periodic bot heartbeats, external command & control tunneling | Command & Control |
| `data_exfiltration` | High-volume outbound transfer, staging archive exfiltration | Exfiltrate |

---

## 🖥️ SOC Analyst Views

The frontend provides four dedicated operational views accessible via the top floating navigation rail:

1. **Dashboard (`/`)**:
   - Executive network pulse, throughput (EPS), processed event counter, and correlated incident tallies.
   - Real-time **Attack Topology Graph** and **Live Alert Feed** streaming from `/ws/live`.
   - Detailed **Incident Investigation Dossier** displaying timeline progressions, supporting events, and evidence provenance.
   - Analysis execution controls (`Start Analysis`, `Stop`).
2. **Threat Hunting (`/threat-hunting`)**:
   - Filterable search interface supporting complex criteria across severity, telemetry layer, and containment status.
   - Deep-dive entity telemetry dossiers and host quarantine simulation controls.
3. **Entity Graph (`/entity-graph`)**:
   - Full-canvas Cytoscape.js network topology viewer displaying observed flows and inferred pivot edges.
   - Graph controls: zoom, fit, relayout, node inspect, and kill-chain spatial depth projection.
4. **Reports (`/reports`)**:
   - Incident audit summaries and threat vector distribution analytics.
   - Raw audit export in JSON (`AEGIS-Security-Audit-Report.json`) and CSV formats.

---

## 🔐 API & Security Endpoints

| Method | Endpoint | Auth Required | Description |
|---|---|:---:|---|
| `GET` | `/health` / `/api/health` | No | Authentic health check returning backend status and classifier readiness. |
| `GET` | `/api/stats/summary` | No | Real-time aggregate telemetry statistics. |
| `GET` | `/api/alerts` | No | Recent alerts with calibrated confidence scores and feature importance. |
| `GET` | `/api/incidents` | No | Correlated incidents with multi-event timelines and supporting evidence. |
| `GET` | `/api/analysis/files` | No | Available analysis datasets (`.jsonl`, `.csv`, `.pcap`). |
| `POST`| `/api/analysis/start` | No | Initiates telemetry replay or live analysis stream. |
| `POST`| `/api/analysis/stop` | No | Terminates active telemetry processing. |
| `GET` | `/api/model/info` | No | Inspects loaded classifier metadata and calibration state. |
| `POST`| `/api/model/reload` | **`AEGIS_ADMIN_KEY`** | Reloads trained model artifacts from disk with fail-closed key validation. |
| `POST`| `/api/ingest/reset` | **`AEGIS_ADMIN_KEY`** | Flushes in-memory ingestion queues and reset trackers. |
| `WS`  | `/ws/live` | No | Bidirectional live telemetry WebSocket broadcast stream. |

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ & npm
- Git

### 2. Setup Environment
```bash
git clone https://github.com/akashcodes23/AEGIS-ML.git
cd AEGIS-ML

# Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# Frontend dependencies
npm --prefix frontend install

# Environment configuration
cp .env.example .env
```

### 3. Run Backend & Frontend
**Terminal 1 — Backend:**
```bash
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
npm --prefix frontend run dev
```

Visit the dashboard at `http://localhost:5173`. Interactive OpenAPI docs are at `http://localhost:8000/docs`.

---

## 🧪 Verification & Test Suites

```bash
# 1. Full Pytest Suite (336 passing tests)
PYTHONPATH=. pytest tests/ -v

# 2. Frontend Unit & Depth Tests (18 passing tests)
node --test frontend/src/**/*.test.js

# 3. Frontend Production Build & Bundle Verification
npm --prefix frontend run build
```

---

---

## 🎨 Visual Tour (Stage 1–5 Interface)

AEGIS-ML features a cinematic, high-density spatial intelligence interface built on the "Depth is Data" design philosophy. All screenshots are captured directly from the live application running on synthetic replay telemetry.

> [!NOTE]
> **Synthetic Demo Disclosure:** Every screenshot below depicts scenario-grouped synthetic telemetry (`behavioral_diversity_labeled.jsonl`). A permanent non-dismissible ribbon is displayed across the top of every active view.

| View | Screenshot | Interaction & Semantic Meaning |
|---|---|---|
| **SOC Operator Dashboard** | ![Dashboard](docs/assets/dashboard.png) | Unified incident overview showing telemetry ingress rates, severity distribution, active incident dossiers, and temporal playhead. |
| **Kill-Chain Depth Topology** | ![Entity Graph](docs/assets/entity_graph_depth.png) | 500+ entity graph mapping MITRE ATT&CK stages to spatial depth ($z=-70$ to $z=0$). High-confidence nodes render crisp; uncertain classifications render softly defocused. |
| **Calibrated Alert Stream** | ![Alert Feed](docs/assets/alert_feed_confidence.png) | Live alert feed pairing WCAG AA severity tokens with isotonic calibrated posterior probabilities $\hat{P}(Y=c\|X)$ and model-level feature contributions. |
| **Evidence Provenance Trail** | ![Evidence Trail](docs/assets/evidence_trail_gap.png) | 5-step causal verification chain (`Packet` → `ML` → `Graph` → `Incident` → `Response`). Missing telemetry links are truthfully annotated with dashed gaps. |
| **Temporal Investigation Scrubber** | ![Temporal Scrubber](docs/assets/scrubber_past_state.png) | Non-destructive incident replay slider allowing analysts to reconstruct past network states while buffering live streaming telemetry in memory. |
| **Command & Entity Palette** | ![Command Palette](docs/assets/command_palette.png) | Instant keyboard navigation (`⌘K` / `Ctrl+K`) supporting fuzzy search across entities, IP addresses, MITRE stages, and system actions. |
| **Threat Hunting Focus Mode** | ![Hunting Focus](docs/assets/hunting_focus.png) | Query-driven investigation overlay highlighting matched attack entities while dimming non-relevant background topology. |
| **Executive Incident Briefing** | ![Briefing Report](docs/assets/printed_briefing.png) | Print-ready incident dossier featuring canonical SHA-256 integrity checksum, observation vs hypothesis timeline, and downloadable JSON data. |

For full design specifications, token scales, and motion parameters, see [`docs/design-system.md`](docs/design-system.md).

---

## 🚀 Performance & Benchmark Results

All figures below were empirically measured in a clean production environment on an **Apple M4** host machine (macOS arm64).

### 1. Route-Level Code Splitting & Bundle Sizes
Initial application load was separated into lazy-loaded route chunks (`ThreatHunting`, `EntityGraphView`, `Reports`, and `FirstRunIntro`), reducing initial entry payload by **70.8% gzip**:

| Chunk | Raw Size | Gzip Size | Role / Lazy Route |
|---|---|---|---|
| **Main Entry (`index.js`)** | **255.67 kB** | **75.98 kB** | App shell, navigation dock, stores (formerly 865.78 kB / 257.03 kB) |
| **`ThreatHunting.js`** | 29.79 kB | 7.41 kB | Query parser, filter controls, hunting focus engine (Lazy) |
| **`Reports.js`** | 15.64 kB | 4.26 kB | Incident dossiers, briefing report builder (Lazy) |
| **`EntityGraphView.js`** | 4.99 kB | 1.48 kB | Cytoscape graph canvas & depth layer controls (Lazy) |
| **`FirstRunIntro.js`** | 4.37 kB | 1.62 kB | Lightweight SVG brand assembly (Lazy, under 10 kB budget) |
| **`AmbientFieldCanvas.js`** | 530.70 kB | 132.27 kB | Three.js particle field with adaptive DPR scaling (Lazy) |
| **`TemporalScrubber.js`** | 551.19 kB | 172.65 kB | Timeline reconstructor & historical state filter (Lazy) |

### 2. Core Web Vitals (Clean Preview on Apple M4)
| Route | Largest Contentful Paint (LCP) | Cumulative Layout Shift (CLS) | Total Blocking Time (TBT) | Long Tasks |
|---|---|---|---|---|
| **Dashboard (`/`)** | 452 ms | 0.0262 | 7 ms | 0 |
| **Threat Hunting (`/threat-hunting`)** | 48 ms | 0.0250 | 1 ms | 0 |
| **Entity Graph (`/entity-graph`)** | 56 ms | 0.0250 | 1 ms | 0 |
| **Reports (`/reports`)** | 48 ms | 0.0250 | 2 ms | 0 |

### 3. Hardware Throttling Simulation (Playwright CDP)
Frame times and UI dispatch latencies measured under Chrome DevTools Protocol CPU throttling:

| Test Scenario | 1x (Unthrottled) | 4x CPU Throttling | 6x CPU Throttling | Status / Guardrail |
|---|---|---|---|---|
| **`AmbientField` Frame Time** | 16.58 ms (60 FPS) | 16.56 ms (60 FPS) | 16.57 ms (60 FPS) | Zero frame drops; adaptive DPR maintains 60 FPS |
| **Scrubber Slider Interaction** | 50.31 ms | 50.03 ms | 50.00 ms | Consistent input dispatch across 20-step replay |
| **500-Node Graph Pan & Drag** | 16.59 ms (p95: 16.8 ms) | 16.54 ms (p95: 17.5 ms) | 16.38 ms (p95: 17.9 ms) | Smooth 60 FPS pan across 500 nodes and 750 edges |

---

## ♿ Accessibility Statement

AEGIS-ML is engineered to adhere to **WCAG 2.1 Level AA** criteria.

### 1. Automated Audit Results (`axe-core` 4.10.3)
Automated testing evaluated all 4 primary routes across 3 environmental configurations (`3D On`, `3D Off`, and `prefers-reduced-motion: reduce`) and 5 interactive modal/view states (Command Palette open, Briefing Report open, Evidence Trail open, Scrubber in past state, and Hunting Focus active):
- **Violations (Critical):** 0
- **Violations (Serious):** 0
- **Violations (Moderate):** 0
- **Violations (Minor):** 0

### 2. Programmatic Contrast Audit
All 55 text/surface token pairs and 6 soft badge pairs were programmatically evaluated against W3C relative luminance standards. The complete mathematical verification table is committed in [`docs/design-system.md#28-comprehensive-programmatic-contrast-audit-wcag-21-aaaa`](docs/design-system.md#28-comprehensive-programmatic-contrast-audit-wcag-21-aaaa).
- Critical severity uses `#ff3366` strictly, achieving $>5.6:1$ contrast against the obsidian canvas and $>4.8:1$ on tinted surfaces.
- Solid obsidian backings guarantee minimum 4.5:1 contrast for all small badges (<14px bold).

### 3. Responsive & Assistive Display Verification
- **Mobile Viewport (390px):** Zero horizontal overflow (`scrollWidth === innerWidth`). Navigation tabs wrap and collapse cleanly.
- **Desktop Viewport (1440px):** Fluid spatial grid with high information density.
- **200% Browser Zoom & Text Spacing (WCAG 1.4.12):** Tested with line-height 1.5, letter-spacing 0.12em, word-spacing 0.16em without broken buttons or clipped headings.
- **Windows High Contrast Mode (`forced-colors: active`):** Verified automatic inheritance of system `CanvasText`, `Canvas`, and visible `Highlight` focus borders.

### 4. Keyboard Navigation Walkthrough
1. **Skip Navigation:** Top-level hidden Skip Link (`Tab` #1) allows immediate bypass of navigation dock directly into `#main-content`.
2. **Command Palette:** `⌘K` (macOS) and `Ctrl+K` (Windows/Linux) open the modal, focus the combobox, navigate via `ArrowDown`/`ArrowUp`, execute on `Enter`, and restore prior focus on `Escape`.
3. **Temporal Scrubber:** Native accessible range input (`aria-valuenow`, `aria-valuetext`) operable via `ArrowLeft`/`ArrowRight`/`Home`/`End`.
4. **Modal Dialogs:** Briefing and Evidence Trail modals enforce `role="dialog"`, `aria-modal="true"`, and dismiss on `Escape`.

### 5. Manual Screen-Reader Verification Checklist
Automated tools cannot replace testing with real screen-reader users. A comprehensive evaluation script covering VoiceOver (macOS/iOS) and NVDA (Windows) is documented in [`docs/accessibility-checklist.md`](docs/accessibility-checklist.md).
> *Note: Screen-reader evaluations were not executed by the AI agent; human verification using the checklist is required prior to production sign-off.*

---

## ⚠️ Known Limitations & Honest Scope

1. **In-Memory Queue Volatility:** The ingestion queue is held in memory (`asyncio.Queue`). Abnormal process termination will drop in-flight queue items. Zero-loss persistence across server restarts requires an external message broker (Kafka/RabbitMQ).
2. **Synthetic vs. Real-World Accuracy:** High reported benchmark metrics reflect controlled scenario-grouped synthetic fixtures. Enterprise production deployments face concept drift and novel attack vectors requiring ongoing baseline adaptation.
3. **Status of External Datasets (CIC-IDS2017 is BLOCKED):** Public CIC-IDS2017 releases lack endpoint execution context, user identities, and process lineage required by the 48-feature schema.
4. **Relational Analysis:** Graph metrics are computed deterministically via NetworkX rather than an end-to-end differentiable Temporal Graph Neural Network (T-GNN).
5. **No Kernel-Level Enforcement:** AEGIS-ML is a detection, scoring, and correlation engine; it does not deploy kernel-mode EDR drivers or automated firewall configuration agents.

---

## 📄 License & Release Metadata

- **Release:** `v1.0.0-rc.1` (Release Candidate 1)
- **License:** [Apache 2.0](LICENSE)
- **Maintainer:** [@akashcodes23](https://github.com/akashcodes23)

