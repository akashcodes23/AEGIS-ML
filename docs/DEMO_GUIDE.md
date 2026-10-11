# AEGIS-ML v1.0.0-rc.1: Reproducible Demonstration & Operator Guide

This guide describes how to run and demonstrate the AEGIS-ML system locally using verified endpoints, real commands, and synthetic test payloads.

---

## 1. Prerequisites

- **Python:** 3.10, 3.11, or 3.12
- **Node.js:** 18.x or 20.x
- **Package Managers:** `pip` and `npm`
- **Operating System:** Linux, macOS, or Windows (WSL recommended)

---

## 2. Installation & Setup

### 2.1 Clone and Environment Setup
```bash
cd ~/major_project/AEGIS-ML

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install --upgrade pip
pip install -r backend/requirements.txt

# Install frontend dependencies
npm --prefix frontend install
```

### 2.2 Configure Environment
```bash
# Copy example configuration template
cp .env.example .env
```
*(The default `.env` is preconfigured for local development with `PORT=8000`, `CORS_ORIGINS=http://localhost:5173`, and `AEGIS_MODEL_DIR=data/models`.)*

---

## 3. Starting the Services

### 3.1 Terminal 1: Launch Backend
```bash
# From repository root with virtual environment activated
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```
The FastAPI backend starts at `http://localhost:8000`.

### 3.2 Terminal 2: Launch Frontend Dashboard
```bash
cd frontend
npm run dev
```
The React 19 + Cytoscape dashboard runs at `http://localhost:5173`.

---

## 4. Health Check Verification

Verify backend initialization and model loading:
```bash
curl -s http://localhost:8000/health | python -m json.tool
```

Expected output:
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "model_loaded": true,
    "model_version": "23.0.0",
    "model_calibrated": true,
    "total_events_processed": 0,
    "active_alerts": 0
}
```

---

## 5. Demonstration Walk-Through

### Step 1: Ingest a Benign Synthetic Event
Submit a normal internal HTTP network transaction with synchronous detection enabled (`detect=true`):
```bash
curl -s -X POST "http://localhost:8000/api/ingest/event?detect=true" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_event": {
      "event_id": "demo-benign-001",
      "timestamp": "2026-10-11T12:00:00Z",
      "layer": "network",
      "src_ip": "10.0.1.15",
      "dst_ip": "10.0.1.50",
      "src_port": 49152,
      "dst_port": 80,
      "protocol": "TCP",
      "bytes_sent": 450,
      "bytes_received": 1200,
      "action": "http_request"
    }
  }' | python -m json.tool
```

**Observation:**
- `status`: `"accepted"`
- `detection.threat_type`: `"benign"`
- `detection.is_calibrated`: `true`
- No high-severity alert is raised.

---

### Step 2: Demonstrate Deduplication & Idempotency
Resubmit the identical event payload:
```bash
curl -s -X POST "http://localhost:8000/api/ingest/event?detect=true" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_event": {
      "event_id": "demo-benign-001",
      "timestamp": "2026-10-11T12:00:00Z",
      "layer": "network",
      "src_ip": "10.0.1.15",
      "dst_ip": "10.0.1.50",
      "src_port": 49152,
      "dst_port": 80,
      "protocol": "TCP",
      "bytes_sent": 450,
      "bytes_received": 1200,
      "action": "http_request"
    }
  }' | python -m json.tool
```

**Observation:**
- `status`: `"duplicate"`
- `reason`: `"duplicate_event_id:demo-benign-001"`
- Ingestion metrics increment `total_duplicates` without re-executing detection.

---

### Step 3: Ingest Attack Telemetry (Brute Force Simulation)
Submit a high-volume authentication failure burst:
```bash
curl -s -X POST "http://localhost:8000/api/ingest/event?detect=true" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_event": {
      "event_id": "demo-attack-001",
      "timestamp": "2026-10-11T12:05:00Z",
      "layer": "application",
      "src_ip": "185.220.101.45",
      "dst_ip": "10.0.0.5",
      "src_port": 58921,
      "dst_port": 22,
      "protocol": "TCP",
      "action": "auth_failure",
      "status_code": 401,
      "auth_result": "failure",
      "user_id": "root"
    }
  }' | python -m json.tool
```

**Observation:**
- `status`: `"accepted"`
- `detection.threat_type`: `"brute_force"`
- `alert.severity`: `"critical"` or `"high"`
- `alert.current_kill_chain_stage`: `"Weaponize"` / `"Delivery"`
- An `incident_id` (e.g. `INC-...`) is assigned.

---

### Step 4: Demonstrate Incident Correlation
Submit a follow-up lateral movement action involving the same compromised target:
```bash
curl -s -X POST "http://localhost:8000/api/ingest/event?detect=true" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_event": {
      "event_id": "demo-attack-002",
      "timestamp": "2026-10-11T12:06:00Z",
      "layer": "endpoint",
      "src_ip": "10.0.0.5",
      "dst_ip": "10.0.0.22",
      "action": "process_spawn",
      "process_name": "psexec.exe",
      "user_id": "root",
      "host_id": "srv-db-01"
    }
  }' | python -m json.tool
```

Inspect active incidents:
```bash
curl -s http://localhost:8000/api/incidents | python -m json.tool
```

**Observation:**
- Both alerts are correlated into a single incident timeline showing multi-stage kill-chain progression from initial authentication abuse to lateral execution.

---

### Step 5: Inspect Asynchronous Queue Metrics
Query queue depth and accounting counters:
```bash
curl -s http://localhost:8000/api/ingest/queue/metrics | python -m json.tool
```

**Observation:**
Returns `queue_depth`, `submitted_events`, `accepted_events`, `duplicate_count`, `rejected_count`, `completed_events`, `processing_events`, and latency percentiles ($p_{50}, p_{95}$).

---

### Step 6: Interactive Dashboard Demonstration
1. Open `http://localhost:5173` in a web browser.
2. View real-time alert feed streaming over WebSocket (`ws://localhost:8000/ws/live`).
3. View the Cytoscape entity topology graph updating host relationships dynamically.
4. Filter alerts by MITRE ATT&CK kill-chain stage and severity level.

---

## 6. Reproducing Verifications and Tests

### 6.1 Full Backend Test Suite
```bash
python -m pytest tests/ -v
```
*(Verifies all 324 unit, regression, integration, and security tests).*

### 6.2 Model & Dataset Bit-Level Reproducibility
```bash
python backend/evaluation/evaluation_reproducibility_audit.py
```
*(Confirms zero scenario overlap, 99.45% accuracy, 99.09% macro-F1, and cell-by-cell confusion matrix reconstruction).*

### 6.3 Sustained-Load & Queue Reconciliation Benchmark
```bash
python backend/evaluation/sustained_load_test.py
```
*(Executes 100, 250, 500, and 1,000 event workloads and verifies 0 unexplained event loss).*

### 6.4 Frontend Production Build
```bash
npm --prefix frontend run build
```
*(Validates complete React/Vite bundling).*

---

## 7. Clean Shutdown

- In Terminal 1 (Backend): Press `Ctrl+C`. The async queue drains pending events gracefully up to timeout.
- In Terminal 2 (Frontend): Press `Ctrl+C`.

---

## 8. Portfolio Walkthrough Script (2–3 Minute Screen Recording)

Use this structured script to record a concise technical presentation for recruiters or interviewers:

| Timestamp | Visual Screen | Voiceover / Action Script |
|:---|:---|:---|
| **0:00 – 0:30** | Browser at `http://localhost:5173` (Dashboard view) | *"AEGIS-ML is a multi-layer cyber threat intelligence engine. Rather than relying on single-signal signatures, it ingests network flows, endpoint process logs, and authentication telemetry into a unified 48-feature causal contract."* Point out the topology graph and MITRE kill chain categories. |
| **0:30 – 1:00** | Terminal split-screen with curl command | Send Step 1 (benign event) and Step 2 (duplicate event). *"Here we submit a normal network request—ingested and classified as benign. When we re-submit the identical payload, the LRU deduplication layer immediately marks it as duplicate without re-running expensive ML inference."* |
| **1:00 – 1:45** | Terminal + Dashboard live view | Send Step 3 (brute-force attack) followed by Step 4 (lateral movement). *"Now we simulate an adversary brute-forcing SSH credentials, followed by lateral movement via PsExec. Notice how the dashboard receives the alert over WebSockets, the calibrated Random Forest identifies the threat class with 99%+ confidence, and the graph engine pivots to show the compromised host."* |
| **1:45 – 2:15** | Dashboard Incident tab | Open correlated incident view. *"The incident correlator groups both alerts into a single unified incident, mapping the kill-chain trajectory from Delivery to Lateral Movement with full timeline traceability."* |
| **2:15 – 2:45** | Terminal test run | Run `python -m pytest tests/ -v` (or reproducibility audit). *"The system is backed by 324 automated tests with zero train-test scenario leakage and exact bit-level reproduction of all evaluation metrics."* |

### Capturing Genuine Screenshots
To obtain authentic screenshots for technical portfolios or presentation slides:
1. Follow Steps 1–4 above to populate the running dashboard with live synthetic alerts and entity topology nodes.
2. In the dashboard (`http://localhost:5173`), toggle between the Alert Feed, Kill-Chain Matrix, and Cytoscape Network Topology Graph.
3. Capture full-resolution application window captures (e.g. `Command + Shift + 4` on macOS or `PrtScn` on Linux).
4. Save captures to a presentation folder or slide deck without editing or mocking UI states.
