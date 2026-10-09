# 🛡️ AEGIS-ML

### Enterprise Cyber Threat Intelligence & Anomaly Detection Pipeline

> Real-Time Multi-Layer Cyber Defense using Random Forest Threat Classification, Isolation Forest Anomaly Detection, Behavioral Profiling, and Temporal Knowledge Graphs.

---

## 🌐 Overview

**AEGIS-ML** is a machine learning-powered cybersecurity intelligence platform designed to detect, analyze, correlate, and visualize multi-layer threats across enterprise networks. It ingests network flows, endpoint process logs, and application events, mapping detected threats to the **MITRE ATT&CK** kill chain.

### Core Architecture

```text
       ┌────────────────────────┐
       │ Ingestion & Normalizer │
       └───────────┬────────────┘
                   │  UnifiedEvent
       ┌───────────▼────────────────────────┐
       │   Feature Engineering (15 dims)    │
       │  (Causal, Leaked-Free Extraction)  │
       └─────┬────────────────────────┬─────┘
             │                        │
┌────────────▼──────────────┐  ┌──────▼─────────────────────┐
│ Isolation Forest Detectors │  │ Behavioral Baseline Profiler│
│ (Network & Endpoint Flow) │  │  (Host & Svc-Account Dev)  │
└────────────┬──────────────┘  └──────┬─────────────────────┘
             │                        │
             └───────────┬────────────┘
                         │
       ┌─────────────────▼──────────────────┐
       │ Random Forest Threat Classifier    │
       │ (Balanced, 5 Canonical Classes)    │
       └─────────────────┬──────────────────┘
                         │ Threat Prediction & Consensus
       ┌─────────────────▼──────────────────┐
       │     Weighted Evidence Fusion       │
       │  (IF + Baselines + Graph + RF)     │
       └─────────────────┬──────────────────┘
                         │ Alerts & Kill-Chain Stages
       ┌─────────────────▼──────────────────┐
       │ FastAPI Backend (REST & WebSocket) │
       │        Port 8000                   │
       └─────────────────┬──────────────────┘
                         │ Real-Time WS Stream
       ┌─────────────────▼──────────────────┐
       │ React + Cytoscape + Vite Dashboard │
       │        Port 5173                   │
       └────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Actual Technology & Version |
|---|---|
| **API Backend** | FastAPI, Uvicorn, WebSockets, Pydantic v2 |
| **Frontend** | React 19, Vite, Cytoscape.js (Topology Graph), Recharts |
| **Supervised ML** | scikit-learn Random Forest Classifier (`balanced` class weighting) |
| **Unsupervised ML** | scikit-learn Isolation Forest (`contamination=0.05`) |
| **Resampling** | `imbalanced-learn` (`ImbPipeline` with SMOTE in train folds only) |
| **Graph Analysis** | NetworkX (Temporal Knowledge Graph & Entity Edge Tracking) |
| **Serialization** | Joblib / Pickle with metadata verification |
| **Testing** | pytest, pytest-asyncio, FastAPI TestClient |

---

## 🎯 Threat Classes & Label Mapping

The model classifies telemetry events into 5 canonical categories:

1. `benign`: Normal business traffic, legitimate service polling, regular downloads.
2. `brute_force`: Credential stuffing, repetitive authentication failures, password spraying.
3. `lateral_movement`: Internal reconnaissance, PSExec usage, internal host port scanning.
4. `c2_beaconing`: Command & control beaconing, periodic bot heartbeats, external tunneling.
5. `data_exfiltration`: High-volume data egress, archive staging, abnormal upload ratios.

### Dataset Mapping

Third-party datasets (such as CICIDS2017) are normalized and mapped using the following schema:

| Dataset Label | Canonical Class | MITRE Kill-Chain Stage |
|---|---|---|
| `BENIGN`, `Normal` | `benign` | N/A |
| `FTP-Patator`, `SSH-Patator`, `Web Attack - Brute Force` | `brute_force` | Weaponize / Delivery |
| `PortScan`, `Infiltration` | `lateral_movement` | Install |
| `Bot`, `DDoS`, `DoS Hulk`, `DoS GoldenEye` | `c2_beaconing` | Command & Control (C2) |
| `Heartbleed`, `Infiltration` (data egress) | `data_exfiltration` | Exfiltrate |
| *Unmapped / Unknown Labels* | *Flagged explicitly & reported in diagnostics* | *Under Review* |

---

## ⚡ Installation & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.10.12)
- Node.js 18+ and npm

### 1️⃣ Clone and Environment Configuration

```bash
git clone https://github.com/akashcodes23/AEGIS-ML.git
cd AEGIS-ML

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Copy environment template
cp .env.example .env
```

### 2️⃣ Generate Synthetic Scenarios (Optional if no external dataset is present)

```bash
python3 -m backend.data_generator.orchestrator train
# Generates data/raw/combined_labeled.jsonl with realistic multi-layer attack scenarios
```

---

## 🏋️ Training & Evaluation

AEGIS-ML features a reproducible, leak-free training pipeline adhering to industry MLOps best practices:
- **Strict Data Partitioning:** 80% train / 20% holdout test partition created *before* any feature fitting.
- **Leak-Free Resampling:** SMOTE applied strictly within training folds using `imblearn.pipeline.Pipeline`. Never applied to test data.
- **Baseline Profiling:** Entity baselines built *strictly* on benign training samples to prevent baseline poisoning.
- **Baseline Benchmarking:** Evaluated alongside a stratified `DummyClassifier`.
- **Transparent Artifacts:** Model weights, feature names, sklearn versions, and JSON metrics are saved to `data/models/`.

### Run Model Training

```bash
# Train on default synthetic dataset
python3 -m backend.detection.model_trainer train

# Or train on a custom dataset file (CSV / JSONL)
python3 -m backend.detection.model_trainer train path/to/dataset.csv
```

### Run Independent Evaluation

```bash
# Evaluate existing saved models on an untouched dataset
python3 -m backend.detection.model_trainer evaluate data/raw/combined_labeled.jsonl
```

### Output Artifacts
- `data/models/threat_classifier.pkl` (Fitted Random Forest classifier)
- `data/models/isolation_forest_network.pkl` (Network Isolation Forest with scaling statistics)
- `data/models/isolation_forest_endpoint.pkl` (Endpoint Isolation Forest)
- `data/models/entity_baselines.pkl` (Entity profiles for internal hosts)
- `data/models/eval_results.json` (Machine-readable evaluation metrics)

---

## 🧪 Automated Testing

Run the automated test suite covering dataset parsing, normalization, feature extraction, causal time windowing, model validation, and API contracts:

```bash
pytest tests/ -v
```

All 21 test suites execute in ~2.5s with zero external dataset requirements.

---

## 🚀 Running the System

### 1. Start the FastAPI Backend

```bash
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Check: [http://localhost:8000/health](http://localhost:8000/health)

### 2. Start the Frontend Dashboard

```bash
cd frontend
npm install
npm run dev
```
Dashboard will be available at [http://localhost:5173](http://localhost:5173).

---

## 📡 API Endpoints

### REST Endpoints
- `GET /health`: Health status, model readiness, and dataset availability.
- `POST /api/detect`: Direct prediction for a single `UnifiedEvent` payload via the full ML pipeline.
- `GET /api/alerts`: List latest 100 detected alerts.
- `GET /api/stats/summary`: Aggregate statistics (total events, alerts by severity, EPS).
- `GET /api/analysis/files`: List available dataset files.
- `POST /api/analysis/start` & `POST /api/analysis/stop`: Start/stop streaming dataset evaluation.
- `POST /api/incident/{event_id}/remediate`: Mark alert incident resolved.
- `POST /api/incident/{event_id}/isolate`: Network kill-switch to isolate compromised source entity.

### WebSocket
- `ws://localhost:8000/ws/live`: Real-time streaming channel broadcasting `new_alert`, `graph_update`, and `stats_update`.

---

## ⚠️ Known Limitations & Scope

1. **Uncalibrated Random Forest Probabilities:** Random Forest class probabilities represent tree consensus rather than Bayesian posterior probabilities. Threat severity is decoupled from raw confidence.
2. **Tabular Feature Extraction vs. Deep Temporal Graphs:** AEGIS-ML utilizes NetworkX for topological graph metrics combined with tabular tree ensembles. A deep PyTorch Temporal Graph Neural Network (T-GNN) is part of the future research roadmap.
3. **Synthetic vs. Real-World Benchmarks:** While the model achieves high F1 on synthetic and CICIDS2017 flow datasets, real-world deployment requires continuous baseline adaptation and ongoing false-positive calibration.
