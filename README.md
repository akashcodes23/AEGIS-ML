# AEGIS-ML 🛡️
### AI-Powered Network Threat Intelligence — Hack Malenadu Championship Build

> *"Half the infrastructure, twice the intelligence."*

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  FRONTEND  (frontend/index.html)                        │
│  Three.js 3D attack universe · Socket.IO real-time     │
│  Cyberpunk dashboard · 4-scenario offline fallback     │
└────────────────────────┬────────────────────────────────┘
                         │ WebSocket + REST
┌────────────────────────▼────────────────────────────────┐
│  API SERVER  (server.py)                                │
│  Flask · Flask-SocketIO · eventlet async                │
└────┬──────────────┬────────────────┬────────────────────┘
     │              │                │
┌────▼──────┐  ┌────▼──────┐  ┌────▼──────────┐
│  T-GNN    │  │ AutoGen   │  │ Data Generator│
│ Defender  │  │  Agents   │  │ (4 scenarios) │
│ pure PyTor│  │ mock mode │  │               │
└───────────┘  └───────────┘  └───────────────┘
```

**Innovation Stack:**
- **T-GNN Core** — Pure-PyTorch Graph Attention Network + sinusoidal temporal encoding
- **Multi-Agent Debate** — 4 specialist AI agents with structured consensus
- **Adversarial Validation** — Self-validates robustness under Gaussian perturbations
- **3D Attack Universe** — Three.js force graph with kill-chain ring animations

---

## Quick Start

### 1. Install Python dependencies

```bash
cd aegis_ml
pip install -r requirements.txt
```

### 2. Start the backend server

```bash
python server.py
# → http://0.0.0.0:5000
```

### 3. Open the frontend

```bash
open frontend/index.html
# or serve it:
python -m http.server 8080 --directory frontend
# → http://localhost:8080
```

> **No server needed for the demo!** The frontend has all 4 scenarios embedded as offline fallback data. Just open `frontend/index.html` directly.

---

## Smoketest

```bash
python -c "
from aegis_core.tgnn_defender import AEGISDefender
from aegis_core.data_generator import generate_scenario

defender = AEGISDefender()
graph = generate_scenario('apt_chain')
predictions = defender.detect(graph)

print(f'✅ PyTorch: OK')
print(f'✅ T-GNN: loaded')
print(f'✅ APT Chain: {len(predictions)} threats detected')
for p in predictions[:3]:
    print(f'   [{p.kill_chain_stage}] {p.node_id} → score={p.threat_score:.2f}')
print('✅ READY TO WIN')
"
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server + T-GNN status |
| GET | `/api/scenarios` | List all 4 scenarios |
| GET | `/api/scenario/<name>` | Graph structure for a scenario |
| POST | `/api/scan` | Run T-GNN detection `{scenario: "apt_chain"}` |
| POST | `/api/agents/analyze` | Multi-agent debate `{threat: {...}, scenario: "..."}` |

**Socket events (client → server):**
- `run_scenario` `{ scenario }` — starts real-time streaming pipeline
- `test_robustness` `{ scenario }` — starts adversarial validation

**Socket events (server → client):**
- `graph_data`, `threat_detected`, `agent_message`, `kill_chain_update`, `scenario_complete`, `robustness_result`, `adversarial_complete`

---

## Scenarios

| Scenario | Threat Actor | Techniques |
|----------|-------------|------------|
| `apt_chain` | APT29 / Cozy Bear | T1595, T1566.001, T1059.001, T1021.001, T1078, T1048 |
| `lateral_movement` | Unknown (Ransomware Precursor) | T1021.002, T1003.001, T1047, T1135 |
| `ransomware` | LockBit 3.0 Variant | T1486, T1071.001, T1490, T1082 |
| `insider_threat` | Malicious Insider | T1039, T1052, T1213 |

---

## Environment Variables

Copy `.env.example` to `.env`:

```
OPENAI_API_KEY=   # Optional — mock agents work without this
PORT=5000
DEBUG=True
```
