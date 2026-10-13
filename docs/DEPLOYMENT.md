# AEGIS-ML Public Demo Deployment Guide

This guide provides verified instructions for deploying the AEGIS-ML system for public portfolio demonstration using **Render** for the Python/FastAPI backend and **Vercel** for the React/Vite frontend.

---

## 1. Architecture & Deployment Overview

```
┌─────────────────────────────────┐           ┌───────────────────────────────────┐
│         Vercel (Frontend)       │           │          Render (Backend)         │
│   React 19 + Cytoscape + Vite   │  HTTPS    │     FastAPI + ML Detection Engine │
│                                 │──────────>│       Uvicorn (Port $PORT)        │
│   https://<your-app>.vercel.app │   WSS     │                                   │
│                                 │──────────>│   https://<your-api>.onrender.com │
└─────────────────────────────────┘           └───────────────────────────────────┘
```

- **Frontend:** Static Single Page Application (SPA) deployed to Vercel's Edge CDN. Communicates with the backend via HTTPS REST calls and secure WebSockets (`wss://`).
- **Backend:** Python Web Service deployed to Render. Loads serialized models (`calibrated_threat_classifier.pkl`), handles streaming ingestion, executes 48-feature causal inference, and streams live alerts.

---

## 2. Backend Deployment on Render

### 2.1 Service Configuration
In the [Render Dashboard](https://dashboard.render.com/):
1. Click **New +** $\rightarrow$ **Web Service**.
2. Connect your GitHub repository: `akashcodes23/AEGIS-ML`.
3. Configure the service settings:

| Setting | Value | Notes |
|:---|:---|:---|
| **Name** | `aegis-backend` | Or any preferred service name |
| **Region** | Oregon (US West) or Frankfurt | Choose closest region to target users |
| **Branch** | `main` | Production branch |
| **Root Directory** | *(leave blank / repository root)* | Runs from repo root |
| **Runtime** | `Python 3` | Python 3.10.12 (specified via `.python-version`) |
| **Build Command** | `pip install --upgrade pip setuptools wheel && pip install -r backend/requirements.txt` | Upgrades pip to ensure prebuilt binary wheels are used (avoids SciPy Fortran compilation) |
| **Start Command** | `uvicorn backend.api.main:app --host 0.0.0.0 --port $PORT` | Uses Render dynamic `$PORT` |
| **Instance Type** | Free or Starter (512MB–1GB RAM) | Fits model memory footprint ($<150\text{ MB}$) |

### 2.2 Backend Environment Variables (Render Dashboard)
Add the following in the **Environment Variables** tab:

| Variable | Recommended Demo Value | Description |
|:---|:---|:---|
| `PYTHON_VERSION` | `3.10.12` | Ensures consistent Python runtime |
| `AEGIS_ENV` | `production` | Enables production security mode |
| `AEGIS_ADMIN_KEY` | *(generate a strong random string)* | Protects admin endpoints (`/api/model/reload`, `/api/ingest/reset`, etc.) |
| `AEGIS_DATASET_DIR` | *(optional / mounted disk)* | Custom path for dataset discovery (e.g. Render Disk mount). Discovers datasets alongside `data/raw/` |
| `CORS_ORIGIN_REGEX` | `https://.*\.vercel\.app` | Automatically allows all Vercel deployment preview and production domains |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated list of allowed origins (production Vercel domain is always preserved) |
| `AEGIS_QUEUE_MAX_SIZE` | `1000` | Bounded capacity for async detection queue |
| `AEGIS_QUEUE_WORKERS` | `2` | Number of concurrent background detection workers |

*(Alternatively, apply the included `render.yaml` via Render Blueprints).*

---

## 3. Frontend Deployment on Vercel

### 3.1 Project Import & Build Settings
In the [Vercel Dashboard](https://vercel.com/new):
1. Import your GitHub repository: `akashcodes23/AEGIS-ML`.
2. Configure project setup:

| Setting | Value | Notes |
|:---|:---|:---|
| **Framework Preset** | `Vite` | Auto-detects Vite configuration |
| **Root Directory** | `frontend` | **Crucial:** Click "Edit" and set to `frontend` |
| **Build Command** | `npm run build` | Default |
| **Output Directory** | `dist` | Default for Vite |
| **Install Command** | `npm install` | Default |

### 3.2 Frontend Environment Variables (Vercel Dashboard)
In the **Environment Variables** section, configure:

| Variable | Value | Notes |
|:---|:---|:---|
| `VITE_API_BASE_URL` | `https://<your-render-service-name>.onrender.com` | Base URL of your deployed Render backend |
| `VITE_WS_URL` | `wss://<your-render-service-name>.onrender.com/ws/live` | Secure WebSocket endpoint (must use `wss://`) |

*Note: If `VITE_WS_URL` is omitted, the frontend automatically derives `wss://.../ws/live` from `VITE_API_BASE_URL`.*

---

## 4. Health-Check & Connectivity Verification

Once both services are deployed:

### 4.1 Backend Health Check
```bash
curl -s https://<your-render-backend>.onrender.com/health | python -m json.tool
```

Expected response:
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

### 4.2 Cross-Origin Ingestion Check
Send a benign synthetic event from your terminal:
```bash
curl -s -X POST "https://<your-render-backend>.onrender.com/api/ingest/event?detect=true" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_event": {
      "event_id": "demo-verify-001",
      "timestamp": "2026-10-11T12:00:00Z",
      "layer": "network",
      "src_ip": "10.0.1.20",
      "dst_ip": "10.0.1.80",
      "src_port": 51234,
      "dst_port": 443,
      "protocol": "TCP",
      "bytes_sent": 800,
      "bytes_received": 2400,
      "action": "connect"
    }
  }' | python -m json.tool
```

### 4.3 WebSocket Check in Browser
1. Open your Vercel URL: `https://<your-app>.vercel.app`.
2. Open Browser Developer Tools $\rightarrow$ **Console** / **Network** (Filter: `WS`).
3. Verify connection to `wss://<your-render-backend>.onrender.com/ws/live` shows status `101 Switching Protocols`.
4. The dashboard header should display "LIVE STREAM" with active connection indicator.

---

## 5. Public Deployment Security & Safeguards

When exposing the demo to the public:
1. **Administrative Endpoints Remain Fail-Closed:**
   Endpoints such as `/api/model/reload`, `/api/ingest/reset`, and `/api/ingest/queue/dead-letter` strictly require `AEGIS_ADMIN_KEY`. If `AEGIS_ADMIN_KEY` is not provided via `X-AEGIS-Admin-Key` or `Authorization: Bearer <key>`, requests fail with HTTP 401 or 403.
   **Never expose `AEGIS_ADMIN_KEY` in frontend environment variables.**
2. **Backpressure & Saturation Bounds:**
   Public event submissions are constrained by the in-memory queue (`AEGIS_QUEUE_MAX_SIZE=1000`). If abusive traffic floods the ingestion endpoint, events are rejected with HTTP 429 under backpressure policies, protecting the container from memory exhaustion.
3. **Batch Size Limits:**
   Batch ingestion (`/api/ingest/batch`) rejects batches exceeding 500 events with HTTP 400.
4. **Credential Sanitization:**
   Any failed events routed to the dead-letter queue have authorization headers and secret tokens recursively stripped prior to in-memory logging.

---

## 6. Known Limitations on Free Hosting

- **Render Free Tier Cold Starts:** Free Render instances spin down after 15 minutes of inactivity. The first request after idle may take 30–50 seconds to initialize while the Python process starts and loads the ML models into memory. The frontend automatically performs exponential backoff reconnection up to 60 attempts (~5 minutes) and provides an interactive retry button.
- **In-Memory Queue Volatility:** The event queue and dynamic topology graph are held in application memory. When Render restarts or redeploys the container, historical in-memory counters reset to zero.
- **WebSocket Timeout on Free Proxies:** Some free edge proxies terminate idle WebSocket connections after 60–100 seconds. The frontend includes automatic exponential backoff reconnection to restore connections seamlessly.

---

## 7. Troubleshooting

| Symptom | Cause | Solution |
|:---|:---|:---|
| **CORS Error in Browser** | `CORS_ORIGINS` or `CORS_ORIGIN_REGEX` missing frontend domain | Set `CORS_ORIGIN_REGEX=https://.*\.vercel\.app` or add exact Vercel URL to `CORS_ORIGINS` in Render. |
| **WebSocket Connection Failed / System Offline** | Missing production URLs or premature disconnect | The frontend now builds with `frontend/.env.production` pointing to `https://aegis-ml-api.onrender.com` by default. If on cold start, wait for Render container initialization or click the status badge to retry. |
| **No Datasets Found** | Datasets directory empty on cloud host | Commit benchmark files (e.g. `data/raw/behavioral_diversity_labeled.jsonl`) or configure `AEGIS_DATASET_DIR` to a mounted Render Disk. |
| **Model Load Error on Render** | Model artifact missing or path incorrect | Verify `calibrated_threat_classifier.pkl` is committed and `AEGIS_MODEL_DIR` is default `data/models`. |
| **Render Build Fails on Python Version** | Defaulting to older Python | Set `PYTHON_VERSION=3.10.12` in Render Environment Variables or commit `.python-version`. |
| **SciPy Build Failure ("Unknown compiler(s): gfortran")** | Pip defaulted to building SciPy from source instead of using prebuilt wheel | Upgrade pip before installing (`pip install --upgrade pip setuptools wheel && pip install -r backend/requirements.txt`) and ensure Python 3.10+ is active. |
| **Vercel Build Fails (404 on subpaths)** | Missing SPA rewrites | Ensure `frontend/vercel.json` contains reverse-proxy rewrites for `/api/:path*` and `/health` to Render, plus SPA fallback to `/index.html`. |
