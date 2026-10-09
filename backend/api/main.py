import asyncio
import hashlib
import math
import os
import time
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ── Path resolution ───────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATASET_DIR = PROJECT_ROOT / "datasets"

# ── Core & ML imports ─────────────────────────────────────────────────────────
try:
    from backend.core.config import (
        CONFIDENCE_ALERT_MIN,
        ANOMALY_THRESHOLD,
        PORT_RISK,
        RF_CLASSIFIER_PATH,
        IF_NETWORK_PATH,
        IF_ENDPOINT_PATH,
        BASELINES_PATH,
    )
    from backend.core.schemas import UnifiedEvent, DetectionResult, Alert, Incident, TimelineEntry
    from backend.detection.isolation_forest import IsolationForestDetector
    from backend.detection.baseline_profiler import BehavioralBaselineProfiler
    from backend.detection.threat_classifier import ThreatClassifier
    from backend.detection.model_trainer import extract_features
    from backend.correlation.weighted_fusion import WeightedEvidenceFusion
    from backend.correlation.incident_correlator import IncidentCorrelator
    from backend.explainability.explainer import LocalFeatureExplainer
except ModuleNotFoundError:
    from core.config import (
        CONFIDENCE_ALERT_MIN,
        ANOMALY_THRESHOLD,
        PORT_RISK,
        RF_CLASSIFIER_PATH,
        IF_NETWORK_PATH,
        IF_ENDPOINT_PATH,
        BASELINES_PATH,
    )
    from core.schemas import UnifiedEvent, DetectionResult, Alert, Incident, TimelineEntry
    from detection.isolation_forest import IsolationForestDetector
    from detection.baseline_profiler import BehavioralBaselineProfiler
    from detection.threat_classifier import ThreatClassifier
    from detection.model_trainer import extract_features
    from correlation.weighted_fusion import WeightedEvidenceFusion
    from correlation.incident_correlator import IncidentCorrelator
    from explainability.explainer import LocalFeatureExplainer



# ── WebSocket Manager ─────────────────────────────────────────────────────────
class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active_connections:
            self.active_connections.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


# ── App Lifecycle ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    """FastAPI lifespan handler: initializes state and starts dataset worker task."""
    application.state.ws_manager = WebSocketManager()
    application.state.alerts = []
    application.state.incidents = []
    application.state.total_events = 0
    application.state.eps = 0.0
    application.state.alerts_by_severity = {}
    application.state.analysis_running = False
    application.state._logged_errs = set()
    application.state.isolated_ips = set()
    _load_models_from_disk(application.state)
    worker_task = asyncio.create_task(dataset_worker(application.state))
    yield
    # Shutdown: cancel background worker gracefully
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass


# ── App & CORS Setup ──────────────────────────────────────────────────────────
app = FastAPI(
    title="AEGIS Threat Detection API",
    description="Real-Time Network Threat Intelligence and ML Detection API",
    version="1.0.0",
    lifespan=lifespan,
)

# Configurable CORS
cors_env = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000")
allowed_origins = [orig.strip() for orig in cors_env.split(",") if orig.strip()]
if "*" in allowed_origins or os.getenv("AEGIS_ALLOW_ALL_ORIGINS", "false").lower() == "true":
    allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True if allowed_origins != ["*"] else False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ── MITRE ATT&CK & Kill Chain Mappings ─────────────────────────────────────────
KILL_CHAIN_STAGES = {
    "brute_force": "Weaponize",
    "lateral_movement": "Install",
    "c2_beaconing": "C2",
    "data_exfiltration": "Exfiltrate",
    "benign": "None",
}

NEXT_STAGE = {
    "Recon": "Weaponize",
    "Weaponize": "Delivery",
    "Delivery": "Exploit",
    "Exploit": "Install",
    "Install": "C2",
    "C2": "Exfiltrate",
    "Exfiltrate": "Impact",
    "Impact": "Impact",
    "None": "None",
}

DEFAULT_SEVERITY = {
    "brute_force": "medium",
    "lateral_movement": "high",
    "c2_beaconing": "high",
    "data_exfiltration": "critical",
    "benign": None,
}


def _build_graph(alerts: list, incidents: Optional[list] = None) -> dict:
    """Build Cytoscape graph structure distinguishing observed telemetry flows from inferred correlation hypotheses."""
    nodes_map: dict = {}
    edges_map: dict = {}
    risk_map = {"critical": 0.95, "high": 0.80, "medium": 0.55, "low": 0.30}

    # 1. Observed telemetry edges from processed alerts
    for a in alerts[-200:]:
        src = a.get("src_entity", "")
        dst = a.get("dst_entity", "")
        sev = a.get("severity", "low")
        conf = float(a.get("classifier_probability") or a.get("confidence") or 0.5)
        risk = risk_map.get(sev, conf)
        ts = a.get("timestamp") or a.get("created_at")
        ev_id = a.get("event_id") or a.get("alert_id")

        for entity, is_attacker in [(src, True), (dst, False)]:
            if not entity or entity == "unknown":
                continue
            if entity not in nodes_map:
                nodes_map[entity] = {
                    "id": entity,
                    "label": entity,
                    "type": "ip",
                    "risk_score": risk if is_attacker else 0.1,
                    "event_count": 0,
                    "is_compromised": is_attacker and sev in ("critical", "high"),
                }
            nodes_map[entity]["event_count"] += 1
            if is_attacker:
                nodes_map[entity]["risk_score"] = max(nodes_map[entity]["risk_score"], risk)
                nodes_map[entity]["is_compromised"] = nodes_map[entity]["is_compromised"] or (sev in ("critical", "high"))

        if src and dst and src != "unknown" and dst != "unknown":
            edge_key = (src, dst, "observed_telemetry")
            if edge_key not in edges_map:
                edges_map[edge_key] = {
                    "source": src,
                    "target": dst,
                    "threat_type": a.get("threat_type", "anomaly"),
                    "is_anomalous": sev in ("critical", "high"),
                    "frequency": 0,
                    "edge_type": "observed_telemetry",
                    "claim_type": "observation",
                    "relationship_reason": f"Observed {a.get('layer', 'network')} flow: {a.get('threat_type', 'activity')}",
                    "supporting_event_ids": [],
                    "last_timestamp": str(ts) if ts else None,
                }
            edges_map[edge_key]["frequency"] += 1
            if ev_id and ev_id not in edges_map[edge_key]["supporting_event_ids"]:
                edges_map[edge_key]["supporting_event_ids"].append(ev_id)
            if ts:
                edges_map[edge_key]["last_timestamp"] = str(ts)
            if sev in ("critical", "high"):
                edges_map[edge_key]["is_anomalous"] = True

    # 2. Inferred correlation hypotheses from multi-stage incidents
    if incidents:
        for inc in incidents:
            rel_ev = getattr(inc, "relationship_evidence", []) or []
            if isinstance(rel_ev, list):
                for rel in rel_ev:
                    r_src = rel.get("source_entity")
                    r_dst = rel.get("target_entity")
                    r_type = rel.get("relationship_type", "observed_telemetry")
                    if r_src and r_dst and r_type == "pivot_lateral_movement" and r_src != "unknown" and r_dst != "unknown":
                        edge_key = (r_src, r_dst, "inferred_correlation")
                        if edge_key not in edges_map:
                            edges_map[edge_key] = {
                                "source": r_src,
                                "target": r_dst,
                                "threat_type": "lateral_pivot",
                                "is_anomalous": True,
                                "frequency": 1,
                                "edge_type": "inferred_correlation",
                                "claim_type": "hypothesis",
                                "relationship_reason": rel.get("reason", "Inferred lateral movement campaign pivot"),
                                "supporting_event_ids": rel.get("supporting_event_ids", []),
                                "last_timestamp": rel.get("timestamp"),
                            }

    return {"nodes": list(nodes_map.values()), "edges": list(edges_map.values())}


def _load_models_from_disk(state) -> bool:
    """Safely initialize ML detection models and correlation engine from serialized artifacts."""
    try:
        state.if_detector = IsolationForestDetector()
        state.if_detector.load()

        state.profiler = BehavioralBaselineProfiler()
        state.profiler.load()

        state.classifier = ThreatClassifier()
        clf_loaded = state.classifier.load()

        state.fusion_engine = WeightedEvidenceFusion()

        # Initialize incident correlation and local explainer
        state.correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)
        feature_names = (
            state.classifier.FEATURE_NAMES
            if (clf_loaded and hasattr(state.classifier, "FEATURE_NAMES"))
            else [
                "bytes_sent", "bytes_received", "duration_ms", "hour_of_day",
                "is_business_hours", "bytes_ratio", "port_risk_score",
                "connections_per_minute", "src_internal", "dst_internal",
                "if_score", "baseline_deviation", "graph_degree",
                "graph_external_ratio", "failed_auth_rate"
            ]
        )
        state.explainer = LocalFeatureExplainer(feature_names=feature_names)

        fitted = clf_loaded and state.classifier.is_fitted
        logger.info(f"[AEGIS] Models loaded from disk — classifier fitted={fitted}, correlator initialized")
        return fitted
    except Exception as e:
        logger.error(f"[AEGIS] Model load error: {e}")
        return False


def _discover_dataset_files() -> List[Path]:
    """Discover dataset files across datasets/ and data/raw/."""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    discovered = []
    seen_names = set()
    # 1. Check datasets/
    for p in sorted(DATASET_DIR.glob("*.*")):
        if p.suffix.lower() in [".csv", ".jsonl", ".json"] and p.name != ".gitkeep":
            discovered.append(p)
            seen_names.add(p.name)
    # 2. Check data/raw/
    raw_dir = PROJECT_ROOT / "data" / "raw"
    if raw_dir.exists():
        for p in sorted(raw_dir.glob("*.*")):
            if p.suffix.lower() in [".csv", ".jsonl", ".json"] and p.name != ".gitkeep":
                if p.name not in seen_names:
                    discovered.append(p)
                    seen_names.add(p.name)
    return discovered


# ── Dataset Streaming Worker ──────────────────────────────────────────────────
async def dataset_worker(state):
    """
    Streaming worker that processes datasets and generates alerts and incidents
    based on the real ML pipeline output without artificial threat injection.
    """
    import pandas as pd

    while True:
        if not state.analysis_running:
            await asyncio.sleep(0.2)
            continue

        stream_files = _discover_dataset_files()
        if not stream_files:
            logger.info("[AEGIS] No dataset files found for streaming analysis.")
            state.analysis_running = False
            continue

        for file_path in stream_files:
            if not state.analysis_running:
                break

            is_synthetic = (
                file_path.suffix.lower() == ".jsonl" or
                "synthetic" in file_path.name.lower() or
                "combined_labeled" in file_path.name.lower()
            )

            await state.ws_manager.broadcast({
                "type": "stats_update",
                "data": {
                    "current_file": file_path.name,
                    "is_synthetic": is_synthetic,
                    "total_events": state.total_events,
                    "total_alerts": len(state.alerts),
                    "total_incidents": len(state.correlator.incidents) if hasattr(state, "correlator") else len(state.incidents),
                    "events_per_second": state.eps,
                    "false_positive_rate": None,  # Ground-truth unlabelled stream: represented as null (N/A)
                    "alerts_by_severity": state.alerts_by_severity,
                    "analysis_complete": False,
                }
            })

            from backend.detection.model_trainer import load_flexible_dataset
            events, _ = load_flexible_dataset(str(file_path), max_rows=1500)
            if not events:
                continue

            t0 = time.time()
            for event in events:
                if not state.analysis_running:
                    break

                # Kill switch check
                isolated = getattr(state, "isolated_ips", set())
                if event.src_entity in isolated or event.dst_entity in isolated:
                    continue

                state.total_events += 1
                elapsed = time.time() - t0
                state.eps = round(state.total_events / max(elapsed, 0.001), 1)

                # Deduplication check
                fp = state.correlator.compute_event_fingerprint(event) if hasattr(state, "correlator") else None
                if fp and state.correlator.is_duplicate(fp, event.timestamp):
                    continue

                alert_obj: Optional[Alert] = None

                # Production ML detection path
                if hasattr(state, "classifier") and state.classifier.is_fitted:
                    try:
                        if_score = state.if_detector.predict(event)
                        base_dev = state.profiler.compute_deviation_score(event)
                        failed_auth = 1.0 if (event.status_code == 401 or event.auth_result == "failure") else 0.0

                        features = extract_features(
                            event=event,
                            if_score=if_score,
                            baseline_deviation=base_dev,
                            profiler=state.profiler,
                            failed_auth_rate=failed_auth
                        )

                        prediction = state.classifier.predict(features)

                        local_explanations = {}
                        if hasattr(state, "explainer"):
                            local_explanations = state.explainer.explain(
                                features,
                                global_importances=prediction.feature_importances,
                                entity_profile=state.profiler.profiles.get(event.src_entity)
                            )

                        is_threat = prediction.threat_type != "benign"
                        is_anomalous = if_score >= ANOMALY_THRESHOLD or base_dev >= 0.70

                        ev_raw = event.dict()

                        if is_threat and prediction.confidence >= CONFIDENCE_ALERT_MIN:
                            stage = KILL_CHAIN_STAGES.get(prediction.threat_type, "Weaponize")
                            alert_obj = Alert(
                                event_id=event.event_id,
                                timestamp=event.timestamp,
                                created_at=datetime.utcnow(),
                                threat_type=prediction.threat_type,
                                severity=prediction.severity or "medium",
                                confidence=round(prediction.confidence, 4),
                                classifier_probability=round(prediction.confidence, 4),
                                anomaly_score=round(if_score, 4),
                                baseline_deviation=round(base_dev, 4),
                                src_entity=event.src_entity,
                                dst_entity=event.dst_entity,
                                layer=event.layer,
                                source_file=file_path.name,
                                is_synthetic=is_synthetic,
                                feature_importance=local_explanations,
                                global_feature_importances=prediction.feature_importances,
                                current_kill_chain_stage=stage,
                                predicted_next_stage=NEXT_STAGE.get(stage, "Impact"),
                                fingerprint=fp,
                                raw_event=ev_raw,
                                is_false_positive=None,
                            )
                        elif is_anomalous:
                            # Genuine statistical anomaly alert without forcing supervised class
                            alert_obj = Alert(
                                event_id=event.event_id,
                                timestamp=event.timestamp,
                                created_at=datetime.utcnow(),
                                threat_type="statistical_anomaly",
                                severity="high" if (if_score >= 0.85 or base_dev >= 0.85) else "medium",
                                confidence=round(if_score, 4),
                                classifier_probability=None,
                                anomaly_score=round(if_score, 4),
                                baseline_deviation=round(base_dev, 4),
                                src_entity=event.src_entity,
                                dst_entity=event.dst_entity,
                                layer=event.layer,
                                source_file=file_path.name,
                                is_synthetic=is_synthetic,
                                feature_importance=local_explanations,
                                global_feature_importances=prediction.feature_importances,
                                current_kill_chain_stage="Anomaly",
                                predicted_next_stage="Investigation",
                                fingerprint=fp,
                                raw_event=ev_raw,
                                is_false_positive=None,
                            )
                    except Exception as exc:
                        if not hasattr(state, "_logged_errs"):
                            state._logged_errs = set()
                        err_key = type(exc).__name__
                        if err_key not in state._logged_errs:
                            logger.error(f"[AEGIS] Real detection pipeline error ({err_key}): {exc}")
                            state._logged_errs.add(err_key)

                if alert_obj:
                    # Incrementally correlate alert into incident
                    incident, is_new = state.correlator.correlate_alert(alert_obj, raw_event=event)
                    
                    alert_dict = alert_obj.dict()
                    alert_dict["event_id"] = alert_obj.event_id
                    alert_dict["incident_id"] = incident.incident_id
                    alert_dict["timestamp"] = alert_obj.timestamp.isoformat() if alert_obj.timestamp else datetime.utcnow().isoformat()
                    alert_dict["created_at"] = alert_obj.created_at.isoformat()

                    state.alerts.append(alert_dict)
                    sev = alert_dict["severity"]
                    state.alerts_by_severity[sev] = state.alerts_by_severity.get(sev, 0) + 1

                    inc_dict = incident.dict()
                    inc_dict["created_at"] = incident.created_at.isoformat()
                    inc_dict["updated_at"] = incident.updated_at.isoformat()
                    for t in inc_dict.get("timeline", []):
                        if isinstance(t.get("timestamp"), datetime):
                            t["timestamp"] = t["timestamp"].isoformat()

                    # Synchronize incident state
                    inc_idx = next((i for i, inc in enumerate(state.incidents) if inc.get("incident_id") == incident.incident_id), None)
                    if inc_idx is not None:
                        state.incidents[inc_idx] = inc_dict
                    else:
                        state.incidents.append(inc_dict)

                    # Stream incident and alert over WebSocket
                    if is_new:
                        await state.ws_manager.broadcast({"type": "new_incident", "data": inc_dict})
                    else:
                        await state.ws_manager.broadcast({"type": "incident_update", "data": inc_dict})

                    await state.ws_manager.broadcast({"type": "new_alert", "data": alert_dict})

                # Periodic stats update
                if state.total_events % 100 == 0:
                    await state.ws_manager.broadcast({
                        "type": "stats_update",
                        "data": {
                            "current_file": file_path.name,
                            "is_synthetic": is_synthetic,
                            "total_events": state.total_events,
                            "total_alerts": len(state.alerts),
                            "total_incidents": len(state.correlator.incidents),
                            "events_per_second": state.eps,
                            "false_positive_rate": None,
                            "alerts_by_severity": state.alerts_by_severity,
                            "analysis_complete": False,
                        }
                    })

                # Broadcast graph periodically
                if len(state.alerts) == 1 or (len(state.alerts) > 0 and len(state.alerts) % 5 == 0):
                    inc_list = state.correlator.get_all_incidents() if hasattr(state, "correlator") else []
                    await state.ws_manager.broadcast({
                        "type": "graph_update",
                        "data": _build_graph(state.alerts, inc_list)
                    })

                await asyncio.sleep(0.01)

        state.analysis_running = False
        final_incs = state.correlator.get_all_incidents() if hasattr(state, "correlator") else []
        await state.ws_manager.broadcast({"type": "graph_update", "data": _build_graph(state.alerts, final_incs)})
        await state.ws_manager.broadcast({
            "type": "stats_update",
            "data": {
                "current_file": None,
                "is_synthetic": False,
                "total_events": state.total_events,
                "total_alerts": len(state.alerts),
                "total_incidents": len(state.correlator.incidents) if hasattr(state, "correlator") else len(state.incidents),
                "events_per_second": 0,
                "false_positive_rate": None,
                "alerts_by_severity": state.alerts_by_severity,
                "analysis_complete": True,
            }
        })




# ── REST API Endpoints ─────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    fitted = getattr(getattr(app.state, "classifier", None), "is_fitted", False)
    csv_count = len(list(DATASET_DIR.glob("*.csv"))) if DATASET_DIR.exists() else 0
    return {
        "status": "ok",
        "models_loaded": hasattr(app.state, "classifier"),
        "classifier_fitted": fitted,
        "dataset_dir": str(DATASET_DIR),
        "csv_count": csv_count,
    }


@app.get("/api/alerts")
def get_alerts():
    return app.state.alerts[-100:]


@app.get("/api/incidents")
def get_incidents():
    if hasattr(app.state, "correlator") and app.state.correlator.incidents:
        return [
            {
                **inc.dict(),
                "created_at": inc.created_at.isoformat() if hasattr(inc.created_at, "isoformat") else str(inc.created_at),
                "updated_at": inc.updated_at.isoformat() if hasattr(inc.updated_at, "isoformat") else str(inc.updated_at),
                "timeline": [
                    {
                        **t.dict(),
                        "timestamp": t.timestamp.isoformat() if hasattr(t.timestamp, "isoformat") else str(t.timestamp)
                    }
                    for t in inc.timeline
                ]
            }
            for inc in app.state.correlator.get_all_incidents()
        ]
    return app.state.incidents


@app.get("/api/incident/{incident_id}")
def get_incident(incident_id: str):
    inc = None
    if hasattr(app.state, "correlator"):
        inc = app.state.correlator.get_incident(incident_id)
        if not inc:
            for candidate in app.state.correlator.get_all_incidents():
                if incident_id in candidate.alert_ids or any(e.get("event_id") == incident_id for e in candidate.supporting_events):
                    inc = candidate
                    break

    if not inc:
        for i in app.state.incidents:
            if i.get("incident_id") == incident_id or incident_id in i.get("alert_ids", []):
                return i
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        **inc.dict(),
        "created_at": inc.created_at.isoformat() if hasattr(inc.created_at, "isoformat") else str(inc.created_at),
        "updated_at": inc.updated_at.isoformat() if hasattr(inc.updated_at, "isoformat") else str(inc.updated_at),
        "timeline": [
            {
                **t.dict(),
                "timestamp": t.timestamp.isoformat() if hasattr(t.timestamp, "isoformat") else str(t.timestamp)
            }
            for t in inc.timeline
        ]
    }


@app.get("/api/stats/summary")
def get_stats_summary():
    discovered = _discover_dataset_files()
    files = [f.name for f in discovered]
    return {
        "total_events": app.state.total_events,
        "total_alerts": len(app.state.alerts),
        "total_incidents": len(app.state.correlator.incidents) if hasattr(app.state, "correlator") else len(app.state.incidents),
        "false_positive_rate": None,
        "analysis_running": app.state.analysis_running,
        "dataset_files": files,
        "alerts_by_severity": app.state.alerts_by_severity,
    }


@app.get("/api/analysis/files")
def list_dataset_files():
    discovered = _discover_dataset_files()
    files = []
    for f in discovered:
        is_synth = f.suffix.lower() == ".jsonl" or "synthetic" in f.name.lower() or "combined_labeled" in f.name.lower()
        files.append({
            "name": f.name,
            "size_mb": round(f.stat().st_size / 1e6, 2),
            "is_synthetic": is_synth,
            "source_type": "Synthetic Benchmark" if is_synth else "Real Network PCAP Capture",
        })
    return {"files": files, "count": len(files)}


@app.post("/api/analysis/start")
def start_analysis():
    if app.state.analysis_running:
        return {"status": "already_running"}
    # Reset stream state
    app.state.alerts = []
    app.state.incidents = []
    if hasattr(app.state, "correlator"):
        app.state.correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)
    app.state.total_events = 0
    app.state.eps = 0.0
    app.state.alerts_by_severity = {}
    app.state._logged_errs = set()
    app.state.isolated_ips = set()

    fitted = _load_models_from_disk(app.state)
    app.state.analysis_running = True
    return {"status": "analysis_started", "classifier_fitted": fitted}


@app.post("/api/analysis/stop")
def stop_analysis():
    app.state.analysis_running = False
    return {"status": "analysis_stopped"}


@app.post("/api/simulation/start")
def start_simulation():
    return start_analysis()


@app.post("/api/simulation/stop")
def stop_simulation():
    return stop_analysis()


@app.post("/api/incident/{incident_id}/remediate")
async def remediate_incident(incident_id: str):
    found_inc = None
    if hasattr(app.state, "correlator"):
        found_inc = app.state.correlator.get_incident(incident_id)
        if not found_inc:
            for inc in app.state.correlator.get_all_incidents():
                if incident_id in inc.alert_ids or any(e.get("event_id") == incident_id for e in inc.supporting_events):
                    found_inc = inc
                    break

    if found_inc:
        found_inc.status = "resolved"
        # Update corresponding alerts
        for a in app.state.alerts:
            if a.get("incident_id") == found_inc.incident_id or a.get("event_id") in found_inc.alert_ids:
                a["status"] = "resolved"

        inc_dict = found_inc.model_dump() if hasattr(found_inc, "model_dump") else found_inc.dict()
        inc_dict["created_at"] = found_inc.created_at.isoformat()
        inc_dict["updated_at"] = found_inc.updated_at.isoformat()
        for t in inc_dict.get("timeline", []):
            if isinstance(t.get("timestamp"), datetime):
                t["timestamp"] = t["timestamp"].isoformat()

        await app.state.ws_manager.broadcast({
            "type": "incident_update",
            "data": {**inc_dict, "status": "resolved", "action_taken": "playbook_executed (simulated)"}
        })
        return {"status": "success", "message": f"Incident {found_inc.incident_id} marked resolved (simulated)."}

    # Fallback to direct alert match
    for a in app.state.alerts:
        if a.get("event_id") == incident_id or a.get("alert_id") == incident_id:
            a["status"] = "resolved"
            await app.state.ws_manager.broadcast({
                "type": "incident_update",
                "data": {"incident_id": incident_id, "event_id": incident_id, "status": "resolved", "action_taken": "playbook_executed (simulated)"}
            })
            return {"status": "success", "message": "Playbook executed successfully (simulated)."}

    return {"status": "not_found", "message": "Incident not found in active stream."}


@app.post("/api/incident/{incident_id}/isolate")
async def isolate_host(incident_id: str):
    found_inc = None
    if hasattr(app.state, "correlator"):
        found_inc = app.state.correlator.get_incident(incident_id)
        if not found_inc:
            for inc in app.state.correlator.get_all_incidents():
                if incident_id in inc.alert_ids or any(e.get("event_id") == incident_id for e in inc.supporting_events):
                    found_inc = inc
                    break

    if found_inc:
        found_inc.status = "isolated"
        attacker = found_inc.primary_attacker
        if attacker:
            if not hasattr(app.state, "isolated_ips"):
                app.state.isolated_ips = set()
            app.state.isolated_ips.add(attacker)

        for a in app.state.alerts:
            if a.get("incident_id") == found_inc.incident_id or a.get("event_id") in found_inc.alert_ids:
                a["status"] = "isolated"

        inc_dict = found_inc.model_dump() if hasattr(found_inc, "model_dump") else found_inc.dict()
        inc_dict["created_at"] = found_inc.created_at.isoformat()
        inc_dict["updated_at"] = found_inc.updated_at.isoformat()
        for t in inc_dict.get("timeline", []):
            if isinstance(t.get("timestamp"), datetime):
                t["timestamp"] = t["timestamp"].isoformat()

        await app.state.ws_manager.broadcast({
            "type": "incident_update",
            "data": {**inc_dict, "status": "isolated", "action_taken": f"Host {attacker} isolated (Simulated: memory-blocked in stream filter; no firewall integration active)"}
        })
        return {"status": "success", "message": f"Host {attacker} marked as isolated (Simulated)."}

    # Fallback alert match
    for a in app.state.alerts:
        if a.get("event_id") == incident_id or a.get("alert_id") == incident_id:
            a["status"] = "isolated"
            src = a.get("src_entity")
            if src:
                if not hasattr(app.state, "isolated_ips"):
                    app.state.isolated_ips = set()
                app.state.isolated_ips.add(src)

            await app.state.ws_manager.broadcast({
                "type": "incident_update",
                "data": {"incident_id": incident_id, "event_id": incident_id, "status": "isolated", "action_taken": f"Host {src} isolated (Simulated)"}
            })
            return {"status": "success", "message": "Host isolated securely (Simulated)."}

    return {"status": "not_found", "message": "Incident not found in active stream."}



@app.post("/api/detect", response_model=DetectionResult)
def detect_single_event(event: UnifiedEvent):
    """
    Direct synchronous prediction endpoint for a single UnifiedEvent.
    Executes the genuine 15-feature ML pipeline and evidence fusion.
    """
    if not hasattr(app.state, "classifier") or not app.state.classifier.is_fitted:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat detection models are not loaded or fitted."
        )

    try:
        if_score = app.state.if_detector.predict(event)
        base_dev = app.state.profiler.compute_deviation_score(event)
        features = extract_features(
            event=event,
            if_score=if_score,
            baseline_deviation=base_dev,
            profiler=app.state.profiler,
            failed_auth_rate=0.0
        )
        prediction = app.state.classifier.predict(features)

        result = app.state.fusion_engine.fuse(
            event=event,
            if_score=if_score,
            baseline_deviation=base_dev,
            graph_score=0.0,
            threat_type=prediction.threat_type,
            classifier_confidence=prediction.confidence,
            severity=prediction.severity
        )
        return result
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error executing threat prediction."
        )


# ── WebSocket Endpoint ────────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await app.state.ws_manager.connect(websocket)
    try:
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug(f"[WS] Client exception: {exc}")
    finally:
        app.state.ws_manager.disconnect(websocket)
