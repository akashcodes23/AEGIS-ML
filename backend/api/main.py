import asyncio
import hashlib
import hmac
import math
import os
import time
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Union, Tuple
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status, Header, Query
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
    from backend.core.schemas import (
        UnifiedEvent, DetectionResult, Alert, Incident, TimelineEntry,
        IngestionEventRequest, IngestionBatchRequest, IngestionItemResult,
        IngestionBatchResponse, StreamingIngestionStats, ReplayRequest, ReplayResponse,
        QueueMetrics, DeadLetterItem, AsyncQueueConfig, EventProcessingState,
    )
    from backend.detection.isolation_forest import IsolationForestDetector
    from backend.detection.baseline_profiler import BehavioralBaselineProfiler
    from backend.detection.threat_classifier import ThreatClassifier
    from backend.detection.model_trainer import extract_features, extract_full_causal_features
    from backend.detection.model_lifecycle import ModelLifecycleManager
    from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
    from backend.detection.sequence_context import CausalSequenceTracker
    from backend.correlation.weighted_fusion import WeightedEvidenceFusion
    from backend.correlation.incident_correlator import IncidentCorrelator
    from backend.explainability.explainer import LocalFeatureExplainer
    from backend.ingestion.streaming_ingestion import StreamingIngestionManager
    from backend.ingestion.normalizer import NormalizerPipeline, NormalizationError
    from backend.ingestion.replay import DeterministicEventReplayer, ReplayConfig
    from backend.ingestion.async_queue import (
        AsyncDetectionQueue, TransientDetectionError, PermanentDetectionError,
    )
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
    from core.schemas import (
        UnifiedEvent, DetectionResult, Alert, Incident, TimelineEntry,
        IngestionEventRequest, IngestionBatchRequest, IngestionItemResult,
        IngestionBatchResponse, StreamingIngestionStats, ReplayRequest, ReplayResponse,
        QueueMetrics, DeadLetterItem, AsyncQueueConfig, EventProcessingState,
    )
    from detection.isolation_forest import IsolationForestDetector
    from detection.baseline_profiler import BehavioralBaselineProfiler
    from detection.threat_classifier import ThreatClassifier
    from detection.model_trainer import extract_features, extract_full_causal_features
    from detection.model_lifecycle import ModelLifecycleManager
    from detection.temporal_graph_extractor import CausalTemporalGraphTracker
    from detection.sequence_context import CausalSequenceTracker
    from correlation.weighted_fusion import WeightedEvidenceFusion
    from correlation.incident_correlator import IncidentCorrelator
    from explainability.explainer import LocalFeatureExplainer
    from ingestion.streaming_ingestion import StreamingIngestionManager
    from ingestion.normalizer import NormalizerPipeline, NormalizationError
    from ingestion.replay import DeterministicEventReplayer, ReplayConfig
    from ingestion.async_queue import (
        AsyncDetectionQueue, TransientDetectionError, PermanentDetectionError,
    )



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

    # Initialize Phase 27 bounded async detection worker pool
    application.state.async_queue = AsyncDetectionQueue(
        config=AsyncQueueConfig(
            max_queue_size=int(os.getenv("AEGIS_QUEUE_MAX_SIZE", "1000")),
            worker_concurrency=int(os.getenv("AEGIS_QUEUE_WORKERS", "2")),
        ),
        detection_handler=lambda ev: _evaluate_event_detection(ev, application.state),
    )
    await application.state.async_queue.start()

    worker_task = asyncio.create_task(dataset_worker(application.state))
    yield
    # Shutdown: cancel background worker and stop async detection queue gracefully
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    if hasattr(application.state, "async_queue") and application.state.async_queue:
        await application.state.async_queue.stop()


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

        state.graph_tracker = CausalTemporalGraphTracker()
        state.sequence_tracker = CausalSequenceTracker(window_seconds=300.0)
        state.ingestion_manager = StreamingIngestionManager(
            sequence_tracker=state.sequence_tracker,
            graph_tracker=state.graph_tracker,
            detection_handler=lambda ev: _evaluate_event_detection(ev, state),
        )

        # Initialize ModelLifecycleManager and load versioned/calibrated model
        state.lifecycle_manager = ModelLifecycleManager()
        clf_loaded = state.lifecycle_manager.load_artifact()
        if clf_loaded and state.lifecycle_manager.active_classifier:
            state.classifier = state.lifecycle_manager.active_classifier
        else:
            state.classifier = ThreatClassifier()
            clf_loaded = state.classifier.load()

        state.fusion_engine = WeightedEvidenceFusion()

        # Initialize incident correlation and local explainer
        state.correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=60)
        feature_names = (
            state.classifier.feature_names
            if (clf_loaded and hasattr(state.classifier, "feature_names"))
            else getattr(state.classifier, "FEATURE_NAMES", [])
        )
        state.explainer = LocalFeatureExplainer(feature_names=feature_names)

        fitted = clf_loaded and state.classifier.is_fitted
        is_cal = getattr(state.classifier, "is_calibrated", False)
        ver = getattr(state.classifier, "model_version", "legacy")
        logger.info(
            f"[AEGIS] Models loaded from disk — classifier fitted={fitted}, "
            f"version={ver}, calibrated={is_cal}, correlator initialized"
        )
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

                        if getattr(state.classifier, "n_features", 15) == 48 and hasattr(state, "graph_tracker") and hasattr(state, "sequence_tracker"):
                            features = extract_full_causal_features(
                                event=event,
                                if_score=if_score,
                                baseline_deviation=base_dev,
                                profiler=state.profiler,
                                failed_auth_rate=failed_auth,
                                graph_tracker=state.graph_tracker,
                                sequence_tracker=state.sequence_tracker,
                            )
                        else:
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
                                is_calibrated=prediction.is_calibrated,
                                calibrated_confidence=round(prediction.confidence, 4) if prediction.is_calibrated else None,
                                calibrated_probabilities=prediction.calibrated_probabilities,
                                raw_probabilities=prediction.raw_probabilities,
                                model_version=prediction.model_version,
                                confidence_qualification=prediction.confidence_qualification,
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
        failed_auth = 1.0 if (event.status_code == 401 or str(event.auth_result or "").strip().lower() == "failure") else 0.0

        if getattr(app.state.classifier, "n_features", 15) == 48:
            if not (hasattr(app.state, "graph_tracker") and hasattr(app.state, "sequence_tracker")):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Required temporal graph and sequence trackers are uninitialized."
                )
            features = extract_full_causal_features(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                profiler=app.state.profiler,
                failed_auth_rate=failed_auth,
                graph_tracker=app.state.graph_tracker,
                sequence_tracker=app.state.sequence_tracker,
            )
        else:
            features = extract_features(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                profiler=app.state.profiler,
                failed_auth_rate=failed_auth
            )
        prediction = app.state.classifier.predict(features)

        result = app.state.fusion_engine.fuse(
            event=event,
            if_score=if_score,
            baseline_deviation=base_dev,
            graph_score=0.0,
            threat_type=prediction.threat_type,
            classifier_confidence=prediction.confidence,
            severity=prediction.severity,
            is_calibrated=prediction.is_calibrated,
            calibrated_probabilities=prediction.calibrated_probabilities,
            raw_probabilities=prediction.raw_probabilities,
            model_version=prediction.model_version,
            confidence_qualification=prediction.confidence_qualification,
        )
        return result
    except ValueError as ve:
        logger.warning(f"Detection request rejected due to invalid input: {ve}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid feature inputs: {str(ve)}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error executing threat prediction."
        )


def _require_admin_authorization(
    x_aegis_admin_key: Optional[str],
    action_description: str = "administrative action",
) -> None:
    """
    Validate administrative caller authorization using constant-time comparison.
    Enforces key requirement in production/staging and checks configured AEGIS_ADMIN_KEY.
    """
    configured_key = os.environ.get("AEGIS_ADMIN_KEY")
    env = os.environ.get("AEGIS_ENV", os.environ.get("ENV", "development")).lower()
    is_exposed = env in ("production", "prod", "staging")

    if is_exposed and not configured_key:
        logger.error(
            "[Security] %s rejected: AEGIS_ADMIN_KEY is required in %s environment.",
            action_description,
            env,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: {action_description} requires AEGIS_ADMIN_KEY in {env} deployment."
        )

    if configured_key:
        if not x_aegis_admin_key or not hmac.compare_digest(x_aegis_admin_key, configured_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: invalid or missing admin authorization key."
            )
    else:
        logger.warning(
            "[Security] %s executed without AEGIS_ADMIN_KEY configured in %s mode.",
            action_description,
            env,
        )


def _evaluate_event_detection(
    event: UnifiedEvent,
    state: Any,
) -> Tuple[Optional[DetectionResult], Optional[Alert]]:
    """
    Evaluate an accepted UnifiedEvent through the complete detection pipeline:
    extract features (48 causal features if configured), execute calibrated classifier,
    fuse evidence, generate Alert if threat/anomaly thresholds are met, and correlate
    into incident graph.
    """
    if not hasattr(state, "classifier") or not state.classifier or not getattr(state.classifier, "is_fitted", False):
        return None, None

    try:
        if_score = state.if_detector.predict(event) if hasattr(state, "if_detector") and state.if_detector else 0.0
        base_dev = state.profiler.compute_deviation_score(event) if hasattr(state, "profiler") and state.profiler else 0.0
        failed_auth = 1.0 if (event.status_code == 401 or str(event.auth_result or "").strip().lower() == "failure") else 0.0

        if getattr(state.classifier, "n_features", 15) == 48 and hasattr(state, "graph_tracker") and hasattr(state, "sequence_tracker"):
            features = extract_full_causal_features(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                profiler=state.profiler,
                failed_auth_rate=failed_auth,
                graph_tracker=state.graph_tracker,
                sequence_tracker=state.sequence_tracker,
            )
        else:
            features = extract_features(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                profiler=state.profiler,
                failed_auth_rate=failed_auth,
            )

        prediction = state.classifier.predict(features)

        fusion_result = None
        if hasattr(state, "fusion_engine") and state.fusion_engine:
            fusion_result = state.fusion_engine.fuse(
                event=event,
                if_score=if_score,
                baseline_deviation=base_dev,
                graph_score=0.0,
                threat_type=prediction.threat_type,
                classifier_confidence=prediction.confidence,
                severity=prediction.severity,
                is_calibrated=prediction.is_calibrated,
                calibrated_probabilities=prediction.calibrated_probabilities,
                raw_probabilities=prediction.raw_probabilities,
                model_version=prediction.model_version,
                confidence_qualification=prediction.confidence_qualification,
            )

        is_threat = prediction.threat_type != "benign"
        is_anomalous = if_score >= ANOMALY_THRESHOLD or base_dev >= 0.70
        alert_obj = None

        if is_threat and prediction.confidence >= CONFIDENCE_ALERT_MIN:
            stage = KILL_CHAIN_STAGES.get(prediction.threat_type, "Weaponize")
            local_explanations = {}
            if hasattr(state, "explainer") and state.explainer:
                try:
                    local_explanations = state.explainer.explain(
                        features,
                        global_importances=prediction.feature_importances,
                        entity_profile=state.profiler.profiles.get(event.src_entity) if hasattr(state, "profiler") and state.profiler else None,
                    )
                except Exception as ex_err:
                    logger.debug("Local explainer error during streaming detection: %s", ex_err)

            alert_obj = Alert(
                event_id=event.event_id,
                timestamp=event.timestamp or datetime.utcnow(),
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
                source_file="streaming_ingestion",
                is_synthetic=False,
                feature_importance=local_explanations,
                global_feature_importances=prediction.feature_importances,
                current_kill_chain_stage=stage,
                predicted_next_stage=NEXT_STAGE.get(stage, "Impact"),
                fingerprint=getattr(event, "raw_payload_hash", None) or event.event_id,
                raw_event=event.model_dump() if hasattr(event, "model_dump") else event.dict(),
                is_false_positive=None,
                is_calibrated=prediction.is_calibrated,
                calibrated_confidence=round(prediction.confidence, 4) if prediction.is_calibrated else None,
                calibrated_probabilities=prediction.calibrated_probabilities,
                raw_probabilities=prediction.raw_probabilities,
                model_version=prediction.model_version,
                confidence_qualification=prediction.confidence_qualification,
            )
        elif is_anomalous:
            alert_obj = Alert(
                event_id=event.event_id,
                timestamp=event.timestamp or datetime.utcnow(),
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
                source_file="streaming_ingestion",
                is_synthetic=False,
                feature_importance={},
                global_feature_importances={},
                current_kill_chain_stage="Anomaly",
                predicted_next_stage="Investigation",
                fingerprint=getattr(event, "raw_payload_hash", None) or event.event_id,
                raw_event=event.model_dump() if hasattr(event, "model_dump") else event.dict(),
                is_false_positive=None,
            )

        if alert_obj and hasattr(state, "correlator") and state.correlator:
            incident, is_new = state.correlator.correlate_alert(alert_obj, raw_event=event)
            alert_obj.incident_id = incident.incident_id
            alert_dict = alert_obj.model_dump() if hasattr(alert_obj, "model_dump") else alert_obj.dict()
            alert_dict["event_id"] = alert_obj.event_id
            alert_dict["incident_id"] = incident.incident_id
            alert_dict["timestamp"] = alert_obj.timestamp.isoformat() if alert_obj.timestamp else datetime.utcnow().isoformat()
            alert_dict["created_at"] = alert_obj.created_at.isoformat()

            if hasattr(state, "alerts"):
                state.alerts.append(alert_dict)
            if hasattr(state, "alerts_by_severity"):
                sev = alert_dict["severity"]
                state.alerts_by_severity[sev] = state.alerts_by_severity.get(sev, 0) + 1

            inc_dict = incident.model_dump() if hasattr(incident, "model_dump") else incident.dict()
            inc_dict["created_at"] = incident.created_at.isoformat()
            inc_dict["updated_at"] = incident.updated_at.isoformat()
            for t in inc_dict.get("timeline", []):
                if isinstance(t.get("timestamp"), datetime):
                    t["timestamp"] = t["timestamp"].isoformat()

            if hasattr(state, "incidents"):
                inc_idx = next((i for i, inc in enumerate(state.incidents) if inc.get("incident_id") == incident.incident_id), None)
                if inc_idx is not None:
                    state.incidents[inc_idx] = inc_dict
                else:
                    state.incidents.append(inc_dict)

        return fusion_result, alert_obj

    except Exception as exc:
        logger.error("Error during streaming detection evaluation: %s", exc)
        return None, None


def _get_ingestion_manager(state) -> StreamingIngestionManager:
    """Helper to lazily retrieve or initialize StreamingIngestionManager."""
    if not hasattr(state, "async_queue") or state.async_queue is None:
        state.async_queue = AsyncDetectionQueue(
            config=AsyncQueueConfig(
                max_queue_size=int(os.getenv("AEGIS_QUEUE_MAX_SIZE", "1000")),
                worker_concurrency=int(os.getenv("AEGIS_QUEUE_WORKERS", "2")),
            ),
            detection_handler=lambda ev: _evaluate_event_detection(ev, state),
        )

    if not hasattr(state, "ingestion_manager") or state.ingestion_manager is None:
        seq_tracker = getattr(state, "sequence_tracker", None)
        graph_tracker = getattr(state, "graph_tracker", None)
        state.ingestion_manager = StreamingIngestionManager(
            sequence_tracker=seq_tracker,
            graph_tracker=graph_tracker,
            detection_handler=lambda ev: _evaluate_event_detection(ev, state),
            async_queue=state.async_queue,
        )
    else:
        if getattr(state.ingestion_manager, "detection_handler", None) is None:
            state.ingestion_manager.detection_handler = lambda ev: _evaluate_event_detection(ev, state)
        if getattr(state.ingestion_manager, "async_queue", None) is None:
            state.ingestion_manager.async_queue = state.async_queue
    return state.ingestion_manager


# ── Phase 25 & 27 Ingestion Endpoints ─────────────────────────────────────────

@app.post("/api/ingest/event", response_model=IngestionItemResult)
def ingest_single_event(
    request: Union[IngestionEventRequest, Dict[str, Any]],
    detect: Optional[bool] = Query(None, description="Trigger detection pipeline synchronously for accepted event"),
    async_mode: Optional[bool] = Query(None, alias="async", description="Enqueue accepted event for asynchronous detection worker"),
):
    """
    Ingest, validate, normalize, and deduplicate a single telemetry event.
    Returns structured IngestionItemResult with accepted, duplicate, rejected, or queued status.
    """
    mgr = _get_ingestion_manager(app.state)
    raw_ev = request.raw_event if isinstance(request, IngestionEventRequest) else request
    src_sys = request.source_system if isinstance(request, IngestionEventRequest) else None
    trigger_det = detect if detect is not None else (request.trigger_detection if isinstance(request, IngestionEventRequest) else False)
    is_async = async_mode if async_mode is not None else (request.async_detection if isinstance(request, IngestionEventRequest) else False)
    return mgr.ingest_event(
        raw_ev,
        source_system=src_sys,
        trigger_detection=trigger_det,
        async_detection=is_async,
    )


@app.post("/api/ingest/batch", response_model=IngestionBatchResponse)
def ingest_batch_events(
    request: IngestionBatchRequest,
    detect: Optional[bool] = Query(None, description="Trigger detection pipeline synchronously for accepted events"),
    async_mode: Optional[bool] = Query(None, alias="async", description="Enqueue accepted events for asynchronous detection worker"),
):
    """
    Ingest, validate, normalize, and deduplicate a batch of telemetry events.
    Enforces maximum batch size (500 events) and handles partial batch failures.
    """
    if len(request.events) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {len(request.events)} exceeds maximum permitted limit of 500 events."
        )
    mgr = _get_ingestion_manager(app.state)
    trigger_det = detect if detect is not None else request.trigger_detection
    is_async = async_mode if async_mode is not None else request.async_detection
    return mgr.ingest_batch(
        events=request.events,
        source_system=request.source_system,
        max_batch_size=500,
        trigger_detection=trigger_det,
        async_detection=is_async,
    )


@app.get("/api/ingest/stats", response_model=StreamingIngestionStats)
def get_ingestion_stats():
    """Get streaming ingestion metrics, counters, high-watermark timestamp, and queue metrics."""
    mgr = _get_ingestion_manager(app.state)
    return mgr.stats


@app.get("/api/ingest/queue/metrics", response_model=QueueMetrics)
def get_queue_metrics():
    """Get real-time observability metrics for the asynchronous detection queue."""
    mgr = _get_ingestion_manager(app.state)
    if mgr.async_queue and hasattr(mgr.async_queue, "get_metrics"):
        return mgr.async_queue.get_metrics()
    return QueueMetrics(worker_health="stopped", active_workers=0)


@app.get("/api/ingest/queue/dead-letter", response_model=List[DeadLetterItem])
def get_queue_dead_letter(
    x_aegis_admin_key: Optional[str] = Header(None, alias="X-AEGIS-Admin-Key"),
):
    """Inspect dead-letter queue records for permanently failed events (admin authorization required)."""
    _require_admin_authorization(x_aegis_admin_key, action_description="/api/ingest/queue/dead-letter")
    mgr = _get_ingestion_manager(app.state)
    if mgr.async_queue and hasattr(mgr.async_queue, "get_dead_letter_items"):
        return mgr.async_queue.get_dead_letter_items()
    return []


@app.post("/api/ingest/reset")
def reset_ingestion(
    x_aegis_admin_key: Optional[str] = Header(None, alias="X-AEGIS-Admin-Key"),
):
    """Reset ingestion buffers, watermark, and tracker histories."""
    allow_reset = os.environ.get("AEGIS_ALLOW_INGESTION_RESET", "true").lower()
    if allow_reset in ("false", "0", "disabled", "no"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ingestion reset is administratively disabled in this deployment."
        )

    _require_admin_authorization(x_aegis_admin_key, action_description="/api/ingest/reset")
    mgr = _get_ingestion_manager(app.state)
    mgr.reset()
    return {"status": "success", "message": "Streaming ingestion state and trackers reset."}


@app.post("/api/ingest/replay", response_model=ReplayResponse)
def replay_event_sequence(
    request: ReplayRequest,
    x_aegis_admin_key: Optional[str] = Header(None, alias="X-AEGIS-Admin-Key"),
):
    """
    Deterministically replay an event sequence in an isolated execution sandbox.
    Never modifies live production streaming ingestion buffers or active incident streams.
    """
    _require_admin_authorization(x_aegis_admin_key, action_description="/api/ingest/replay")

    config = ReplayConfig(
        mode=request.mode or "chronological",
        jitter_max_seconds=float(request.jitter_max_seconds or 0.0),
        out_of_order_probability=float(request.out_of_order_probability or 0.0),
        duplicate_injection_rate=float(request.duplicate_injection_rate or 0.0),
        trigger_detection=bool(request.trigger_detection),
        seed=int(request.seed if request.seed is not None else 42),
    )

    det_handler = None
    if request.trigger_detection:
        det_handler = lambda ev: _evaluate_event_detection(ev, app.state)

    replayer = DeterministicEventReplayer(
        config=config,
        detection_handler=det_handler,
    )

    summary = replayer.replay(request.events)

    return ReplayResponse(
        status="success",
        summary=summary.to_dict(),
        alerts_generated=summary.alerts_count,
        incidents_created=summary.incidents_count,
    )


def _sanitize_artifact_filename(filename: str) -> str:
    """Validate that artifact filename contains no directory traversal elements."""
    cleaned = str(filename).strip()
    if not cleaned or ".." in cleaned or "/" in cleaned or "\\" in cleaned or Path(cleaned).name != cleaned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid artifact filename: path traversal characters are prohibited."
        )
    return cleaned


class ArtifactValidationRequest(BaseModel):
    artifact_filename: str
    expected_sha256: Optional[str] = None


class ModelReloadRequest(BaseModel):
    artifact_filename: str
    expected_sha256: Optional[str] = None


@app.get("/api/model/lifecycle")
def get_model_lifecycle():
    """Return inspection metadata, calibration status, and version of active model."""
    if not hasattr(app.state, "lifecycle_manager"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model lifecycle manager is uninitialized."
        )
    return app.state.lifecycle_manager.get_lifecycle_status()


@app.post("/api/model/validate")
def validate_model_artifact(req: ArtifactValidationRequest):
    """Validate a candidate model artifact inside data/models/ before activation."""
    if not hasattr(app.state, "lifecycle_manager"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model lifecycle manager is uninitialized."
        )
    safe_name = _sanitize_artifact_filename(req.artifact_filename)
    target_path = app.state.lifecycle_manager.models_dir / safe_name
    is_valid, msg, meta = app.state.lifecycle_manager.validate_artifact_file(
        target_path,
        expected_sha256=req.expected_sha256
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Artifact validation rejected: {msg}"
        )
    return {
        "valid": True,
        "message": msg,
        "metadata": meta,
    }


@app.post("/api/model/reload")
def reload_model_artifact(
    req: ModelReloadRequest,
    x_aegis_admin_key: Optional[str] = Header(None, alias="X-AEGIS-Admin-Key")
):
    """
    Safely validate and activate a candidate model artifact.
    Preserves currently active model if validation or activation fails.
    """
    _require_admin_authorization(x_aegis_admin_key, action_description="/api/model/reload")

    if not hasattr(app.state, "lifecycle_manager"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model lifecycle manager is uninitialized."
        )

    safe_name = _sanitize_artifact_filename(req.artifact_filename)
    target_path = app.state.lifecycle_manager.models_dir / safe_name

    # Pre-validation
    is_valid, msg, meta = app.state.lifecycle_manager.validate_artifact_file(
        target_path,
        expected_sha256=req.expected_sha256
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Candidate artifact failed pre-activation validation: {msg}"
        )

    # Safe activation
    success = app.state.lifecycle_manager.load_artifact(
        target_path,
        expected_sha256=req.expected_sha256
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate candidate artifact; active model was preserved."
        )

    app.state.classifier = app.state.lifecycle_manager.active_classifier
    logger.info(f"[Lifecycle] Successfully activated new model artifact: {safe_name}")
    return {
        "status": "activated",
        "message": f"Successfully activated artifact {safe_name}",
        "lifecycle": app.state.lifecycle_manager.get_lifecycle_status()
    }


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
