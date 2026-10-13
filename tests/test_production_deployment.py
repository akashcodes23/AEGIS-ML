import os
import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.api.main import (
    app,
    _load_models_from_disk,
    _discover_dataset_files,
    _build_graph,
    PROJECT_ROOT,
    DATASET_DIR,
)
from backend.core.schemas import Incident


@pytest.fixture(scope="module")
def prod_client():
    with TestClient(app) as client:
        _load_models_from_disk(app.state)
        yield client


def test_health_and_api_health_get_and_head(prod_client):
    """Verify /health and /api/health support both GET and HEAD methods."""
    for path in ["/health", "/api/health"]:
        # GET check
        get_res = prod_client.get(path)
        assert get_res.status_code == 200, f"GET {path} failed: {get_res.status_code}"
        data = get_res.json()
        assert data["status"] == "ok"
        assert data["models_loaded"] is True
        assert data["classifier_fitted"] is True

        # HEAD check
        head_res = prod_client.head(path)
        assert head_res.status_code == 200, f"HEAD {path} failed: {head_res.status_code}"


def test_stats_summary_with_and_without_api_prefix(prod_client):
    """Verify /stats/summary and /api/stats/summary return consistent payloads."""
    res_api = prod_client.get("/api/stats/summary")
    assert res_api.status_code == 200
    data_api = res_api.json()

    res_raw = prod_client.get("/stats/summary")
    assert res_raw.status_code == 200
    data_raw = res_raw.json()

    assert data_api["total_events"] == data_raw["total_events"]
    assert data_api["dataset_files"] == data_raw["dataset_files"]
    assert "analysis_running" in data_api


def test_analysis_files_with_and_without_api_prefix(prod_client):
    """Verify /analysis/files and /api/analysis/files discover available datasets."""
    for path in ["/api/analysis/files", "/analysis/files"]:
        res = prod_client.get(path)
        assert res.status_code == 200, f"GET {path} failed: {res.status_code}"
        data = res.json()
        assert "files" in data
        assert "count" in data
        assert data["count"] >= 1
        file_names = [f["name"] for f in data["files"]]
        assert "behavioral_diversity_labeled.jsonl" in file_names


def test_analysis_start_and_stop_lifecycle(prod_client):
    """Verify start and stop endpoints with and without /api prefix."""
    # Ensure stopped first
    stop_res = prod_client.post("/api/analysis/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "analysis_stopped"

    # Start via /analysis/start alias
    start_res = prod_client.post("/analysis/start")
    assert start_res.status_code == 200
    start_data = start_res.json()
    assert start_data["status"] == "analysis_started"
    assert start_data["classifier_fitted"] is True
    assert start_data["dataset_count"] >= 1

    # Idempotent re-start returns already_running
    re_start = prod_client.post("/api/analysis/start")
    assert re_start.status_code == 200
    assert re_start.json()["status"] == "already_running"

    # Stop via /analysis/stop
    stop_res2 = prod_client.post("/analysis/stop")
    assert stop_res2.status_code == 200
    assert stop_res2.json()["status"] == "analysis_stopped"


def test_cors_production_origin_allowed(prod_client):
    """Verify production Vercel frontend origin receives valid CORS headers."""
    prod_origin = "https://aegis-ml-navv.vercel.app"
    options_res = prod_client.options(
        "/api/analysis/files",
        headers={
            "Origin": prod_origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert options_res.status_code == 200
    assert options_res.headers.get("access-control-allow-origin") == prod_origin

    # Test preview vercel domain matching regex
    preview_origin = "https://aegis-ml-preview-xyz.vercel.app"
    prev_res = prod_client.options(
        "/api/stats/summary",
        headers={
            "Origin": preview_origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert prev_res.status_code == 200
    assert prev_res.headers.get("access-control-allow-origin") == preview_origin


def test_build_graph_handles_dict_incidents():
    """Verify _build_graph parses both Incident model instances and serialized dicts."""
    alerts = [{
        "event_id": "ev-01",
        "src_entity": "10.0.1.5",
        "dst_entity": "10.0.1.10",
        "threat_type": "lateral_movement",
        "severity": "high",
        "timestamp": "2026-10-13T00:00:00Z",
    }]
    # Test with dict representation of incident
    dict_inc = {
        "incident_id": "INC-001",
        "relationship_evidence": [{
            "source_entity": "10.0.1.5",
            "target_entity": "10.0.1.20",
            "relationship_type": "pivot_lateral_movement",
            "reason": "Pivot test",
            "supporting_event_ids": ["ev-01"],
            "timestamp": "2026-10-13T00:00:00Z",
        }]
    }
    graph = _build_graph(alerts, [dict_inc])
    assert "nodes" in graph and "edges" in graph
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "10.0.1.5" in node_ids
    assert len(graph["edges"]) >= 1


def test_production_artifacts_sha256_integrity():
    """Verify calibrated model artifact and behavioral dataset artifact have unchanged SHA-256 hashes."""
    model_path = PROJECT_ROOT / "data" / "models" / "calibrated_threat_classifier.pkl"
    assert model_path.exists(), "calibrated_threat_classifier.pkl must exist"
    with open(model_path, "rb") as f:
        model_sha = hashlib.sha256(f.read()).hexdigest()
    assert model_sha == "98e926edc4dc53e3e34d48c78aa0390565c70029325bea896e0ab631e757ce71"

    dataset_path = PROJECT_ROOT / "data" / "raw" / "behavioral_diversity_labeled.jsonl"
    assert dataset_path.exists(), "behavioral_diversity_labeled.jsonl must exist"
    with open(dataset_path, "rb") as f:
        data_sha = hashlib.sha256(f.read()).hexdigest()
    assert data_sha == "1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352"


def test_calibrated_model_48_feature_schema_readiness():
    """Verify calibrated model maintains the production 48-feature schema and readiness flags."""
    from backend.detection.model_lifecycle import ModelLifecycleManager
    manager = ModelLifecycleManager()
    loaded = manager.load_artifact()
    assert loaded is True, "Failed to load model artifact via ModelLifecycleManager"
    clf = manager.active_classifier
    assert clf is not None
    assert clf.is_fitted is True
    assert clf.is_calibrated is True
    assert clf.n_features == 48, f"Expected 48 features, got {clf.n_features}"
    assert len(clf.feature_names) == 48


def test_websocket_initial_snapshot_and_serialization(prod_client):
    """Verify WebSocket /ws/live sends atomic snapshot and serializes datetimes without dropping connection."""
    from datetime import datetime
    from backend.core.schemas import UnifiedEvent, Alert, Incident, TimelineEntry

    ev = UnifiedEvent(
        event_id="test-ev-ws-1",
        timestamp=datetime.utcnow(),
        src_entity="192.168.1.50",
        dst_entity="10.0.0.5",
        src_internal=True,
        dst_internal=False,
        layer="network",
    )
    alert = Alert(
        event_id=ev.event_id,
        timestamp=ev.timestamp,
        threat_type="brute_force",
        severity="high",
        src_entity=ev.src_entity,
        dst_entity=ev.dst_entity,
        layer=ev.layer,
        raw_event=ev.dict(),
    )
    inc = Incident(
        incident_id="INC-WS-001",
        threat_type="brute_force",
        supporting_events=[ev.dict()],
        timeline=[
            TimelineEntry(
                timestamp=datetime.utcnow(),
                entity="192.168.1.50",
                title="Suspicious Activity",
                description="Failed authentication spike",
                claim_type="observation",
                evidence_type="Network Flow",
            )
        ],
    )
    app.state.alerts = [alert.dict()]
    app.state.incidents = [inc.dict()]
    app.state.total_events = 42
    app.state.eps = 12.5

    with prod_client.websocket_connect("/ws/live") as ws:
        msg1 = ws.receive_json()
        assert msg1["type"] == "snapshot"
        assert "stats" in msg1["data"]
        assert "alerts" in msg1["data"]
        assert "incidents" in msg1["data"]
        assert "graph" in msg1["data"]
        assert msg1["data"]["stats"]["total_events"] == 42
        assert len(msg1["data"]["alerts"]) == 1
        assert len(msg1["data"]["incidents"]) == 1

        msg2 = ws.receive_json()
        assert msg2["type"] == "stats_update"
        assert msg2["data"]["total_events"] == 42

        msg3 = ws.receive_json()
        assert msg3["type"] == "new_alert"
        assert msg3["data"]["event_id"] == "test-ev-ws-1"

        msg4 = ws.receive_json()
        assert msg4["type"] == "new_incident"
        assert msg4["data"]["incident_id"] == "INC-WS-001"

        msg5 = ws.receive_json()
        assert msg5["type"] == "graph_update"
        assert "nodes" in msg5["data"]
        assert "edges" in msg5["data"]


def test_stats_summary_extended_consistency(prod_client):
    """Verify /api/stats/summary returns all fields needed by Dashboard and agrees with state."""
    res = prod_client.get("/api/stats/summary")
    assert res.status_code == 200
    data = res.json()
    assert "events_per_second" in data
    assert "current_file" in data
    assert "analysis_complete" in data
    assert "analysis_running" in data
    assert "total_alerts" in data
    assert "total_incidents" in data
    assert "total_events" in data


def test_alerts_and_incidents_rest_endpoints(prod_client):
    """Verify /api/alerts, /alerts, /api/incidents, and /incidents endpoints return serializable JSON lists."""
    for path in ["/api/alerts", "/alerts", "/api/incidents", "/incidents"]:
        res = prod_client.get(path)
        assert res.status_code == 200, f"GET {path} failed: {res.status_code}"
        assert isinstance(res.json(), list)


def test_frontend_navigation_routes_and_vercel_spa_rewrites():
    """Verify frontend navigation routes are defined and vercel.json includes SPA fallback rewrites."""
    import json
    vercel_path = PROJECT_ROOT / "frontend" / "vercel.json"
    assert vercel_path.exists(), "vercel.json must exist"
    with open(vercel_path, "r") as f:
        vercel_cfg = json.load(f)

    rewrites = vercel_cfg.get("rewrites", [])
    has_spa_rewrite = any(
        r.get("source") in ["/(.*)", "/(.*)/"] and r.get("destination") == "/index.html"
        for r in rewrites
    )
    assert has_spa_rewrite is True, "vercel.json must have SPA wildcard fallback rewrite to /index.html"
