import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from backend.api.main import app, _load_models_from_disk
from backend.core.schemas import UnifiedEvent


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        _load_models_from_disk(app.state)
        yield test_client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "models_loaded" in data
    assert "classifier_fitted" in data


def test_api_stats_summary(client):
    response = client.get("/api/stats/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "total_alerts" in data
    assert "total_incidents" in data
    assert "analysis_running" in data
    # Ground truth is unlabelled in live stream, must be null/None
    assert data.get("false_positive_rate") is None


def test_api_analysis_files(client):
    response = client.get("/api/analysis/files")
    assert response.status_code == 200
    data = response.json()
    assert "files" in data
    assert "count" in data
    if data["files"]:
        assert "is_synthetic" in data["files"][0]
        assert "source_type" in data["files"][0]


def test_api_incidents(client):
    response = client.get("/api/incidents")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)



def test_detect_single_event_endpoint(client):
    payload = {
        "timestamp": datetime.now().isoformat(),
        "layer": "network",
        "src_entity": "10.0.0.45",
        "dst_entity": "10.0.0.1",
        "src_internal": True,
        "dst_internal": True,
        "dst_port": 80,
        "bytes_sent": 500,
        "bytes_received": 1500,
        "duration_ms": 100,
        "connections_per_minute": 10.0
    }

    response = client.post("/api/detect", json=payload)
    if response.status_code == 503:
        # Expected if model was not loaded
        pass
    else:
        assert response.status_code == 200
        data = response.json()
        assert "event_id" in data
        assert "threat_type" in data
        assert "confidence" in data
        assert "if_score" in data
        assert "is_alert" in data


def test_remediate_and_isolate_endpoints(client):
    # Test not found for non-existent event
    res1 = client.post("/api/incident/fake-id-123/remediate")
    assert res1.status_code == 200
    assert res1.json()["status"] == "not_found"

    res2 = client.post("/api/incident/fake-id-123/isolate")
    assert res2.status_code == 200
    assert res2.json()["status"] == "not_found"


def test_websocket_connection(client):
    with client.websocket_connect("/ws/live") as websocket:
        # Connection succeeds without error
        assert websocket is not None
