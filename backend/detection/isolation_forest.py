import math
import numpy as np
import joblib
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest
import os
from pathlib import Path

from backend.core.schemas import UnifiedEvent
from backend.core.config import (
    IF_NETWORK_PATH,
    IF_ENDPOINT_PATH
)

class IsolationForestDetector:
    def __init__(self):
        self.network_model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
        self.endpoint_model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
        self.payload_mean = 0.0
        self.payload_std = 1.0
        self.port_freqs = {}

    def _compute_stats(self, events: List[UnifiedEvent]):
        payloads = [e.bytes_sent for e in events if e.layer == "network" and e.bytes_sent is not None]
        if payloads:
            self.payload_mean = float(np.mean(payloads))
            self.payload_std = float(np.std(payloads))
            if self.payload_std == 0: self.payload_std = 1.0
            
        ports = [e.dst_port for e in events if e.layer == "network" and e.dst_port is not None]
        total_ports = len(ports)
        if total_ports > 0:
            for p in set(ports):
                self.port_freqs[p] = ports.count(p) / total_ports

    def _extract_network_features(self, event: UnifiedEvent) -> List[float]:
        hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
        protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
        
        payload_z_score = 0.0
        if event.bytes_sent is not None:
             payload_z_score = (event.bytes_sent - self.payload_mean) / self.payload_std
             
        port_freq = self.port_freqs.get(event.dst_port, 0.0)
        
        return [
            payload_z_score,
            port_freq,
            math.log1p(event.duration_ms or 0),
            event.port_risk_score or 0.0,
            event.connections_per_minute or 0.0,
            math.sin(2 * math.pi * hour / 24.0),
            math.cos(2 * math.pi * hour / 24.0),
            0.0 if event.src_internal else 1.0,
            0.0 if event.dst_internal else 1.0,
            float(protocol_map.get(event.protocol, 3))
        ]

    def _extract_endpoint_features(self, event: UnifiedEvent) -> List[float]:
        hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
        action_map = {"exec": 1.0, "read": 0.3, "write": 0.5, "delete": 0.8, "connect": 0.6}
        
        return [
            math.sin(2 * math.pi * hour / 24.0),
            math.cos(2 * math.pi * hour / 24.0),
            float(len(event.process_name)) if event.process_name else 0.0,
            math.log1p(event.pid or 0),
            action_map.get(event.action, 0.0),
            0.0 if event.src_internal else 1.0
        ]

    def fit(self, events: List[UnifiedEvent]) -> None:
        self._compute_stats(events)
        network_events = [e for e in events if e.layer == "network"]
        endpoint_events = [e for e in events if e.layer == "endpoint"]
        
        if network_events:
            X_net = np.array([self._extract_network_features(e) for e in network_events])
            self.network_model.fit(X_net)
            
        if endpoint_events:
            X_end = np.array([self._extract_endpoint_features(e) for e in endpoint_events])
            self.endpoint_model.fit(X_end)

    def predict(self, event: UnifiedEvent) -> float:
        if event.layer == "network":
            features = self._extract_network_features(event)
            model = self.network_model
        elif event.layer == "endpoint":
            features = self._extract_endpoint_features(event)
            model = self.endpoint_model
        else:
            return 0.0
            
        # sklearn score_samples returns negative values where lower is more anomalous
        score = model.score_samples(np.array([features]))[0]
        
        # Convert: anomaly_score = 1 - (score + 0.5)
        anomaly_score = 1.0 - (score + 0.5)
        
        return float(max(0.0, min(1.0, anomaly_score)))

    def save(self) -> None:
        Path(IF_NETWORK_PATH).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.network_model, IF_NETWORK_PATH)
        joblib.dump(self.endpoint_model, IF_ENDPOINT_PATH)

    def load(self) -> None:
        if os.path.exists(IF_NETWORK_PATH):
            self.network_model = joblib.load(IF_NETWORK_PATH)
        if os.path.exists(IF_ENDPOINT_PATH):
            self.endpoint_model = joblib.load(IF_ENDPOINT_PATH)
