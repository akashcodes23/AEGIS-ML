import math
import numpy as np
import joblib
import logging
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
import os
from pathlib import Path

try:
    from core.schemas import UnifiedEvent
    from core.config import IF_NETWORK_PATH, IF_ENDPOINT_PATH, ANOMALY_THRESHOLD
except ModuleNotFoundError:
    from backend.core.schemas import UnifiedEvent
    from backend.core.config import IF_NETWORK_PATH, IF_ENDPOINT_PATH, ANOMALY_THRESHOLD

logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """
    Multi-layer Isolation Forest Anomaly Detector.
    
    Fits separate isolation models for network-layer flow telemetry and endpoint-layer
    process executions.
    """

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.network_model = IsolationForest(
            n_estimators=200, contamination=self.contamination, random_state=self.random_state
        )
        self.endpoint_model = IsolationForest(
            n_estimators=200, contamination=self.contamination, random_state=self.random_state
        )
        self.payload_mean = 0.0
        self.payload_std = 1.0
        self.port_freqs: Dict[int, float] = {}
        self.is_network_fitted = False
        self.is_endpoint_fitted = False

    def _compute_stats(self, events: List[UnifiedEvent]):
        """Compute empirical feature normalization statistics from training events."""
        payloads = [
            e.bytes_sent for e in events
            if e.layer == "network" and e.bytes_sent is not None and not math.isnan(e.bytes_sent)
        ]
        if payloads:
            self.payload_mean = float(np.mean(payloads))
            self.payload_std = float(np.std(payloads))
            if self.payload_std == 0.0 or math.isnan(self.payload_std):
                self.payload_std = 1.0

        ports = [
            e.dst_port for e in events
            if e.layer == "network" and e.dst_port is not None and not math.isnan(e.dst_port)
        ]
        total_ports = len(ports)
        if total_ports > 0:
            port_counts: Dict[int, int] = {}
            for p in ports:
                port_counts[p] = port_counts.get(p, 0) + 1
            self.port_freqs = {p: count / total_ports for p, count in port_counts.items()}

    def _extract_network_features(self, event: UnifiedEvent) -> List[float]:
        hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
        protocol_map = {"TCP": 0.0, "UDP": 1.0, "ICMP": 2.0}

        payload_z_score = 0.0
        if event.bytes_sent is not None and not math.isnan(event.bytes_sent):
            payload_z_score = (event.bytes_sent - self.payload_mean) / self.payload_std
            payload_z_score = float(np.clip(payload_z_score, -10.0, 10.0))

        port_freq = self.port_freqs.get(event.dst_port, 0.0) if event.dst_port else 0.0
        dur_ms = max(0.0, float(event.duration_ms or 0.0))
        port_risk = float(event.port_risk_score or 0.0)
        conn_cpm = float(event.connections_per_minute or 0.0)

        proto_str = str(event.protocol).upper() if event.protocol else "TCP"
        proto_val = protocol_map.get(proto_str, 3.0)

        return [
            payload_z_score,
            float(port_freq),
            math.log1p(dur_ms),
            port_risk,
            conn_cpm,
            math.sin(2 * math.pi * hour / 24.0),
            math.cos(2 * math.pi * hour / 24.0),
            0.0 if event.src_internal else 1.0,
            0.0 if event.dst_internal else 1.0,
            proto_val,
        ]

    def _extract_endpoint_features(self, event: UnifiedEvent) -> List[float]:
        hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
        action_map = {"exec": 1.0, "read": 0.3, "write": 0.5, "delete": 0.8, "connect": 0.6}

        proc_len = float(len(event.process_name)) if event.process_name else 0.0
        pid_val = max(0.0, float(event.pid or 0.0))
        act_val = action_map.get(str(event.action).lower(), 0.0) if event.action else 0.0

        return [
            math.sin(2 * math.pi * hour / 24.0),
            math.cos(2 * math.pi * hour / 24.0),
            proc_len,
            math.log1p(pid_val),
            act_val,
            0.0 if event.src_internal else 1.0,
        ]

    def fit(self, events: List[UnifiedEvent]) -> None:
        """Fit Isolation Forest detectors and extract empirical scaling statistics."""
        self._compute_stats(events)
        network_events = [e for e in events if e.layer == "network"]
        endpoint_events = [e for e in events if e.layer == "endpoint"]

        if network_events:
            X_net = np.array([self._extract_network_features(e) for e in network_events], dtype=np.float64)
            X_net = np.nan_to_num(X_net, nan=0.0, posinf=1e6, neginf=-1e6)
            self.network_model.fit(X_net)
            self.is_network_fitted = True

        if endpoint_events:
            X_end = np.array([self._extract_endpoint_features(e) for e in endpoint_events], dtype=np.float64)
            X_end = np.nan_to_num(X_end, nan=0.0, posinf=1e6, neginf=-1e6)
            self.endpoint_model.fit(X_end)
            self.is_endpoint_fitted = True

    def predict(self, event: UnifiedEvent) -> float:
        """
        Compute continuous normalized anomaly score in [0.0, 1.0].
        
        Score definition:
        - 0.0 = completely typical / normal inlier
        - 0.5 = at the contamination decision boundary
        - > 0.65 = anomalous outlier exceeding default threshold
        - 1.0 = extreme anomaly
        """
        if event.layer == "network":
            if not self.is_network_fitted:
                return 0.0
            features = self._extract_network_features(event)
            model = self.network_model
        elif event.layer == "endpoint":
            if not self.is_endpoint_fitted:
                return 0.0
            features = self._extract_endpoint_features(event)
            model = self.endpoint_model
        else:
            return 0.0

        features_arr = np.nan_to_num(np.array([features], dtype=np.float64), nan=0.0)

        try:
            # scikit-learn decision_function: < 0 is outlier, > 0 is inlier
            dec = float(model.decision_function(features_arr)[0])
            # Map continuously to [0, 1] where higher = more anomalous
            anomaly_score = float(np.clip(0.5 - 2.0 * dec, 0.0, 1.0))
            return anomaly_score
        except (NotFittedError, AttributeError):
            return 0.0

    def save(self, net_path: Optional[str] = None, end_path: Optional[str] = None) -> None:
        """Serialize models along with feature scaling statistics."""
        np_path = net_path or IF_NETWORK_PATH
        ep_path = end_path or IF_ENDPOINT_PATH

        Path(np_path).parent.mkdir(parents=True, exist_ok=True)
        net_bundle = {
            "model": self.network_model,
            "payload_mean": self.payload_mean,
            "payload_std": self.payload_std,
            "port_freqs": self.port_freqs,
            "is_fitted": self.is_network_fitted,
        }
        joblib.dump(net_bundle, np_path)

        end_bundle = {
            "model": self.endpoint_model,
            "is_fitted": self.is_endpoint_fitted,
        }
        joblib.dump(end_bundle, ep_path)
        logger.info(f"IsolationForest models saved to {np_path} and {ep_path}")

    def load(self, net_path: Optional[str] = None, end_path: Optional[str] = None) -> bool:
        """Load models and restore feature statistics, supporting both bundles and legacy files."""
        np_path = net_path or IF_NETWORK_PATH
        ep_path = end_path or IF_ENDPOINT_PATH

        success = False
        if os.path.exists(np_path):
            try:
                data = joblib.load(np_path)
                if isinstance(data, dict) and "model" in data:
                    self.network_model = data["model"]
                    self.payload_mean = float(data.get("payload_mean", 0.0))
                    self.payload_std = float(data.get("payload_std", 1.0))
                    self.port_freqs = data.get("port_freqs", {})
                    self.is_network_fitted = bool(data.get("is_fitted", True))
                else:
                    self.network_model = data
                    self.is_network_fitted = hasattr(self.network_model, "estimators_")
                success = True
            except Exception as e:
                logger.error(f"Failed to load network IF model from {np_path}: {e}")

        if os.path.exists(ep_path):
            try:
                data = joblib.load(ep_path)
                if isinstance(data, dict) and "model" in data:
                    self.endpoint_model = data["model"]
                    self.is_endpoint_fitted = bool(data.get("is_fitted", True))
                else:
                    self.endpoint_model = data
                    self.is_endpoint_fitted = hasattr(self.endpoint_model, "estimators_")
            except Exception as e:
                logger.error(f"Failed to load endpoint IF model from {ep_path}: {e}")

        return success
