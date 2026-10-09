import numpy as np
import joblib
import os
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import NotFittedError
from sklearn.metrics import classification_report
import sklearn

try:
    from core.config import RF_CLASSIFIER_PATH
except ModuleNotFoundError:
    from backend.core.config import RF_CLASSIFIER_PATH

logger = logging.getLogger(__name__)


@dataclass
class ThreatPrediction:
    threat_type: str
    confidence: float
    severity: Optional[str]
    feature_importances: Dict[str, float]
    raw_probabilities: Dict[str, float]


class ThreatClassifier:
    """
    Random Forest multi-class threat classifier for AEGIS-ML.
    
    Predicts MITRE-aligned canonical threat categories from normalized 15-dimensional
    behavioral and telemetry feature vectors.
    """
    CLASSES = ["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"]
    N_FEATURES = 15

    FEATURE_NAMES = [
        "if_anomaly_score", "baseline_deviation", "graph_new_connections",
        "failed_auth_rate", "connection_frequency", "bytes_sent_zscore",
        "bytes_sent_log", "bytes_ratio", "conn_rate_zscore",
        "dst_port_risk", "is_new_destination", "is_external_dst",
        "hour_of_day_sin", "hour_of_day_cos", "cross_layer_match"
    ]

    # Explicit threat severity baseline policy separated from model vote confidence
    BASE_SEVERITY = {
        "benign": None,
        "brute_force": "medium",
        "lateral_movement": "high",
        "c2_beaconing": "high",
        "data_exfiltration": "critical",
    }

    def __init__(self, random_state: int = 42, feature_names: Optional[List[str]] = None):
        self.random_state = random_state
        self.feature_names = list(feature_names) if feature_names is not None else list(self.FEATURE_NAMES)
        self.n_features = len(self.feature_names)
        self.model = RandomForestClassifier(
            n_estimators=300,
            max_depth=15,
            random_state=self.random_state,
            class_weight="balanced"
        )
        self.is_fitted = False
        self.metadata: Dict[str, Any] = {}

    def validate_features(self, features: Any) -> np.ndarray:
        """
        Validate feature vector length, type, and check for NaN/Inf.
        """
        arr = np.asarray(features, dtype=np.float64).flatten()
        if len(arr) != self.n_features:
            raise ValueError(
                f"Feature vector length mismatch: expected {self.n_features} features, "
                f"got {len(arr)} (features: {self.feature_names})"
            )
        if np.isnan(arr).any():
            # Cleanly replace NaN with 0.0 to prevent unhandled crashes, but warn
            logger.warning("NaN encountered in feature vector; replacing with 0.0")
            arr = np.nan_to_num(arr, nan=0.0)
        if np.isinf(arr).any():
            logger.warning("Inf encountered in feature vector; clipping to valid range")
            arr = np.nan_to_num(arr, posinf=1e6, neginf=-1e6)
        return arr

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Fit the Random Forest classifier on preprocessed features.
        Note: Any resampling (e.g. SMOTE) or split must be performed prior
        to calling fit or within cross-validation folds to prevent data leakage.
        """
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y)

        if len(X) == 0:
            raise ValueError("Cannot fit model on empty feature matrix.")
        if X.shape[1] != self.n_features:
            raise ValueError(f"Feature matrix columns ({X.shape[1]}) != expected ({self.n_features})")

        self.model.fit(X, y)
        self.is_fitted = True
        self.metadata = {
            "feature_names": self.feature_names,
            "classes": list(self.model.classes_),
            "sklearn_version": sklearn.__version__,
            "n_samples": len(X),
            "n_features": self.n_features
        }

    def predict(self, features: List[float]) -> ThreatPrediction:
        """
        Predict threat category and derive confidence & severity.
        
        NOTE ON CONFIDENCE:
        The probability returned by RandomForestClassifier represents the fraction of trees
        voting for the predicted class. It is NOT a calibrated Bayesian posterior real-world
        probability. Threat severity is determined by an explicit policy based on attack impact.
        """
        if not self.is_fitted:
            raise NotFittedError(
                "ThreatClassifier is not fitted or loaded. Predictions cannot be served. "
                "Call load() with an existing model artifact or run the training pipeline first."
            )

        features_arr = self.validate_features(features)
        X = features_arr.reshape(1, -1)
        probas = self.model.predict_proba(X)[0]
        max_idx = int(np.argmax(probas))
        confidence = float(probas[max_idx])
        predicted_class = str(self.model.classes_[max_idx])

        # Map probabilities for all classes
        raw_probs = {
            str(cls): float(probas[idx])
            for idx, cls in enumerate(self.model.classes_)
        }

        severity = self.determine_severity(predicted_class, confidence)

        importances = {}
        if hasattr(self.model, "feature_importances_"):
            importances = {
                self.feature_names[i]: float(val)
                for i, val in enumerate(self.model.feature_importances_)
                if i < len(self.feature_names)
            }

        return ThreatPrediction(
            threat_type=predicted_class,
            confidence=confidence,
            severity=severity,
            feature_importances=importances,
            raw_probabilities=raw_probs
        )

    def determine_severity(self, threat_type: str, confidence: float) -> Optional[str]:
        """
        Decoupled threat severity policy.
        Threat severity is based on the impact of the attack type in enterprise networks,
        rather than relying solely on model ensemble agreement percentage.
        """
        if threat_type == "benign":
            return None

        base = self.BASE_SEVERITY.get(threat_type, "medium")

        # Modulate severity if model tree consensus is exceptionally high or marginal
        if confidence >= 0.95 and base == "medium":
            return "high"
        if confidence < 0.40 and base == "critical":
            return "high"

        return base

    def save(self, path: Optional[str] = None) -> str:
        """Serialize model artifact with full metadata."""
        if not self.is_fitted:
            raise NotFittedError("Cannot save unfitted ThreatClassifier.")
        target_path = path or RF_CLASSIFIER_PATH
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "is_fitted": self.is_fitted,
            "model": self.model,
            "feature_names": self.FEATURE_NAMES,
            "classes": list(self.model.classes_),
            "sklearn_version": sklearn.__version__,
            "metadata": self.metadata
        }
        joblib.dump(artifact, target_path)
        logger.info(f"ThreatClassifier saved to {target_path}")
        return str(target_path)

    def load(self, path: Optional[str] = None) -> bool:
        """Load model artifact and validate feature/class compatibility."""
        target_path = path or RF_CLASSIFIER_PATH
        if not os.path.exists(target_path):
            logger.warning(f"ThreatClassifier artifact not found at {target_path}")
            self.is_fitted = False
            return False

        try:
            data = joblib.load(target_path)
            if isinstance(data, dict) and "model" in data:
                self.model = data["model"]
                self.is_fitted = bool(data.get("is_fitted", True))
                self.metadata = data.get("metadata", {})
                saved_features = data.get("feature_names") or self.metadata.get("feature_names")
                if saved_features:
                    self.feature_names = list(saved_features)
                    self.n_features = len(self.feature_names)
                if saved_features and saved_features != self.FEATURE_NAMES:
                    logger.warning(
                        f"Feature names in loaded model ({saved_features}) differ from "
                        f"current default ({self.FEATURE_NAMES})"
                    )
            else:
                self.model = data
                self.is_fitted = hasattr(self.model, "classes_")
            return self.is_fitted
        except Exception as e:
            logger.error(f"Failed to load ThreatClassifier from {target_path}: {e}")
            self.is_fitted = False
            return False
