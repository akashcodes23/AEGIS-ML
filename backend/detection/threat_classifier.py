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
    """Prediction output from ThreatClassifier, exposing calibrated confidence and diagnostics."""
    threat_type: str
    confidence: float
    severity: Optional[str]
    feature_importances: Dict[str, float]
    raw_probabilities: Dict[str, float]
    calibrated_probabilities: Optional[Dict[str, float]] = None
    is_calibrated: bool = False
    calibration_method: Optional[str] = None
    model_version: Optional[str] = None
    confidence_qualification: Optional[str] = None


class ThreatClassifier:
    """
    Random Forest multi-class threat classifier for AEGIS-ML with probability calibration support.
    
    Predicts MITRE-aligned canonical threat categories from normalized behavioral and telemetry
    feature vectors (supporting 15, 36, or 48 feature representations).
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

    def __init__(
        self,
        random_state: int = 42,
        feature_names: Optional[List[str]] = None,
        model_version: str = "23.0.0",
    ):
        self.random_state = random_state
        self.feature_names = list(feature_names) if feature_names is not None else list(self.FEATURE_NAMES)
        self.n_features = len(self.feature_names)
        self.model = RandomForestClassifier(
            n_estimators=300,
            max_depth=15,
            random_state=self.random_state,
            class_weight="balanced"
        )
        self.calibrator = None
        self.is_calibrated = False
        self.calibration_method: Optional[str] = None
        self.model_version = model_version
        self.schema_version = "1.0.0"
        self.classes: List[str] = list(self.CLASSES)
        self.is_fitted = False
        self.metadata: Dict[str, Any] = {}

    def validate_features(self, features: Any) -> np.ndarray:
        """
        Validate feature vector length, type, and check for NaN/Inf.
        """
        arr = np.asarray(features, dtype=np.float64).flatten()
        if len(arr) != self.n_features:
            if len(arr) == 15 and self.n_features == 48:
                padded = np.zeros(48, dtype=np.float64)
                padded[:15] = arr
                arr = padded
            else:
                raise ValueError(
                    f"Feature vector length mismatch: expected {self.n_features} features, "
                    f"got {len(arr)} (features: {self.feature_names})"
                )
        if not np.all(np.isfinite(arr)):
            logger.warning("Non-finite values (NaN/Inf) encountered in feature vector; replacing with finite values")
            arr = np.nan_to_num(arr, nan=0.0, posinf=1e5, neginf=-1e5)
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
        self.classes = list(self.model.classes_)
        self.metadata = {
            "feature_names": self.feature_names,
            "classes": self.classes,
            "sklearn_version": sklearn.__version__,
            "n_samples": len(X),
            "n_features": self.n_features,
            "model_version": self.model_version,
            "is_calibrated": False,
        }

    def fit_calibrator(self, X_val: np.ndarray, y_val: np.ndarray, method: str = "isotonic") -> None:
        """
        Fit a probability calibrator on validation data using FrozenEstimator.
        Guarantees that base model weights are not modified and test data is not seen.
        """
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.frozen import FrozenEstimator

        if not self.is_fitted:
            raise NotFittedError("Base model must be fitted before fitting calibrator.")

        cal = CalibratedClassifierCV(estimator=FrozenEstimator(self.model), method=method)
        cal.fit(X_val, y_val)
        self.calibrator = cal
        self.is_calibrated = True
        self.calibration_method = method
        self.metadata["is_calibrated"] = True
        self.metadata["calibration_method"] = method

    def predict(self, features: List[float]) -> ThreatPrediction:
        """
        Predict threat category and derive confidence & severity.
        
        When calibrated:
        Returns calibrated posterior probabilities (with sum-to-one validation) and
        sets confidence to the calibrated posterior probability.
        
        When uncalibrated:
        Returns raw ensemble tree-vote agreement fractions.
        """
        if not self.is_fitted:
            raise NotFittedError(
                "ThreatClassifier is not fitted or loaded. Predictions cannot be served. "
                "Call load() with an existing model artifact or run the training pipeline first."
            )

        features_arr = self.validate_features(features)
        X = features_arr.reshape(1, -1)

        # 1. Raw ensemble tree-vote probabilities
        raw_probas_arr = self.model.predict_proba(X)[0]
        if not np.all(np.isfinite(raw_probas_arr)):
            raise ValueError("Base model produced non-finite raw probabilities.")
        raw_classes = list(self.model.classes_)
        raw_probs = {
            str(cls): float(raw_probas_arr[raw_classes.index(cls)])
            for cls in self.classes
            if cls in raw_classes
        }

        # 2. Calibrated probabilities (if calibrated)
        cal_probs: Optional[Dict[str, float]] = None
        if self.is_calibrated and self.calibrator is not None:
            cal_probas_arr = self.calibrator.predict_proba(X)[0]
            if not np.all(np.isfinite(cal_probas_arr)):
                raise ValueError("Calibrator produced non-finite probabilities.")
            if not np.all((cal_probas_arr >= 0.0) & (cal_probas_arr <= 1.0)):
                raise ValueError("Calibrator produced probabilities out of [0, 1] range.")
            if abs(float(np.sum(cal_probas_arr)) - 1.0) > 1e-4:
                raise ValueError(f"Calibrator probabilities do not sum to 1.0 (sum={np.sum(cal_probas_arr)}).")

            cal_classes = list(self.calibrator.classes_)
            cal_probs = {
                str(cls): float(cal_probas_arr[cal_classes.index(cls)])
                for cls in self.classes
                if cls in cal_classes
            }
            active_probs = cal_probs
            confidence_qualification = (
                "Calibrated probability evaluated on synthetic scenario benchmark; "
                "real-world empirical risk not guaranteed."
            )
        else:
            active_probs = raw_probs
            confidence_qualification = (
                "Uncalibrated tree-vote consensus fraction; does not represent calibrated probability."
            )

        # 3. Decision: argmax over active probabilities
        best_cls = max(active_probs.keys(), key=lambda c: active_probs[c])
        confidence = float(active_probs[best_cls])
        severity = self.determine_severity(best_cls, confidence)

        # 4. Feature importances
        importances = {}
        if hasattr(self.model, "feature_importances_"):
            importances = {
                self.feature_names[i]: float(val)
                for i, val in enumerate(self.model.feature_importances_)
                if i < len(self.feature_names)
            }

        return ThreatPrediction(
            threat_type=best_cls,
            confidence=confidence,
            severity=severity,
            feature_importances=importances,
            raw_probabilities=raw_probs,
            calibrated_probabilities=cal_probs,
            is_calibrated=self.is_calibrated,
            calibration_method=self.calibration_method,
            model_version=self.model_version,
            confidence_qualification=confidence_qualification,
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

        # Modulate severity if model consensus/confidence is exceptionally high or marginal
        if confidence >= 0.95 and base == "medium":
            return "high"
        if confidence < 0.40 and base == "critical":
            return "high"

        return base

    def save(self, path: Optional[str] = None) -> str:
        """Serialize model artifact with full metadata and versioning."""
        if not self.is_fitted:
            raise NotFittedError("Cannot save unfitted ThreatClassifier.")
        target_path = path or RF_CLASSIFIER_PATH
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "schema_version": self.schema_version,
            "model_version": self.model_version,
            "is_fitted": self.is_fitted,
            "is_calibrated": self.is_calibrated,
            "calibration_method": self.calibration_method,
            "model": self.model,
            "calibrator": self.calibrator,
            "feature_names": self.feature_names,
            "classes": list(self.classes),
            "n_features": self.n_features,
            "sklearn_version": sklearn.__version__,
            "metadata": self.metadata,
        }
        joblib.dump(artifact, target_path)
        logger.info(f"ThreatClassifier saved to {target_path} (calibrated={self.is_calibrated})")
        return str(target_path)

    def load(self, path: Optional[str] = None) -> bool:
        """Load model artifact, validating feature/class compatibility and calibration."""
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
                self.model_version = data.get("model_version", "legacy")
                self.schema_version = data.get("schema_version", "1.0.0")

                # Calibration inspection
                calibrator = data.get("calibrator")
                is_calibrated = bool(data.get("is_calibrated", False))
                if is_calibrated and calibrator is not None and hasattr(calibrator, "predict_proba"):
                    self.calibrator = calibrator
                    self.is_calibrated = True
                    self.calibration_method = data.get("calibration_method", "isotonic")
                else:
                    self.calibrator = None
                    self.is_calibrated = False
                    self.calibration_method = None

                saved_features = data.get("feature_names") or self.metadata.get("feature_names")
                if saved_features:
                    self.feature_names = list(saved_features)
                    self.n_features = len(self.feature_names)

                saved_classes = data.get("classes") or list(self.model.classes_)
                self.classes = list(saved_classes)
            else:
                # Raw model fallback
                self.model = data
                self.is_fitted = hasattr(self.model, "classes_")
                self.calibrator = None
                self.is_calibrated = False
                self.calibration_method = None
                if hasattr(self.model, "classes_"):
                    self.classes = list(self.model.classes_)

            return self.is_fitted
        except Exception as e:
            logger.error(f"Failed to load ThreatClassifier from {target_path}: {e}")
            self.is_fitted = False
            return False
