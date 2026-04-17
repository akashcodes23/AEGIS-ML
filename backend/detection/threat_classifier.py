import numpy as np
import joblib
import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import StratifiedKFold, cross_val_score
import warnings
from pathlib import Path

from backend.core.config import RF_CLASSIFIER_PATH

@dataclass
class ThreatPrediction:
    threat_type: str
    confidence: float
    severity: Optional[str]
    feature_importances: Dict[str, float]

class ThreatClassifier:
    CLASSES = ["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"]
    
    FEATURE_NAMES = [
        "if_anomaly_score",
        "baseline_deviation",
        "graph_new_connections",
        "failed_auth_rate",
        "connection_frequency",
        "bytes_sent_zscore",
        "dst_port_risk",
        "is_new_destination",
        "is_external_dst",
        "hour_of_day_sin",
        "hour_of_day_cos",
        "cross_layer_match"
    ]

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=300, 
            max_depth=15, 
            random_state=42, 
            class_weight="balanced"
        )
        self.is_fitted = False

    def fit(self, X: np.array, y: np.array) -> None:
        unique_classes, counts = np.unique(y, return_counts=True)
        min_samples = np.min(counts)
        
        # Apply SMOTE if we have imbalanced classes with enough samples
        if len(unique_classes) > 1 and min_samples > 1:
            k_neighbors = min(5, min_samples - 1)
            if k_neighbors > 0:
                smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
                try:
                    X, y = smote.fit_resample(X, y)
                    print(f"Applied SMOTE. New class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
                except Exception as e:
                    print(f"SMOTE skipped: {e}")
            
            # Cross validation
            n_splits = min(5, min_samples)
            if n_splits > 1:
                cv = StratifiedKFold(n_splits=n_splits)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    scores = cross_val_score(self.model, X, y, cv=cv, scoring='f1_weighted')
                print(f"Cross-Validation F1 Scores: {scores}")
                print(f"Mean CV F1: {np.mean(scores):.2f}")

        self.model.fit(X, y)
        self.is_fitted = True
        
        # Print classification report on training data
        y_pred = self.model.predict(X)
        print("Threat Classifier Training Report:")
        print(classification_report(y, y_pred, labels=self.CLASSES))

    def predict(self, features: List[float]) -> ThreatPrediction:
        if not self.is_fitted:
            # Fallback if not fitted, predict benign
            return ThreatPrediction(
                threat_type="benign",
                confidence=1.0,
                severity=None,
                feature_importances={}
            )
            
        X = np.array([features])
        
        # Predict probabilities
        probas = self.model.predict_proba(X)[0]
        
        # Get max class probability and index
        max_idx = np.argmax(probas)
        confidence = float(probas[max_idx])
        
        # The classes_ attribute contains the unique classes the model saw during fit
        predicted_class = self.model.classes_[max_idx]
        
        severity = self.severity_from_confidence(confidence) if predicted_class != "benign" else None
        
        importances = {}
        if hasattr(self.model, "feature_importances_"):
            importances = {
                self.FEATURE_NAMES[i]: float(val) 
                for i, val in enumerate(self.model.feature_importances_)
            }
            
        return ThreatPrediction(
            threat_type=predicted_class,
            confidence=confidence,
            severity=severity,
            feature_importances=importances
        )

    def severity_from_confidence(self, conf: float) -> Optional[str]:
        if conf >= 0.90: return "critical"
        if conf >= 0.75: return "high"
        if conf >= 0.50: return "medium"
        if conf >= 0.40: return "low"
        return None

    def save(self) -> None:
        if self.is_fitted:
            Path(RF_CLASSIFIER_PATH).parent.mkdir(parents=True, exist_ok=True)
            # Save a tuple containing whether it is fitted and the model
            joblib.dump({"is_fitted": self.is_fitted, "model": self.model}, RF_CLASSIFIER_PATH)

    def load(self) -> None:
        if os.path.exists(RF_CLASSIFIER_PATH):
            data = joblib.load(RF_CLASSIFIER_PATH)
            if isinstance(data, dict) and "is_fitted" in data and "model" in data:
                 self.is_fitted = data["is_fitted"]
                 self.model = data["model"]
            else:
                 # Backward compatibility if only model was saved
                 self.model = data
                 self.is_fitted = True
