"""AEGIS-ML Phase 23: Model Artifact Lifecycle and Version Management.

Module: backend.detection.model_lifecycle

Provides a robust, reproducible model artifact lifecycle for AEGIS-ML:
1. Versioned artifact packaging with cryptographic SHA-256 checksums.
2. Artifact validation (schema, feature alignment, class ordering, probability constraints).
3. Safe loading with retention of previous known-good model on failure.
4. Export and registration of calibrated model artifacts.
5. Inspection endpoints for active model metadata and qualification disclaimers.

Design Principles:
- Strictly trusted model paths: only loads from within the designated models directory.
- No arbitrary remote paths or untrusted deserialization.
- Explicit fail-safe error handling: never misrepresents uncalibrated predictions as calibrated.
- Mathematical integrity: validates probability bounds, class alignment, and feature schemas.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import sklearn

from backend.core.config import PROJECT_ROOT, resolve_model_path
from backend.detection.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)

# Canonical artifact paths
CALIBRATED_CLASSIFIER_PATH = resolve_model_path("calibrated_threat_classifier.pkl")
LEGACY_CLASSIFIER_PATH = resolve_model_path("threat_classifier.pkl")
DEFAULT_MODEL_VERSION = "23.0.0"
CURRENT_ARTIFACT_SCHEMA_VERSION = "1.0.0"

SCIENTIFIC_DISCLAIMER = (
    "Model confidence calibrated via isotonic regression on scenario-grouped synthetic benchmarks. "
    "Real-world generalization on organic enterprise network telemetry has not been independently established."
)


@dataclass
class ModelArtifactMetadata:
    """Metadata describing a versioned model artifact."""
    schema_version: str
    model_version: str
    artifact_filename: str
    artifact_sha256: str
    is_calibrated: bool
    calibration_method: Optional[str]
    model_algorithm: str
    classes: List[str]
    feature_names: List[str]
    n_features: int
    sklearn_version: str
    created_at: str
    dataset_sha256: Optional[str] = None
    dataset_records: Optional[int] = None
    split_seed: Optional[int] = None
    training_samples: Optional[int] = None
    validation_samples: Optional[int] = None
    evaluation_reference: Optional[str] = None
    scientific_disclaimer: str = SCIENTIFIC_DISCLAIMER


def compute_file_sha256(path: Union[str, Path]) -> str:
    """Compute SHA-256 hex digest of a file on disk."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class ModelLifecycleManager:
    """
    Manages the lifecycle, validation, activation, and metadata inspection
    of ML detection artifacts in AEGIS-ML.
    """

    def __init__(self, models_dir: Optional[Union[str, Path]] = None):
        self.models_dir = Path(models_dir or (PROJECT_ROOT / "data" / "models")).resolve()
        self.active_classifier: Optional[ThreatClassifier] = None
        self.active_metadata: Optional[ModelArtifactMetadata] = None
        self.previous_classifier: Optional[ThreatClassifier] = None
        self.previous_metadata: Optional[ModelArtifactMetadata] = None

    def _is_safe_path(self, target_path: Union[str, Path]) -> bool:
        """Ensure path is within the designated models directory to prevent traversal attacks."""
        resolved = Path(target_path).resolve()
        try:
            resolved.relative_to(self.models_dir)
            return True
        except ValueError:
            return False

    def validate_artifact_file(
        self,
        artifact_path: Union[str, Path],
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Rigorously validate an artifact file before activation.
        
        Checks:
        1. File exists and is within trusted models directory.
        2. Successfully deserializes without errors.
        3. Schema keys are present (`model`, `classes`, `feature_names`).
        4. Model is fitted and has `predict_proba`.
        5. Classes match canonical MITRE-aligned classes.
        6. If calibrated: calibrator is present, fitted, and classes align with model classes.
        7. Runs a test inference on a dummy feature vector to confirm numerical stability.
        """
        p = Path(artifact_path).resolve()
        if not p.exists():
            return False, f"Artifact file does not exist: {p.name}", None

        if not self._is_safe_path(p):
            return False, f"Untrusted path rejected: {p} is outside {self.models_dir}", None

        try:
            data = joblib.load(p)
        except Exception as exc:
            return False, f"Failed to deserialize artifact: {exc}", None

        if not isinstance(data, dict):
            # Legacy raw model object
            if hasattr(data, "classes_") and hasattr(data, "predict_proba"):
                return True, "Valid legacy model object (uncalibrated)", {
                    "is_calibrated": False,
                    "classes": list(data.classes_),
                    "n_features": getattr(data, "n_features_in_", 15),
                }
            return False, "Artifact is neither a dict nor a valid scikit-learn estimator", None

        # 1. Check required keys
        if "model" not in data:
            return False, "Missing 'model' key in artifact dictionary", None

        base_model = data["model"]
        if not hasattr(base_model, "predict_proba") or not hasattr(base_model, "classes_"):
            return False, "Base model is not a fitted scikit-learn classifier with predict_proba", None

        # 2. Check classes
        classes = data.get("classes") or list(base_model.classes_)
        canonical_classes = ThreatClassifier.CLASSES
        if set(classes) != set(canonical_classes):
            return False, f"Classes {classes} do not match canonical classes {canonical_classes}", None

        # 3. Check features
        feature_names = data.get("feature_names")
        if not feature_names or not isinstance(feature_names, list):
            return False, "Missing or invalid 'feature_names' in artifact", None

        n_features = len(feature_names)
        if hasattr(base_model, "n_features_in_") and base_model.n_features_in_ != n_features:
            return False, (
                f"Feature count mismatch: model expects {base_model.n_features_in_}, "
                f"metadata lists {n_features}"
            ), None

        # 4. Check calibrator if calibrated
        is_calibrated = bool(data.get("is_calibrated", False))
        calibrator = data.get("calibrator")
        if is_calibrated:
            if calibrator is None or not hasattr(calibrator, "predict_proba"):
                return False, "Artifact declares is_calibrated=True but missing valid calibrator", None
            if hasattr(calibrator, "classes_") and set(calibrator.classes_) != set(classes):
                return False, (
                    f"Calibrator classes {list(calibrator.classes_)} do not align with model classes {classes}"
                ), None

        # 5. Numerical dry-run test
        try:
            dummy_x = np.zeros((1, n_features), dtype=np.float64)
            raw_p = base_model.predict_proba(dummy_x)[0]
            if not np.all(np.isfinite(raw_p)):
                return False, "Base model produced non-finite probabilities on zero input", None

            if is_calibrated:
                cal_p = calibrator.predict_proba(dummy_x)[0]
                if not np.all(np.isfinite(cal_p)):
                    return False, "Calibrator produced non-finite probabilities on zero input", None
                if not np.all((cal_p >= 0.0) & (cal_p <= 1.0)):
                    return False, "Calibrator probabilities out of [0, 1] bounds", None
                if abs(float(np.sum(cal_p)) - 1.0) > 1e-4:
                    return False, f"Calibrator probabilities do not sum to 1.0: sum={np.sum(cal_p)}", None
        except Exception as exc:
            return False, f"Numerical dry-run prediction failed: {exc}", None

        meta_summary = {
            "schema_version": data.get("schema_version", "legacy"),
            "model_version": data.get("model_version", "legacy"),
            "is_calibrated": is_calibrated,
            "calibration_method": data.get("calibration_method", "isotonic" if is_calibrated else None),
            "classes": classes,
            "feature_names": feature_names,
            "n_features": n_features,
            "sklearn_version": data.get("sklearn_version", "unknown"),
        }
        return True, "Artifact validation passed successfully", meta_summary

    def load_artifact(self, artifact_path: Optional[Union[str, Path]] = None) -> bool:
        """
        Safely load and activate a model artifact.
        
        If loading fails, the previous active classifier is preserved (fail-safe).
        """
        if artifact_path is not None:
            target = Path(artifact_path)
            if not target.exists():
                logger.warning(f"[Lifecycle] Specified artifact does not exist: {target}")
                return False
        else:
            target = Path(CALIBRATED_CLASSIFIER_PATH)
            if not target.exists():
                # Fall back to legacy classifier if calibrated does not exist yet
                target = Path(LEGACY_CLASSIFIER_PATH)
            if not target.exists():
                logger.warning(f"[Lifecycle] Neither calibrated nor legacy artifact found at {target}")
                return False

        is_valid, msg, meta = self.validate_artifact_file(target)
        if not is_valid:
            logger.error(f"[Lifecycle] Artifact validation failed for {target.name}: {msg}")
            return False

        try:
            file_sha = compute_file_sha256(target)
            new_clf = ThreatClassifier()
            loaded_ok = new_clf.load(str(target))
            if not loaded_ok:
                logger.error(f"[Lifecycle] ThreatClassifier.load returned False for {target.name}")
                return False

            # Archive previous classifier
            if self.active_classifier is not None:
                self.previous_classifier = self.active_classifier
                self.previous_metadata = self.active_metadata

            self.active_classifier = new_clf
            self.active_metadata = ModelArtifactMetadata(
                schema_version=meta.get("schema_version", "1.0.0"),
                model_version=meta.get("model_version", DEFAULT_MODEL_VERSION),
                artifact_filename=target.name,
                artifact_sha256=file_sha,
                is_calibrated=new_clf.is_calibrated,
                calibration_method=getattr(new_clf, "calibration_method", None),
                model_algorithm="RandomForestClassifier",
                classes=new_clf.classes,
                feature_names=new_clf.feature_names,
                n_features=new_clf.n_features,
                sklearn_version=sklearn.__version__,
                created_at=datetime.utcnow().isoformat(),
            )
            logger.info(
                f"[Lifecycle] Activated artifact {target.name} (version {self.active_metadata.model_version}, "
                f"calibrated={self.active_metadata.is_calibrated}, sha256={file_sha[:12]}...)"
            )
            return True
        except Exception as exc:
            logger.error(f"[Lifecycle] Failed to activate artifact {target.name}: {exc}")
            # Retain previous if available
            return False

    def get_lifecycle_status(self) -> Dict[str, Any]:
        """Return inspection status of the active model and lifecycle manager."""
        if self.active_classifier is None or not self.active_classifier.is_fitted:
            return {
                "status": "uninitialized",
                "active_model_version": None,
                "is_calibrated": False,
                "message": "No model artifact is currently loaded.",
            }

        meta = self.active_metadata
        return {
            "status": "ready",
            "model_version": meta.model_version if meta else "unknown",
            "schema_version": meta.schema_version if meta else "1.0.0",
            "artifact_filename": meta.artifact_filename if meta else None,
            "artifact_sha256": meta.artifact_sha256 if meta else None,
            "is_calibrated": self.active_classifier.is_calibrated,
            "calibration_method": getattr(self.active_classifier, "calibration_method", None),
            "classes": self.active_classifier.classes,
            "feature_count": self.active_classifier.n_features,
            "feature_names": self.active_classifier.feature_names,
            "sklearn_version": sklearn.__version__,
            "scientific_disclaimer": SCIENTIFIC_DISCLAIMER,
        }

    def export_calibrated_artifact(
        self,
        base_rf_model,
        calibrator_model,
        feature_names: List[str],
        output_path: Optional[Union[str, Path]] = None,
        dataset_sha256: Optional[str] = None,
        dataset_records: Optional[int] = None,
        split_seed: int = 42,
        training_samples: int = 3972,
        validation_samples: int = 754,
        evaluation_reference: str = "Phase 22 Config B (Isotonic Calibration)",
    ) -> Path:
        """
        Package and export a versioned, calibrated model artifact bundle.
        """
        out_path = Path(output_path or CALIBRATED_CLASSIFIER_PATH).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        artifact_dict = {
            "schema_version": CURRENT_ARTIFACT_SCHEMA_VERSION,
            "model_version": DEFAULT_MODEL_VERSION,
            "created_at": datetime.utcnow().isoformat(),
            "is_calibrated": True,
            "calibration_method": "isotonic",
            "model": base_rf_model,
            "calibrator": calibrator_model,
            "classes": list(base_rf_model.classes_),
            "feature_names": list(feature_names),
            "n_features": len(feature_names),
            "sklearn_version": sklearn.__version__,
            "metadata": {
                "dataset_sha256": dataset_sha256,
                "dataset_records": dataset_records,
                "split_seed": split_seed,
                "training_samples": training_samples,
                "validation_samples": validation_samples,
                "evaluation_reference": evaluation_reference,
                "scientific_disclaimer": SCIENTIFIC_DISCLAIMER,
            },
        }

        joblib.dump(artifact_dict, out_path)
        logger.info(f"[Lifecycle] Exported calibrated model artifact to {out_path}")

        # Also write human-readable JSON metadata companion
        json_meta_path = out_path.parent / (out_path.stem + "_metadata.json")
        json_dict = {
            "schema_version": artifact_dict["schema_version"],
            "model_version": artifact_dict["model_version"],
            "created_at": artifact_dict["created_at"],
            "is_calibrated": artifact_dict["is_calibrated"],
            "calibration_method": artifact_dict["calibration_method"],
            "classes": artifact_dict["classes"],
            "feature_names": artifact_dict["feature_names"],
            "n_features": artifact_dict["n_features"],
            "sklearn_version": artifact_dict["sklearn_version"],
            "artifact_sha256": compute_file_sha256(out_path),
            "metadata": artifact_dict["metadata"],
        }
        with open(json_meta_path, "w", encoding="utf-8") as f:
            json.dump(json_dict, f, indent=2)
        logger.info(f"[Lifecycle] Exported artifact metadata JSON to {json_meta_path}")

        return out_path


def train_and_export_default_calibrated_artifact(
    dataset_path: Optional[Union[str, Path]] = None,
    output_path: Optional[Union[str, Path]] = None,
    seed: int = 42,
) -> Path:
    """
    Train and export the canonical Phase 23 calibrated threat classifier.
    Uses behavioral diversity dataset (seed 42, 80 training scenarios, 14 validation scenarios),
    SMOTE on training data only, and Isotonic Calibration on validation data.
    """
    from collections import Counter
    from backend.evaluation.false_positive_calibration import (
        load_flexible_dataset,
        _partition_train_val_test,
        _build_feature_matrix_48,
        PHASE22_BASELINE_FEATURE_NAMES,
        DIVERSITY_DATASET_REL_PATH,
        compute_file_sha256 as p22_compute_sha,
    )
    from backend.detection.baseline_profiler import BehavioralBaselineProfiler
    from backend.detection.isolation_forest import IsolationForestDetector
    from backend.detection.model_trainer import calculate_failed_auth_rate
    from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
    from backend.detection.sequence_context import CausalSequenceTracker
    from imblearn.over_sampling import SMOTE
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.frozen import FrozenEstimator

    data_file = Path(dataset_path or (PROJECT_ROOT / DIVERSITY_DATASET_REL_PATH)).resolve()
    ds_sha = p22_compute_sha(data_file)
    events, _ = load_flexible_dataset(str(data_file))
    labels = [e.attack_type or "benign" for e in events]

    tr_idx, val_idx, te_idx, _ = _partition_train_val_test(events, labels, seed=seed)
    tr_ev = [events[i] for i in tr_idx]
    y_tr = [labels[i] for i in tr_idx]
    val_ev = [events[i] for i in val_idx]
    y_val = [labels[i] for i in val_idx]

    prof = BehavioralBaselineProfiler()
    prof.build_baselines(tr_ev, benign_only=True)
    if_det = IsolationForestDetector(random_state=seed)
    if_det.fit(tr_ev)
    fa_tr = calculate_failed_auth_rate(tr_ev)
    fa_val = calculate_failed_auth_rate(val_ev)

    gt = CausalTemporalGraphTracker()
    gt.fit_baseline_pairs(tr_ev)
    st_tr = CausalSequenceTracker(300.0)
    st_val = CausalSequenceTracker(300.0)

    X_tr = _build_feature_matrix_48(tr_ev, if_det, prof, fa_tr, gt, st_tr)
    st_val.reset()
    X_val = _build_feature_matrix_48(val_ev, if_det, prof, fa_val, gt, st_val)

    min_c = min(Counter(y_tr).values())
    sm = SMOTE(k_neighbors=max(1, min(4, min_c - 1)), random_state=seed)
    X_tr_res, y_tr_res = sm.fit_resample(X_tr, y_tr)

    rf = ThreatClassifier(random_state=seed, feature_names=PHASE22_BASELINE_FEATURE_NAMES)
    rf.fit(X_tr_res, y_tr_res)

    cal = CalibratedClassifierCV(estimator=FrozenEstimator(rf.model), method="isotonic")
    cal.fit(X_val, y_val)

    mgr = ModelLifecycleManager()
    out = mgr.export_calibrated_artifact(
        base_rf_model=rf.model,
        calibrator_model=cal,
        feature_names=PHASE22_BASELINE_FEATURE_NAMES,
        output_path=output_path,
        dataset_sha256=ds_sha,
        dataset_records=len(events),
        split_seed=seed,
        training_samples=len(tr_ev),
        validation_samples=len(val_ev),
    )
    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Training and exporting canonical Phase 23 calibrated model artifact...")
    path = train_and_export_default_calibrated_artifact()
    print(f"Artifact created at {path}")
    manager = ModelLifecycleManager()
    ok, msg, meta = manager.validate_artifact_file(path)
    print(f"Validation: ok={ok}, msg={msg}")
    print(f"Metadata: {meta}")
