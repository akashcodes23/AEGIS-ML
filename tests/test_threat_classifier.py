import pytest
import numpy as np
from sklearn.exceptions import NotFittedError

from backend.detection.threat_classifier import ThreatClassifier, ThreatPrediction


def test_threat_classifier_unfitted_raises_error():
    clf = ThreatClassifier()
    assert clf.is_fitted is False

    features = [0.1] * 15
    with pytest.raises(NotFittedError, match="ThreatClassifier is not fitted or loaded"):
        clf.predict(features)


def test_threat_classifier_feature_validation():
    clf = ThreatClassifier()

    # Wrong length
    with pytest.raises(ValueError, match="Feature vector length mismatch"):
        clf.validate_features([0.1] * 10)

    # NaN / Inf handling
    features_with_nan = [0.1] * 14 + [np.nan]
    cleaned = clf.validate_features(features_with_nan)
    assert not np.isnan(cleaned).any()
    assert cleaned[-1] == 0.0

    features_with_inf = [np.inf] + [0.1] * 14
    cleaned_inf = clf.validate_features(features_with_inf)
    assert not np.isinf(cleaned_inf).any()


def test_threat_classifier_fit_predict_and_persistence(tmp_path):
    clf = ThreatClassifier(random_state=42)

    # Synthetic small dataset
    X = np.random.RandomState(42).randn(50, 15)
    y = np.array(["benign"] * 20 + ["brute_force"] * 15 + ["data_exfiltration"] * 15)

    clf.fit(X, y)
    assert clf.is_fitted is True

    test_feat = [0.2] * 15
    pred = clf.predict(test_feat)
    assert isinstance(pred, ThreatPrediction)
    assert pred.threat_type in ["benign", "brute_force", "data_exfiltration"]
    assert 0.0 <= pred.confidence <= 1.0

    # Persistence
    model_path = str(tmp_path / "test_rf.pkl")
    clf.save(model_path)

    new_clf = ThreatClassifier()
    loaded = new_clf.load(model_path)
    assert loaded is True
    assert new_clf.is_fitted is True

    pred_reloaded = new_clf.predict(test_feat)
    assert pred_reloaded.threat_type == pred.threat_type
    assert pytest.approx(pred_reloaded.confidence, 0.001) == pred.confidence


def test_severity_policy_decoupling():
    clf = ThreatClassifier()

    # Benign has None severity regardless of confidence
    assert clf.determine_severity("benign", 0.99) is None

    # Critical threat preserves high/critical severity even at lower confidence
    assert clf.determine_severity("data_exfiltration", 0.50) == "critical"

    # Medium threat elevates to high if tree consensus is near unanimous
    assert clf.determine_severity("brute_force", 0.96) == "high"
    assert clf.determine_severity("brute_force", 0.70) == "medium"
