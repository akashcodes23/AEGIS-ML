"""
AEGIS-ML Local Feature Explainer
---------------------------------
Computes deterministic, documented local feature contributions for individual network events.

IMPORTANT — What this module computes and what it does NOT:
  A. This module computes BEHAVIORAL DEVIATION from a reference baseline.
     It answers: "Which features deviated most from expected values for this entity?"
  B. It does NOT compute SHAP values or any model-internal attribution.
     It does NOT explain the model's internal decision tree path.
  C. Global feature importances from the RandomForestClassifier are used only as
     weighting factors to surface features the model considers relevant.
     They are labeled explicitly as model importances, not local Shapley values.

Formula (per feature i):
  1. Normalized deviation:
       dev_i = |x_i - baseline_mean_i| / (baseline_std_i + 1e-5), clipped to [0, 5], then /5
  2. Weighted contribution:
       raw_score_i = dev_i * global_importance_weight_i
  3. Normalized percentage:
       pct_i = raw_score_i / sum(all raw_score)
"""

from typing import Dict, List, Optional, Any
import numpy as np

try:
    from detection.threat_classifier import ThreatClassifier
except ModuleNotFoundError:
    from backend.detection.threat_classifier import ThreatClassifier


class LocalFeatureExplainer:
    """
    Computes local feature deviations and explanations for a single event.

    Uses ThreatClassifier.FEATURE_NAMES as the canonical feature reference.
    The DEFAULT_NORMAL_MEANS and DEFAULT_NORMAL_STDS are approximate reference
    baselines for the AEGIS 15-feature space. Per-entity profiles from the
    BehavioralBaselineProfiler override these defaults where available.
    """

    # Reference baseline values keyed by ThreatClassifier.FEATURE_NAMES.
    # These represent approximate typical values for benign enterprise traffic
    # and are used only when no entity-specific profile is available.
    DEFAULT_NORMAL_MEANS: Dict[str, float] = {
        "if_anomaly_score":     0.20,
        "baseline_deviation":   0.15,
        "graph_new_connections": 0.10,
        "failed_auth_rate":     0.00,
        "connection_frequency": 2.00,
        "bytes_sent_zscore":    0.50,
        "bytes_sent_log":       7.50,   # log1p(~1800 bytes)
        "bytes_ratio":          1.20,
        "conn_rate_zscore":     0.00,
        "dst_port_risk":        0.10,
        "is_new_destination":   0.10,
        "is_external_dst":      0.10,
        "hour_of_day_sin":      0.00,
        "hour_of_day_cos":      0.70,   # ~business hours cosine
        "cross_layer_match":    0.00,
    }

    DEFAULT_NORMAL_STDS: Dict[str, float] = {
        "if_anomaly_score":     0.15,
        "baseline_deviation":   0.15,
        "graph_new_connections": 0.20,
        "failed_auth_rate":     0.10,
        "connection_frequency": 5.00,
        "bytes_sent_zscore":    2.00,
        "bytes_sent_log":       3.00,
        "bytes_ratio":          0.80,
        "conn_rate_zscore":     2.00,
        "dst_port_risk":        0.25,
        "is_new_destination":   0.30,
        "is_external_dst":      0.30,
        "hour_of_day_sin":      0.70,
        "hour_of_day_cos":      0.50,
        "cross_layer_match":    0.10,
    }

    # Binary/categorical features that use exact-match deviation
    BINARY_FEATURES = frozenset({"is_new_destination", "is_external_dst", "cross_layer_match"})

    def __init__(self, feature_names: List[str]):
        # Validate that provided names are a known subset
        canonical = set(ThreatClassifier.FEATURE_NAMES)
        unknown = [n for n in feature_names if n not in canonical]
        if unknown:
            import logging
            logging.getLogger(__name__).warning(
                f"[Explainer] Unrecognized feature names (not in ThreatClassifier.FEATURE_NAMES): {unknown}. "
                "Explanation quality may be reduced."
            )
        self.feature_names = feature_names

    def explain(
        self,
        features: List[float],
        global_importances: Optional[Dict[str, float]] = None,
        entity_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """
        Compute normalized local contribution percentages for the top driving factors.

        Returns a dict mapping feature names to their relative contribution (0.0-1.0),
        sorted descending. The contributions sum to 1.0 across returned keys.

        Interpretation:
          - High value = this feature deviated substantially from baseline AND the
            RandomForest assigns it high global importance.
          - This reflects BEHAVIORAL DEVIATION, not a model-internal causal explanation.

        Args:
            features: Feature vector matching self.feature_names order.
            global_importances: RandomForest feature_importances_ dict (optional weight).
            entity_profile: BehavioralBaselineProfiler profile for the source entity (optional).

        Returns:
            Dict of {feature_name: normalized_contribution} for top 6 contributors.
            Empty dict if input vector is invalid or zero deviation detected.
        """
        if not features or len(features) != len(self.feature_names):
            return {}

        global_importances = global_importances or {}
        raw_scores: Dict[str, float] = {}

        for idx, name in enumerate(self.feature_names):
            val = float(features[idx])
            mean = self.DEFAULT_NORMAL_MEANS.get(name, 0.0)
            std = self.DEFAULT_NORMAL_STDS.get(name, 1.0)

            # Override baseline from entity-specific profile where available
            if entity_profile:
                if name == "bytes_sent_log" and "avg_bytes_sent" in entity_profile:
                    import math
                    mean = math.log1p(float(entity_profile["avg_bytes_sent"]))
                    if "std_bytes_sent" in entity_profile:
                        std = float(entity_profile["std_bytes_sent"]) / (float(entity_profile["avg_bytes_sent"]) + 1.0)
                elif name == "connection_frequency" and "avg_connections_per_min" in entity_profile:
                    mean = float(entity_profile["avg_connections_per_min"])
                elif name == "conn_rate_zscore" and "avg_connections_per_min" in entity_profile:
                    mean = 0.0  # z-score is already centered

            std = max(std, 1e-5)

            # Deviation computation
            if name in self.BINARY_FEATURES:
                # For binary indicators: any non-zero value is a deviation
                dev = 1.0 if abs(val - mean) > 0.5 else 0.0
            else:
                # Continuous: absolute z-score clipped to [0, 5], normalized to [0, 1]
                z = abs(val - mean) / std
                dev = min(z / 5.0, 1.0)

            # Weight by model feature importance (global, not local)
            weight = float(global_importances.get(name, 1.0 / max(len(self.feature_names), 1)))
            raw_scores[name] = dev * weight

        total_score = sum(raw_scores.values())
        if total_score <= 1e-7:
            # No meaningful deviation detected — return empty rather than uniform noise
            return {}

        # Normalize contributions to sum to 1.0, return top 6
        normalized = {k: round(v / total_score, 4) for k, v in raw_scores.items()}
        sorted_items = sorted(normalized.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_items[:6])
