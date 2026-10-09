from typing import Dict, List, Optional
from datetime import datetime

try:
    from core.schemas import UnifiedEvent, DetectionResult
    from core.config import (
        ANOMALY_THRESHOLD,
        CONFIDENCE_ALERT_MIN,
        CONFIDENCE_CRITICAL,
        CONFIDENCE_HIGH,
        CONFIDENCE_MEDIUM,
    )
    from graph.temporal_kg import TemporalKnowledgeGraph
except ModuleNotFoundError:
    from backend.core.schemas import UnifiedEvent, DetectionResult
    from backend.core.config import (
        ANOMALY_THRESHOLD,
        CONFIDENCE_ALERT_MIN,
        CONFIDENCE_CRITICAL,
        CONFIDENCE_HIGH,
        CONFIDENCE_MEDIUM,
    )
    from backend.graph.temporal_kg import TemporalKnowledgeGraph


class WeightedEvidenceFusion:
    """
    Weighted Evidence Fusion Engine for AEGIS-ML.
    
    Synthesizes multiple multi-layer detection signals:
    - Isolation Forest anomaly score (unsupervised statistical novelty)
    - Behavioral baseline profiler deviation (entity historical deviation)
    - Temporal Knowledge Graph score (topological and relational risk)
    - Random Forest threat classifier confidence (supervised threat pattern recognition)
    """

    def __init__(
        self,
        weight_if: float = 0.25,
        weight_baseline: float = 0.20,
        weight_graph: float = 0.20,
        weight_classifier: float = 0.35,
        alert_threshold: float = 0.60
    ):
        total_w = weight_if + weight_baseline + weight_graph + weight_classifier
        self.w_if = weight_if / total_w
        self.w_base = weight_baseline / total_w
        self.w_graph = weight_graph / total_w
        self.w_clf = weight_classifier / total_w
        self.alert_threshold = alert_threshold

    def fuse(
        self,
        event: UnifiedEvent,
        if_score: float,
        baseline_deviation: float,
        graph_score: float,
        threat_type: Optional[str] = None,
        classifier_confidence: float = 0.0,
        severity: Optional[str] = None,
    ) -> DetectionResult:
        """
        Combine evidence scores into a unified DetectionResult.
        """
        is_attack = threat_type is not None and threat_type != "benign"
        clf_signal = classifier_confidence if is_attack else 0.0

        fused_score = (
            self.w_if * float(if_score) +
            self.w_base * float(baseline_deviation) +
            self.w_graph * float(graph_score) +
            self.w_clf * float(clf_signal)
        )

        # Alert decision: trigger alert if supervised model identifies threat with confidence >= threshold,
        # or if composite fused multi-signal anomaly exceeds alert_threshold
        is_alert = False
        if is_attack and classifier_confidence >= CONFIDENCE_ALERT_MIN:
            is_alert = True
        elif fused_score >= self.alert_threshold:
            is_alert = True

        return DetectionResult(
            event_id=event.event_id,
            timestamp=event.timestamp,
            layer=event.layer,
            src_entity=event.src_entity,
            dst_entity=event.dst_entity,
            if_score=float(if_score),
            baseline_deviation=float(baseline_deviation),
            graph_score=float(graph_score),
            threat_type=threat_type,
            confidence=float(classifier_confidence if is_attack else (1.0 - fused_score)),
            severity=severity,
            is_alert=is_alert,
        )


# Preserve TemporalKnowledgeGraph alias for backwards compatibility
__all__ = ["WeightedEvidenceFusion", "TemporalKnowledgeGraph"]
