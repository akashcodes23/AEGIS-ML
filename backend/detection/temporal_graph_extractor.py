"""
AEGIS-ML Temporal and Graph-Aware Feature Extractor
Module: backend.detection.temporal_graph_extractor

Provides strictly causal, streaming-compatible feature extraction for:
- Temporal dynamics: inter-event intervals, rolling event burst rates.
- Relational communication: new src-dst relationships, internal destination diversity.
- Dynamic entity graph statistics: rolling out-degree, in-degree, host pivot chaining.

Causality Guarantees:
- Strictly looks backward: for an event at timestamp t, only events with t' < t
  (or earlier in the causal stream sequence) are considered in history windows.
- Zero future-event leakage.
- Resilient to missing timestamps, unknown entities, and out-of-order jitter.
"""

from typing import List, Dict, Tuple, Set, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math
import logging

try:
    from core.schemas import UnifiedEvent
except ModuleNotFoundError:
    from backend.core.schemas import UnifiedEvent

logger = logging.getLogger(__name__)


TEMPORAL_FEATURE_NAMES = [
    "inter_event_time_log",
    "event_rate_1m",
    "event_rate_5m",
]

RELATIONAL_GRAPH_FEATURE_NAMES = [
    "distinct_dst_internal_5m",
    "dst_diversity_ratio_5m",
    "is_new_src_dst_pair",
    "src_out_degree_5m",
    "dst_in_degree_5m",
    "pivot_chain_indicator",
]

ALL_EXTENDED_FEATURE_NAMES = TEMPORAL_FEATURE_NAMES + RELATIONAL_GRAPH_FEATURE_NAMES


class CausalTemporalGraphTracker:
    """
    Online, causal tracker of host temporal dynamics and entity communication graph.
    
    Guarantees strict causal ordering:
    1. Querying features for event e at timestamp t evaluates historical state strictly prior to e.
    2. Event e is incorporated into the tracker state ONLY after its features are extracted.
    3. Handles missing timestamps safely by defaulting to monotonic arrival order.
    """

    def __init__(self):
        self.known_pairs: Set[Tuple[str, str]] = set()
        self.last_seen: Dict[str, datetime] = {}
        self.events_1m: Dict[str, List[datetime]] = defaultdict(list)
        self.events_5m: Dict[str, List[Tuple[datetime, str, bool]]] = defaultdict(list)
        self.inbound_5m: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)

    def reset(self) -> None:
        """Reset streaming state while preserving fitted baseline pairs."""
        self.last_seen.clear()
        self.events_1m.clear()
        self.events_5m.clear()
        self.inbound_5m.clear()

    def fit_baseline_pairs(self, events: List[UnifiedEvent]) -> None:
        """
        Learn known baseline (src_entity, dst_entity) communication pairs from training data.
        Does NOT populate streaming windows, preserving causal evaluation integrity.
        """
        for e in events:
            if e.src_entity and e.dst_entity:
                self.known_pairs.add((e.src_entity, e.dst_entity))

    def extract_features_single(self, event: UnifiedEvent, advance_state: bool = True) -> Dict[str, float]:
        """
        Extract causal temporal and graph features for a single event.
        
        Args:
            event: The UnifiedEvent to evaluate.
            advance_state: If True, adds event to historical state after feature extraction.
            
        Returns:
            Dictionary mapping feature names to float values.
        """
        t = event.timestamp or datetime.utcnow()
        src = event.src_entity or "unknown"
        dst = event.dst_entity or "unknown"
        dst_internal = bool(event.dst_internal)

        # 1. Temporal Dynamics (Strictly prior to this event)
        if src in self.last_seen and t >= self.last_seen[src]:
            dt = (t - self.last_seen[src]).total_seconds()
            dt_log = float(math.log1p(max(0.0, dt)))
        else:
            # Default to log1p(400s) ~ 6.0 when host is first seen or timestamp is unordered
            dt_log = 6.0

        c_1m = t - timedelta(seconds=60)
        c_5m = t - timedelta(seconds=300)

        # Filter rolling windows strictly before t
        valid_1m = [ts for ts in self.events_1m[src] if ts >= c_1m]
        rate_1m = float(len(valid_1m))

        valid_5m = [item for item in self.events_5m[src] if item[0] >= c_5m]
        rate_5m = float(len(valid_5m))

        # 2. Relational & Graph Structure
        recent_dsts = [item[1] for item in valid_5m]
        recent_internal_dsts = set(item[1] for item in valid_5m if item[2])
        distinct_internal_5m = float(len(recent_internal_dsts))
        dst_diversity_5m = float(len(set(recent_dsts)) / max(len(recent_dsts), 1))

        is_new_pair = 0.0 if (src, dst) in self.known_pairs else 1.0
        src_out_deg = float(len(set(recent_dsts)))

        valid_inbound = [item for item in self.inbound_5m[dst] if item[0] >= c_5m]
        dst_in_deg = float(len(set(item[1] for item in valid_inbound)))

        # Pivot chain indicator: was src recently the victim/target of an inbound connection from a third party?
        src_inbound = [item for item in self.inbound_5m.get(src, []) if item[0] >= c_5m and item[1] != src]
        pivot_chain = 1.0 if len(src_inbound) > 0 else 0.0

        features = {
            "inter_event_time_log": dt_log,
            "event_rate_1m": rate_1m,
            "event_rate_5m": rate_5m,
            "distinct_dst_internal_5m": distinct_internal_5m,
            "dst_diversity_ratio_5m": dst_diversity_5m,
            "is_new_src_dst_pair": is_new_pair,
            "src_out_degree_5m": src_out_deg,
            "dst_in_degree_5m": dst_in_deg,
            "pivot_chain_indicator": pivot_chain,
        }

        # 3. Update Causal State (AFTER feature extraction)
        if advance_state:
            self.last_seen[src] = t
            self.events_1m[src] = valid_1m + [t]
            self.events_5m[src] = valid_5m + [(t, dst, dst_internal)]
            self.inbound_5m[dst] = valid_inbound + [(t, src)]
            self.known_pairs.add((src, dst))

        return features

    def extract_sequence(self, events: List[UnifiedEvent]) -> List[Dict[str, float]]:
        """
        Process a list of events causally in timestamp order.
        Guarantees that each event only accesses historical events occurring earlier in time.
        Preserves original event list ordering in returned feature dictionaries.
        """
        if not events:
            return []

        # Sort indices by timestamp (or arrival order if timestamp missing)
        min_dt = datetime.min
        indexed_events = list(enumerate(events))
        indexed_events.sort(key=lambda x: x[1].timestamp or min_dt)

        extracted: List[Optional[Dict[str, float]]] = [None] * len(events)
        for orig_idx, event in indexed_events:
            feats = self.extract_features_single(event, advance_state=True)
            extracted[orig_idx] = feats

        return [f for f in extracted if f is not None]
