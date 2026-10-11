"""
AEGIS-ML Deterministic Event Replay Facility.

Provides reproducible, controlled replay of recorded telemetry sequences with:
- Strict isolation from live production ingestion state
- Normal chronological order, original order, or configurable jitter/out-of-order injection
- Controlled duplicate injection for deduplication and correlation stress testing
- Comprehensive recording of ingestion, detection, alert, and incident outcomes
- Seed-driven reproducibility for deterministic test pipelines
"""

import copy
import json
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple, Callable

from backend.core.schemas import (
    UnifiedEvent,
    IngestionItemResult,
    DetectionResult,
    Alert,
    Incident,
)
from backend.detection.sequence_context import CausalSequenceTracker
from backend.detection.temporal_graph_extractor import CausalTemporalGraphTracker
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.ingestion.streaming_ingestion import StreamingIngestionManager

logger = logging.getLogger(__name__)


@dataclass
class ReplayConfig:
    """Configuration governing deterministic replay execution."""
    mode: str = "chronological"  # 'chronological', 'original', 'out_of_order', 'jittered'
    jitter_max_seconds: float = 0.0
    out_of_order_probability: float = 0.0
    duplicate_injection_rate: float = 0.0
    trigger_detection: bool = False
    seed: int = 42
    dedup_window_seconds: float = 60.0
    late_tolerance_seconds: float = 300.0
    max_seen_ids: int = 100_000


@dataclass
class ReplaySummary:
    """Structured summary and results of a replay execution."""
    total_input_events: int
    total_replayed_events: int
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    late_count: int
    clock_skew_count: int
    detections_count: int
    alerts_count: int
    incidents_count: int
    alerts: List[Alert] = field(default_factory=list)
    incidents: List[Incident] = field(default_factory=list)
    results: List[IngestionItemResult] = field(default_factory=list)
    start_watermark: Optional[datetime] = None
    end_watermark: Optional[datetime] = None
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary metrics to JSON-serializable dictionary."""
        return {
            "total_input_events": self.total_input_events,
            "total_replayed_events": self.total_replayed_events,
            "accepted_count": self.accepted_count,
            "duplicate_count": self.duplicate_count,
            "rejected_count": self.rejected_count,
            "late_count": self.late_count,
            "clock_skew_count": self.clock_skew_count,
            "detections_count": self.detections_count,
            "alerts_count": self.alerts_count,
            "incidents_count": self.incidents_count,
            "start_watermark": self.start_watermark.isoformat() if self.start_watermark else None,
            "end_watermark": self.end_watermark.isoformat() if self.end_watermark else None,
            "config": self.config,
        }


class DeterministicEventReplayer:
    """
    Deterministic Replayer isolating replay execution from live server state.
    """

    def __init__(
        self,
        config: Optional[ReplayConfig] = None,
        detection_handler: Optional[Callable[[UnifiedEvent], Tuple[Optional[DetectionResult], Optional[Alert]]]] = None,
    ):
        self.config = config or ReplayConfig()
        self.detection_handler = detection_handler
        self._rng = random.Random(self.config.seed)

        # Isolated trackers and state
        self.sequence_tracker = CausalSequenceTracker(window_seconds=300.0)
        self.graph_tracker = CausalTemporalGraphTracker()
        self.correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=int(self.config.dedup_window_seconds))

        # Setup ingestion manager
        self.ingestion_manager = StreamingIngestionManager(
            dedup_window_seconds=self.config.dedup_window_seconds,
            late_tolerance_seconds=self.config.late_tolerance_seconds,
            max_seen_ids=self.config.max_seen_ids,
            sequence_tracker=self.sequence_tracker,
            graph_tracker=self.graph_tracker,
            detection_handler=self._handle_detection,
        )

        self.generated_alerts: List[Alert] = []
        self.created_incidents: Dict[str, Incident] = {}

    def reset(self) -> None:
        """Reset internal replay state and re-initialize RNG with configured seed."""
        self._rng = random.Random(self.config.seed)
        self.sequence_tracker.reset()
        self.graph_tracker.reset()
        self.correlator = IncidentCorrelator(time_window_seconds=600, dedup_window_seconds=int(self.config.dedup_window_seconds))
        self.ingestion_manager.reset()
        self.generated_alerts.clear()
        self.created_incidents.clear()

    def _handle_detection(self, event: UnifiedEvent) -> Tuple[Optional[DetectionResult], Optional[Alert]]:
        """Invoked when detection is triggered during replay."""
        det_result = None
        alert_result = None

        if self.detection_handler:
            det_result, alert_result = self.detection_handler(event)
        
        # If an alert is produced, incrementally correlate into replayer's isolated incident correlator
        if alert_result:
            self.generated_alerts.append(alert_result)
            incident, _ = self.correlator.correlate_alert(alert_result, raw_event=event)
            alert_result.incident_id = incident.incident_id
            self.created_incidents[incident.incident_id] = incident

        return det_result, alert_result

    def _prepare_event_sequence(self, raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Transform raw event stream based on ReplayConfig:
        - chronological sorting
        - duplicate injection
        - out-of-order permutation or timestamp jitter
        """
        events = [copy.deepcopy(e) for e in raw_events]
        self._rng = random.Random(self.config.seed)

        # 1. Mode ordering
        if self.config.mode == "chronological":
            def get_ts(ev: Dict[str, Any]) -> str:
                return str(ev.get("timestamp") or ev.get("time") or "")
            events.sort(key=get_ts)
        elif self.config.mode == "jittered" and self.config.jitter_max_seconds > 0:
            for ev in events:
                raw_ts = ev.get("timestamp")
                if raw_ts:
                    try:
                        ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                        jitter = timedelta(seconds=self._rng.uniform(0, self.config.jitter_max_seconds))
                        ev["timestamp"] = (ts + jitter).isoformat()
                    except Exception:
                        pass
        elif self.config.mode == "out_of_order" or self.config.out_of_order_probability > 0:
            prob = self.config.out_of_order_probability if self.config.out_of_order_probability > 0 else 0.2
            for i in range(len(events) - 1):
                if self._rng.random() < prob:
                    # Swap with neighbor to simulate out-of-order delivery
                    events[i], events[i + 1] = events[i + 1], events[i]

        # 2. Duplicate injection
        if self.config.duplicate_injection_rate > 0 and len(events) > 0:
            injected_events = []
            for ev in events:
                injected_events.append(ev)
                if self._rng.random() < self.config.duplicate_injection_rate:
                    dup_ev = copy.deepcopy(ev)
                    # Either exact copy or copy with slight delay
                    injected_events.append(dup_ev)
            events = injected_events

        return events

    def replay(
        self,
        events: List[Dict[str, Any]],
        source_system: Optional[str] = "replay_facility",
    ) -> ReplaySummary:
        """
        Replay an event sequence deterministically and return complete execution summary.
        """
        self.reset()
        prepared_events = self._prepare_event_sequence(events)
        results: List[IngestionItemResult] = []

        start_wm = self.ingestion_manager.watermark_timestamp

        for raw_ev in prepared_events:
            item_res = self.ingestion_manager.ingest_event(
                raw_event=raw_ev,
                source_system=source_system,
                dispatch_trackers=True,
                trigger_detection=self.config.trigger_detection,
            )
            results.append(item_res)

        end_wm = self.ingestion_manager.watermark_timestamp
        stats = self.ingestion_manager.stats

        detections_count = sum(1 for r in results if r.detection is not None)
        alerts_count = len(self.generated_alerts)
        incidents_count = len(self.created_incidents)

        return ReplaySummary(
            total_input_events=len(events),
            total_replayed_events=len(prepared_events),
            accepted_count=stats.total_ingested,
            duplicate_count=stats.total_duplicates,
            rejected_count=stats.total_rejected,
            late_count=stats.total_late_arriving,
            clock_skew_count=stats.total_clock_skew,
            detections_count=detections_count,
            alerts_count=alerts_count,
            incidents_count=incidents_count,
            alerts=list(self.generated_alerts),
            incidents=list(self.created_incidents.values()),
            results=results,
            start_watermark=start_wm,
            end_watermark=end_wm,
            config={
                "mode": self.config.mode,
                "seed": self.config.seed,
                "jitter_max_seconds": self.config.jitter_max_seconds,
                "out_of_order_probability": self.config.out_of_order_probability,
                "duplicate_injection_rate": self.config.duplicate_injection_rate,
                "trigger_detection": self.config.trigger_detection,
                "dedup_window_seconds": self.config.dedup_window_seconds,
                "late_tolerance_seconds": self.config.late_tolerance_seconds,
            },
        )

    def replay_file(
        self,
        file_path: Union[str, Path],
        source_system: Optional[str] = "replay_facility",
    ) -> ReplaySummary:
        """Read and replay a JSONL or JSON file of events."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Replay file not found: {file_path}")

        events: List[Dict[str, Any]] = []
        if p.suffix == ".jsonl":
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str:
                        events.append(json.loads(line_str))
        else:
            with open(p, "r", encoding="utf-8") as f:
                content = json.load(f)
                if isinstance(content, list):
                    events = content
                elif isinstance(content, dict) and "events" in content:
                    events = content["events"]
                else:
                    raise ValueError(f"Unrecognized JSON structure in {file_path}")

        return self.replay(events, source_system=source_system)
