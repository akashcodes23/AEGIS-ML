"""
backend/ingestion/streaming_ingestion.py
──────────────────────────────────────────────────────────────────────────────
StreamingIngestionManager: Manages continuous telemetry ingestion, deduplication,
high-watermark tracking, late-arriving event tolerance, and causal state dispatch.

Core Architectural Guarantees:
  1. Two-Tier Deduplication:
     • Exact Event ID matching against a bounded LRU cache.
     • Invariant payload fingerprinting within a sliding time window (60s).
  2. Late-Arriving & Out-of-Order Policy:
     • Tracks high-watermark timestamp across arriving telemetry.
     • Events arriving beyond the late tolerance window (300s) are flagged
       `is_late_arriving=True` and isolated from rolling causal sequence
       backfilling to preserve monotonic causal boundaries.
  3. Clock Skew Detection:
     • Detects events stamped > 300s in the future relative to ingestion UTC.
  4. Causal State & Host Isolation:
     • Dispatches normalized events strictly partitioned by host identifier.
     • Zero cross-host event contamination in sequence buffers.
     • Full state reset capability for independent test and replay streams.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timedelta
import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.core.schemas import (
    UnifiedEvent,
    IngestionItemResult,
    IngestionBatchResponse,
    StreamingIngestionStats,
)
from backend.ingestion.normalizer import NormalizerPipeline, NormalizationError

logger = logging.getLogger(__name__)


class StreamingIngestionManager:
    """
    Stateful streaming ingestion manager providing deduplication, watermark
    tracking, late-event handling, and causal host isolation.
    """

    def __init__(
        self,
        dedup_window_seconds: float = 60.0,
        late_tolerance_seconds: float = 300.0,
        max_seen_ids: int = 100_000,
        sequence_tracker: Optional[Any] = None,
        graph_tracker: Optional[Any] = None,
    ):
        self.dedup_window_seconds = float(dedup_window_seconds)
        self.late_tolerance_seconds = float(late_tolerance_seconds)
        self.max_seen_ids = int(max_seen_ids)
        self.sequence_tracker = sequence_tracker
        self.graph_tracker = graph_tracker

        # In-memory deduplication state
        self._seen_event_ids: OrderedDict[str, datetime] = OrderedDict()
        self._seen_fingerprints: Dict[str, datetime] = {}

        # Stream timing state
        self.watermark_timestamp: Optional[datetime] = None

        # Telemetry metrics
        self.total_ingested: int = 0
        self.total_duplicates: int = 0
        self.total_rejected: int = 0
        self.total_late_arriving: int = 0
        self.total_clock_skew: int = 0
        self._active_hosts: set = set()

    def reset(self) -> None:
        """
        Reset all streaming ingestion state, deduplication buffers,
        watermarks, and underlying causal trackers.
        """
        self._seen_event_ids.clear()
        self._seen_fingerprints.clear()
        self.watermark_timestamp = None
        self.total_ingested = 0
        self.total_duplicates = 0
        self.total_rejected = 0
        self.total_late_arriving = 0
        self.total_clock_skew = 0
        self._active_hosts.clear()

        if self.sequence_tracker and hasattr(self.sequence_tracker, "reset"):
            self.sequence_tracker.reset()
        if self.graph_tracker and hasattr(self.graph_tracker, "reset"):
            self.graph_tracker.reset()

        logger.info("[StreamingIngestionManager] Ingestion state and trackers reset successfully.")

    @staticmethod
    def compute_payload_fingerprint(event: UnifiedEvent) -> str:
        """
        Compute an invariant SHA-256 fingerprint from core observable telemetry fields.
        Used to detect duplicates when event IDs are generated or unstable.
        """
        raw_key = (
            f"{event.src_entity}|{event.dst_entity}|{event.layer}|"
            f"{event.src_port}|{event.dst_port}|{event.protocol}|"
            f"{event.bytes_sent}|{event.action}|{event.process_name}|"
            f"{event.timestamp.isoformat()}"
        )
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def check_duplicate(self, event: UnifiedEvent) -> Tuple[bool, Optional[str], str]:
        """
        Check whether an event is a duplicate via exact event_id or sliding-window fingerprint.
        Returns: (is_duplicate, reason, fingerprint)
        """
        # Tier 1: Exact Event ID
        if event.event_id and event.event_id in self._seen_event_ids:
            return True, "duplicate_event_id", ""

        # Tier 2: Invariant Payload Fingerprint
        fp = self.compute_payload_fingerprint(event)
        cached_ts = self._seen_fingerprints.get(fp)
        if cached_ts is not None:
            time_diff = abs((event.timestamp - cached_ts).total_seconds())
            if time_diff <= self.dedup_window_seconds:
                return True, "duplicate_payload_fingerprint", fp

        return False, None, fp

    def _record_accepted(self, event: UnifiedEvent, fingerprint: str) -> None:
        """Record accepted event in bounded LRU and fingerprint cache."""
        now = event.timestamp

        # Store in bounded ID LRU
        if event.event_id:
            self._seen_event_ids[event.event_id] = now
            if len(self._seen_event_ids) > self.max_seen_ids:
                self._seen_event_ids.popitem(last=False)

        # Store in fingerprint cache
        self._seen_fingerprints[fingerprint] = now
        event.dedup_fingerprint = fingerprint

        # Prune fingerprints older than 2x window relative to event timestamp
        cutoff = now - timedelta(seconds=self.dedup_window_seconds * 2.0)
        stale_fps = [k for k, ts in self._seen_fingerprints.items() if ts < cutoff]
        for k in stale_fps:
            self._seen_fingerprints.pop(k, None)

        # Track active host
        host = event.host_id or event.src_entity
        if host:
            self._active_hosts.add(host)

    def evaluate_timing(self, event: UnifiedEvent) -> None:
        """
        Evaluate high-watermark, late arrival, and clock skew.
        """
        if self.watermark_timestamp is not None:
            # If event timestamp is older than watermark minus tolerance, mark late
            late_threshold = self.watermark_timestamp - timedelta(seconds=self.late_tolerance_seconds)
            if event.timestamp < late_threshold:
                event.is_late_arriving = True
                self.total_late_arriving += 1
            else:
                event.is_late_arriving = False
                if event.timestamp > self.watermark_timestamp:
                    self.watermark_timestamp = event.timestamp
        else:
            event.is_late_arriving = False
            self.watermark_timestamp = event.timestamp

        if event.clock_skew_detected:
            self.total_clock_skew += 1

    def dispatch_causal_trackers(
        self,
        event: UnifiedEvent,
    ) -> Dict[str, Any]:
        """
        Safely update attached causal sequence and graph trackers.
        Enforces:
          - Host isolation: buffers are keyed strictly by host.
          - Late-arriving policy: events flagged late do not advance sequence state,
            preventing corrupting the causal rolling window for future events.
        """
        tracker_results: Dict[str, Any] = {}

        # Late events do not advance historical monotonic state
        advance = not bool(event.is_late_arriving)

        if self.sequence_tracker and hasattr(self.sequence_tracker, "extract_features_single"):
            seq_feats = self.sequence_tracker.extract_features_single(event, advance_state=advance)
            tracker_results["sequence_features"] = seq_feats

        if self.graph_tracker and hasattr(self.graph_tracker, "extract_features_single"):
            graph_feats = self.graph_tracker.extract_features_single(event, advance_state=advance)
            tracker_results["graph_features"] = graph_feats

        return tracker_results

    def ingest_event(
        self,
        raw_event: Union[Dict[str, Any], UnifiedEvent],
        source_system: Optional[str] = None,
        dispatch_trackers: bool = True,
    ) -> IngestionItemResult:
        """
        Normalize, validate, deduplicate, and process a single incoming telemetry event.
        """
        # 1. Normalize
        if isinstance(raw_event, UnifiedEvent):
            event = raw_event
        else:
            try:
                event = NormalizerPipeline.normalize(
                    raw_event,
                    source_system=source_system,
                    strict=True,
                )
            except NormalizationError as exc:
                self.total_rejected += 1
                logger.debug("Ingestion rejected: %s", exc)
                return IngestionItemResult(
                    event_id=raw_event.get("event_id") if isinstance(raw_event, dict) else None,
                    status="rejected",
                    reason=f"validation_error: {exc.message} (field={exc.field})",
                )
            except Exception as exc:
                self.total_rejected += 1
                return IngestionItemResult(
                    event_id=raw_event.get("event_id") if isinstance(raw_event, dict) else None,
                    status="rejected",
                    reason=f"unexpected_error: {str(exc)}",
                )

        if event is None:
            self.total_rejected += 1
            return IngestionItemResult(
                event_id=None,
                status="rejected",
                reason="unable_to_normalize",
            )

        # 2. Deduplicate
        is_dup, dup_reason, fp = self.check_duplicate(event)
        if is_dup:
            self.total_duplicates += 1
            return IngestionItemResult(
                event_id=event.event_id,
                status="duplicate",
                reason=dup_reason,
                is_late_arriving=bool(event.is_late_arriving),
                clock_skew_detected=bool(event.clock_skew_detected),
                event=event,
            )

        # 3. Timing and Watermark
        self.evaluate_timing(event)

        # 4. Record accepted
        self._record_accepted(event, fp)
        self.total_ingested += 1

        # 5. Causal Dispatch
        if dispatch_trackers:
            self.dispatch_causal_trackers(event)

        return IngestionItemResult(
            event_id=event.event_id,
            status="accepted",
            reason=None,
            is_late_arriving=bool(event.is_late_arriving),
            clock_skew_detected=bool(event.clock_skew_detected),
            event=event,
        )

    def ingest_batch(
        self,
        events: List[Union[Dict[str, Any], UnifiedEvent]],
        source_system: Optional[str] = None,
        max_batch_size: int = 500,
        dispatch_trackers: bool = True,
    ) -> IngestionBatchResponse:
        """
        Batch ingestion with partial failure tolerance and per-item results.
        """
        if len(events) > max_batch_size:
            raise ValueError(f"Batch size {len(events)} exceeds maximum permitted limit {max_batch_size}")

        results: List[IngestionItemResult] = []
        accepted = 0
        duplicate = 0
        rejected = 0

        for raw_ev in events:
            res = self.ingest_event(
                raw_ev,
                source_system=source_system,
                dispatch_trackers=dispatch_trackers,
            )
            results.append(res)
            if res.status == "accepted":
                accepted += 1
            elif res.status == "duplicate":
                duplicate += 1
            elif res.status == "rejected":
                rejected += 1

        return IngestionBatchResponse(
            total_received=len(events),
            accepted_count=accepted,
            duplicate_count=duplicate,
            rejected_count=rejected,
            results=results,
        )

    @property
    def stats(self) -> StreamingIngestionStats:
        """Return real-time ingestion counters and watermark."""
        return StreamingIngestionStats(
            total_ingested=self.total_ingested,
            total_duplicates=self.total_duplicates,
            total_rejected=self.total_rejected,
            total_late_arriving=self.total_late_arriving,
            total_clock_skew=self.total_clock_skew,
            watermark_timestamp=self.watermark_timestamp,
            active_hosts_tracked=len(self._active_hosts),
        )
