"""AEGIS-ML Phase 21: Sequence-Aware Feature Extraction and Evidence Semantics.

Module: backend.detection.sequence_context

Extracts causal, online sequence-level features and attribution signals
across observed telemetry streams without introducing future-event leakage,
cross-host event mixing, or synthetic provenance contamination.

Evidence Taxonomy:
- Level 1 (Directly Observed Event): Attributes directly measured by local sensor
  (e.g., event.parent_process, event.layer, event.action).
- Level 2 (Verified Socket Binding): Explicit OS process-to-socket binding proven
  by matching process_guid and socket_id.
- Level 3 (Inferred Temporal/Behavioral Link): Host-scoped temporal sequencing
  (e.g., endpoint file read followed by network transmission within lookback window).
  Crucially, this is an inferred hypothesis, NEVER labeled as confirmed attribution.
- Level 4 (Unknown / Unobserved Attribution): Missing or decoupled telemetry
  explicitly evaluated as 0.0.

Strict Guarantees:
1. Strict Causality: At timestamp t, only events with t' <= t within lookback window W
   are evaluated. Zero future-event leakage.
2. Host Isolation: Event buffers are strictly partitioned by host (src_ip). Events
   from different hosts are NEVER joined.
3. Zero Provenance Contamination: scenario_id, scenario_type, generator_version,
   and event_id are prohibited from predictive features.
4. No Fabricated Attribution: Missing socket_id or process_guid evaluates strictly to 0.0.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import ipaddress
import math
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:
    from core.schemas import UnifiedEvent
except ModuleNotFoundError:
    from backend.core.schemas import UnifiedEvent


SEQUENCE_FEATURE_NAMES = [
    "seq_window_event_count_host",
    "seq_window_endpoint_event_count",
    "seq_window_network_event_count",
    "seq_time_since_last_host_event_log",
    "seq_time_since_last_endpoint_event_log",
    "seq_time_since_last_network_event_log",
    "seq_inferred_file_read_before_outbound_net",
    "seq_inferred_file_read_before_internal_net",
    "seq_window_has_external_transfer",
    "seq_window_bytes_sent_sum_log",
    "seq_process_ancestry_observed",
    "seq_parent_process_is_shell_or_script",
    "seq_verified_socket_attribution",
    "seq_sequence_completeness_score",
]

SHELL_SCRIPT_INTERPRETERS: Set[str] = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "bash",
    "sh",
    "zsh",
    "cscript.exe",
    "wscript.exe",
    "python.exe",
    "python",
    "perl.exe",
}


def is_rfc1918_private(ip_str: Optional[str]) -> bool:
    """Check if an IP string is an RFC 1918 or private/loopback address."""
    if not ip_str or not isinstance(ip_str, str):
        return True
    cleaned = ip_str.strip().lower()
    if cleaned in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        obj = ipaddress.ip_address(cleaned)
        return obj.is_private or obj.is_loopback
    except ValueError:
        return True


@dataclass
class HostEventRecord:
    """Historical event record maintained strictly in causal arrival order."""
    timestamp: datetime
    layer: str
    is_endpoint: bool
    is_network: bool
    is_file_read: bool
    is_outbound_external: bool
    is_internal_net: bool
    bytes_sent: float
    process_name: Optional[str]


class CausalSequenceTracker:
    """
    Online, causal tracker for host-scoped event sequences and attribution signals.
    
    Guarantees:
    - At any evaluation point t, only historical events within [t - window_seconds, t]
      on the same host are consulted.
    - Zero future-event leakage: future events are never queried.
    - Zero cross-host joins: buffers are partitioned strictly by host.
    - Handles missing timestamps, out-of-order events, and sparse telemetry gracefully.
    """

    def __init__(self, window_seconds: float = 300.0):
        self.window_seconds = float(window_seconds)
        self.host_history: Dict[str, List[HostEventRecord]] = defaultdict(list)

    def reset(self) -> None:
        """Clear all historical state for a new independent evaluation stream."""
        self.host_history.clear()

    def _is_event_file_read(self, event: UnifiedEvent) -> bool:
        """Determine if an endpoint event represents file reading/staging."""
        if event.layer != "endpoint":
            return False
        action = str(event.action).lower() if event.action else ""
        if action in ("read", "access", "open"):
            return True
        if event.file_path and action not in ("delete", "remove"):
            return True
        proc = str(event.process_name).lower() if event.process_name else ""
        if proc in ("7z.exe", "robocopy.exe", "tar.exe", "zip.exe") and action != "write":
            return True
        return False

    def _is_network_external(self, event: UnifiedEvent) -> bool:
        """Determine if a network event has an external destination."""
        if event.layer != "network":
            return False
        if event.dst_internal is False:
            return True
        if event.dst_ip and not is_rfc1918_private(event.dst_ip):
            return True
        return False

    def _is_network_internal(self, event: UnifiedEvent) -> bool:
        """Determine if a network event is within the internal corporate network."""
        if event.layer != "network":
            return False
        if event.dst_internal is True:
            return True
        if event.dst_ip and is_rfc1918_private(event.dst_ip):
            return True
        return False

    def extract_features_single(
        self, event: UnifiedEvent, advance_state: bool = True
    ) -> Dict[str, float]:
        """
        Extract sequence features for a single event, then optionally record it.
        
        Args:
            event: The UnifiedEvent to evaluate.
            advance_state: If True, adds the event to the causal host buffer.
            
        Returns:
            Dictionary mapping feature names to float values.
        """
        host = event.src_ip or event.src_entity or "unknown_host"
        t = event.timestamp or datetime.utcnow()
        t_cutoff = t - timedelta(seconds=self.window_seconds)

        # 1. Retrieve host history strictly before or at t, within [t - W, t]
        history = self.host_history[host]
        valid_prior = [r for r in history if t_cutoff <= r.timestamp <= t]

        # Current event properties
        cur_is_endpoint = event.layer == "endpoint"
        cur_is_network = event.layer == "network"
        cur_is_file_read = self._is_event_file_read(event)
        cur_is_ext_net = self._is_network_external(event)
        cur_is_int_net = self._is_network_internal(event)
        cur_bytes = float(event.bytes_sent or 0.0)

        # Feature 1: Host event count in window
        f_host_event_count = float(len(valid_prior))

        # Feature 2: Endpoint event count in window
        ep_priors = [r for r in valid_prior if r.is_endpoint]
        f_ep_count = float(len(ep_priors))

        # Feature 3: Network event count in window
        net_priors = [r for r in valid_prior if r.is_network]
        f_net_count = float(len(net_priors))

        # Feature 4: Elapsed time since last host event (log1p sec)
        if valid_prior:
            dt_host = max(0.0, (t - valid_prior[-1].timestamp).total_seconds())
            f_time_last_host = float(math.log1p(dt_host))
        else:
            f_time_last_host = float(math.log1p(self.window_seconds))

        # Feature 5: Elapsed time since last endpoint event (log1p sec)
        if ep_priors:
            dt_ep = max(0.0, (t - ep_priors[-1].timestamp).total_seconds())
            f_time_last_ep = float(math.log1p(dt_ep))
        else:
            f_time_last_ep = float(math.log1p(self.window_seconds))

        # Feature 6: Elapsed time since last network event (log1p sec)
        if net_priors:
            dt_net = max(0.0, (t - net_priors[-1].timestamp).total_seconds())
            f_time_last_net = float(math.log1p(dt_net))
        else:
            f_time_last_net = float(math.log1p(self.window_seconds))

        # Feature 7: Inferred file read followed by outbound external transfer (Level 3)
        # Evaluates if host performed file read and subsequently initiated external network transfer
        prior_file_reads = [r for r in valid_prior if r.is_file_read]
        prior_ext_nets = [r for r in valid_prior if r.is_outbound_external]
        
        has_file_read_before_ext = False
        if prior_file_reads and cur_is_ext_net:
            has_file_read_before_ext = True
        elif prior_file_reads and prior_ext_nets:
            earliest_read_ts = min(r.timestamp for r in prior_file_reads)
            if any(n.timestamp >= earliest_read_ts for n in prior_ext_nets):
                has_file_read_before_ext = True
        f_file_read_before_ext = 1.0 if has_file_read_before_ext else 0.0

        # Feature 8: Inferred file read followed by internal network transfer (Level 3)
        # (e.g. backup or local SMB file sharing)
        prior_int_nets = [r for r in valid_prior if r.is_internal_net]
        has_file_read_before_int = False
        if prior_file_reads and cur_is_int_net:
            has_file_read_before_int = True
        elif prior_file_reads and prior_int_nets:
            earliest_read_ts = min(r.timestamp for r in prior_file_reads)
            if any(n.timestamp >= earliest_read_ts for n in prior_int_nets):
                has_file_read_before_int = True
        f_file_read_before_int = 1.0 if has_file_read_before_int else 0.0

        # Feature 9: Window has external transfer
        has_ext_net = cur_is_ext_net or any(r.is_outbound_external for r in valid_prior)
        f_has_ext = 1.0 if has_ext_net else 0.0

        # Feature 10: Sum of bytes sent in window (log1p)
        total_bytes = sum(r.bytes_sent for r in valid_prior)
        if cur_is_network:
            total_bytes += cur_bytes
        f_bytes_sum_log = float(math.log1p(total_bytes))

        # Feature 11: Process ancestry explicitly observed (Level 1)
        f_ancestry_observed = 1.0 if event.parent_process is not None else 0.0

        # Feature 12: Parent process is shell or script interpreter
        parent_name = str(event.parent_process).lower() if event.parent_process else ""
        f_parent_is_shell = 1.0 if parent_name in SHELL_SCRIPT_INTERPRETERS else 0.0

        # Feature 13: Verified socket attribution (Level 2)
        # Strictly 0.0 unless both socket_id and process_guid are present on event
        f_verified_socket = (
            1.0 if (event.socket_id is not None and event.process_guid is not None) else 0.0
        )

        # Feature 14: Sequence completeness score across expected layers
        observed_layers = set(r.layer for r in valid_prior if r.layer in ("endpoint", "network", "application"))
        if event.layer in ("endpoint", "network", "application"):
            observed_layers.add(event.layer)
        f_completeness = float(len(observed_layers) / 3.0)

        # 2. Advance causal state if requested
        if advance_state:
            record = HostEventRecord(
                timestamp=t,
                layer=event.layer or "unknown",
                is_endpoint=cur_is_endpoint,
                is_network=cur_is_network,
                is_file_read=cur_is_file_read,
                is_outbound_external=cur_is_ext_net,
                is_internal_net=cur_is_int_net,
                bytes_sent=cur_bytes,
                process_name=event.process_name,
            )
            self.host_history[host].append(record)
            # Prune old records strictly beyond window to preserve bounded memory
            cutoff_prune = t - timedelta(seconds=self.window_seconds * 2.0)
            if len(self.host_history[host]) > 100:
                self.host_history[host] = [
                    r for r in self.host_history[host] if r.timestamp >= cutoff_prune
                ]

        return {
            "seq_window_event_count_host": f_host_event_count,
            "seq_window_endpoint_event_count": f_ep_count,
            "seq_window_network_event_count": f_net_count,
            "seq_time_since_last_host_event_log": f_time_last_host,
            "seq_time_since_last_endpoint_event_log": f_time_last_ep,
            "seq_time_since_last_network_event_log": f_time_last_net,
            "seq_inferred_file_read_before_outbound_net": f_file_read_before_ext,
            "seq_inferred_file_read_before_internal_net": f_file_read_before_int,
            "seq_window_has_external_transfer": f_has_ext,
            "seq_window_bytes_sent_sum_log": f_bytes_sum_log,
            "seq_process_ancestry_observed": f_ancestry_observed,
            "seq_parent_process_is_shell_or_script": f_parent_is_shell,
            "seq_verified_socket_attribution": f_verified_socket,
            "seq_sequence_completeness_score": f_completeness,
        }

    def extract_sequence(self, events: Sequence[UnifiedEvent]) -> List[Dict[str, float]]:
        """
        Extract sequence features for a stream of events processed in chronological order.
        
        Args:
            events: Sequence of UnifiedEvents.
            
        Returns:
            List of feature dictionaries, one per event.
        """
        results: List[Dict[str, float]] = []
        for e in events:
            results.append(self.extract_features_single(e, advance_state=True))
        return results
