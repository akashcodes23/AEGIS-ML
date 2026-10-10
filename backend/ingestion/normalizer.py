"""
backend/ingestion/normalizer.py
──────────────────────────────────────────────────────────────────────────────
NormalizerPipeline: Translates raw telemetry dictionaries from any log source
(network, endpoint, application) into canonical, validated UnifiedEvent objects.

Preserves the distinction between:
  A. Directly observed evidence (raw sensor telemetry).
  B. Derived values computed from observed evidence (e.g. bytes_ratio, hour_of_day).
  C. Inferred temporal or relational associations (populated by downstream graph/sequence correlators).
  D. Verified telemetry attribution (explicit process-to-socket bindings).
  E. Unknown or unavailable evidence (explicitly tracked in missing_fields).

Security & Integrity Guarantees:
  • Sensitive payload redaction (passwords, auth tokens, secrets) before logging/storage.
  • Strict typing and schema bounds checking (IP addresses, port ranges, non-negative volumes).
  • Timezone conversion to UTC and clock skew detection.
  • Does not invent telemetry or convert malformed values into legitimate-looking data.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from datetime import datetime, timezone, timedelta
from math import log
from typing import Any, Dict, List, Optional, Set

from backend.core.config import INTERNAL_IPS, PORT_RISK
from backend.core.schemas import UnifiedEvent

logger = logging.getLogger(__name__)

# Keys whose values should be redacted to prevent credential/secret leakage
SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "auth_bearer",
    "cookie",
    "api_key",
    "apikey",
    "session_id",
    "private_key",
)

# Layer-specific expected telemetry contracts for explicit missingness auditing
EXPECTED_TELEMETRY = {
    "network": [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "bytes_sent",
        "bytes_received",
    ],
    "endpoint": [
        "host_id",
        "process_name",
        "pid",
        "parent_pid",
        "user_account",
        "action",
    ],
    "application": [
        "http_method",
        "endpoint_path",
        "status_code",
        "auth_result",
    ],
}


class NormalizationError(ValueError):
    """Raised when an incoming telemetry payload fails validation."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        raw_event: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.field = field
        self.raw_event = redact_sensitive_payload(raw_event) if raw_event else None


def redact_sensitive_payload(raw_event: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively sanitize dictionaries to mask sensitive credentials, tokens, and keys.
    """
    if not isinstance(raw_event, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for k, v in raw_event.items():
        k_str = str(k).lower()
        if any(substr in k_str for substr in SENSITIVE_KEY_SUBSTRINGS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = redact_sensitive_payload(v)
        else:
            sanitized[k] = v
    return sanitized


class NormalizerPipeline:
    """
    Normalization pipeline transforming raw heterogeneous telemetry into
    canonical UnifiedEvent objects with evidence provenance.
    """

    @classmethod
    def normalize_strict(
        cls,
        raw_event: Dict[str, Any],
        source_system: Optional[str] = None,
    ) -> UnifiedEvent:
        """
        Strict normalization: raises NormalizationError on any validation failure.
        """
        event = cls.normalize(raw_event, source_system=source_system, strict=True)
        if event is None:
            raise NormalizationError("Normalization failed to produce an event", raw_event=raw_event)
        return event

    @classmethod
    def normalize(
        cls,
        raw_event: Dict[str, Any],
        source_system: Optional[str] = None,
        strict: bool = False,
    ) -> Optional[UnifiedEvent]:
        """
        Accept an arbitrary raw log dict, detect or validate its layer, validate
        all fields, compute derived metrics, track evidence provenance, and
        return a canonical UnifiedEvent.

        Parameters
        ----------
        raw_event:
            Raw dictionary from telemetry producer or log adapter.
        source_system:
            Optional identifier of the reporting system (e.g. "suricata", "sysmon").
        strict:
            If True, raises NormalizationError on validation errors.
            If False, returns None on fatal errors, logs warning, and records
            non-fatal anomalies in missing_fields.
        """
        if not isinstance(raw_event, dict):
            if strict:
                raise NormalizationError("Input event must be a dictionary")
            return None

        # Redact raw payload for auditing
        sanitized_raw = redact_sensitive_payload(raw_event)
        missing_fields: List[str] = []
        observed_fields: Set[str] = set()

        # ── 1. Layer Detection ────────────────────────────────────────────
        layer = raw_event.get("layer")
        if layer:
            layer = str(layer).strip().lower()
            if layer not in ("network", "endpoint", "application"):
                if strict:
                    raise NormalizationError(f"Invalid telemetry layer: '{layer}'", field="layer", raw_event=raw_event)
                return None
            observed_fields.add("layer")
        else:
            # Auto-detect layer from telemetry signatures
            if any(k in raw_event for k in ("dst_port", "src_port", "bytes_sent", "bytes_received", "tcp_flags", "protocol")):
                layer = "network"
            elif any(k in raw_event for k in ("process_name", "parent_process", "pid", "parent_pid", "action", "file_path", "user_account")):
                layer = "endpoint"
            elif any(k in raw_event for k in ("http_method", "endpoint_path", "status_code", "user_agent", "payload_size_bytes", "auth_result")):
                layer = "application"
            elif raw_event.get("src_ip") or raw_event.get("dst_ip"):
                layer = "network"
            else:
                if strict:
                    raise NormalizationError("Undetectable telemetry layer: missing layer indicators", field="layer", raw_event=raw_event)
                logger.debug("Layer undetectable – skipping event: %s", sanitized_raw)
                return None

        # ── 2. Entity Resolution ──────────────────────────────────────────
        src_entity = (
            raw_event.get("src_entity")
            or raw_event.get("src_ip")
            or raw_event.get("user_account")
            or raw_event.get("process_name")
            or raw_event.get("host_id")
            or ""
        )
        dst_entity = (
            raw_event.get("dst_entity")
            or raw_event.get("dst_ip")
            or raw_event.get("file_path")
            or raw_event.get("endpoint_path")
            or (f"port_{raw_event.get('dst_port')}" if raw_event.get("dst_port") is not None else "")
            or raw_event.get("process_name")
            or raw_event.get("host_id")
            or ""
        )

        src_entity = str(src_entity).strip()
        dst_entity = str(dst_entity).strip()

        if not src_entity or not dst_entity:
            missing_f = "src_entity" if not src_entity else "dst_entity"
            if strict:
                raise NormalizationError(f"Required entity missing: '{missing_f}' cannot be resolved", field=missing_f, raw_event=raw_event)
            return None

        if "src_entity" in raw_event:
            observed_fields.add("src_entity")
        if "dst_entity" in raw_event:
            observed_fields.add("dst_entity")

        # ── 3. Timestamps & Timezone Normalization ────────────────────────
        raw_ts = raw_event.get("timestamp") or raw_event.get("time") or raw_event.get("@timestamp") or raw_event.get("event_time")
        timestamp: Optional[datetime] = None

        if raw_ts is not None and str(raw_ts).strip() not in ("", "None", "nan", "null"):
            observed_fields.add("timestamp")
            if isinstance(raw_ts, datetime):
                if raw_ts.tzinfo is not None:
                    timestamp = raw_ts.astimezone(timezone.utc).replace(tzinfo=None)
                else:
                    timestamp = raw_ts
            elif isinstance(raw_ts, (int, float)):
                try:
                    fval = float(raw_ts)
                    if math.isnan(fval) or math.isinf(fval):
                        raise ValueError("Timestamp value is NaN or Inf")
                    if fval > 1e14:  # microseconds
                        fval /= 1e6
                    elif fval > 1e11:  # milliseconds
                        fval /= 1e3
                    timestamp = datetime.utcfromtimestamp(fval)
                except Exception as exc:
                    if strict:
                        raise NormalizationError(f"Invalid epoch timestamp: '{raw_ts}' ({exc})", field="timestamp", raw_event=raw_event)
                    missing_fields.append("timestamp_invalid")
                    timestamp = None
            elif isinstance(raw_ts, str):
                s = raw_ts.strip()
                try:
                    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                    if dt.tzinfo is not None:
                        timestamp = dt.astimezone(timezone.utc).replace(tzinfo=None)
                    else:
                        timestamp = dt
                except Exception:
                    try:
                        import dateutil.parser
                        dt = dateutil.parser.parse(s)
                        if dt.tzinfo is not None:
                            timestamp = dt.astimezone(timezone.utc).replace(tzinfo=None)
                        else:
                            timestamp = dt
                    except Exception as exc:
                        if strict:
                            raise NormalizationError(f"Unparseable ISO-8601 timestamp: '{s}' ({exc})", field="timestamp", raw_event=raw_event)
                        missing_fields.append("timestamp_invalid")
                        timestamp = None

        ingestion_ts = datetime.utcnow()
        if timestamp is None:
            if strict:
                raise NormalizationError("Missing required event timestamp", field="timestamp", raw_event=raw_event)
            timestamp = ingestion_ts
            missing_fields.append("timestamp")

        # Clock skew detection (> 5 minutes in future)
        clock_skew_detected = timestamp > (ingestion_ts + timedelta(seconds=300))

        # ── 4. IP Validation ──────────────────────────────────────────────
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        raw_src_ip = raw_event.get("src_ip")
        if raw_src_ip is not None and str(raw_src_ip).strip() not in ("", "None", "nan", "null"):
            cleaned_src = str(raw_src_ip).strip()
            try:
                ipaddress.ip_address(cleaned_src)
                src_ip = cleaned_src
                observed_fields.add("src_ip")
            except ValueError:
                if strict:
                    raise NormalizationError(f"Malformed IP address in src_ip: '{cleaned_src}'", field="src_ip", raw_event=raw_event)
                missing_fields.append("src_ip_invalid")
                src_ip = None

        raw_dst_ip = raw_event.get("dst_ip")
        if raw_dst_ip is not None and str(raw_dst_ip).strip() not in ("", "None", "nan", "null"):
            cleaned_dst = str(raw_dst_ip).strip()
            try:
                ipaddress.ip_address(cleaned_dst)
                dst_ip = cleaned_dst
                observed_fields.add("dst_ip")
            except ValueError:
                if strict:
                    raise NormalizationError(f"Malformed IP address in dst_ip: '{cleaned_dst}'", field="dst_ip", raw_event=raw_event)
                missing_fields.append("dst_ip_invalid")
                dst_ip = None

        src_internal: bool = (src_ip in INTERNAL_IPS) if src_ip else False
        dst_internal: bool = (dst_ip in INTERNAL_IPS) if dst_ip else False

        # ── 5. Port Validation ────────────────────────────────────────────
        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        for port_field in ("src_port", "dst_port"):
            raw_p = raw_event.get(port_field)
            if raw_p is not None and str(raw_p).strip() not in ("", "None", "nan", "null"):
                try:
                    pval = int(raw_p)
                except (ValueError, TypeError):
                    if strict:
                        raise NormalizationError(f"Malformed non-integer port: {raw_p}", field=port_field, raw_event=raw_event)
                    missing_fields.append(f"{port_field}_invalid")
                    continue

                if 0 <= pval <= 65535:
                    if port_field == "src_port":
                        src_port = pval
                    else:
                        dst_port = pval
                    observed_fields.add(port_field)
                else:
                    if strict:
                        raise NormalizationError(f"Port number out of range (0-65535): {raw_p}", field=port_field, raw_event=raw_event)
                    missing_fields.append(f"{port_field}_invalid")

        # ── 6. Protocol Normalization ─────────────────────────────────────
        protocol: Optional[str] = None
        raw_proto = raw_event.get("protocol")
        if raw_proto is not None and str(raw_proto).strip() not in ("", "None", "nan", "null"):
            proto_str = str(raw_proto).strip().upper()
            if proto_str in ("6", "TCP"):
                protocol = "TCP"
            elif proto_str in ("17", "UDP"):
                protocol = "UDP"
            elif proto_str in ("1", "ICMP"):
                protocol = "ICMP"
            elif proto_str in ("0", "IP"):
                protocol = "IP"
            else:
                protocol = proto_str
            observed_fields.add("protocol")

        # ── 7. Numerical Volume Counters ──────────────────────────────────
        bytes_sent: Optional[int] = None
        bytes_received: Optional[int] = None
        packets_sent: Optional[int] = None
        packets_received: Optional[int] = None

        for field_name in ("bytes_sent", "bytes_received", "packets_sent", "packets_received"):
            val = raw_event.get(field_name)
            if val is not None and str(val).strip() not in ("", "None", "nan", "null"):
                try:
                    fval = float(val)
                except (ValueError, TypeError):
                    if strict:
                        raise NormalizationError(f"Malformed numerical counter for '{field_name}': {val}", field=field_name, raw_event=raw_event)
                    missing_fields.append(f"{field_name}_invalid")
                    continue

                if math.isnan(fval) or math.isinf(fval) or fval < 0:
                    if strict:
                        raise NormalizationError(f"Invalid non-negative numerical counter for '{field_name}': {val}", field=field_name, raw_event=raw_event)
                    missing_fields.append(f"{field_name}_invalid")
                else:
                    int_val = int(fval)
                    if field_name == "bytes_sent":
                        bytes_sent = int_val
                    elif field_name == "bytes_received":
                        bytes_received = int_val
                    elif field_name == "packets_sent":
                        packets_sent = int_val
                    elif field_name == "packets_received":
                        packets_received = int_val
                    observed_fields.add(field_name)

        # Duration units: if flow duration in microseconds (>100,000), convert to ms
        duration_ms: Optional[int] = None
        raw_dur = raw_event.get("duration_ms")
        if raw_dur is not None and str(raw_dur).strip() not in ("", "None", "nan", "null"):
            try:
                fdur = float(raw_dur)
                if not (math.isnan(fdur) or math.isinf(fdur) or fdur < 0):
                    if fdur > 100000:
                        duration_ms = max(0, int(fdur / 1000.0))
                    else:
                        duration_ms = max(0, int(fdur))
                    observed_fields.add("duration_ms")
            except (ValueError, TypeError):
                if strict:
                    raise NormalizationError(f"Malformed duration_ms: {raw_dur}", field="duration_ms", raw_event=raw_event)
                missing_fields.append("duration_ms_invalid")

        # ── 8. Endpoint & Process Fields ──────────────────────────────────
        pid: Optional[int] = None
        parent_pid: Optional[int] = None

        for pid_field in ("pid", "parent_pid"):
            val = raw_event.get(pid_field)
            if val is not None and str(val).strip() not in ("", "None", "nan", "null"):
                try:
                    ival = int(val)
                except (ValueError, TypeError):
                    if strict:
                        raise NormalizationError(f"Malformed PID: {val}", field=pid_field, raw_event=raw_event)
                    missing_fields.append(f"{pid_field}_invalid")
                    continue

                if ival >= 0:
                    if pid_field == "pid":
                        pid = ival
                    else:
                        parent_pid = ival
                    observed_fields.add(pid_field)
                else:
                    if strict:
                        raise NormalizationError(f"Negative PID not permitted: {val}", field=pid_field, raw_event=raw_event)
                    missing_fields.append(f"{pid_field}_invalid")

        process_name = raw_event.get("process_name")
        if process_name:
            observed_fields.add("process_name")

        parent_process = raw_event.get("parent_process")
        if parent_process:
            observed_fields.add("parent_process")

        user_account = raw_event.get("user_account")
        if user_account:
            observed_fields.add("user_account")

        host_id = raw_event.get("host_id")
        if host_id:
            observed_fields.add("host_id")

        action = raw_event.get("action")
        if action:
            observed_fields.add("action")

        file_path = raw_event.get("file_path")
        if file_path:
            observed_fields.add("file_path")

        # ── 9. Application Fields ─────────────────────────────────────────
        http_method = raw_event.get("http_method")
        if http_method:
            http_method = str(http_method).strip().upper()
            observed_fields.add("http_method")

        endpoint_path = raw_event.get("endpoint_path")
        if endpoint_path:
            observed_fields.add("endpoint_path")

        status_code: Optional[int] = None
        raw_sc = raw_event.get("status_code")
        if raw_sc is not None and str(raw_sc).strip() not in ("", "None", "nan", "null"):
            try:
                status_code = int(raw_sc)
                observed_fields.add("status_code")
            except (ValueError, TypeError):
                if strict:
                    raise NormalizationError(f"Malformed HTTP status code: {raw_sc}", field="status_code", raw_event=raw_event)
                missing_fields.append("status_code_invalid")

        auth_result = raw_event.get("auth_result")
        if auth_result:
            observed_fields.add("auth_result")

        # ── 10. Audit Missingness against Telemetry Contract ──────────────
        expected_keys = EXPECTED_TELEMETRY.get(layer, [])
        for ek in expected_keys:
            if ek not in observed_fields:
                missing_fields.append(ek)

        # ── 11. Compute Derived Metrics ───────────────────────────────────
        hour = timestamp.hour
        is_business = 8 <= hour <= 18
        b_sent_eff = bytes_sent if bytes_sent is not None else 0
        b_recv_eff = bytes_received if bytes_received is not None else 0
        bytes_ratio = log(1.0 + b_sent_eff) / log(2.0 + b_recv_eff)
        port_risk = PORT_RISK.get(dst_port, 0.0) if dst_port else 0.0

        derived_fields: Dict[str, str] = {
            "hour_of_day": f"Extracted UTC hour ({hour}) from canonical event timestamp",
            "is_business_hours": f"Evaluated business window 08:00–18:00 UTC ({is_business})",
            "bytes_ratio": f"Log-scaled transmission ratio log(1+{b_sent_eff})/log(2+{b_recv_eff}) = {bytes_ratio:.4f}",
            "port_risk_score": f"Static risk score for destination port {dst_port}: {port_risk:.2f}",
            "src_internal": f"Evaluated internal subnet membership for {src_ip} ({src_internal})",
            "dst_internal": f"Evaluated internal subnet membership for {dst_ip} ({dst_internal})",
        }

        # ── 12. Attribution & Evidence Provenance (Step 4) ─────────────────
        # Determine verified attribution: requires genuine observed process identifier
        # coupled with explicit socket binding or process GUID
        socket_id = raw_event.get("socket_id")
        process_guid = raw_event.get("process_guid")
        if (socket_id or process_guid) and pid is not None:
            attribution_status = "verified"
        else:
            attribution_status = "unverified"

        provenance: Dict[str, Any] = {
            "observed_fields": sorted(list(observed_fields)),
            "derived_fields": derived_fields,
            "inferred_associations": [],
            "attribution_status": attribution_status,
            "unavailable_telemetry": sorted(list(set(missing_fields))),
        }

        # Collect event_id
        event_id = str(raw_event.get("event_id") or "").strip()
        if not event_id:
            import uuid
            event_id = str(uuid.uuid4())

        # Source system
        eff_source_system = source_system or raw_event.get("source_system")

        # Event type
        event_type = raw_event.get("event_type")
        if not event_type:
            if layer == "network":
                event_type = "network_flow"
            elif layer == "endpoint":
                event_type = "process_activity" if pid is not None else "endpoint_event"
            else:
                event_type = "application_request"

        # ── 13. Construct Validated UnifiedEvent ──────────────────────────
        try:
            return UnifiedEvent(
                event_id=event_id,
                timestamp=timestamp,
                layer=layer,
                src_entity=src_entity,
                dst_entity=dst_entity,
                src_internal=src_internal,
                dst_internal=dst_internal,
                # Network fields
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                packets_sent=packets_sent,
                packets_received=packets_received,
                duration_ms=duration_ms,
                tcp_flags=raw_event.get("tcp_flags"),
                # Endpoint fields
                process_name=process_name,
                parent_process=parent_process,
                user_account=user_account,
                pid=pid,
                parent_pid=parent_pid,
                file_path=file_path,
                action=action,
                host_id=host_id,
                process_guid=process_guid,
                socket_id=socket_id,
                telemetry_source=raw_event.get("telemetry_source"),
                # Application fields
                http_method=http_method,
                endpoint_path=endpoint_path,
                status_code=status_code,
                payload_size_bytes=raw_event.get("payload_size_bytes"),
                user_agent=raw_event.get("user_agent"),
                geo_country=raw_event.get("geo_country"),
                auth_result=auth_result,
                # Derived fields
                hour_of_day=hour,
                is_business_hours=is_business,
                bytes_ratio=bytes_ratio,
                port_risk_score=port_risk,
                connections_per_minute=raw_event.get("connections_per_minute"),
                # Provenance and Phase 25 metadata
                event_type=event_type,
                ingestion_timestamp=ingestion_ts,
                source_system=eff_source_system,
                schema_version=raw_event.get("schema_version") or "25.0.0",
                provenance=provenance,
                missing_fields=sorted(list(set(missing_fields))),
                clock_skew_detected=clock_skew_detected,
                # Training / evaluation labels
                scenario_id=raw_event.get("scenario_id"),
                scenario_type=raw_event.get("scenario_type"),
                generator_version=raw_event.get("generator_version"),
                raw_label=raw_event.get("raw_label"),
                attack_type=raw_event.get("attack_type"),
            )
        except Exception as exc:
            if strict:
                raise NormalizationError(f"Validation failure during UnifiedEvent construction: {exc}", raw_event=raw_event)
            logger.warning("UnifiedEvent validation failed: %s | event=%s", exc, sanitized_raw)
            return None
