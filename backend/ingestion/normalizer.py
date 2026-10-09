"""
backend/ingestion/normalizer.py
──────────────────────────────────────────────────────────────────────────────
NormalizerPipeline: translates raw dicts from any log source (network,
endpoint, application) into validated UnifiedEvent objects.

Derived fields computed here:
  • src_internal / dst_internal  – IPs resolved against INTERNAL_IPS list
  • hour_of_day                   – extracted from timestamp
  • is_business_hours             – True between 08:00 – 18:00
  • bytes_ratio                   – bytes_sent / (bytes_received + 1)
  • port_risk_score               – looked up from PORT_RISK config table
  • hour_sin / hour_cos           – cyclic encodings (stored in raw_label
                                     field override is NOT done here; these
                                     are available as local variables for
                                     downstream feature engineering)
"""

from __future__ import annotations

import logging
from datetime import datetime
from math import cos, pi, sin, log
from typing import Optional

from backend.core.config import INTERNAL_IPS, PORT_RISK
from backend.core.schemas import UnifiedEvent

logger = logging.getLogger(__name__)

# Fields from the raw dict that map 1-to-1 onto UnifiedEvent model fields
_PASSTHROUGH_FIELDS = frozenset(UnifiedEvent.model_fields.keys())


class NormalizerPipeline:
    """Stateless pipeline: call :meth:`normalize` on each raw log dict."""

    @staticmethod
    def normalize(raw_event: dict) -> Optional[UnifiedEvent]:
        """
        Accept a raw dict from any log source, auto-detect its layer, map
        fields into a :class:`~backend.core.schemas.UnifiedEvent`, compute
        derived fields, and return a validated model instance.

        Parameters
        ----------
        raw_event:
            Arbitrary dict as produced by a data-generator or log adaptor.

        Returns
        -------
        UnifiedEvent | None
            A fully-validated event, or ``None`` if the layer cannot be
            detected or if Pydantic validation fails.
        """

        # ── 1. Layer detection ────────────────────────────────────────────
        if "dst_port" in raw_event or "bytes_sent" in raw_event:
            layer = "network"
        elif "process_name" in raw_event or "pid" in raw_event:
            layer = "endpoint"
        elif "http_method" in raw_event or "status_code" in raw_event:
            layer = "application"
        else:
            logger.debug("Layer undetectable – skipping event: %s", raw_event)
            return None

        # ── 2. Internal-IP flags ──────────────────────────────────────────
        src_ip: str = raw_event.get("src_ip", "") or ""
        dst_ip: str = raw_event.get("dst_ip", "") or ""
        src_internal: bool = src_ip in INTERNAL_IPS
        dst_internal: bool = dst_ip in INTERNAL_IPS

        # ── 3. Temporal derived fields ────────────────────────────────────
        raw_ts = raw_event.get("timestamp")
        timestamp: datetime = (
            raw_ts if isinstance(raw_ts, datetime) else datetime.now()
        )
        hour: int = timestamp.hour
        hour_sin: float = sin(2 * pi * hour / 24)   # cyclic feature
        hour_cos: float = cos(2 * pi * hour / 24)   # cyclic feature
        is_business: bool = 8 <= hour <= 18

        # ── 4. Traffic-volume derived fields ─────────────────────────────
        bytes_sent: int = max(0, int(raw_event.get("bytes_sent", 0) or 0))
        bytes_recv: int = max(0, int(raw_event.get("bytes_received", 0) or 0))
        bytes_ratio: float = log(1.0 + bytes_sent) / log(2.0 + bytes_recv)

        # ── 5. Port-risk score ────────────────────────────────────────────
        dst_port = raw_event.get("dst_port")
        port_risk: float = PORT_RISK.get(dst_port, 0.0) if dst_port else 0.0

        # ── 6. Entity resolution ──────────────────────────────────────────
        src_entity: str = (
            raw_event.get("src_ip")
            or raw_event.get("user_account")
            or ""
        )
        dst_entity: str = (
            raw_event.get("dst_ip")
            or raw_event.get("file_path")
            or ""
        )

        # ── 7. Collect pass-through fields ───────────────────────────────
        # Exclude any key we have already set explicitly above so that we
        # never pass a duplicate keyword argument to the constructor.
        _explicit = {
            "timestamp", "layer", "src_entity", "dst_entity",
            "src_internal", "dst_internal", "hour_of_day",
            "is_business_hours", "bytes_ratio", "port_risk_score",
        }
        passthrough = {
            k: v
            for k, v in raw_event.items()
            if k in _PASSTHROUGH_FIELDS and k not in _explicit
        }

        # ── 8. Build and validate UnifiedEvent ───────────────────────────
        try:
            return UnifiedEvent(
                # Core identity
                timestamp=timestamp,
                layer=layer,
                src_entity=src_entity,
                dst_entity=dst_entity,
                src_internal=src_internal,
                dst_internal=dst_internal,
                # Derived / computed
                hour_of_day=hour,
                is_business_hours=is_business,
                bytes_ratio=bytes_ratio,
                port_risk_score=port_risk,
                # Merge raw pass-through fields last so that any explicit
                # derived value above wins over the raw counterpart.
                **passthrough,
            )
        except Exception as exc:
            logger.warning("Normalization failed: %s | event=%s", exc, raw_event)
            return None
