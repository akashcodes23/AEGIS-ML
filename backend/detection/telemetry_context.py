"""AEGIS-ML Phase 20: Telemetry-Context Features and Missingness Indicators.

Module: backend.detection.telemetry_context

Provides explicit telemetry-context features and missingness indicators:
1. Layer context: is_network_layer, is_endpoint_layer, is_application_layer.
2. Context presence: has_process_context, has_network_context.
3. Traffic directionality: direction_internal, direction_outbound, direction_inbound.
4. Transfer size category: transfer_size_bucket (binned ordinal).
5. Verified socket binding: has_verified_socket_binding (strictly unobserved/0.0 if not present).
6. Explicit missingness indicators: missing_dst_port, missing_bytes_sent, missing_bytes_received, missing_process_name, missing_auth_result.

Strict Attribution Semantics:
- Does NOT fabricate process GUIDs, socket IDs, or event relationships.
- Unobserved attribution is explicitly represented as unknown (0.0).
- Provenance identifiers (scenario_id, scenario_type, generator_version, event_id)
  are strictly prohibited from all feature vectors.
"""

from typing import List, Dict, Any, Optional, Set
import math
import numpy as np

from backend.core.schemas import UnifiedEvent


SUPPORTED_CONTEXT_FEATURE_NAMES: List[str] = [
    "is_network_layer",
    "is_endpoint_layer",
    "is_application_layer",
    "has_process_context",
    "has_network_context",
    "direction_internal",
    "direction_outbound",
    "direction_inbound",
    "transfer_size_bucket",
    "has_verified_socket_binding",
]

MISSINGNESS_FEATURE_NAMES: List[str] = [
    "missing_dst_port",
    "missing_bytes_sent",
    "missing_bytes_received",
    "missing_process_name",
    "missing_auth_result",
]


def extract_telemetry_context_features(event: UnifiedEvent) -> List[float]:
    """
    Extract 10 explicit telemetry-context features from a UnifiedEvent.
    
    Guarantees:
    - Never uses provenance fields (scenario_id, scenario_type, generator_version).
    - Never fabricates socket identifiers or process bindings.
    """
    # 1. Layer context
    layer_str = (event.layer or "").lower()
    is_network = 1.0 if layer_str == "network" else 0.0
    is_endpoint = 1.0 if layer_str == "endpoint" else 0.0
    is_application = 1.0 if layer_str == "application" else 0.0

    # 2. Context presence
    has_process = 1.0 if event.process_name is not None and len(str(event.process_name).strip()) > 0 else 0.0
    has_network = 1.0 if (event.dst_port is not None or event.bytes_sent is not None) else 0.0

    # 3. Traffic directionality
    src_int = event.src_internal if event.src_internal is not None else True
    dst_int = event.dst_internal if event.dst_internal is not None else True

    conn_dir = (event.connection_direction or "").lower()
    if conn_dir == "internal":
        dir_internal, dir_outbound, dir_inbound = 1.0, 0.0, 0.0
    elif conn_dir == "outbound":
        dir_internal, dir_outbound, dir_inbound = 0.0, 1.0, 0.0
    elif conn_dir == "inbound":
        dir_internal, dir_outbound, dir_inbound = 0.0, 0.0, 1.0
    else:
        # Infer from internal IP flags safely
        dir_internal = 1.0 if (src_int and dst_int) else 0.0
        dir_outbound = 1.0 if (src_int and not dst_int) else 0.0
        dir_inbound = 1.0 if (not src_int and dst_int) else 0.0

    # 4. Transfer size bucket (binned ordinal)
    # 0.0: None / no bytes recorded
    # 1.0: Small (< 10 KB)
    # 2.0: Medium (10 KB - 1 MB)
    # 3.0: Large (1 MB - 50 MB)
    # 4.0: Bulk (> 50 MB)
    bs = event.bytes_sent
    if bs is None or bs <= 0:
        transfer_bucket = 0.0
    elif bs < 10240:
        transfer_bucket = 1.0
    elif bs < 1048576:
        transfer_bucket = 2.0
    elif bs < 52428800:
        transfer_bucket = 3.0
    else:
        transfer_bucket = 4.0

    # 5. Verified socket binding
    # Only 1.0 if BOTH socket_id and process_guid are verified on the event
    has_verified_binding = 1.0 if (event.socket_id is not None and event.process_guid is not None) else 0.0

    vec = [
        float(is_network),
        float(is_endpoint),
        float(is_application),
        float(has_process),
        float(has_network),
        float(dir_internal),
        float(dir_outbound),
        float(dir_inbound),
        float(transfer_bucket),
        float(has_verified_binding),
    ]

    assert len(vec) == len(SUPPORTED_CONTEXT_FEATURE_NAMES)
    return vec


def extract_missingness_features(event: UnifiedEvent) -> List[float]:
    """
    Extract 5 explicit missingness indicator features from a UnifiedEvent.
    
    Returns 1.0 if the field is missing (None), else 0.0.
    Enables trees to distinguish unobserved fields from explicit zero values.
    """
    m_port = 1.0 if event.dst_port is None else 0.0
    m_bytes_sent = 1.0 if event.bytes_sent is None else 0.0
    m_bytes_recv = 1.0 if event.bytes_received is None else 0.0
    m_process = 1.0 if event.process_name is None else 0.0
    m_auth = 1.0 if event.auth_result is None else 0.0

    vec = [
        float(m_port),
        float(m_bytes_sent),
        float(m_bytes_recv),
        float(m_process),
        float(m_auth),
    ]

    assert len(vec) == len(MISSINGNESS_FEATURE_NAMES)
    return vec
