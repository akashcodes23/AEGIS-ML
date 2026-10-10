from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime, timezone
import uuid

class UnifiedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    layer: Literal["network", "endpoint", "application"]
    src_entity: str
    dst_entity: str
    src_internal: bool
    dst_internal: bool

    # Network fields
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration_ms: Optional[int] = None
    tcp_flags: Optional[str] = None

    # Endpoint fields
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    user_account: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    file_path: Optional[str] = None
    action: Optional[str] = None

    # Process-to-network attribution fields (Phase 13)
    host_id: Optional[str] = None
    process_guid: Optional[str] = None
    process_start_time: Optional[datetime] = None
    process_end_time: Optional[datetime] = None
    connection_direction: Optional[Literal["inbound", "outbound", "unknown"]] = None
    socket_id: Optional[str] = None
    telemetry_source: Optional[str] = None

    # Application fields
    http_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    status_code: Optional[int] = None
    payload_size_bytes: Optional[int] = None
    user_agent: Optional[str] = None
    geo_country: Optional[str] = None
    auth_result: Optional[str] = None

    # Computed at normalization
    hour_of_day: Optional[int] = None
    is_business_hours: Optional[bool] = None
    bytes_ratio: Optional[float] = None
    port_risk_score: Optional[float] = None
    connections_per_minute: Optional[float] = None

    # Scenario provenance metadata (Phase 17)
    scenario_id: Optional[str] = None
    scenario_type: Optional[str] = None
    generator_version: Optional[str] = None

    # Training labels (None in demo mode)
    raw_label: Optional[str] = None
    attack_type: Optional[str] = None

    # Phase 25 Canonical Telemetry & Ingestion Fields
    event_type: Optional[str] = None
    ingestion_timestamp: Optional[datetime] = None
    packets_sent: Optional[int] = None
    packets_received: Optional[int] = None
    source_system: Optional[str] = None
    schema_version: str = "25.0.0"
    provenance: Optional[Dict[str, Any]] = None
    missing_fields: List[str] = Field(default_factory=list)
    clock_skew_detected: Optional[bool] = None
    is_late_arriving: Optional[bool] = None
    dedup_fingerprint: Optional[str] = None

    @field_validator("timestamp", "ingestion_timestamp", "process_start_time", "process_end_time", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, (int, float)):
            if v > 1e14:  # microseconds
                v = v / 1e6
            elif v > 1e11:  # milliseconds
                v = v / 1e3
            return datetime.utcfromtimestamp(v)
        if isinstance(v, str):
            v_str = v.strip()
            if not v_str or v_str.lower() in ("none", "null", "nan"):
                return None
            try:
                dt = datetime.fromisoformat(v_str.replace("Z", "+00:00"))
            except Exception:
                import dateutil.parser
                dt = dateutil.parser.parse(v_str)
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        if isinstance(v, datetime):
            if v.tzinfo is not None:
                return v.astimezone(timezone.utc).replace(tzinfo=None)
            return v
        return v



class DetectionResult(BaseModel):
    event_id: str
    timestamp: datetime
    layer: str
    src_entity: str
    dst_entity: str
    if_score: float = 0.0
    baseline_deviation: float = 0.0
    graph_score: float = 0.0
    threat_type: Optional[str] = None
    confidence: float = 0.0
    classifier_probability: Optional[float] = None
    severity: Optional[str] = None
    is_alert: bool = False
    fused_score: float = 0.0
    local_deviations: Dict[str, float] = {}
    is_calibrated: bool = False
    calibrated_probabilities: Optional[Dict[str, float]] = None
    raw_probabilities: Optional[Dict[str, float]] = None
    model_version: Optional[str] = None
    confidence_qualification: Optional[str] = None


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    timestamp: Optional[datetime] = None
    threat_type: str
    severity: str
    confidence: float = 0.5  # Backwards compatibility
    classifier_probability: Optional[float] = None  # Random Forest tree vote consensus
    anomaly_score: float = 0.0  # Isolation Forest continuous outlier score
    baseline_deviation: float = 0.0
    fused_risk_score: float = 0.0
    src_entity: str
    dst_entity: str
    layer: str
    layers_involved: List[str] = []
    source_file: Optional[str] = None
    is_synthetic: bool = False
    feature_importance: Dict[str, float] = {}  # Local explanations / deviations
    global_feature_importances: Dict[str, float] = {}  # Model-level importances
    explanation: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    current_kill_chain_stage: Optional[str] = None
    predicted_next_stage: Optional[str] = None
    fingerprint: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None
    is_false_positive: Optional[bool] = None  # None if unlabelled/unknown
    fp_reason: Optional[str] = None
    status: Literal["open", "investigating", "resolved", "isolated"] = "open"
    is_calibrated: bool = False
    calibrated_confidence: Optional[float] = None
    calibrated_probabilities: Optional[Dict[str, float]] = None
    raw_probabilities: Optional[Dict[str, float]] = None
    model_version: Optional[str] = None
    confidence_qualification: Optional[str] = None


class TimelineEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    entity: str
    title: str
    description: str
    claim_type: Literal["observation", "hypothesis"]  # Concrete observed telemetry vs inferred hypothesis
    evidence_type: str  # e.g., Network Flow, Statistical Anomaly, Kill Chain Stage
    confidence_or_severity: Optional[str] = None
    linked_event_id: Optional[str] = None


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    title: str = "Correlated Network Threat"
    status: Literal["open", "investigating", "resolved", "isolated"] = "open"
    threat_type: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    priority_score: float = 50.0  # 0 to 100
    risk_score: float = 0.5  # 0.0 to 1.0 composite risk
    confidence: float = 0.5
    classifier_probability: Optional[float] = None
    anomaly_score: float = 0.0
    primary_attacker: Optional[str] = None
    primary_target: Optional[str] = None
    affected_entities: List[str] = []
    layers_involved: List[str] = []
    alert_ids: List[str] = []
    supporting_events: List[Dict[str, Any]] = []
    timeline: List[TimelineEntry] = []
    correlation_reason: str = ""
    alternative_hypotheses: List[str] = []
    is_synthetic: bool = False
    source_files: List[str] = []
    mitre_techniques: List[Dict[str, Any]] = []
    current_kill_chain_stage: Optional[str] = None
    predicted_next_stage: Optional[str] = None
    playbook: Optional[List[str]] = None
    is_false_positive: Optional[bool] = None
    fp_reason: Optional[str] = None
    matched_rules: List[str] = []
    relationship_evidence: List[Dict[str, Any]] = []
    uncertainty_notes: List[str] = []
    priority_calculation_breakdown: Dict[str, Any] = {}


# ── Phase 25 Ingestion & Streaming Schemas ───────────────────────────────────

class IngestionEventRequest(BaseModel):
    raw_event: Dict[str, Any]
    source_system: Optional[str] = None
    schema_version: Optional[str] = "25.0.0"
    trigger_detection: bool = False


class IngestionBatchRequest(BaseModel):
    events: List[Dict[str, Any]]
    source_system: Optional[str] = None
    schema_version: Optional[str] = "25.0.0"
    trigger_detection: bool = False


class IngestionItemResult(BaseModel):
    event_id: Optional[str] = None
    status: Literal["accepted", "duplicate", "rejected"]
    reason: Optional[str] = None
    is_late_arriving: bool = False
    clock_skew_detected: bool = False
    event: Optional[UnifiedEvent] = None
    detection: Optional[DetectionResult] = None
    alert: Optional[Alert] = None


class IngestionBatchResponse(BaseModel):
    total_received: int
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    results: List[IngestionItemResult]


class StreamingIngestionStats(BaseModel):
    total_ingested: int
    total_duplicates: int
    total_rejected: int
    total_late_arriving: int
    total_clock_skew: int
    watermark_timestamp: Optional[datetime] = None
    active_hosts_tracked: int


