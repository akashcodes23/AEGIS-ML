from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime, timezone
from enum import Enum
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
    incident_id: Optional[str] = None
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


# ── Phase 25 & 27 Ingestion, Streaming, and Queue Schemas ─────────────────────

class EventProcessingState(str, Enum):
    """Explicit lifecycle state of an event in the AEGIS-ML ingestion and detection pipeline."""
    ACCEPTED = "accepted"            # Normalized and accepted into process memory
    QUEUED = "queued"                # Enqueued onto in-memory detection worker queue
    PROCESSING = "processing"        # Dequeued; actively undergoing feature extraction or ML inference
    COMPLETED = "completed"          # Finished detection and incident correlation
    DUPLICATE = "duplicate"          # Rejected as exact event_id or sliding-window payload duplicate
    REJECTED = "rejected"            # Rejected due to schema validation or normalizer failure
    RETRY_PENDING = "retry_pending"  # Transient failure encountered; waiting for backoff retry
    FAILED = "failed"                # Permanent failure or retry limit exhausted (dead letter)


class QueueBackpressurePolicy(str, Enum):
    """Policy applied when the bounded in-memory detection queue is saturated."""
    REJECT = "reject"                # Immediately reject with queue_full reason
    BLOCK_TIMEOUT = "block_timeout"  # Wait up to timeout_seconds before rejecting with queue_saturated


class AsyncQueueConfig(BaseModel):
    """Configuration for bounded asynchronous detection worker pool."""
    max_queue_size: int = 1000
    worker_concurrency: int = 2
    backpressure_policy: QueueBackpressurePolicy = QueueBackpressurePolicy.REJECT
    timeout_seconds: float = 0.5
    max_retries: int = 3
    retry_backoff_base_seconds: float = 0.05
    retry_backoff_multiplier: float = 2.0
    dead_letter_capacity: int = 500


class DeadLetterItem(BaseModel):
    """Record of an event that permanently failed detection processing."""
    event_id: Optional[str] = None
    event: Optional[Dict[str, Any]] = None
    failed_at: datetime = Field(default_factory=datetime.utcnow)
    attempts: int = 0
    failure_reason: str
    transient: bool = False


class QueueMetrics(BaseModel):
    """Real-time observability metrics for the asynchronous detection queue."""
    queue_depth: int = 0
    queue_capacity: int = 1000
    accepted_events: int = 0
    queued_events: int = 0
    processing_events: int = 0
    completed_events: int = 0
    failed_events: int = 0
    retry_count: int = 0
    duplicate_count: int = 0
    rejected_count: int = 0
    dead_letter_count: int = 0
    queue_wait_time_ms: Dict[str, float] = Field(default_factory=lambda: {"p50": 0.0, "p95": 0.0, "mean": 0.0})
    processing_time_ms: Dict[str, float] = Field(default_factory=lambda: {"p50": 0.0, "p95": 0.0, "mean": 0.0})
    end_to_end_latency_ms: Dict[str, float] = Field(default_factory=lambda: {"p50": 0.0, "p95": 0.0, "mean": 0.0})
    worker_health: str = "healthy"  # "healthy", "degraded", "stopped"
    active_workers: int = 0
    inference_failure_count: int = 0
    is_durable: bool = False
    durability_guarantee: str = "in_memory_volatile_queue_loss_possible_on_process_restart"


class IngestionEventRequest(BaseModel):
    raw_event: Dict[str, Any]
    source_system: Optional[str] = None
    schema_version: Optional[str] = "25.0.0"
    trigger_detection: bool = False
    async_detection: bool = False


class IngestionBatchRequest(BaseModel):
    events: List[Dict[str, Any]]
    source_system: Optional[str] = None
    schema_version: Optional[str] = "25.0.0"
    trigger_detection: bool = False
    async_detection: bool = False


class IngestionItemResult(BaseModel):
    event_id: Optional[str] = None
    status: Literal["accepted", "duplicate", "rejected", "queued"] = "accepted"
    reason: Optional[str] = None
    is_late_arriving: bool = False
    clock_skew_detected: bool = False
    event: Optional[UnifiedEvent] = None
    detection: Optional[DetectionResult] = None
    alert: Optional[Alert] = None
    processing_state: Optional[str] = None
    queue_position: Optional[int] = None


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
    queue_metrics: Optional[QueueMetrics] = None


class ReplayRequest(BaseModel):
    events: List[Dict[str, Any]]
    mode: Optional[str] = "chronological"
    jitter_max_seconds: Optional[float] = 0.0
    out_of_order_probability: Optional[float] = 0.0
    duplicate_injection_rate: Optional[float] = 0.0
    trigger_detection: Optional[bool] = False
    seed: Optional[int] = 42


class ReplayResponse(BaseModel):
    status: str = "success"
    summary: Dict[str, Any]
    alerts_generated: int
    incidents_created: int



