from pydantic import BaseModel, Field
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime
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

    # Training labels (None in demo mode)
    raw_label: Optional[str] = None
    attack_type: Optional[str] = None


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

