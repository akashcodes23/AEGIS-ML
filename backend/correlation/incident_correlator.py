"""
AEGIS-ML Incremental Incident Correlator
Correlates security alerts and events into structured, evidence-backed Incidents.
Features:
- Deterministic event deduplication via cryptographic fingerprinting
- Configurable sliding time windows
- Entity, host session, and kill-chain phase progression linking
- Clear separation of concrete Observations vs inferential Hypotheses
- Alternative benign interpretations and uncertainty reporting
- Evidence traceability back to raw event IDs
"""

import hashlib
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

try:
    from core.schemas import Alert, Incident, TimelineEntry, UnifiedEvent
    from core.config import MITRE_TECHNIQUES, KILL_CHAIN_STAGES
except ModuleNotFoundError:
    from backend.core.schemas import Alert, Incident, TimelineEntry, UnifiedEvent
    from backend.core.config import MITRE_TECHNIQUES, KILL_CHAIN_STAGES

logger = logging.getLogger(__name__)

# Alternative benign hypotheses by threat type
ALTERNATIVE_HYPOTHESES: Dict[str, List[str]] = {
    "brute_force": [
        "Automated script or service account running with an expired password.",
        "Internal vulnerability scanner or configuration audit probe.",
        "Misconfigured LDAP/AD client attempting periodic retry loops.",
    ],
    "lateral_movement": [
        "Legitimate systems administration or configuration deployment (e.g. Ansible, Puppet, SSH).",
        "Scheduled IT maintenance script executing remote commands across nodes.",
        "Internal network diagnostics or asset inventory scan.",
    ],
    "data_exfiltration": [
        "Scheduled off-site database or filesystem cloud backup.",
        "Large software update or ISO artifact transfer by an authorized developer.",
        "Legitimate user transferring media or compressed archive to external cloud storage.",
    ],
    "c2_beaconing": [
        "Periodic NTP synchronization, DNS keep-alive, or telemetry heartbeat from licensed software.",
        "Health-check monitoring probe querying external status endpoints.",
        "Cloud agent (e.g., Datadog, AWS SSM) transmitting normal telemetry packets.",
    ],
    "statistical_anomaly": [
        "Sudden seasonal or peak-business traffic burst.",
        "New developer workstation or microservice spinning up in the environment.",
        "Unscheduled database maintenance generating atypical bandwidth.",
    ],
}

RECOMMENDED_PLAYBOOKS: Dict[str, List[str]] = {
    "brute_force": [
        "Inspect target authentication service logs for repeated failure patterns.",
        "Verify if any login attempts succeeded from the source IP.",
        "Block or rate-limit the source IP at perimeter/host firewall.",
        "Trigger forced password reset and MFA prompt for targeted accounts.",
    ],
    "lateral_movement": [
        "Isolate the source endpoint from the VLAN to contain movement.",
        "Invalidate active Kerberos/SSH/RDP sessions across affected hosts.",
        "Collect volatile memory dumps from intermediate pivot hosts.",
        "Cross-reference scheduled task creation and process ancestry logs.",
    ],
    "data_exfiltration": [
        "Immediately terminate outbound network session to external destination.",
        "Inspect NetFlow/proxy logs to identify exact payload volume and destination ASN.",
        "Notify Data Loss Prevention (DLP) and Incident Response lead.",
        "Preserve packet captures and disk forensically for legal compliance.",
    ],
    "c2_beaconing": [
        "Sinkhole or block destination IP and DNS domain across corporate resolvers.",
        "Quarantine beaconing host and scan running memory for injected DLLs/processes.",
        "Inspect parent process and persistence mechanisms (cron, registry, services).",
        "Hunt across network fleet for matching beacon intervals and jitter.",
    ],
    "default": [
        "Preserve event telemetry and raw packet evidence.",
        "Verify whether observed entity behavior aligns with scheduled business tasks.",
        "Review affected systems for unauthorized configuration alterations.",
        "Escalate to Security Operations Tier 2 if malicious intent is corroborated.",
    ],
}


class IncidentCorrelator:
    """
    Incremental Correlation Engine for AEGIS-ML.
    Aggregates multi-layer alerts into coherent, evidence-traceable incidents.
    """

    def __init__(
        self,
        time_window_seconds: int = 600,  # 10 minutes sliding window
        dedup_window_seconds: int = 60,   # 1 minute deduplication cache
    ):
        self.time_window_seconds = time_window_seconds
        self.dedup_window_seconds = dedup_window_seconds
        self.incidents: Dict[str, Incident] = {}
        # Mapping from entity -> latest active incident_id
        self.entity_to_incident: Dict[str, str] = {}
        # Mapping from entity -> list of all associated incident_ids
        self.entity_to_incidents: Dict[str, List[str]] = {}
        # Mapping from host_id -> list of incident_ids
        self.host_to_incidents: Dict[str, List[str]] = {}
        # Mapping from socket_id -> incident_id
        self.socket_to_incident: Dict[str, str] = {}
        # Deduplication cache: fingerprint -> timestamp
        self.seen_fingerprints: Dict[str, datetime] = {}

    def _extract_process_telemetry(self, alert: Alert, raw_event: Optional[UnifiedEvent] = None) -> Dict[str, Any]:
        """Extract process and socket attribution fields from alert and raw_event."""
        raw = alert.raw_event or {}
        host = (raw_event.host_id if raw_event and raw_event.host_id else None) or raw.get("host_id") or alert.src_entity
        pid = (raw_event.pid if raw_event and raw_event.pid is not None else None) or raw.get("pid")
        pname = (raw_event.process_name if raw_event and raw_event.process_name else None) or raw.get("process_name")
        socket_id = (raw_event.socket_id if raw_event and raw_event.socket_id else None) or raw.get("socket_id")
        guid = (raw_event.process_guid if raw_event and raw_event.process_guid else None) or raw.get("process_guid")
        pstart = (raw_event.process_start_time if raw_event and raw_event.process_start_time else None) or raw.get("process_start_time")
        direction = (raw_event.connection_direction if raw_event and raw_event.connection_direction else None) or raw.get("connection_direction")
        return {
            "host_id": host,
            "pid": pid,
            "process_name": pname,
            "socket_id": socket_id,
            "process_guid": guid,
            "process_start_time": pstart,
            "connection_direction": direction,
        }

    def compute_event_fingerprint(self, event: UnifiedEvent) -> str:
        """
        Deterministic SHA-256 fingerprint for deduplication.
        Fingerprint represents the invariant event payload characteristics:
        source, destination, layer, protocol, ports, bytes, and action.
        Temporal deduplication across intervals is governed by is_duplicate() window.
        """
        payload = (
            f"{event.src_entity}|{event.dst_entity}|{event.layer}|"
            f"{event.src_port}|{event.dst_port}|{event.protocol}|{event.bytes_sent}|{event.action}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def is_duplicate(self, fingerprint: str, event_time: Optional[datetime] = None) -> bool:
        """
        Check if an identical event fingerprint was processed within the deduplication window.
        """
        now = event_time if isinstance(event_time, datetime) else datetime.utcnow()
        if fingerprint in self.seen_fingerprints:
            last_seen = self.seen_fingerprints[fingerprint]
            if abs((now - last_seen).total_seconds()) <= self.dedup_window_seconds:
                return True
        self.seen_fingerprints[fingerprint] = now
        # Prune old fingerprints occasionally
        if len(self.seen_fingerprints) > 10000:
            cutoff = now - timedelta(seconds=self.dedup_window_seconds * 2)
            self.seen_fingerprints = {k: v for k, v in self.seen_fingerprints.items() if v >= cutoff}
        return False

    def correlate_alert(self, alert: Alert, raw_event: Optional[UnifiedEvent] = None) -> Tuple[Incident, bool]:
        """
        Correlate an incoming Alert into an existing Incident or create a new one.

        Returns:
            Tuple[Incident, bool]: (Incident instance, is_new_incident boolean)
        """
        alert_time = alert.timestamp
        if alert_time is None and alert.raw_event and alert.raw_event.get("timestamp"):
            raw_ts = alert.raw_event["timestamp"]
            alert_time = raw_ts if isinstance(raw_ts, datetime) else None
            if alert_time is None:
                try:
                    alert_time = datetime.fromisoformat(str(raw_ts))
                except Exception:
                    pass
        if alert_time is None:
            alert_time = alert.created_at or datetime.utcnow()

        if not isinstance(alert_time, datetime):
            try:
                alert_time = datetime.fromisoformat(str(alert_time))
            except Exception:
                alert_time = datetime.utcnow()

        src = alert.src_entity
        dst = alert.dst_entity

        matched_incident: Optional[Incident] = None
        proc_tel = self._extract_process_telemetry(alert, raw_event)

        # 1. Search for active incident involving these entities/hosts/sockets within time window
        candidates = []
        candidate_ids = set()
        for ent in (src, dst):
            if ent:
                if hasattr(self, "entity_to_incidents") and ent in self.entity_to_incidents:
                    candidate_ids.update(self.entity_to_incidents[ent])
                elif ent in self.entity_to_incident:
                    candidate_ids.add(self.entity_to_incident[ent])

        if proc_tel.get("socket_id") and proc_tel["socket_id"] in getattr(self, "socket_to_incident", {}):
            candidate_ids.add(self.socket_to_incident[proc_tel["socket_id"]])
        if proc_tel.get("host_id") and proc_tel["host_id"] in getattr(self, "host_to_incidents", {}):
            candidate_ids.update(self.host_to_incidents[proc_tel["host_id"]])

        for cid in candidate_ids:
            if cid in self.incidents:
                candidates.append(self.incidents[cid])

        matched_rule = None
        for inc in candidates:
            if inc and inc.status in ["open", "investigating"]:
                diff = abs((alert_time - inc.updated_at).total_seconds())
                if diff <= self.time_window_seconds:
                    # Behavioral and process-to-network attribution check
                    is_rel, r_name = self._is_behaviorally_related(inc, alert, raw_event)
                    if is_rel:
                        matched_incident = inc
                        matched_rule = r_name
                        break

        is_new = False
        if matched_incident is None:
            # Create a new incident with a stable, deterministic ID prefix
            stable_seed = f"{src}_{alert_time.strftime('%Y%m%d%H%M')}_{alert.threat_type}"
            inc_id = f"INC-{hashlib.md5(stable_seed.encode()).hexdigest()[:8].upper()}"
            matched_incident = self._create_incident(inc_id, alert, alert_time, raw_event)
            is_new = True
        else:
            self._update_incident(matched_incident, alert, alert_time, raw_event, matched_rule=matched_rule)

        # Update entity, host, and socket lookups
        if src:
            self.entity_to_incident[src] = matched_incident.incident_id
            if not hasattr(self, "entity_to_incidents"):
                self.entity_to_incidents = {}
            self.entity_to_incidents.setdefault(src, [])
            if matched_incident.incident_id not in self.entity_to_incidents[src]:
                self.entity_to_incidents[src].append(matched_incident.incident_id)
        if dst:
            self.entity_to_incident[dst] = matched_incident.incident_id
            if not hasattr(self, "entity_to_incidents"):
                self.entity_to_incidents = {}
            self.entity_to_incidents.setdefault(dst, [])
            if matched_incident.incident_id not in self.entity_to_incidents[dst]:
                self.entity_to_incidents[dst].append(matched_incident.incident_id)
        if proc_tel.get("socket_id"):
            if not hasattr(self, "socket_to_incident"):
                self.socket_to_incident = {}
            self.socket_to_incident[proc_tel["socket_id"]] = matched_incident.incident_id
        if proc_tel.get("host_id"):
            if not hasattr(self, "host_to_incidents"):
                self.host_to_incidents = {}
            self.host_to_incidents.setdefault(proc_tel["host_id"], [])
            if matched_incident.incident_id not in self.host_to_incidents[proc_tel["host_id"]]:
                self.host_to_incidents[proc_tel["host_id"]].append(matched_incident.incident_id)

        self.incidents[matched_incident.incident_id] = matched_incident

        return matched_incident, is_new

    def _is_behaviorally_related(
        self,
        inc: Incident,
        alert: Alert,
        raw_event: Optional[UnifiedEvent] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify explicit behavioral link and process-to-network attribution.

        Rules:
          0. Directly observed process socket binding or corroborated host process lineage.
          1. Same primary attacker is continuing the campaign (strongest signal).
          2. A previously-compromised host is now acting as a pivot source.
          3. The attacker is directly targeting the primary target from an affected entity.
        """
        proc_tel = self._extract_process_telemetry(alert, raw_event)
        alert_host = proc_tel["host_id"]
        alert_pid = proc_tel["pid"]
        alert_pname = proc_tel["process_name"]
        alert_socket = proc_tel["socket_id"]
        alert_guid = proc_tel["process_guid"]
        alert_pstart = proc_tel["process_start_time"]

        # Check process-to-network attribution against existing supporting events
        for ev in inc.supporting_events:
            ev_host = ev.get("host_id") or ev.get("src_entity") or ev.get("src_ip")
            ev_socket = ev.get("socket_id")
            ev_guid = ev.get("process_guid")
            ev_pid = ev.get("pid")
            ev_pname = ev.get("process_name")
            ev_pstart = ev.get("process_start_time")

            # 1. Exact socket_id match on the same host
            if alert_socket and ev_socket and alert_socket == ev_socket:
                if alert_host == ev_host:
                    return True, "RULE_0_DIRECT_PROCESS_SOCKET_BINDING"

            # 2. Verified process_guid match on the same host
            if alert_guid and ev_guid and alert_guid == ev_guid:
                if alert_host == ev_host:
                    return True, "RULE_0_PROCESS_GUID_CORROBORATION"

            # 3. Matching process ID on the SAME host
            if alert_pid is not None and ev_pid is not None and alert_pid == ev_pid:
                # PIDs are strictly host-local: matching PIDs on different hosts are UNRELATED
                if alert_host == ev_host:
                    is_reuse = False
                    if alert_pstart and ev_pstart and alert_pstart != ev_pstart:
                        is_reuse = True
                    if alert_pname and ev_pname and alert_pname != ev_pname:
                        is_reuse = True
                    if not is_reuse:
                        return True, "RULE_0_PROCESS_LINEAGE_MATCH"

        # Rule 1: Same confirmed attacker continuing campaign
        if inc.primary_attacker and alert.src_entity == inc.primary_attacker:
            return True, "RULE_1_SAME_ATTACKER_CAMPAIGN"

        # Rule 2: Pivot / Lateral Movement — target of previous stage becomes source
        if alert.src_entity in inc.affected_entities:
            is_pivot = (
                alert.threat_type in ("lateral_movement", "brute_force")
                or (alert.current_kill_chain_stage and inc.current_kill_chain_stage
                    and alert.current_kill_chain_stage != inc.current_kill_chain_stage)
                or alert.src_entity == inc.primary_target  # Confirmed pivot: victim becomes attacker
            )
            if is_pivot:
                return True, "RULE_2_LATERAL_MOVEMENT_PIVOT"

        # Rule 3: Continued attack against the same primary target from a known affiliate
        if (inc.primary_target
                and alert.dst_entity == inc.primary_target
                and alert.src_entity == inc.primary_attacker):
            return True, "RULE_3_MULTI_STAGE_PROGRESSION"

        return False, None

    def _create_incident(
        self,
        inc_id: str,
        alert: Alert,
        alert_time: datetime,
        raw_event: Optional[UnifiedEvent] = None
    ) -> Incident:
        """Initialize a new structured incident from the initial triggering alert."""
        threat_type = alert.threat_type or "statistical_anomaly"
        title = f"{threat_type.replace('_', ' ').title()} Campaign targeting {alert.dst_entity}"

        entities = [alert.src_entity]
        if alert.dst_entity and alert.dst_entity not in entities:
            entities.append(alert.dst_entity)

        # Construct initial timeline entries (1 Observation, 1 Hypothesis)
        timeline = self._build_initial_timeline(alert, alert_time, raw_event)

        # Derive alternative hypotheses
        alt_hypotheses = ALTERNATIVE_HYPOTHESES.get(
            threat_type,
            ALTERNATIVE_HYPOTHESES["statistical_anomaly"]
        )

        playbook = RECOMMENDED_PLAYBOOKS.get(threat_type, RECOMMENDED_PLAYBOOKS["default"])

        # Trace supporting event
        supporting_events = []
        if alert.raw_event:
            supporting_events.append(alert.raw_event)
        elif raw_event:
            supporting_events.append(raw_event.model_dump())

        # Determine evidence-backed priority score and formula breakdown
        priority, risk, breakdown = self._calculate_priority_and_risk(
            severities=[alert.severity],
            layers=[alert.layer],
            event_count=1,
            max_prob=alert.classifier_probability or alert.confidence or 0.5,
            anomaly_score=alert.anomaly_score
        )

        reason = (
            f"Incident opened upon detection of {threat_type.replace('_', ' ')} "
            f"originating from {alert.src_entity} targeting {alert.dst_entity} "
            f"on {alert.layer} layer."
        )

        src_files = [alert.source_file] if alert.source_file else []

        # Concrete relationship evidence
        rel_evidence = [{
            "source_entity": alert.src_entity,
            "target_entity": alert.dst_entity or "unknown",
            "relationship_type": "observed_telemetry",
            "claim_type": "observation",
            "correlation_rule": "RULE_0_INITIAL_TRIGGER",
            "evidence_provenance": alert.source_file or ("synthetic_telemetry" if alert.is_synthetic else "network_telemetry"),
            "reason": f"Initial triggering {alert.layer} alert: {threat_type.replace('_', ' ')}",
            "supporting_event_ids": [alert.event_id or alert.alert_id],
            "timestamp": alert_time.isoformat(),
            "uncertainty_notes": "Initial telemetry observation. Multi-event context requires subsequent telemetry confirmation.",
            "missing_evidence": ["subsequent_activity_unobserved"],
        }]

        uncertainty_notes = [
            "Baseline deviation reflects comparative telemetry against normal entity baselines.",
            "Network entity identities assume un-spoofed IP and MAC telemetry.",
        ]
        if not alert.layer or alert.layer == "network":
            uncertainty_notes.append("Endpoint process lineage (parent PID, command line) is not present in network-layer telemetry.")

        return Incident(
            incident_id=inc_id,
            created_at=alert_time,
            updated_at=alert_time,
            title=title,
            status="open",
            threat_type=threat_type,
            severity=alert.severity if alert.severity in ["low", "medium", "high", "critical"] else "medium",
            priority_score=priority,
            risk_score=risk,
            confidence=round(alert.confidence, 4),
            classifier_probability=alert.classifier_probability,
            anomaly_score=round(alert.anomaly_score, 4),
            primary_attacker=alert.src_entity,
            primary_target=alert.dst_entity,
            affected_entities=entities,
            layers_involved=[alert.layer],
            alert_ids=[alert.alert_id],
            supporting_events=supporting_events,
            timeline=timeline,
            correlation_reason=reason,
            alternative_hypotheses=alt_hypotheses,
            is_synthetic=alert.is_synthetic,
            source_files=src_files,
            mitre_techniques=[{"id": alert.mitre_technique_id, "name": alert.mitre_technique_name}] if alert.mitre_technique_id else [],
            current_kill_chain_stage=alert.current_kill_chain_stage or "Initial Access",
            predicted_next_stage=alert.predicted_next_stage or "Execution",
            playbook=playbook,
            matched_rules=["RULE_0_INITIAL_TRIGGER_ALERT"],
            relationship_evidence=rel_evidence,
            uncertainty_notes=uncertainty_notes,
            priority_calculation_breakdown=breakdown,
        )

    def _update_incident(
        self,
        inc: Incident,
        alert: Alert,
        alert_time: datetime,
        raw_event: Optional[UnifiedEvent] = None,
        matched_rule: Optional[str] = None
    ) -> None:
        """Update an existing incident with a correlated alert and supporting event."""
        inc.updated_at = max(inc.updated_at, alert_time)
        if alert.alert_id not in inc.alert_ids:
            inc.alert_ids.append(alert.alert_id)

        # Track matched rules
        if matched_rule and matched_rule not in inc.matched_rules:
            inc.matched_rules.append(matched_rule)

        # Entities
        for e in [alert.src_entity, alert.dst_entity]:
            if e and e not in inc.affected_entities:
                inc.affected_entities.append(e)

        # Layers
        if alert.layer not in inc.layers_involved:
            inc.layers_involved.append(alert.layer)

        # Source files
        if alert.source_file and alert.source_file not in inc.source_files:
            inc.source_files.append(alert.source_file)

        # Supporting raw events — deduplicated by event_id to prevent bloat
        seen_event_ids = {
            e.get("event_id") for e in inc.supporting_events
            if isinstance(e, dict) and e.get("event_id")
        }
        new_ev_id = alert.event_id or alert.alert_id
        if alert.raw_event and alert.raw_event.get("event_id") not in seen_event_ids:
            inc.supporting_events.append(alert.raw_event)
        elif raw_event:
            ev_dict = raw_event.model_dump()
            if ev_dict.get("event_id") not in seen_event_ids:
                inc.supporting_events.append(ev_dict)

        # Add explicit relationship evidence with complete provenance, uncertainty, and missing evidence
        is_pivot = bool(matched_rule and "PIVOT" in matched_rule)
        has_endpoint = any(l == "endpoint" for l in inc.layers_involved) or (alert.layer == "endpoint") or bool(raw_event and raw_event.layer == "endpoint")
        has_network = any(l == "network" for l in inc.layers_involved) or (alert.layer == "network") or bool(raw_event and raw_event.layer == "network")
        is_cross_layer = has_endpoint and has_network

        proc_tel = self._extract_process_telemetry(alert, raw_event)
        alert_socket = proc_tel["socket_id"]
        alert_pid = proc_tel["pid"]
        alert_pname = proc_tel["process_name"]
        alert_host = proc_tel["host_id"]

        matched_rule_str = matched_rule or ""
        is_direct_socket_binding = matched_rule_str == "RULE_0_DIRECT_PROCESS_SOCKET_BINDING"
        is_process_corroboration = matched_rule_str in ("RULE_0_PROCESS_GUID_CORROBORATION", "RULE_0_PROCESS_LINEAGE_MATCH")

        # Also check if raw_event itself contains simultaneous endpoint process + network socket telemetry
        if not is_direct_socket_binding and raw_event and raw_event.pid and (raw_event.socket_id or (raw_event.dst_port and raw_event.dst_ip)):
            is_direct_socket_binding = True

        missing_evidence = []
        if is_direct_socket_binding:
            rel_type = "direct_process_socket_binding"
            claim_type = "observation"
            missing_evidence = []
            unc_note = (
                f"Direct socket binding verified tying process {alert_pname or ('PID ' + str(alert_pid))} "
                f"to network communication on host {alert_host}."
            )
        elif is_process_corroboration:
            rel_type = "corroborated_multi_observation"
            claim_type = "observation"
            missing_evidence = ["packet_payload_uninspected"]
            unc_note = (
                f"Process lineage ({alert_pname or ('PID ' + str(alert_pid))}) corroborated across "
                f"multiple observations on host {alert_host}."
            )
        elif is_cross_layer:
            rel_type = "cross_layer_co_occurrence"
            claim_type = "hypothesis"
            missing_evidence = ["socket_to_pid_binding_absent", "kernel_handle_lineage_unverified"]
            unc_note = (
                "File activity and network connection co-occur on the same host within the time window. "
                "Because OS process handle lineage and packet payload bindings are unverified, "
                "data exfiltration is an inferred hypothesis, not an established fact."
            )
        elif is_pivot:
            rel_type = "pivot_lateral_movement"
            claim_type = "hypothesis"
            missing_evidence = ["internal_pivot_credentials_unverified"]
            unc_note = (
                f"Entity {alert.src_entity} was a prior target/victim and is now initiating outbound attack traffic. "
                "Inferred as lateral pivot step; legitimate administrative chaining remains an alternative explanation."
            )
        else:
            rel_type = "observed_telemetry"
            claim_type = "observation"
            missing_evidence = []
            unc_note = f"Observed {alert.layer} telemetry associated via rule {matched_rule_str}."

        provenance_str = alert.source_file or ("synthetic_telemetry" if alert.is_synthetic else "network_telemetry")

        inc.relationship_evidence.append({
            "source_entity": alert.src_entity,
            "target_entity": alert.dst_entity or "unknown",
            "relationship_type": rel_type,
            "claim_type": claim_type,
            "correlation_rule": matched_rule_str,
            "evidence_provenance": provenance_str,
            "reason": f"Correlated via {matched_rule_str}: {alert.threat_type}",
            "supporting_event_ids": [new_ev_id],
            "timestamp": alert_time.isoformat(),
            "uncertainty_notes": unc_note,
            "missing_evidence": missing_evidence,
        })

        # Append timeline entries (Observation + Hypothesis)
        new_timeline = self._build_subsequent_timeline(inc, alert, alert_time, raw_event)
        inc.timeline.extend(new_timeline)

        # Escalating severity & threat type
        severities = ["low", "medium", "high", "critical"]
        curr_idx = severities.index(inc.severity) if inc.severity in severities else 1
        new_idx = severities.index(alert.severity) if alert.severity in severities else 1
        if new_idx > curr_idx:
            inc.severity = alert.severity

        # Kill chain stage progression
        if alert.current_kill_chain_stage:
            inc.current_kill_chain_stage = alert.current_kill_chain_stage
        if alert.predicted_next_stage:
            inc.predicted_next_stage = alert.predicted_next_stage

        # Recalculate priority & composite risk using UNIQUE alerts (prevents duplicate inflation)
        all_sevs = [inc.severity, alert.severity]
        prob = max(inc.classifier_probability or 0.0, alert.classifier_probability or 0.0, alert.confidence)
        unique_event_count = len(set(inc.alert_ids))
        priority, risk, breakdown = self._calculate_priority_and_risk(
            severities=all_sevs,
            layers=inc.layers_involved,
            event_count=unique_event_count,
            max_prob=prob,
            anomaly_score=max(inc.anomaly_score, alert.anomaly_score)
        )
        inc.priority_score = priority
        inc.risk_score = risk
        inc.confidence = round(prob, 4)
        inc.priority_calculation_breakdown = breakdown

        # Update correlation reason
        inc.correlation_reason = (
            f"Correlated {len(inc.alert_ids)} alerts across {len(inc.layers_involved)} layers "
            f"({', '.join(inc.layers_involved)}) involving {len(inc.affected_entities)} entities "
            f"linked to primary attacker {inc.primary_attacker} via rules: {', '.join(inc.matched_rules)}."
        )

    def _build_initial_timeline(
        self,
        alert: Alert,
        alert_time: datetime,
        raw_event: Optional[UnifiedEvent] = None
    ) -> List[TimelineEntry]:
        """Construct initial timeline with concrete Observation and inferred Hypothesis."""
        entries = []
        event_id = alert.event_id or alert.alert_id

        # 1. Concrete Observation
        obs_desc = (
            f"Observed {alert.layer} activity from {alert.src_entity} to {alert.dst_entity}."
        )
        if raw_event and raw_event.bytes_sent:
            obs_desc += f" Volume: {raw_event.bytes_sent} bytes transferred."
        if raw_event and raw_event.dst_port:
            obs_desc += f" Target Port: {raw_event.dst_port}/{raw_event.protocol or 'tcp'}."

        entries.append(TimelineEntry(
            timestamp=alert_time,
            entity=alert.src_entity,
            title="Telemetry Observation Recorded",
            description=obs_desc,
            claim_type="observation",
            evidence_type=f"{alert.layer.title()} Flow",
            confidence_or_severity=alert.severity,
            linked_event_id=event_id,
        ))

        # 2. Inferred Hypothesis
        hyp_desc = (
            f"Automated threat engine classified behavior as probable {alert.threat_type.replace('_', ' ')} "
            f"(Model consensus probability: {round((alert.classifier_probability or alert.confidence) * 100)}%, "
            f"Anomaly score: {round(alert.anomaly_score, 2)})."
        )
        entries.append(TimelineEntry(
            timestamp=alert_time,
            entity=alert.dst_entity,
            title="Threat Hypothesis Inferred",
            description=hyp_desc,
            claim_type="hypothesis",
            evidence_type="Model Inference",
            confidence_or_severity=alert.severity,
            linked_event_id=event_id,
        ))

        return entries

    def _build_subsequent_timeline(
        self,
        inc: Incident,
        alert: Alert,
        alert_time: datetime,
        raw_event: Optional[UnifiedEvent] = None
    ) -> List[TimelineEntry]:
        """Construct follow-up timeline entries for correlated events."""
        entries = []
        event_id = alert.event_id or alert.alert_id

        # Observation
        obs_desc = (
            f"Correlated subsequent {alert.layer} event: {alert.src_entity} -> {alert.dst_entity}."
        )
        if raw_event and raw_event.bytes_sent:
            obs_desc += f" Transferred {raw_event.bytes_sent} bytes."
        entries.append(TimelineEntry(
            timestamp=alert_time,
            entity=alert.src_entity,
            title="Additional Correlated Telemetry",
            description=obs_desc,
            claim_type="observation",
            evidence_type=f"{alert.layer.title()} Flow",
            confidence_or_severity=alert.severity,
            linked_event_id=event_id,
        ))

        # Hypothesis if stage escalated
        if alert.current_kill_chain_stage and alert.current_kill_chain_stage != inc.current_kill_chain_stage:
            entries.append(TimelineEntry(
                timestamp=alert_time,
                entity=alert.dst_entity,
                title=f"Kill Chain Escalation: {alert.current_kill_chain_stage}",
                description=(
                    f"Behavioral progression matches transition to MITRE ATT&CK {alert.current_kill_chain_stage} stage. "
                    f"Predicted next step: {alert.predicted_next_stage}."
                ),
                claim_type="hypothesis",
                evidence_type="Kill Chain Analysis",
                confidence_or_severity=alert.severity,
                linked_event_id=event_id,
            ))

        return entries

    def _calculate_priority_and_risk(
        self,
        severities: List[str],
        layers: List[str],
        event_count: int,
        max_prob: float,
        anomaly_score: float
    ) -> Tuple[float, float, Dict[str, Any]]:
        """
        Evidence-based priority (0 to 100) and composite risk (0.0 to 1.0)
        with an explicit, documented calculation breakdown.
        """
        sev_weights = {"low": 20.0, "medium": 45.0, "high": 75.0, "critical": 95.0}
        highest_sev = max([sev_weights.get(s, 40.0) for s in severities])

        # Layer diversity bonus (+10 per additional layer, capped at 20)
        layer_bonus = min(len(set(layers)) * 10.0, 20.0)

        # Unique event frequency bonus (+2 per event, capped at 15)
        count_bonus = min(event_count * 2.0, 15.0)

        # Probabilistic model confidence weight
        confidence_factor = max_prob * 10.0

        raw_priority = highest_sev + layer_bonus + count_bonus + confidence_factor
        priority_score = round(min(max(raw_priority, 10.0), 99.0), 1)

        # Risk score in [0.0, 1.0]
        composite_risk = round(min(0.4 * (highest_sev / 100.0) + 0.3 * max_prob + 0.3 * anomaly_score, 1.0), 3)

        breakdown = {
            "base_severity_weight": highest_sev,
            "layer_diversity_bonus": layer_bonus,
            "event_count_bonus": count_bonus,
            "confidence_factor": round(confidence_factor, 2),
            "formula": "min(99.0, base_severity_weight + layer_diversity_bonus + event_count_bonus + confidence_factor)",
            "final_priority_score": priority_score,
            "composite_risk_formula": "0.4 * (base_sev / 100) + 0.3 * classifier_prob + 0.3 * anomaly_score",
            "final_composite_risk": composite_risk,
        }

        return priority_score, composite_risk, breakdown

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def get_all_incidents(self) -> List[Incident]:
        return sorted(self.incidents.values(), key=lambda i: i.updated_at, reverse=True)
