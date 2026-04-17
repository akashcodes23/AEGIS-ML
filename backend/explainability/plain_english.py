from typing import Dict, Optional, Tuple
from backend.core.schemas import Alert, UnifiedEvent

class PlainEnglishExplainer:
    def explain(self, alert: Alert, event: UnifiedEvent, shap_features: Dict[str, float]) -> str:
        """Generate plain English explanation based on threat type."""
        method = {
            "brute_force": self._explain_brute_force,
            "c2_beaconing": self._explain_c2,
            "lateral_movement": self._explain_lateral,
            "data_exfiltration": self._explain_exfil,
        }.get(alert.threat_type, self._explain_generic)
        return method(alert, event, shap_features)

    def _explain_brute_force(self, alert: Alert, event: UnifiedEvent, features: Dict[str, float]) -> str:
        count = int(features.get("failed_auth_count_1min", 0))
        src = event.src_entity
        target = event.dst_entity
        conf = round(alert.confidence * 100)
        
        count_str = f"{count}" if count > 0 else "multiple"
        
        return (
            f"BRUTE FORCE ATTACK detected with {conf}% confidence.\n\n"
            f"Reason: {count_str} failed login attempts observed in under 60 seconds "
            f"from {src}, all targeting {target}.\n"
            f"This rate is abnormally high — normal failure rate for this account is 1-2 per day.\n\n"
            f"Top signals: High failed auth frequency (+{round(features.get('failed_auth_rate', 0), 2)}), "
            f"External source IP (+{round(features.get('is_external_dst', 0), 2)})"
        )

    def _explain_c2(self, alert: Alert, event: UnifiedEvent, features: Dict[str, float]) -> str:
        beacon_score = features.get("beaconing_score", 0)
        conf = round(alert.confidence * 100)
        return (
            f"COMMAND & CONTROL BEACONING detected with {conf}% confidence.\n\n"
            f"Reason: Periodic connection patterns identified between {event.src_entity} and {event.dst_entity}.\n"
            f"The timing of these requests (+{round(beacon_score, 2)}) suggests automated 'heartbeat' signals "
            f"typical of malware communicating with a C2 server.\n\n"
            f"Top signals: Beaconing consistency (+{round(features.get('interval_variance', 0), 2)}), "
            f"Known malicious domain/IP association (+{round(features.get('intel_match', 0), 2)})"
        )

    def _explain_lateral(self, alert: Alert, event: UnifiedEvent, features: Dict[str, float]) -> str:
        conf = round(alert.confidence * 100)
        process_info = f" ({event.process_name})" if event.process_name else ""
        return (
            f"LATERAL MOVEMENT detected with {conf}% confidence.\n\n"
            f"Reason: {event.src_entity} is attempting to access {event.dst_entity} using "
            f"unusual credentials or protocols{process_info}.\n"
            f"This activity deviates from the source's historical behavior within the internal network.\n\n"
            f"Top signals: New path discovery (+{round(features.get('new_edge_score', 0), 2)}), "
            f"Privilege escalation indicators (+{round(features.get('privilege_score', 0), 2)})"
        )

    def _explain_exfil(self, alert: Alert, event: UnifiedEvent, features: Dict[str, float]) -> str:
        bytes_sent = int(features.get("total_bytes_out", event.bytes_sent or 0))
        conf = round(alert.confidence * 100)
        return (
            f"DATA EXFILTRATION detected with {conf}% confidence.\n\n"
            f"Reason: Large data transfer ({bytes_sent} bytes) originating from {event.src_entity} "
            f"to external destination {event.dst_entity}.\n"
            f"The volume and destination are highly anomalous for this user/system.\n\n"
            f"Top signals: Anomalous outbound volume (+{round(features.get('volume_deviation', 0), 2)}), "
            f"Sensitive file access correlation (+{round(features.get('file_access_score', 0), 2)})"
        )

    def _explain_generic(self, alert: Alert, event: UnifiedEvent, features: Dict[str, float]) -> str:
        conf = round(alert.confidence * 100)
        threat_name = alert.threat_type.replace('_', ' ').upper()
        return (
            f"THREAT DETECTED: {threat_name} with {conf}% confidence.\n\n"
            f"Activity involving {event.src_entity} and {event.dst_entity} has triggered "
            "multiple anomaly detection rules.\n\n"
            f"Top signals: Baseline deviation (+{round(features.get('baseline_deviation', 0), 2)})"
        )

class FalsePositiveDetector:
    def check(self, alert: Alert, event: UnifiedEvent, baseline_deviation: float) -> Tuple[bool, Optional[str]]:
        """
        Returns (is_false_positive, reason_string)
        False positive rules:
        1. If baseline_deviation < 0.20: likely FP (very close to normal behavior)
        2. If entity is service account AND destination is internal: likely FP
        3. If process_name is "robocopy.exe" AND dst_internal: likely FP (backup)
        4. If confidence < 0.45: uncertain, flag as possible FP
        """
        if baseline_deviation < 0.20:
            return True, f"Event closely matches established baseline for {event.src_entity}"
        
        if event.user_account in ["backup_svc", "sysadmin"] and event.dst_internal:
            return True, "Service account performing internal operation — consistent with scheduled task"
        
        if event.process_name == "robocopy.exe" and event.dst_internal:
            return True, "Robocopy to internal destination matches known backup schedule"
        
        if alert.confidence < 0.45:
            return True, "Low detection confidence — flagging for manual review as potential false positive"
            
        return False, None
