import uuid
from datetime import datetime
from typing import Dict, List, Optional
from backend.core.schemas import Incident

class PlaybookGenerator:
    PLAYBOOK_TEMPLATES = {
        "brute_force": {
            "immediate": [
                {"priority": 1, "action": "Block source IPs at firewall", "urgency": "DO NOW", "reason": "Stop ongoing attack"},
                {"priority": 2, "action": "Lock targeted user account temporarily", "urgency": "DO NOW", "reason": "Prevent successful authentication"},
                {"priority": 3, "action": "Enable MFA on all admin accounts", "urgency": "WITHIN 10 MINUTES", "reason": "Harden against repeat attempts"},
            ],
            "investigate": [
                "Check if any login attempt succeeded (status 200 in logs)",
                "Review all sessions from flagged IPs in last 24 hours",
                "Check for account lockout bypass attempts"
            ],
            "prevent": [
                "Implement rate limiting: max 5 failed logins per minute per IP",
                "Add geo-blocking for countries with no business relationships",
                "Deploy CAPTCHA after 3 failed attempts"
            ],
            "predict_preparation": [
                "Scan {src_entity} for existing malware persistence",
                "Audit logs for successful logons from {src_entity} using other protocols"
            ]
        },
        "c2_beaconing": {
            "immediate": [
                {"priority": 1, "action": "Isolate host {src_entity} from network", "urgency": "DO NOW", "reason": "Stop attacker command channel"},
                {"priority": 2, "action": "Block outbound traffic to detected C2 destinations", "urgency": "DO NOW", "reason": "Cut C2 server communication"},
            ],
            "investigate": [
                "Analyze network traffic patterns for other heartbeat signals",
                "Perform memory forensics on {src_entity} to identify beaconing process",
                "Check for recent file downloads or executable modifications on {src_entity}"
            ],
            "prevent": [
                "Implement DNS filtering to block known malicious domains",
                "Deploy endpoint detection and response (EDR) in blocking mode",
                "Enforce strict outbound firewall rules (allow-list only)"
            ],
            "predict_preparation": [
                "Disable SMB (port 445) on all non-file-server hosts",
                "Alert on any new internal connections from {src_entity}",
                "Monitor for PsExec.exe, net.exe, whoami.exe execution"
            ]
        },
        "lateral_movement": {
            "immediate": [
                {"priority": 1, "action": "Revoke all active sessions for {src_entity}", "urgency": "DO NOW", "reason": "Stop attacker movement"},
                {"priority": 2, "action": "Reset password for potentially compromised user {src_entity}", "urgency": "DO NOW", "reason": "Invalidate attacker credentials"},
                {"priority": 3, "action": "Block internal RDP/SSH access from {src_entity}", "urgency": "WITHIN 5 MINUTES", "reason": "Contain the threat"},
            ],
            "investigate": [
                "Trace {src_entity}'s move-set using Event ID 4624/4625",
                "Check for unusual service installations (Event ID 7045)",
                "Audit use of administrative shares (C$, ADMIN$)"
            ],
            "prevent": [
                "Implement Just-In-Time (JIT) access for administrative roles",
                "Enforce Tiered Administration model",
                "Segment the network using micro-segmentation"
            ],
            "predict_preparation": [
                "Audit access to sensitive file shares for {src_entity}",
                "Check for scheduled task creation on neighboring systems",
                "Review browser history and local file access for staging behavior"
            ]
        },
        "data_exfiltration": {
            "immediate": [
                {"priority": 1, "action": "Terminate all outbound connections from {src_entity} to external IP", "urgency": "DO NOW", "reason": "Stop data loss"},
                {"priority": 2, "action": "Revoke access tokens for {src_entity}'s cloud storage accounts", "urgency": "DO NOW", "reason": "Prevent cloud-based exfiltration"},
                {"priority": 3, "action": "Quarantine {src_entity} for forensic imaging", "urgency": "WITHIN 15 MINUTES", "reason": "Preserve evidence"},
            ],
            "investigate": [
                "Calculate total data volume transferred to external destinations",
                "Identify specific files/databases accessed by {src_entity} before exfiltration",
                "Review NetFlow logs for long-duration outbound sessions"
            ],
            "prevent": [
                "Implement DLP policies to block large transfers of sensitive data",
                "Limit outbound traffic to known-good domains (Allowlist)",
                "Enforce TLS inspection for outbound traffic"
            ],
            "predict_preparation": [
                "Scan all systems for signs of cleanup tools (stager removal)",
                "Monitor for 'suicide' scripts or data destruction activity",
                "Check for recent backup deletions or volume shadow copy removals"
            ]
        }
    }

    def generate(self, incident: Incident, predicted_next_stage: str) -> Dict:
        """
        Generate dynamic playbook for an incident.
        Fills template placeholders with actual entity values.
        Adds predicted-stage preparation steps.
        """
        template = self.PLAYBOOK_TEMPLATES.get(incident.threat_type, {})
        
        # Replace placeholders
        entities = incident.affected_entities
        src = entities[0] if entities else "unknown"
        
        def fill(text: str) -> str:
            return text.replace("{src_entity}", src)
            
        immediate = [
            {**step, "action": fill(step["action"])}
            for step in template.get("immediate", [])
        ]
        
        return {
            "playbook_id": str(uuid.uuid4()),
            "incident_id": incident.incident_id,
            "generated_at": datetime.now().isoformat(),
            "current_stage": incident.current_kill_chain_stage,
            "predicted_next_stage": predicted_next_stage,
            "immediate_actions": immediate,
            "investigate_actions": [fill(a) for a in template.get("investigate", [])],
            "prevent_actions": [fill(a) for a in template.get("prevent", [])],
            "predicted_stage_preparation": [
                fill(a) for a in template.get("predict_preparation", [])
            ]
        }
