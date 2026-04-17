from typing import Dict, Optional

MITRE_MAP = {
    "brute_force": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "sub_technique": "T1110.004 — Credential Stuffing",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversaries use credential stuffing to gain initial access"
    },
    "c2_beaconing": {
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "sub_technique": "T1071.001 — Web Protocols",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Adversaries communicate using existing protocols to blend with traffic"
    },
    "lateral_movement": {
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "sub_technique": "T1021.002 — SMB/Windows Admin Shares",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "description": "Adversaries use SMB to move laterally through a network"
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "sub_technique": "T1048.002 — Exfiltration Over Asymmetric Encrypted Non C2 Protocol",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "description": "Adversaries steal data using protocols not typical for C2"
    }
}

class MITREMapper:
    def map(self, threat_type: str) -> Optional[Dict]:
        """Returns the MITRE mapping for a given threat type."""
        return MITRE_MAP.get(threat_type)

    def get_technique_id(self, threat_type: str) -> Optional[str]:
        """Returns the MITRE technique ID for a given threat type."""
        m = self.map(threat_type)
        return m["technique_id"] if m else None
