from typing import List, Dict, Optional

# Reconstructed STAGES from prompt
STAGES = {
    "initial_access": {"label": "Initial Access", "icon": "🔓", "step": 1},
    "execution": {"label": "Execution", "icon": "⚙", "step": 2},
    "c2_communication": {"label": "C2 Communication", "icon": "📡", "step": 3},
    "lateral_movement": {"label": "Lateral Movement", "icon": "↔", "step": 4},
    "data_collection": {"label": "Data Collection", "icon": "📦", "step": 5},
    "exfiltration": {"label": "Exfiltration", "icon": "🚨", "step": 6},
}

THREAT_TO_STAGE = {
    "brute_force": "initial_access",
    "c2_beaconing": "c2_communication",
    "lateral_movement": "lateral_movement",
    "data_exfiltration": "exfiltration",
}

TRANSITION_PROBABILITIES = {
    "initial_access": [("c2_communication", 0.60), ("execution", 0.30)],
    "execution": [("c2_communication", 0.55), ("lateral_movement", 0.35)],
    "c2_communication": [("lateral_movement", 0.55), ("data_collection", 0.30)],
    "lateral_movement": [("data_collection", 0.70), ("exfiltration", 0.20)],
    "data_collection": [("exfiltration", 0.85)],
    "exfiltration": [],
}

class KillChainStagePredictor:
    def get_current_stage(self, incident_threat_types: List[str]) -> Optional[str]:
        """Return highest (most advanced) stage detected in incident."""
        detected_stages = [
            THREAT_TO_STAGE[t] for t in incident_threat_types
            if t in THREAT_TO_STAGE
        ]
        if not detected_stages:
            return None
        return max(detected_stages, key=lambda s: STAGES[s]["step"])

    def predict_next(self, current_stage: str) -> List[Dict]:
        """Return list of likely next stages with probabilities."""
        transitions = TRANSITION_PROBABILITIES.get(current_stage, [])
        return [
            {
                "stage": stage,
                "label": STAGES[stage]["label"],
                "probability": prob,
                "icon": STAGES[stage]["icon"]
            }
            for stage, prob in sorted(transitions, key=lambda x: -x[1])
        ]

    def get_all_stages_status(self, detected_stages: List[str]) -> List[Dict]:
        """Returns all stages with detected/predicted/future status for UI."""
        current = self.get_current_stage(detected_stages)
        current_step = STAGES[current]["step"] if current else 0
        
        result = []
        for stage_id, stage_data in STAGES.items():
            step = stage_data["step"]
            
            # Map incident threat types to their corresponding stages
            mapped_detected_stages = {THREAT_TO_STAGE[t] for t in detected_stages if t in THREAT_TO_STAGE}
            
            if stage_id in mapped_detected_stages:
                status = "detected"
            elif current_step > 0 and step == current_step + 1:
                status = "predicted"
            elif current_step > 0 and step < current_step:
                status = "passed"
            elif current_step == 0 and step == 1:
                 # If nothing detected, the first stage is predicted
                status = "predicted"
            else:
                status = "future"
                
            result.append({**stage_data, "stage_id": stage_id, "status": status})
            
        return result
