import numpy as np
import pickle
import os
from typing import List, Dict
from pathlib import Path

from backend.core.schemas import UnifiedEvent
from backend.core.config import BASELINES_PATH

class BehavioralBaselineProfiler:
    def __init__(self):
        self.profiles: Dict[str, dict] = {}

    def build_baselines(self, events: List[UnifiedEvent]) -> None:
        # Group events by src_entity
        grouped_events: Dict[str, List[UnifiedEvent]] = {}
        for event in events:
            if event.src_entity not in grouped_events:
                grouped_events[event.src_entity] = []
            grouped_events[event.src_entity].append(event)

        for entity, entity_events in grouped_events.items():
            hours = set()
            bytes_sent_list = []
            destinations = set()
            processes = set()
            connections_per_min = []
            
            for event in entity_events:
                hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
                hours.add(hour)
                
                if event.bytes_sent is not None:
                    bytes_sent_list.append(event.bytes_sent)
                    
                if event.dst_entity is not None:
                    destinations.add(event.dst_entity)
                    
                if event.layer == "endpoint" and event.process_name:
                    processes.add(event.process_name)
                    
                if event.connections_per_minute is not None:
                    connections_per_min.append(event.connections_per_minute)

            avg_bytes_sent = float(np.mean(bytes_sent_list)) if bytes_sent_list else 0.0
            std_bytes_sent = float(np.std(bytes_sent_list)) if bytes_sent_list else 0.0
            avg_connections_per_min = float(np.mean(connections_per_min)) if connections_per_min else 0.0

            self.profiles[entity] = {
                "typical_hours": list(hours),
                "avg_bytes_sent": avg_bytes_sent,
                "std_bytes_sent": std_bytes_sent,
                "typical_destinations": list(destinations),
                "typical_processes": list(processes),
                "avg_connections_per_min": avg_connections_per_min,
                "is_service_account": entity in ["backup_svc", "sysadmin"],
                "event_count": len(entity_events)
            }

    def compute_deviation_score(self, event: UnifiedEvent) -> float:
        if event.src_entity not in self.profiles:
            return 0.5  # neutral — no history
            
        profile = self.profiles[event.src_entity]
        scores = []
        
        hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
        
        # Hour deviation
        if hour not in profile["typical_hours"]:
            scores.append(0.8)
        else:
            scores.append(0.0)
            
        # Bytes deviation (z-score)
        if event.bytes_sent is not None and profile["std_bytes_sent"] > 0:
            z = abs(event.bytes_sent - profile["avg_bytes_sent"]) / profile["std_bytes_sent"]
            scores.append(min(z / 3.0, 1.0))  # clip at 1.0
            
        # New destination check
        if event.dst_entity not in profile["typical_destinations"]:
            scores.append(0.7)
        else:
            scores.append(0.0)
            
        # Service account doing external transfer check
        if profile.get("is_service_account", False) and not event.dst_internal:
            scores.append(0.9)  # service accounts should stay internal
            
        return float(np.mean(scores)) if scores else 0.5

    def save(self) -> None:
        Path(BASELINES_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(BASELINES_PATH, "wb") as f:
            pickle.dump(self.profiles, f)

    def load(self) -> None:
        if os.path.exists(BASELINES_PATH):
            with open(BASELINES_PATH, "rb") as f:
                self.profiles = pickle.load(f)
