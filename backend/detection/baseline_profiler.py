import numpy as np
import pickle
import os
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path

try:
    from core.schemas import UnifiedEvent
    from core.config import BASELINES_PATH
except ModuleNotFoundError:
    from backend.core.schemas import UnifiedEvent
    from backend.core.config import BASELINES_PATH

logger = logging.getLogger(__name__)


class BehavioralBaselineProfiler:
    """
    Entity Behavioral Baseline Profiler for AEGIS-ML.
    
    Maintains historical statistical profiles for known internal entities and service
    accounts to quantify deviations in data transfer volume, destination diversity,
    activity hours, and connection rates.
    """

    def __init__(self):
        self.profiles: Dict[str, dict] = {}

    def build_baselines(self, events: List[UnifiedEvent], benign_only: bool = True) -> None:
        """
        Construct behavioral profiles from historical events.
        
        Parameters
        ----------
        events : List[UnifiedEvent]
            Historical events strictly from the training partition.
        benign_only : bool
            If True, only non-malicious events are incorporated to avoid baseline poisoning.
        """
        # Filter for baseline learning
        filtered_events = []
        for e in events:
            if benign_only:
                is_attack = (e.attack_type is not None and e.attack_type != "benign") or (
                    e.raw_label is not None and e.raw_label == "malicious"
                )
                if is_attack:
                    continue
            filtered_events.append(e)

        if not filtered_events and events:
            logger.warning("No benign events identified for baseline; using all training events.")
            filtered_events = events

        # Group events by src_entity
        grouped_events: Dict[str, List[UnifiedEvent]] = {}
        for event in filtered_events:
            src = event.src_entity or "unknown"
            if src not in grouped_events:
                grouped_events[src] = []
            grouped_events[src].append(event)

        for entity, entity_events in grouped_events.items():
            hours = set()
            bytes_sent_list = []
            destinations = set()
            processes = set()
            connections_per_min = []

            for event in entity_events:
                hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
                hours.add(hour)

                if event.bytes_sent is not None and not np.isnan(event.bytes_sent):
                    bytes_sent_list.append(event.bytes_sent)

                if event.dst_entity:
                    destinations.add(event.dst_entity)

                if event.layer == "endpoint" and event.process_name:
                    processes.add(event.process_name)

                if event.connections_per_minute is not None and not np.isnan(event.connections_per_minute):
                    connections_per_min.append(event.connections_per_minute)

            avg_bytes_sent = float(np.mean(bytes_sent_list)) if bytes_sent_list else 0.0
            std_bytes_sent = float(np.std(bytes_sent_list)) if bytes_sent_list else 1.0
            if std_bytes_sent == 0.0:
                std_bytes_sent = 1.0

            avg_conn_per_min = float(np.mean(connections_per_min)) if connections_per_min else 0.0

            self.profiles[entity] = {
                "typical_hours": list(hours),
                "avg_bytes_sent": avg_bytes_sent,
                "std_bytes_sent": std_bytes_sent,
                "typical_destinations": list(destinations),
                "typical_processes": list(processes),
                "avg_connections_per_min": avg_conn_per_min,
                "is_service_account": entity in ["backup_svc", "sysadmin"],
                "event_count": len(entity_events),
            }

    def compute_deviation_score(self, event: UnifiedEvent) -> float:
        """
        Compute an empirical deviation score in [0.0, 1.0] for the observed event.
        Returns 0.5 (neutral / unknown) if no baseline profile exists for the entity.
        """
        src = event.src_entity
        if not src or src not in self.profiles:
            return 0.5  # Neutral default for unseen entity

        profile = self.profiles[src]
        scores = []

        hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour

        # 1. Hour deviation: anomalous if outside observed activity hours
        if hour not in profile.get("typical_hours", []):
            scores.append(0.8)
        else:
            scores.append(0.0)

        # 2. Bytes deviation: z-score against historical transfer volume
        if event.bytes_sent is not None and profile.get("std_bytes_sent", 0) > 0:
            z = abs(event.bytes_sent - profile["avg_bytes_sent"]) / profile["std_bytes_sent"]
            scores.append(min(z / 3.0, 1.0))

        # 3. Destination novelty
        if event.dst_entity and event.dst_entity not in profile.get("typical_destinations", []):
            scores.append(0.7)
        else:
            scores.append(0.0)

        # 4. Service account policy deviation
        if profile.get("is_service_account", False) and not event.dst_internal:
            scores.append(0.9)

        if not scores:
            return 0.5

        return float(np.clip(np.mean(scores), 0.0, 1.0))

    def save(self, path: Optional[str] = None) -> None:
        target_path = path or BASELINES_PATH
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "wb") as f:
            pickle.dump(self.profiles, f)
        logger.info(f"Behavioral baselines saved to {target_path}")

    def load(self, path: Optional[str] = None) -> bool:
        target_path = path or BASELINES_PATH
        if os.path.exists(target_path):
            try:
                with open(target_path, "rb") as f:
                    self.profiles = pickle.load(f)
                return True
            except Exception as e:
                logger.error(f"Failed to load baseline profiles from {target_path}: {e}")
                return False
        return False
