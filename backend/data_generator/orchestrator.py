import asyncio
from collections import Counter
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import random
from typing import List, Dict, Any, Optional

from backend.data_generator.attack_scenarios import (
    generate_brute_force_attack,
    generate_c2_beaconing,
    generate_lateral_movement,
    generate_false_positive,
    generate_benign_traffic,
    generate_data_exfiltration,
    DEFAULT_GENERATOR_VERSION,
)
from backend.core.schemas import UnifiedEvent


class DataOrchestrator:
    def generate_scenario_dataset(
        self,
        output_path: str = "data/raw/scenario_aware_labeled.jsonl",
        seed: int = 42,
        bf_scenarios: int = 5,
        c2_scenarios: int = 30,
        lm_scenarios: int = 15,
        exfil_scenarios: int = 10,
        fp_scenarios: int = 1,
        benign_sessions: int = 20,
        benign_events_per_session: int = 100,
        base_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Generate a synthetic dataset with full scenario provenance and deterministic reproducibility.

        Each scenario instance receives a unique scenario_id shared across all its events.
        Events within the same scenario share identical scenario_id, scenario_type, and generator_version.
        """
        rng = random.Random(seed)
        start_time = base_time or datetime(2026, 10, 10, 0, 0, 0)
        events: List[UnifiedEvent] = []
        scenario_catalog: Dict[str, Dict[str, Any]] = {}

        # 1. Brute Force Scenarios
        for i in range(bf_scenarios):
            sc_id = f"scenario_bf_{i:03d}"
            sc_events = generate_brute_force_attack(
                start_time=start_time + timedelta(hours=i),
                scenario_id=sc_id,
                generator_version=DEFAULT_GENERATOR_VERSION,
                rng=rng,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "brute_force",
                "attack_type": "brute_force",
                "event_count": len(sc_events),
            }

        # 2. C2 Beaconing Scenarios
        for i in range(c2_scenarios):
            sc_id = f"scenario_c2_{i:03d}"
            sc_events = generate_c2_beaconing(
                start_time=start_time + timedelta(minutes=i * 10),
                duration_seconds=600,
                scenario_id=sc_id,
                generator_version=DEFAULT_GENERATOR_VERSION,
                rng=rng,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "c2_beaconing",
                "attack_type": "c2_beaconing",
                "event_count": len(sc_events),
            }

        # 3. Lateral Movement Scenarios
        for i in range(lm_scenarios):
            sc_id = f"scenario_lm_{i:03d}"
            sc_events = generate_lateral_movement(
                start_time=start_time + timedelta(minutes=i * 25),
                scenario_id=sc_id,
                generator_version=DEFAULT_GENERATOR_VERSION,
                rng=rng,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "lateral_movement",
                "attack_type": "lateral_movement",
                "event_count": len(sc_events),
            }

        # 4. Data Exfiltration Scenarios
        for i in range(exfil_scenarios):
            sc_id = f"scenario_exfil_{i:03d}"
            sc_events = generate_data_exfiltration(
                start_time=start_time + timedelta(hours=i * 2),
                scenario_id=sc_id,
                generator_version=DEFAULT_GENERATOR_VERSION,
                rng=rng,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "data_exfiltration",
                "attack_type": "data_exfiltration",
                "event_count": len(sc_events),
            }

        # 5. False Positive Benign Backups
        for i in range(fp_scenarios):
            sc_id = f"scenario_fp_{i:03d}"
            sc_events = generate_false_positive(
                start_time=start_time + timedelta(days=i),
                scenario_id=sc_id,
                generator_version=DEFAULT_GENERATOR_VERSION,
                rng=rng,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "false_positive_backup",
                "attack_type": "benign",
                "event_count": len(sc_events),
            }

        # 6. Benign Workstation / Server Sessions
        for i in range(benign_sessions):
            sc_id = f"scenario_benign_{i:03d}"
            sc_events = generate_benign_traffic(
                start_time=start_time + timedelta(hours=i),
                count=benign_events_per_session,
                scenario_id=sc_id,
                generator_version=DEFAULT_GENERATOR_VERSION,
                rng=rng,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "benign_traffic",
                "attack_type": "benign",
                "event_count": len(sc_events),
            }

        # Validate that EVERY event has scenario provenance
        for e in events:
            assert e.scenario_id is not None, f"Event {e.event_id} missing scenario_id!"
            assert e.scenario_type is not None, f"Event {e.event_id} missing scenario_type!"
            assert e.generator_version is not None, f"Event {e.event_id} missing generator_version!"

        # Deterministic shuffle then chronological sort
        rng.shuffle(events)
        events.sort(key=lambda e: e.timestamp)

        # Write to output file
        target_file = Path(output_path)
        target_file.parent.mkdir(parents=True, exist_ok=True)

        with open(target_file, "w", encoding="utf-8") as f:
            for event in events:
                f.write(event.model_dump_json() + "\n")

        # Compute SHA-256 hash of output file
        hasher = hashlib.sha256()
        with open(target_file, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        dataset_sha256 = hasher.hexdigest()

        # Class counts
        class_counts = Counter(e.attack_type or "benign" for e in events)
        scenarios_by_type = Counter(info["scenario_type"] for info in scenario_catalog.values())

        summary = {
            "dataset_path": str(target_file),
            "sha256": dataset_sha256,
            "seed": seed,
            "total_events": len(events),
            "total_scenarios": len(scenario_catalog),
            "scenarios_by_type": dict(scenarios_by_type),
            "class_distribution": dict(class_counts),
            "generator_version": DEFAULT_GENERATOR_VERSION,
            "generation_parameters": {
                "bf_scenarios": bf_scenarios,
                "c2_scenarios": c2_scenarios,
                "lm_scenarios": lm_scenarios,
                "exfil_scenarios": exfil_scenarios,
                "fp_scenarios": fp_scenarios,
                "benign_sessions": benign_sessions,
                "benign_events_per_session": benign_events_per_session,
            },
        }

        print(
            f"Generated {len(events)} events across {len(scenario_catalog)} scenarios to {output_path} "
            f"(SHA256: {dataset_sha256[:16]}...)"
        )
        return summary

    def training_mode(self, output_path: str = "data/raw/scenario_aware_labeled.jsonl", seed: int = 42) -> Dict[str, Any]:
        """Generate training dataset with scenario provenance."""
        return self.generate_scenario_dataset(output_path=output_path, seed=seed)

    async def demo_mode(self, queue: asyncio.Queue):
        base_time = datetime.now()

        async def run_scenario(events: List[UnifiedEvent], delay_seconds: int):
            await asyncio.sleep(delay_seconds)
            if not events:
                return

            events.sort(key=lambda x: x.timestamp)
            first_time = events[0].timestamp
            start_real_time = datetime.now()

            for event in events:
                expected_offset = (event.timestamp - first_time).total_seconds()
                real_offset = (datetime.now() - start_real_time).total_seconds()

                if expected_offset > real_offset:
                    await asyncio.sleep(expected_offset - real_offset)

                await queue.put(event)

        async def benign_traffic_loop():
            while True:
                batch_size = random.randint(50, 100)
                batch = generate_benign_traffic(datetime.now(), count=batch_size)
                sleep_interval = 1.0 / batch_size

                for event in batch:
                    event.timestamp = datetime.now()
                    await queue.put(event)
                    await asyncio.sleep(sleep_interval)

        bf_events = generate_brute_force_attack(base_time + timedelta(seconds=30), scenario_id="demo_bf_001")
        c2_events = generate_c2_beaconing(base_time + timedelta(seconds=60), scenario_id="demo_c2_001")
        lm_events = generate_lateral_movement(base_time + timedelta(seconds=300), scenario_id="demo_lm_001")
        fp_events = generate_false_positive(base_time, scenario_id="demo_fp_001")
        exfil_events = generate_data_exfiltration(base_time + timedelta(seconds=200), scenario_id="demo_exfil_001")

        print("Starting demo mode...")
        await asyncio.gather(
            run_scenario(bf_events, delay_seconds=30),
            run_scenario(c2_events, delay_seconds=60),
            run_scenario(lm_events, delay_seconds=300),
            run_scenario(fp_events, delay_seconds=0),
            run_scenario(exfil_events, delay_seconds=200),
            benign_traffic_loop(),
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "train":
            DataOrchestrator().training_mode()
        elif sys.argv[1] == "demo":
            asyncio.run(DataOrchestrator().demo_mode(asyncio.Queue()))
        else:
            print("Usage: python orchestrator.py [train|demo]")
    else:
        print("Usage: python orchestrator.py [train|demo]")
