import asyncio
import json
from datetime import datetime, timedelta
from typing import List
import random
from pathlib import Path

from backend.data_generator.attack_scenarios import (
    generate_brute_force_attack,
    generate_c2_beaconing,
    generate_lateral_movement,
    generate_false_positive,
    generate_benign_traffic,
    generate_data_exfiltration
)
from backend.core.schemas import UnifiedEvent

class DataOrchestrator:
    def training_mode(self, output_path="data/raw/combined_labeled.jsonl"):
        start_time = datetime.now()
        
        events = []
        
        # Attack events
        # Multiply instances to ensure enough support for models
        for i in range(5):
            events.extend(generate_brute_force_attack(start_time + timedelta(hours=i)))
        for i in range(30):
            events.extend(generate_c2_beaconing(start_time + timedelta(minutes=i*10), duration_seconds=600))
        for i in range(15):
            events.extend(generate_lateral_movement(start_time + timedelta(minutes=i*25)))
        for i in range(10):
            events.extend(generate_data_exfiltration(start_time + timedelta(hours=i*2)))
        
        # False positive events (also benign)
        events.extend(generate_false_positive(start_time))
        
        # Generate 2000 benign traffic events
        events.extend(generate_benign_traffic(start_time, count=2000))
        
        # Shuffle randomly
        random.shuffle(events)
        
        # Keep timestamps sorted after shuffle
        events.sort(key=lambda e: e.timestamp)
        
        # Ensure data directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Write each UnifiedEvent as JSON line to output file
        with open(output_path, "w") as f:
            for event in events:
                f.write(event.model_dump_json() + "\n")
                
        print(f"Generated {len(events)} events to {output_path}")

    async def demo_mode(self, queue: asyncio.Queue):
        base_time = datetime.now()

        async def run_scenario(events: List[UnifiedEvent], delay_seconds: int):
            await asyncio.sleep(delay_seconds)
            if not events: return
            
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
            # Mix in benign events continuously
            while True:
                # Target 50-100 events per second
                batch_size = random.randint(50, 100)
                batch = generate_benign_traffic(datetime.now(), count=batch_size)
                
                sleep_interval = 1.0 / batch_size
                
                for event in batch:
                    event.timestamp = datetime.now()  # Real-time
                    await queue.put(event)
                    await asyncio.sleep(sleep_interval)

        # Generate attack scenario events
        bf_events = generate_brute_force_attack(base_time + timedelta(seconds=30))
        c2_events = generate_c2_beaconing(base_time + timedelta(seconds=60))
        lm_events = generate_lateral_movement(base_time + timedelta(seconds=300))
        fp_events = generate_false_positive(base_time)
        exfil_events = generate_data_exfiltration(base_time + timedelta(seconds=200))

        print("Starting demo mode...")
        await asyncio.gather(
            run_scenario(bf_events, delay_seconds=30),
            run_scenario(c2_events, delay_seconds=60),
            run_scenario(lm_events, delay_seconds=300),
            run_scenario(fp_events, delay_seconds=0),
            run_scenario(exfil_events, delay_seconds=200),
            benign_traffic_loop()
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

