from typing import List, Optional
from datetime import datetime, timedelta
import random
import uuid

from backend.core.schemas import UnifiedEvent
from backend.core.config import ATTACKER_IPS, C2_SERVER_IP, C2_PORT, INTERNAL_IPS

DEFAULT_GENERATOR_VERSION = "2.0.0"


def generate_event_uuid(scenario_id: Optional[str], event_idx: int, rng: Optional[random.Random]) -> str:
    """Generate deterministic UUID based on scenario_id and event index, or fallback to rng/uuid4."""
    if scenario_id:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{scenario_id}_{event_idx}"))
    if rng is not None:
        return str(uuid.UUID(int=rng.getrandbits(128)))
    return str(uuid.uuid4())


def generate_brute_force_attack(
    start_time: datetime,
    scenario_id: Optional[str] = None,
    generator_version: str = DEFAULT_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    
    attempts = r.randint(150, 450)
    for i in range(attempts):
        time_offset = timedelta(seconds=(r.uniform(30.0, 120.0) / attempts) * i)
        event_time = start_time + time_offset
        src_ip = ATTACKER_IPS[i % len(ATTACKER_IPS)]
        
        if i == attempts - r.randint(1, 5):
            status_code = 200
            auth_result = "success"
        else:
            status_code = 401
            auth_result = "failure"
            
        # Application event
        app_event = UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, i * 2, rng),
            timestamp=event_time,
            layer="application",
            src_entity=src_ip,
            dst_entity="api.corp.com/login",
            src_internal=False,
            dst_internal=True,
            src_ip=src_ip,
            http_method="POST",
            endpoint_path="/api/login",
            status_code=status_code,
            auth_result=auth_result,
            raw_label="malicious",
            attack_type="brute_force",
            scenario_id=scenario_id,
            scenario_type="brute_force" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        )
        events.append(app_event)
        
        # Matching network layer event
        net_event = UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, i * 2 + 1, rng),
            timestamp=event_time,
            layer="network",
            src_entity=src_ip,
            dst_entity="api.corp.com",
            src_internal=False,
            dst_internal=True,
            src_ip=src_ip,
            dst_port=443,
            bytes_sent=512,
            bytes_received=256,
            raw_label="malicious",
            attack_type="brute_force",
            scenario_id=scenario_id,
            scenario_type="brute_force" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        )
        events.append(net_event)
        
    return events


def generate_c2_beaconing(
    start_time: datetime,
    duration_seconds: int = 300,
    scenario_id: Optional[str] = None,
    generator_version: str = DEFAULT_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    
    current_time = start_time
    end_time = start_time + timedelta(seconds=duration_seconds)
    beacon_count = 0
    event_counter = 0
    
    while current_time < end_time:
        net_event = UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity="10.0.0.23",
            dst_entity=C2_SERVER_IP,
            src_internal=True,
            dst_internal=False,
            src_ip="10.0.0.23",
            dst_ip=C2_SERVER_IP,
            dst_port=C2_PORT,
            protocol="TCP",
            bytes_sent=64,
            bytes_received=r.randint(128, 256),
            raw_label="malicious",
            attack_type="c2_beaconing",
            scenario_id=scenario_id,
            scenario_type="c2_beaconing" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        )
        events.append(net_event)
        beacon_count += 1
        event_counter += 1
        
        if beacon_count == 5:
            endpoint_event = UnifiedEvent(
                event_id=generate_event_uuid(scenario_id, event_counter, rng),
                timestamp=current_time,
                layer="endpoint",
                src_entity="10.0.0.23",
                dst_entity="10.0.0.23",
                src_internal=True,
                dst_internal=True,
                src_ip="10.0.0.23",
                process_name="cmd.exe",
                parent_process="explorer.exe",
                user_account="jsmith",
                action="exec",
                raw_label="malicious",
                attack_type="c2_beaconing",
                scenario_id=scenario_id,
                scenario_type="c2_beaconing" if scenario_id else None,
                generator_version=generator_version if scenario_id else None,
            )
            events.append(endpoint_event)
            event_counter += 1
            
        jitter = r.randint(-5, 5)
        current_time += timedelta(seconds=60 + jitter)
        
    return events


def generate_lateral_movement(
    start_time: datetime,
    scenario_id: Optional[str] = None,
    generator_version: str = DEFAULT_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    event_counter = 0
    
    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=start_time,
        layer="endpoint",
        src_entity="10.0.0.23",
        dst_entity="10.0.0.23",
        src_internal=True,
        dst_internal=True,
        src_ip="10.0.0.23",
        process_name="net.exe",
        user_account="jsmith",
        action="exec",
        raw_label="malicious",
        attack_type="lateral_movement",
        scenario_id=scenario_id,
        scenario_type="lateral_movement" if scenario_id else None,
        generator_version=generator_version if scenario_id else None,
    ))
    event_counter += 1
    
    psexec_time = start_time + timedelta(seconds=2)
    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=psexec_time,
        layer="endpoint",
        src_entity="10.0.0.23",
        dst_entity="10.0.0.23",
        src_internal=True,
        dst_internal=True,
        src_ip="10.0.0.23",
        process_name="psexec.exe",
        user_account="jsmith",
        action="exec",
        raw_label="malicious",
        attack_type="lateral_movement",
        scenario_id=scenario_id,
        scenario_type="lateral_movement" if scenario_id else None,
        generator_version=generator_version if scenario_id else None,
    ))
    event_counter += 1
    
    current_time = psexec_time + timedelta(seconds=1)
    scan_count = r.randint(10, 30)
    for i in range(scan_count):
        target_ip = f"10.0.0.{r.randint(20, 200)}"
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity="10.0.0.23",
            dst_entity=target_ip,
            src_internal=True,
            dst_internal=True,
            src_ip="10.0.0.23",
            dst_ip=target_ip,
            dst_port=445,
            protocol="TCP",
            bytes_sent=128,
            bytes_received=r.randint(64, 512),
            raw_label="malicious",
            attack_type="lateral_movement",
            scenario_id=scenario_id,
            scenario_type="lateral_movement" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        current_time += timedelta(milliseconds=r.randint(100, 500))
        
    return events


def generate_false_positive(
    start_time: datetime,
    scenario_id: Optional[str] = None,
    generator_version: str = DEFAULT_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    event_counter = 0
    
    start_time = start_time.replace(hour=2, minute=0, second=0, microsecond=0)
    
    for i in range(50):
        file_ext = r.choice([".xlsx", ".pdf"])
        file_name = f"C:\\Finance\\Q{r.randint(1,4)}_Report_{i}{file_ext}"
        
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=start_time + timedelta(seconds=i*54 + r.randint(-10, 10)),
            layer="endpoint",
            src_entity="10.0.0.5",
            dst_entity="10.0.0.5",
            src_internal=True,
            dst_internal=True,
            src_ip="10.0.0.5",
            process_name="robocopy.exe",
            user_account="backup_svc",
            file_path=file_name,
            action="read",
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="false_positive_backup" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        
    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=start_time,
        layer="network",
        src_entity="10.0.0.5",
        dst_entity="10.0.0.90",
        src_internal=True,
        dst_internal=True,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.90",
        dst_port=445,
        protocol="TCP",
        bytes_sent=r.randint(1900*1024*1024, 2100*1024*1024),
        bytes_received=1024 * 512,
        duration_ms=45 * 60 * 1000,
        raw_label="benign",
        attack_type=None,
        scenario_id=scenario_id,
        scenario_type="false_positive_backup" if scenario_id else None,
        generator_version=generator_version if scenario_id else None,
    ))
    
    return events


def generate_benign_traffic(
    start_time: datetime,
    count: int = 500,
    scenario_id: Optional[str] = None,
    generator_version: str = DEFAULT_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    
    destinations = [
        ("10.0.0.10", 80, "HTTP", "application"),
        ("10.0.0.11", 53, "DNS", "network"),
        ("10.0.0.12", 445, "SMB", "network"),
        ("10.0.0.13", 25, "SMTP", "network")
    ]
    
    current_time = start_time
    
    for i in range(count):
        src_ip = r.choice(INTERNAL_IPS)
        dst_ip, dst_port, protocol, layer = r.choice(destinations)
        
        if layer == "application":
            event = UnifiedEvent(
                event_id=generate_event_uuid(scenario_id, i, rng),
                timestamp=current_time,
                layer="application",
                src_entity=src_ip,
                dst_entity=f"{dst_ip}/intranet",
                src_internal=True,
                dst_internal=True,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="TCP",
                http_method="GET",
                endpoint_path="/intranet",
                status_code=200,
                bytes_sent=r.randint(500, 2000),
                bytes_received=r.randint(5000, 50000),
                raw_label="benign",
                attack_type=None,
                scenario_id=scenario_id,
                scenario_type="benign_traffic" if scenario_id else None,
                generator_version=generator_version if scenario_id else None,
            )
        else:
            event = UnifiedEvent(
                event_id=generate_event_uuid(scenario_id, i, rng),
                timestamp=current_time,
                layer="network",
                src_entity=src_ip,
                dst_entity=dst_ip,
                src_internal=True,
                dst_internal=True,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                bytes_sent=r.randint(100, 1000),
                bytes_received=r.randint(100, 5000),
                raw_label="benign",
                attack_type=None,
                scenario_id=scenario_id,
                scenario_type="benign_traffic" if scenario_id else None,
                generator_version=generator_version if scenario_id else None,
            )
            
        events.append(event)
        current_time += timedelta(milliseconds=r.randint(100, 2000))
        
    return events


def generate_data_exfiltration(
    start_time: datetime,
    duration_seconds: int = 120,
    scenario_id: Optional[str] = None,
    generator_version: str = DEFAULT_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    event_counter = 0
    
    current_time = start_time
    target_ip = "192.168.100.50" 
    
    for i in range(120): 
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity="10.0.0.33",
            dst_entity=target_ip,
            src_internal=True,
            dst_internal=False,
            src_ip="10.0.0.33",
            dst_ip=target_ip,
            dst_port=443,
            protocol="TCP",
            bytes_sent=r.randint(5 * 1024 * 1024, 25 * 1024 * 1024), 
            bytes_received=r.randint(128, 512),
            raw_label="malicious",
            attack_type="data_exfiltration",
            scenario_id=scenario_id,
            scenario_type="data_exfiltration" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        
        if i % 10 == 0:
            events.append(UnifiedEvent(
                event_id=generate_event_uuid(scenario_id, event_counter, rng),
                timestamp=current_time,
                layer="endpoint",
                src_entity="10.0.0.33",
                dst_entity="10.0.0.33",
                src_internal=True,
                dst_internal=True,
                src_ip="10.0.0.33",
                process_name="7z.exe",
                user_account="jsmith",
                action="read",
                raw_label="malicious",
                attack_type="data_exfiltration",
                scenario_id=scenario_id,
                scenario_type="data_exfiltration" if scenario_id else None,
                generator_version=generator_version if scenario_id else None,
            ))
            event_counter += 1
            
        current_time += timedelta(seconds=r.randint(2, 5))
        
    return events
