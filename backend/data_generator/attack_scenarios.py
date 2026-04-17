from typing import List
from datetime import datetime, timedelta
import random

from backend.core.schemas import UnifiedEvent
from backend.core.config import ATTACKER_IPS, C2_SERVER_IP, C2_PORT, INTERNAL_IPS

def generate_brute_force_attack(start_time: datetime) -> List[UnifiedEvent]:
    events = []
    
    # Generate 300 application-layer events
    for i in range(300):
        # Timestamps: spread across 60 seconds from start_time
        time_offset = timedelta(seconds=(60.0 / 300.0) * i)
        event_time = start_time + time_offset
        
        src_ip = ATTACKER_IPS[i % len(ATTACKER_IPS)]
        
        # Determine status
        if i == 298:
            status_code = 200
            auth_result = "success"
        else:
            status_code = 401
            auth_result = "failure"
            
        # Application event
        app_event = UnifiedEvent(
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
            attack_type="brute_force"
        )
        events.append(app_event)
        
        # Matching network layer event
        net_event = UnifiedEvent(
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
            attack_type="brute_force"
        )
        events.append(net_event)
        
    return events

def generate_c2_beaconing(start_time: datetime, duration_seconds=300) -> List[UnifiedEvent]:
    events = []
    
    current_time = start_time
    end_time = start_time + timedelta(seconds=duration_seconds)
    beacon_count = 0
    
    while current_time < end_time:
        # Network event for beacon
        net_event = UnifiedEvent(
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
            bytes_received=random.randint(128, 256),
            raw_label="malicious",
            attack_type="c2_beaconing"
        )
        events.append(net_event)
        beacon_count += 1
        
        if beacon_count == 5:
            endpoint_event = UnifiedEvent(
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
                attack_type="c2_beaconing"
            )
            events.append(endpoint_event)
            
        jitter = random.randint(-5, 5)
        current_time += timedelta(seconds=60 + jitter)
        
    return events

def generate_lateral_movement(start_time: datetime) -> List[UnifiedEvent]:
    events = []
    
    # Endpoint events for discovering and moving laterally
    # net.exe execution
    events.append(UnifiedEvent(
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
        attack_type="lateral_movement"
    ))
    
    # psexec.exe execution
    psexec_time = start_time + timedelta(seconds=2)
    events.append(UnifiedEvent(
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
        attack_type="lateral_movement"
    ))
    
    # Network scan and connection attempts to 16 internal hosts
    current_time = psexec_time + timedelta(seconds=1)
    
    for i in range(24, 40):
        target_ip = f"10.0.0.{i}"
        
        events.append(UnifiedEvent(
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
            bytes_received=random.randint(64, 512),
            raw_label="malicious",
            attack_type="lateral_movement"
        ))
        
        # fast connections, add between 100-500 ms
        current_time += timedelta(milliseconds=random.randint(100, 500))
        
    return events

def generate_false_positive(start_time: datetime) -> List[UnifiedEvent]:
    events = []
    
    # Adjust start time to 2:00 AM
    start_time = start_time.replace(hour=2, minute=0, second=0, microsecond=0)
    
    # Generate 50 file access endpoint events reading .xlsx and .pdf files
    for i in range(50):
        file_ext = random.choice([".xlsx", ".pdf"])
        file_name = f"C:\\Finance\\Q{random.randint(1,4)}_Report_{i}{file_ext}"
        
        events.append(UnifiedEvent(
            timestamp=start_time + timedelta(seconds=i*54), # Spread across 45 mins (2700s)
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
            attack_type=None
        ))
        
    # Single large network transfer event representing the backup
    events.append(UnifiedEvent(
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
        bytes_sent=random.randint(1900*1024*1024, 2100*1024*1024),
        bytes_received=1024 * 512, # 512 KB of overhead
        duration_ms=45 * 60 * 1000, # 45 minutes
        raw_label="benign",
        attack_type=None
    ))
    
    return events

def generate_benign_traffic(start_time: datetime, count=500) -> List[UnifiedEvent]:
    events = []
    
    # Common internal destinations
    destinations = [
        ("10.0.0.10", 80, "HTTP", "application"), # Intranet
        ("10.0.0.11", 53, "DNS", "network"),      # DNS
        ("10.0.0.12", 445, "SMB", "network"),     # File server
        ("10.0.0.13", 25, "SMTP", "network")      # Mail server
    ]
    
    current_time = start_time
    
    for i in range(count):
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip, dst_port, protocol, layer = random.choice(destinations)
        
        if layer == "application":
            event = UnifiedEvent(
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
                bytes_sent=random.randint(500, 2000),
                bytes_received=random.randint(5000, 50000),
                raw_label="benign",
                attack_type=None
            )
        else:
            event = UnifiedEvent(
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
                bytes_sent=random.randint(100, 1000),
                bytes_received=random.randint(100, 5000),
                raw_label="benign",
                attack_type=None
            )
            
        events.append(event)
        current_time += timedelta(milliseconds=random.randint(100, 2000))
        
    return events

def generate_data_exfiltration(start_time: datetime, duration_seconds: int = 120) -> List[UnifiedEvent]:
    events = []
    
    current_time = start_time
    target_ip = "192.168.100.50" 
    
    for i in range(120): 
        events.append(UnifiedEvent(
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
            bytes_sent=random.randint(5 * 1024 * 1024, 25 * 1024 * 1024), 
            bytes_received=random.randint(128, 512),
            raw_label="malicious",
            attack_type="data_exfiltration"
        ))
        
        if i % 10 == 0:
            events.append(UnifiedEvent(
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
                attack_type="data_exfiltration"
            ))
            
        current_time += timedelta(seconds=random.randint(2, 5))
        
    return events
