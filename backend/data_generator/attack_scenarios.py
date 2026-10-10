from typing import List, Optional, Tuple
from datetime import datetime, timedelta
import random
import uuid

from backend.core.schemas import UnifiedEvent
from backend.core.config import ATTACKER_IPS, C2_SERVER_IP, C2_PORT, INTERNAL_IPS

DEFAULT_GENERATOR_VERSION = "2.0.0"
PHASE19_GENERATOR_VERSION = "3.0.0"


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
    target_port: Optional[int] = None,
    auth_protocol: str = "HTTP",
    min_attempts: int = 150,
    max_attempts: int = 450,
    target_endpoint: Optional[str] = None,
    target_host: Optional[str] = None,
    target_ip: Optional[str] = None,
    success_at_end: bool = True,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []

    attempts = r.randint(min_attempts, max_attempts)
    dest_port = target_port if target_port is not None else (22 if auth_protocol == "SSH" else (3389 if auth_protocol == "RDP" else 443))
    dest_host = target_host or ("ssh.corp.com" if auth_protocol == "SSH" else ("rdp.corp.com" if auth_protocol == "RDP" else "api.corp.com"))
    endpoint_p = target_endpoint or ("/api/login" if auth_protocol == "HTTP" else ("ssh-daemon" if auth_protocol == "SSH" else "termsrv"))
    dest_ip = target_ip or "10.0.0.10"

    for i in range(attempts):
        time_offset = timedelta(seconds=(r.uniform(30.0, 120.0) / max(1, attempts)) * i)
        event_time = start_time + time_offset
        src_ip = ATTACKER_IPS[i % len(ATTACKER_IPS)]

        is_success = (i == attempts - r.randint(1, 5)) if success_at_end else False
        if is_success:
            status_code = 200
            auth_result = "success"
        else:
            status_code = 401
            auth_result = "failure"

        # Application / auth event
        if auth_protocol == "HTTP":
            app_event = UnifiedEvent(
                event_id=generate_event_uuid(scenario_id, i * 2, rng),
                timestamp=event_time,
                layer="application",
                src_entity=src_ip,
                dst_entity=f"{dest_host}{endpoint_p}",
                src_internal=False,
                dst_internal=True,
                src_ip=src_ip,
                dst_ip=dest_ip,
                http_method="POST",
                endpoint_path=endpoint_p,
                status_code=status_code,
                auth_result=auth_result,
                raw_label="malicious",
                attack_type="brute_force",
                scenario_id=scenario_id,
                scenario_type="brute_force" if scenario_id else None,
                generator_version=generator_version if scenario_id else None,
            )
        else:
            app_event = UnifiedEvent(
                event_id=generate_event_uuid(scenario_id, i * 2, rng),
                timestamp=event_time,
                layer="application",
                src_entity=src_ip,
                dst_entity=f"{dest_host}:{dest_port}",
                src_internal=False,
                dst_internal=True,
                src_ip=src_ip,
                dst_ip=dest_ip,
                endpoint_path=endpoint_p,
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
            dst_entity=dest_host,
            src_internal=False,
            dst_internal=True,
            src_ip=src_ip,
            dst_ip=dest_ip,
            dst_port=dest_port,
            protocol="TCP",
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
    c2_ip: Optional[str] = None,
    c2_port: Optional[int] = None,
    interval_seconds: int = 60,
    jitter_seconds: int = 5,
    src_ip: Optional[str] = None,
    payload_bytes_sent: int = 64,
    payload_bytes_recv_range: Optional[Tuple[int, int]] = None,
    process_name: str = "cmd.exe",
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []

    current_time = start_time
    end_time = start_time + timedelta(seconds=duration_seconds)
    beacon_count = 0
    event_counter = 0

    dest_ip = c2_ip or C2_SERVER_IP
    dest_port = c2_port or C2_PORT
    source_ip = src_ip or "10.0.0.23"
    recv_range = payload_bytes_recv_range or (128, 256)

    while current_time < end_time:
        net_event = UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity=source_ip,
            dst_entity=dest_ip,
            src_internal=True,
            dst_internal=False,
            src_ip=source_ip,
            dst_ip=dest_ip,
            dst_port=dest_port,
            protocol="TCP",
            bytes_sent=payload_bytes_sent,
            bytes_received=r.randint(recv_range[0], recv_range[1]),
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
                src_entity=source_ip,
                dst_entity=source_ip,
                src_internal=True,
                dst_internal=True,
                src_ip=source_ip,
                process_name=process_name,
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

        jitter = r.randint(-jitter_seconds, jitter_seconds)
        current_time += timedelta(seconds=max(5, interval_seconds + jitter))

    return events


def generate_lateral_movement(
    start_time: datetime,
    scenario_id: Optional[str] = None,
    generator_version: str = DEFAULT_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
    src_ip: Optional[str] = None,
    pivot_targets: Optional[List[str]] = None,
    tool_process: str = "psexec.exe",
    dst_port: int = 445,
    scan_count_range: Optional[Tuple[int, int]] = None,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    event_counter = 0
    source_ip = src_ip or "10.0.0.23"

    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=start_time,
        layer="endpoint",
        src_entity=source_ip,
        dst_entity=source_ip,
        src_internal=True,
        dst_internal=True,
        src_ip=source_ip,
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

    tool_time = start_time + timedelta(seconds=2)
    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=tool_time,
        layer="endpoint",
        src_entity=source_ip,
        dst_entity=source_ip,
        src_internal=True,
        dst_internal=True,
        src_ip=source_ip,
        process_name=tool_process,
        user_account="jsmith",
        action="exec",
        raw_label="malicious",
        attack_type="lateral_movement",
        scenario_id=scenario_id,
        scenario_type="lateral_movement" if scenario_id else None,
        generator_version=generator_version if scenario_id else None,
    ))
    event_counter += 1

    current_time = tool_time + timedelta(seconds=1)
    scan_min, scan_max = scan_count_range or (10, 30)
    scan_count = r.randint(scan_min, scan_max)
    for i in range(scan_count):
        if pivot_targets and len(pivot_targets) > 0:
            target_ip = pivot_targets[i % len(pivot_targets)]
        else:
            target_ip = f"10.0.0.{r.randint(20, 200)}"
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity=source_ip,
            dst_entity=target_ip,
            src_internal=True,
            dst_internal=True,
            src_ip=source_ip,
            dst_ip=target_ip,
            dst_port=dst_port,
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
    src_ip: Optional[str] = None,
    target_ip: Optional[str] = None,
    staging_tool: Optional[str] = "7z.exe",
    dst_port: int = 443,
    chunk_size_range_mb: Optional[Tuple[int, int]] = None,
    transfer_count: int = 120,
) -> List[UnifiedEvent]:
    r = rng if rng is not None else random
    events = []
    event_counter = 0

    current_time = start_time
    source_ip = src_ip or "10.0.0.33"
    dest_ip = target_ip or "192.168.100.50"
    min_mb, max_mb = chunk_size_range_mb or (5, 25)

    for i in range(transfer_count):
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity=source_ip,
            dst_entity=dest_ip,
            src_internal=True,
            dst_internal=False,
            src_ip=source_ip,
            dst_ip=dest_ip,
            dst_port=dst_port,
            protocol="TCP",
            bytes_sent=r.randint(min_mb * 1024 * 1024, max_mb * 1024 * 1024),
            bytes_received=r.randint(128, 512),
            raw_label="malicious",
            attack_type="data_exfiltration",
            scenario_id=scenario_id,
            scenario_type="data_exfiltration" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1

        if staging_tool and (i % 10 == 0):
            events.append(UnifiedEvent(
                event_id=generate_event_uuid(scenario_id, event_counter, rng),
                timestamp=current_time,
                layer="endpoint",
                src_entity=source_ip,
                dst_entity=source_ip,
                src_internal=True,
                dst_internal=True,
                src_ip=source_ip,
                process_name=staging_tool,
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


# ==============================================================================
# PHASE 19: BENIGN ADMINISTRATIVE & HARD-NEGATIVE SCENARIO GENERATORS
# ==============================================================================

def generate_scheduled_backup(
    start_time: datetime,
    scenario_id: Optional[str] = None,
    generator_version: str = PHASE19_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
    host_ip: str = "10.0.0.5",
    dest_ip: str = "10.0.0.90",
    backup_size_mb: int = 1000,
    file_count: int = 30,
    tool_name: str = "robocopy.exe",
    user_account: str = "backup_svc",
    dst_port: int = 445,
) -> List[UnifiedEvent]:
    """Legitimate scheduled backup scenario using robocopy or wbengine."""
    r = rng if rng is not None else random
    events = []
    event_counter = 0

    # 1. Endpoint file read events
    for i in range(file_count):
        file_ext = r.choice([".xlsx", ".pdf", ".bak", ".vmdk", ".sql"])
        file_name = f"C:\\CompanyData\\Volume_{i // 10}\\BackupItem_{i}{file_ext}"
        t_offset = timedelta(seconds=i * 2 + r.uniform(-0.5, 0.5))
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=start_time + t_offset,
            layer="endpoint",
            src_entity=host_ip,
            dst_entity=host_ip,
            src_internal=True,
            dst_internal=True,
            src_ip=host_ip,
            process_name=tool_name,
            user_account=user_account,
            file_path=file_name,
            action="read",
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="scheduled_backup" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1

    # 2. Network transmission chunks to backup vault
    chunks = max(3, file_count // 5)
    bytes_per_chunk = (backup_size_mb * 1024 * 1024) // chunks
    for j in range(chunks):
        t_net = start_time + timedelta(seconds=j * 15 + r.uniform(-1.0, 1.0))
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=t_net,
            layer="network",
            src_entity=host_ip,
            dst_entity=dest_ip,
            src_internal=True,
            dst_internal=True,
            src_ip=host_ip,
            dst_ip=dest_ip,
            dst_port=dst_port,
            protocol="TCP",
            bytes_sent=bytes_per_chunk + r.randint(-512, 512),
            bytes_received=1024 * r.randint(64, 256),
            duration_ms=r.randint(5000, 30000),
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="scheduled_backup" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1

    return events


def generate_large_file_transfer(
    start_time: datetime,
    scenario_id: Optional[str] = None,
    generator_version: str = PHASE19_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
    src_ip: str = "10.0.0.15",
    dst_ip: str = "10.0.0.40",
    dst_port: int = 443,
    total_size_mb: int = 500,
    chunk_count: int = 20,
    process_name: str = "azcopy.exe",
    user_account: str = "corp_admin",
) -> List[UnifiedEvent]:
    """Legitimate large administrative file transfer (ISO image, artifact repo, cloud backup)."""
    r = rng if rng is not None else random
    events = []
    event_counter = 0

    # Process execution
    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=start_time,
        layer="endpoint",
        src_entity=src_ip,
        dst_entity=src_ip,
        src_internal=True,
        dst_internal=True,
        src_ip=src_ip,
        process_name=process_name,
        user_account=user_account,
        action="exec",
        raw_label="benign",
        attack_type=None,
        scenario_id=scenario_id,
        scenario_type="large_file_transfer" if scenario_id else None,
        generator_version=generator_version if scenario_id else None,
    ))
    event_counter += 1

    # Network chunk transfers
    bytes_per_chunk = (total_size_mb * 1024 * 1024) // max(1, chunk_count)
    current_time = start_time + timedelta(seconds=1)
    for _ in range(chunk_count):
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity=src_ip,
            dst_entity=dst_ip,
            src_internal=True,
            dst_internal=dst_ip.startswith("10."),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="TCP",
            bytes_sent=bytes_per_chunk + r.randint(-1024, 1024),
            bytes_received=r.randint(1024, 8192),
            duration_ms=r.randint(2000, 15000),
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="large_file_transfer" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        current_time += timedelta(seconds=r.randint(3, 8))

    return events


def generate_smb_file_sharing(
    start_time: datetime,
    count: int = 30,
    scenario_id: Optional[str] = None,
    generator_version: str = PHASE19_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
    client_ip: str = "10.0.0.14",
    server_ip: str = "10.0.0.12",
    user_account: str = "finance_user",
) -> List[UnifiedEvent]:
    """Legitimate workstation-to-server SMB file operations (reading/writing office documents)."""
    r = rng if rng is not None else random
    events = []
    event_counter = 0

    current_time = start_time
    for i in range(count):
        file_ext = r.choice([".docx", ".xlsx", ".pptx", ".pdf", ".txt"])
        action = r.choice(["read", "write", "open"])
        file_name = f"\\\\filesrv\\shared_drive\\Project_{i % 5}\\Document_{i}{file_ext}"

        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="endpoint",
            src_entity=client_ip,
            dst_entity=client_ip,
            src_internal=True,
            dst_internal=True,
            src_ip=client_ip,
            process_name="explorer.exe",
            user_account=user_account,
            file_path=file_name,
            action=action,
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="smb_file_sharing" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1

        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time + timedelta(milliseconds=r.randint(20, 150)),
            layer="network",
            src_entity=client_ip,
            dst_entity=server_ip,
            src_internal=True,
            dst_internal=True,
            src_ip=client_ip,
            dst_ip=server_ip,
            dst_port=445,
            protocol="TCP",
            bytes_sent=r.randint(4096, 500000),
            bytes_received=r.randint(4096, 1000000),
            duration_ms=r.randint(50, 1200),
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="smb_file_sharing" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        current_time += timedelta(seconds=r.randint(5, 25))

    return events


def generate_bulk_read_archive(
    start_time: datetime,
    file_count: int = 25,
    scenario_id: Optional[str] = None,
    generator_version: str = PHASE19_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
    host_ip: str = "10.0.0.18",
    tool_name: str = "7z.exe",
    user_account: str = "dev_user",
) -> List[UnifiedEvent]:
    """Legitimate local bulk file read and archive creation (no outbound exfiltration)."""
    r = rng if rng is not None else random
    events = []
    event_counter = 0

    current_time = start_time
    for i in range(file_count):
        file_name = f"C:\\BuildWorkspace\\Logs\\run_202610_{i}.log"
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="endpoint",
            src_entity=host_ip,
            dst_entity=host_ip,
            src_internal=True,
            dst_internal=True,
            src_ip=host_ip,
            process_name=tool_name,
            user_account=user_account,
            file_path=file_name,
            action="read",
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="bulk_read_archive" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        current_time += timedelta(milliseconds=r.randint(50, 300))

    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=current_time + timedelta(seconds=1),
        layer="endpoint",
        src_entity=host_ip,
        dst_entity=host_ip,
        src_internal=True,
        dst_internal=True,
        src_ip=host_ip,
        process_name=tool_name,
        user_account=user_account,
        file_path="C:\\BuildWorkspace\\Logs\\archive_202610.7z",
        action="write",
        raw_label="benign",
        attack_type=None,
        scenario_id=scenario_id,
        scenario_type="bulk_read_archive" if scenario_id else None,
        generator_version=generator_version if scenario_id else None,
    ))
    event_counter += 1

    return events


def generate_software_deployment(
    start_time: datetime,
    target_count: int = 25,
    scenario_id: Optional[str] = None,
    generator_version: str = PHASE19_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
    deploy_srv: str = "10.0.0.5",
    tool_name: str = "ccmexec.exe",
    dst_port: int = 135,
) -> List[UnifiedEvent]:
    """Legitimate remote administrative management and software deployment."""
    r = rng if rng is not None else random
    events = []
    event_counter = 0

    events.append(UnifiedEvent(
        event_id=generate_event_uuid(scenario_id, event_counter, rng),
        timestamp=start_time,
        layer="endpoint",
        src_entity=deploy_srv,
        dst_entity=deploy_srv,
        src_internal=True,
        dst_internal=True,
        src_ip=deploy_srv,
        process_name=tool_name,
        user_account="SYSTEM",
        action="exec",
        raw_label="benign",
        attack_type=None,
        scenario_id=scenario_id,
        scenario_type="software_deployment" if scenario_id else None,
        generator_version=generator_version if scenario_id else None,
    ))
    event_counter += 1

    current_time = start_time + timedelta(seconds=1)
    for i in range(target_count):
        target_ip = f"10.0.0.{30 + (i % 50)}"
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity=deploy_srv,
            dst_entity=target_ip,
            src_internal=True,
            dst_internal=True,
            src_ip=deploy_srv,
            dst_ip=target_ip,
            dst_port=dst_port,
            protocol="TCP",
            bytes_sent=r.randint(4096, 65536),
            bytes_received=r.randint(1024, 16384),
            duration_ms=r.randint(100, 2000),
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="software_deployment" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        current_time += timedelta(seconds=r.randint(2, 6))

    return events


def generate_data_synchronization(
    start_time: datetime,
    sync_count: int = 30,
    scenario_id: Optional[str] = None,
    generator_version: str = PHASE19_GENERATOR_VERSION,
    rng: Optional[random.Random] = None,
    host_ip: str = "10.0.0.16",
    sync_target: str = "10.0.0.50",
    dst_port: int = 443,
    tool_name: str = "sync_agent.exe",
) -> List[UnifiedEvent]:
    """Legitimate periodic data synchronization (database replication, cloud drive sync)."""
    r = rng if rng is not None else random
    events = []
    event_counter = 0

    current_time = start_time
    for _ in range(sync_count):
        events.append(UnifiedEvent(
            event_id=generate_event_uuid(scenario_id, event_counter, rng),
            timestamp=current_time,
            layer="network",
            src_entity=host_ip,
            dst_entity=sync_target,
            src_internal=True,
            dst_internal=sync_target.startswith("10."),
            src_ip=host_ip,
            dst_ip=sync_target,
            dst_port=dst_port,
            protocol="TCP",
            bytes_sent=r.randint(50000, 2000000),
            bytes_received=r.randint(10000, 500000),
            duration_ms=r.randint(500, 3000),
            raw_label="benign",
            attack_type=None,
            scenario_id=scenario_id,
            scenario_type="data_synchronization" if scenario_id else None,
            generator_version=generator_version if scenario_id else None,
        ))
        event_counter += 1
        current_time += timedelta(seconds=r.randint(15, 35))

    return events
