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
    generate_scheduled_backup,
    generate_large_file_transfer,
    generate_smb_file_sharing,
    generate_bulk_read_archive,
    generate_software_deployment,
    generate_data_synchronization,
    DEFAULT_GENERATOR_VERSION,
    PHASE19_GENERATOR_VERSION,
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
        Generate Phase 17 synthetic dataset with scenario provenance.
        Preserved for historical reproduction.
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

    def generate_behavioral_diversity_dataset(
        self,
        output_path: str = "data/raw/behavioral_diversity_labeled.jsonl",
        seed: int = 42,
        backup_scenarios: int = 6,
        large_transfer_scenarios: int = 6,
        smb_scenarios: int = 6,
        archive_scenarios: int = 6,
        deploy_scenarios: int = 6,
        sync_scenarios: int = 6,
        benign_traffic_scenarios: int = 20,
        benign_events_per_session: int = 80,
        bf_scenarios: int = 10,
        c2_scenarios: int = 25,
        lm_scenarios: int = 15,
        exfil_scenarios: int = 10,
        base_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Phase 19: Generate diversified synthetic dataset with benign administrative workflows
        and varied attack scenarios.
        """
        rng = random.Random(seed)
        start_time = base_time or datetime(2026, 10, 10, 0, 0, 0)
        events: List[UnifiedEvent] = []
        scenario_catalog: Dict[str, Dict[str, Any]] = {}
        version = PHASE19_GENERATOR_VERSION

        # ----------------------------------------------------------------------
        # 1. Benign: Scheduled Backups (robocopy, wbengine)
        # ----------------------------------------------------------------------
        for i in range(backup_scenarios):
            sc_id = f"p19_backup_{i:03d}"
            host_ip = ["10.0.0.5", "10.0.0.10", "10.0.0.22", "10.0.0.35"][i % 4]
            dest_ip = ["10.0.0.90", "10.0.0.91", "10.0.0.92"][i % 3]
            tool = ["robocopy.exe", "wbengine.exe", "backup_svc.exe"][i % 3]
            size_mb = [250, 500, 1000, 1500, 2000, 2500][i % 6]
            file_count = [20, 30, 40, 25, 35, 45][i % 6]

            sc_events = generate_scheduled_backup(
                start_time=start_time + timedelta(hours=i * 2),
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                host_ip=host_ip,
                dest_ip=dest_ip,
                backup_size_mb=size_mb,
                file_count=file_count,
                tool_name=tool,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "scheduled_backup",
                "attack_type": "benign",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "host_ip": host_ip,
                    "dest_ip": dest_ip,
                    "tool": tool,
                    "backup_size_mb": size_mb,
                    "file_count": file_count,
                },
            }

        # ----------------------------------------------------------------------
        # 2. Benign: Large Administrative File Transfers
        # ----------------------------------------------------------------------
        for i in range(large_transfer_scenarios):
            sc_id = f"p19_transfer_{i:03d}"
            src_ip = ["10.0.0.15", "10.0.0.25", "10.0.0.33", "10.0.0.42"][i % 4]
            dst_ip = ["10.0.0.40", "198.51.100.20", "203.0.113.10", "10.0.0.50"][i % 4]
            dst_port = [443, 22, 8080, 443, 22, 8080][i % 6]
            tool = ["azcopy.exe", "sftp.exe", "curl.exe", "rclone.exe", "scp.exe", "azcopy.exe"][i % 6]
            size_mb = [100, 250, 500, 750, 1000, 1200][i % 6]
            chunks = [15, 20, 25, 18, 22, 28][i % 6]

            sc_events = generate_large_file_transfer(
                start_time=start_time + timedelta(hours=i * 3 + 1),
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                total_size_mb=size_mb,
                chunk_count=chunks,
                process_name=tool,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "large_file_transfer",
                "attack_type": "benign",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "tool": tool,
                    "total_size_mb": size_mb,
                    "chunk_count": chunks,
                },
            }

        # ----------------------------------------------------------------------
        # 3. Benign: SMB Departmental File Sharing
        # ----------------------------------------------------------------------
        for i in range(smb_scenarios):
            sc_id = f"p19_smb_{i:03d}"
            client_ip = ["10.0.0.14", "10.0.0.18", "10.0.0.28", "10.0.0.32", "10.0.0.44", "10.0.0.48"][i % 6]
            server_ip = ["10.0.0.12", "10.0.0.15"][i % 2]
            user = ["alice", "bob", "finance_user", "hr_user", "eng_user", "corp_user"][i % 6]
            count = [20, 25, 30, 22, 28, 35][i % 6]

            sc_events = generate_smb_file_sharing(
                start_time=start_time + timedelta(hours=i * 2 + 1),
                count=count,
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                client_ip=client_ip,
                server_ip=server_ip,
                user_account=user,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "smb_file_sharing",
                "attack_type": "benign",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "user_account": user,
                    "count": count,
                },
            }

        # ----------------------------------------------------------------------
        # 4. Benign: Bulk File Reads and Local Archiving
        # ----------------------------------------------------------------------
        for i in range(archive_scenarios):
            sc_id = f"p19_archive_{i:03d}"
            host_ip = ["10.0.0.18", "10.0.0.25", "10.0.0.30", "10.0.0.38", "10.0.0.45", "10.0.0.52"][i % 6]
            tool = ["7z.exe", "tar.exe", "zip.exe"][i % 3]
            file_count = [15, 20, 25, 30, 22, 28][i % 6]

            sc_events = generate_bulk_read_archive(
                start_time=start_time + timedelta(hours=i * 4),
                file_count=file_count,
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                host_ip=host_ip,
                tool_name=tool,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "bulk_read_archive",
                "attack_type": "benign",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "host_ip": host_ip,
                    "tool": tool,
                    "file_count": file_count,
                },
            }

        # ----------------------------------------------------------------------
        # 5. Benign: Software Deployment and Maintenance
        # ----------------------------------------------------------------------
        for i in range(deploy_scenarios):
            sc_id = f"p19_deploy_{i:03d}"
            deploy_srv = ["10.0.0.5", "10.0.0.8"][i % 2]
            tool = ["ccmexec.exe", "ansible-playbook", "msiexec.exe", "wmic.exe"][i % 4]
            dst_port = [135, 445, 5985, 445, 135, 5985][i % 6]
            target_count = [18, 22, 26, 20, 24, 30][i % 6]

            sc_events = generate_software_deployment(
                start_time=start_time + timedelta(hours=i * 5),
                target_count=target_count,
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                deploy_srv=deploy_srv,
                tool_name=tool,
                dst_port=dst_port,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "software_deployment",
                "attack_type": "benign",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "deploy_srv": deploy_srv,
                    "tool": tool,
                    "dst_port": dst_port,
                    "target_count": target_count,
                },
            }

        # ----------------------------------------------------------------------
        # 6. Benign: Scheduled Data Synchronization
        # ----------------------------------------------------------------------
        for i in range(sync_scenarios):
            sc_id = f"p19_sync_{i:03d}"
            host_ip = ["10.0.0.16", "10.0.0.21", "10.0.0.31", "10.0.0.41"][i % 4]
            target = ["10.0.0.50", "198.51.100.25"][i % 2]
            tool = ["onedrive.exe", "db_replicator.exe", "sync_agent.exe"][i % 3]
            port = [443, 3306, 5432][i % 3]
            count = [20, 25, 30, 22, 28, 32][i % 6]

            sc_events = generate_data_synchronization(
                start_time=start_time + timedelta(hours=i * 3 + 2),
                sync_count=count,
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                host_ip=host_ip,
                sync_target=target,
                dst_port=port,
                tool_name=tool,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "data_synchronization",
                "attack_type": "benign",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "host_ip": host_ip,
                    "sync_target": target,
                    "tool": tool,
                    "dst_port": port,
                    "sync_count": count,
                },
            }

        # ----------------------------------------------------------------------
        # 7. Benign: General Browsing and Workstation Sessions
        # ----------------------------------------------------------------------
        for i in range(benign_traffic_scenarios):
            sc_id = f"p19_benign_{i:03d}"
            sc_events = generate_benign_traffic(
                start_time=start_time + timedelta(hours=i),
                count=benign_events_per_session,
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "benign_traffic",
                "attack_type": "benign",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "count": benign_events_per_session,
                },
            }

        # ----------------------------------------------------------------------
        # 8. Attack: Diversified Brute Force Scenarios
        # ----------------------------------------------------------------------
        proto_list = ["HTTP", "HTTP", "HTTP", "HTTP", "SSH", "SSH", "SSH", "RDP", "RDP", "HTTP"]
        ports_list = [443, 443, 8080, 443, 22, 22, 22, 3389, 3389, 443]
        min_att = [80, 120, 100, 60, 40, 60, 50, 30, 40, 100]
        max_att = [120, 180, 150, 90, 60, 80, 70, 50, 60, 150]
        endpoints = [
            "/api/login", "/admin/login", "/auth/token", "/portal/signin",
            "ssh-daemon", "ssh-daemon", "sshd", "termsrv", "rdp-gw", "/api/v2/auth"
        ]

        for i in range(bf_scenarios):
            sc_id = f"p19_bf_{i:03d}"
            p_proto = proto_list[i % len(proto_list)]
            p_port = ports_list[i % len(ports_list)]
            p_min = min_att[i % len(min_att)]
            p_max = max_att[i % len(max_att)]
            p_ep = endpoints[i % len(endpoints)]

            sc_events = generate_brute_force_attack(
                start_time=start_time + timedelta(hours=i * 2 + 1),
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                target_port=p_port,
                auth_protocol=p_proto,
                min_attempts=p_min,
                max_attempts=p_max,
                target_endpoint=p_ep,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "brute_force",
                "attack_type": "brute_force",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "auth_protocol": p_proto,
                    "target_port": p_port,
                    "target_endpoint": p_ep,
                    "min_attempts": p_min,
                    "max_attempts": p_max,
                },
            }

        # ----------------------------------------------------------------------
        # 9. Attack: Diversified C2 Beaconing Scenarios
        # ----------------------------------------------------------------------
        c2_intervals = [15, 30, 45, 60, 90, 120]
        c2_jitters = [2, 5, 8, 10]
        c2_ips = ["203.0.113.45", "198.51.100.88", "192.0.2.75", "203.0.113.99"]
        c2_ports = [8080, 443, 8443, 8080, 443]
        c2_procs = ["cmd.exe", "powershell.exe", "rundll32.exe"]

        for i in range(c2_scenarios):
            sc_id = f"p19_c2_{i:03d}"
            p_inv = c2_intervals[i % len(c2_intervals)]
            p_jit = c2_jitters[i % len(c2_jitters)]
            p_c2ip = c2_ips[i % len(c2_ips)]
            p_c2port = c2_ports[i % len(c2_ports)]
            p_proc = c2_procs[i % len(c2_procs)]

            sc_events = generate_c2_beaconing(
                start_time=start_time + timedelta(minutes=i * 20),
                duration_seconds=300,
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                c2_ip=p_c2ip,
                c2_port=p_c2port,
                interval_seconds=p_inv,
                jitter_seconds=p_jit,
                process_name=p_proc,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "c2_beaconing",
                "attack_type": "c2_beaconing",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "interval_seconds": p_inv,
                    "jitter_seconds": p_jit,
                    "c2_ip": p_c2ip,
                    "c2_port": p_c2port,
                    "process_name": p_proc,
                },
            }

        # ----------------------------------------------------------------------
        # 10. Attack: Diversified Lateral Movement Scenarios
        # ----------------------------------------------------------------------
        lm_tools = ["psexec.exe", "wmic.exe", "powershell.exe", "ssh.exe"]
        lm_ports = [445, 135, 5985, 22]
        lm_srcs = ["10.0.0.23", "10.0.0.15", "10.0.0.35"]

        for i in range(lm_scenarios):
            sc_id = f"p19_lm_{i:03d}"
            p_tool = lm_tools[i % len(lm_tools)]
            p_port = lm_ports[i % len(lm_ports)]
            p_src = lm_srcs[i % len(lm_srcs)]

            sc_events = generate_lateral_movement(
                start_time=start_time + timedelta(minutes=i * 30 + 5),
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                src_ip=p_src,
                tool_process=p_tool,
                dst_port=p_port,
                scan_count_range=(12, 24),
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "lateral_movement",
                "attack_type": "lateral_movement",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "tool_process": p_tool,
                    "dst_port": p_port,
                    "src_ip": p_src,
                },
            }

        # ----------------------------------------------------------------------
        # 11. Attack: Diversified Data Exfiltration Scenarios
        # ----------------------------------------------------------------------
        ex_tools = ["7z.exe", "tar.exe", "powershell.exe", None]
        ex_targets = ["192.168.100.50", "203.0.113.50", "198.51.100.200"]
        ex_ports = [443, 22, 443, 8080]
        ex_chunks = [(5, 25), (1, 5), (15, 40), (2, 10)]

        for i in range(exfil_scenarios):
            sc_id = f"p19_exfil_{i:03d}"
            p_tool = ex_tools[i % len(ex_tools)]
            p_tgt = ex_targets[i % len(ex_targets)]
            p_port = ex_ports[i % len(ex_ports)]
            p_range = ex_chunks[i % len(ex_chunks)]

            sc_events = generate_data_exfiltration(
                start_time=start_time + timedelta(hours=i * 2 + 1),
                duration_seconds=120,
                scenario_id=sc_id,
                generator_version=version,
                rng=rng,
                target_ip=p_tgt,
                staging_tool=p_tool,
                dst_port=p_port,
                chunk_size_range_mb=p_range,
                transfer_count=70,
            )
            events.extend(sc_events)
            scenario_catalog[sc_id] = {
                "scenario_type": "data_exfiltration",
                "attack_type": "data_exfiltration",
                "event_count": len(sc_events),
                "generation_parameters": {
                    "staging_tool": p_tool,
                    "target_ip": p_tgt,
                    "dst_port": p_port,
                    "chunk_size_range_mb": p_range,
                },
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

        # Write to output file (preserving Phase 19 schema serialization)
        _post_p19_fields = {
            "event_type", "ingestion_timestamp", "packets_sent", "packets_received",
            "source_system", "schema_version", "provenance", "missing_fields",
            "clock_skew_detected", "is_late_arriving", "dedup_fingerprint"
        }
        with open(target_file, "w", encoding="utf-8") as f:
            for event in events:
                f.write(event.model_dump_json(exclude=_post_p19_fields) + "\n")

        # Compute SHA-256 hash
        hasher = hashlib.sha256()
        with open(target_file, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        dataset_sha256 = hasher.hexdigest()

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
            "generator_version": version,
            "generation_parameters": {
                "backup_scenarios": backup_scenarios,
                "large_transfer_scenarios": large_transfer_scenarios,
                "smb_scenarios": smb_scenarios,
                "archive_scenarios": archive_scenarios,
                "deploy_scenarios": deploy_scenarios,
                "sync_scenarios": sync_scenarios,
                "benign_traffic_scenarios": benign_traffic_scenarios,
                "benign_events_per_session": benign_events_per_session,
                "bf_scenarios": bf_scenarios,
                "c2_scenarios": c2_scenarios,
                "lm_scenarios": lm_scenarios,
                "exfil_scenarios": exfil_scenarios,
            },
            "scenario_catalog": scenario_catalog,
        }

        print(
            f"[Phase 19] Generated {len(events)} events across {len(scenario_catalog)} scenarios to {output_path} "
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
        elif sys.argv[1] == "phase19":
            DataOrchestrator().generate_behavioral_diversity_dataset()
        elif sys.argv[1] == "demo":
            asyncio.run(DataOrchestrator().demo_mode(asyncio.Queue()))
        else:
            print("Usage: python orchestrator.py [train|phase19|demo]")
    else:
        print("Usage: python orchestrator.py [train|phase19|demo]")
