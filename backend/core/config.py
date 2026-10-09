# All shared constants — teammates import from here, never hardcode values
from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = os.getenv("AEGIS_MODEL_DIR", str(PROJECT_ROOT / "data" / "models"))

def resolve_model_path(filename: str) -> str:
    """Resolve model artifact path across project root, backend folder, or relative CWD."""
    p1 = Path(MODEL_DIR) / filename
    if p1.exists():
        return str(p1)
    p2 = PROJECT_ROOT / "backend" / "data" / "models" / filename
    if p2.exists():
        return str(p2)
    p3 = Path("data/models") / filename
    if p3.exists():
        return str(p3)
    return str(p1)

INTERNAL_IP_RANGE = "10.0.0.0/8"
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(1, 101)]

# Detection thresholds
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.65"))  # IF score above this = anomalous
CONFIDENCE_ALERT_MIN = float(os.getenv("CONFIDENCE_ALERT_MIN", "0.40"))  # Don't create alert below this confidence
CONFIDENCE_CRITICAL = float(os.getenv("CONFIDENCE_CRITICAL", "0.90"))
CONFIDENCE_HIGH = float(os.getenv("CONFIDENCE_HIGH", "0.75"))
CONFIDENCE_MEDIUM = float(os.getenv("CONFIDENCE_MEDIUM", "0.50"))

# Queue settings
QUEUE_MAX_SIZE = int(os.getenv("QUEUE_MAX_SIZE", "10000"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
TARGET_EVENTS_PER_SEC = int(os.getenv("TARGET_EVENTS_PER_SEC", "500"))

# Simulation settings
SIMULATION_DURATION_SEC = 600  # 10 minutes

# Port risk scores
PORT_RISK = {
    22: 0.6,
    23: 0.9,
    445: 0.7,
    3389: 0.8,
    4444: 1.0,
    8080: 0.5,
    443: 0.1,
    80: 0.1,
    53: 0.0
}

# Known malicious process names
MALICIOUS_PROCESSES = [
    "psexec.exe",
    "mimikatz.exe",
    "cobalt_strike.exe",
    "meterpreter.exe",
    "nc.exe",
    "nmap.exe"
]

# Attack scenario IPs
ATTACKER_IPS = ["185.220.101.45", "185.220.101.46", "185.220.101.47"]
C2_SERVER_IP = "203.0.113.45"
C2_PORT = 8080

# Model file paths
IF_NETWORK_PATH = resolve_model_path("isolation_forest_network.pkl")
IF_ENDPOINT_PATH = resolve_model_path("isolation_forest_endpoint.pkl")
RF_CLASSIFIER_PATH = resolve_model_path("threat_classifier.pkl")
BASELINES_PATH = resolve_model_path("entity_baselines.pkl")

# Canonical MITRE ATT&CK & Kill Chain mappings
KILL_CHAIN_STAGES = {
    "brute_force": "Weaponize",
    "lateral_movement": "Install",
    "c2_beaconing": "C2",
    "data_exfiltration": "Exfiltrate",
    "statistical_anomaly": "Anomaly",
    "benign": "None",
}

MITRE_TECHNIQUES = {
    "brute_force": {"id": "T1110", "name": "Brute Force: Password Guessing"},
    "lateral_movement": {"id": "T1021", "name": "Remote Services: SMB/Windows Admin Shares"},
    "c2_beaconing": {"id": "T1071", "name": "Application Layer Protocol: Web Protocols"},
    "data_exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
    "statistical_anomaly": {"id": "T1046", "name": "Network Service Discovery / Anomaly"},
}

