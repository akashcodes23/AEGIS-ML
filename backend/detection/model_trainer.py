import json
import math
import numpy as np
from typing import List, Dict, Tuple
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
from collections import defaultdict
from datetime import datetime, timedelta
import pandas as pd

from backend.core.schemas import UnifiedEvent
from backend.core.config import PORT_RISK
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.threat_classifier import ThreatClassifier

def load_flexible_dataset(file_path: str) -> List[UnifiedEvent]:
    events = []
    if not Path(file_path).exists():
        print(f"File not found: {file_path}")
        return events
        
    try:
        if str(file_path).endswith('.csv'):
            df = pd.read_csv(file_path)
        else:
            try:
                df = pd.read_json(file_path, lines=True)
            except:
                df = pd.read_json(file_path)
                
        col_map = {
            'source_ip': 'src_ip', 'destination_ip': 'dst_ip',
            'label': 'attack_type', 'src': 'src_entity', 'dst': 'dst_entity',
            'time': 'timestamp'
        }
        df = df.rename(columns=lambda x: col_map.get(x.lower(), x))
        
        # Stratified sampling to handle severe class imbalance
        if 'attack_type' in df.columns:
            class_counts = df['attack_type'].value_counts()
            if not class_counts.empty:
                max_samples = max(100, int(class_counts.median()) * 2)
                sampled_dfs = []
                for label, count in class_counts.items():
                    if count > max_samples:
                        sampled_dfs.append(df[df['attack_type'] == label].sample(n=max_samples, random_state=42))
                    else:
                        sampled_dfs.append(df[df['attack_type'] == label])
                df = pd.concat(sampled_dfs)
                
        df = df.replace({np.nan: None})
        
        for _, row in df.iterrows():
            d = row.to_dict()
            if 'timestamp' not in d or d['timestamp'] is None:
                d['timestamp'] = datetime.now()
            if 'layer' not in d: d['layer'] = 'network'
            if 'src_entity' not in d: d['src_entity'] = d.get('src_ip', 'unknown')
            if 'dst_entity' not in d: d['dst_entity'] = d.get('dst_ip', 'unknown')
            if 'src_internal' not in d: d['src_internal'] = True
            if 'dst_internal' not in d: d['dst_internal'] = True
            
            try:
                 events.append(UnifiedEvent(**d))
            except:
                 pass
                 
    except Exception as e:
        print(f"Pandas load failed ({e}), trying standard JSON parser...")
        with open(file_path, "r") as f:
            for line in f:
                if line.strip():
                    events.append(UnifiedEvent.model_validate_json(line))
                    
    return events

def calculate_failed_auth_rate(events: List[UnifiedEvent]) -> Dict[str, float]:
    """Calculate rolling count of 401s in last 60s for each event's src."""
    # Since we need this per event for training, we'll precalculate for all
    # Sort by time just in case
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    
    # Store history of auth failures per source
    auth_failures = defaultdict(list)
    rates = {}
    
    for event in sorted_events:
        src = event.src_entity
        current_time = event.timestamp
        
        if event.layer == "application" and event.status_code == 401:
            auth_failures[src].append(current_time)
            
        # Clean up old failures (> 60s)
        cutoff = current_time - timedelta(seconds=60)
        auth_failures[src] = [t for t in auth_failures[src] if t >= cutoff]
        
        rates[event.event_id] = float(len(auth_failures[src]))
        
    return rates

def extract_features(
    event: UnifiedEvent, 
    if_score: float, 
    baseline_deviation: float,
    profiler: BehavioralBaselineProfiler,
    failed_auth_rate: float
) -> List[float]:
    
    # graph_new_connections (from TM2's graph, pass as param, default 0)
    graph_new_connections = 0.0
    
    # connection_frequency
    connection_frequency = event.connections_per_minute or 0.0
    
    # bytes_sent_zscore
    bytes_sent_zscore = 0.0
    profile = profiler.profiles.get(event.src_entity)
    if profile and event.bytes_sent is not None and profile.get("std_bytes_sent", 0) > 0:
        bytes_sent_zscore = abs(event.bytes_sent - profile["avg_bytes_sent"]) / profile["std_bytes_sent"]
        
    # dst_port_risk
    dst_port_risk = PORT_RISK.get(event.dst_port, 0.0) if event.dst_port else 0.0
    
    # is_new_destination
    is_new_destination = 1.0
    if profile and event.dst_entity in profile.get("typical_destinations", []):
         is_new_destination = 0.0
         
    # is_external_dst
    is_external_dst = 0.0 if event.dst_internal else 1.0
    
    # hour_of_day
    hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
    hour_of_day_sin = math.sin(2 * math.pi * hour / 24.0)
    hour_of_day_cos = math.cos(2 * math.pi * hour / 24.0)
    
    # cross_layer_match (default False)
    cross_layer_match = 0.0
    
    return [
        if_score,
        baseline_deviation,
        graph_new_connections,
        failed_auth_rate,
        connection_frequency,
        bytes_sent_zscore,
        dst_port_risk,
        is_new_destination,
        is_external_dst,
        hour_of_day_sin,
        hour_of_day_cos,
        cross_layer_match
    ]

def train_pipeline():
    # 1. Load data
    data_path = "data/raw/combined_labeled.jsonl"
    print(f"Loading external dataset from {data_path}...")
    events = load_flexible_dataset(data_path)
    print(f"Loaded {len(events)} events")
    
    if not events:
        print("No events found. Please run data generator first.")
        return

    # 2. Run BehavioralBaselineProfiler
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(events)
    print(f"Baselines built for {len(profiler.profiles)} entities")
    
    # 3. Save baselines
    profiler.save()

    # 4. Train IsolationForestDetector
    if_detector = IsolationForestDetector()
    if_detector.fit(events)
    if_detector.save()
    print("Isolation Forest trained")

    # Precalculate failed auth rates for feature extraction
    failed_auth_rates = calculate_failed_auth_rate(events)

    # 5 & 6 & 7. Extract features for RandomForest
    X = []
    y = []
    
    # ThreatClassifier classes: ["benign", "brute_force", "lateral_movement", "data_exfiltration", "c2_beaconing"]
    for event in events:
         if_score = if_detector.predict(event)
         baseline_dev = profiler.compute_deviation_score(event)
         auth_rate = failed_auth_rates.get(event.event_id, 0.0)
         
         features = extract_features(event, if_score, baseline_dev, profiler, auth_rate)
         
         label = event.attack_type if event.attack_type else "benign"
         if label not in ThreatClassifier.CLASSES:
             label = "benign"
             
         X.append(features)
         y.append(label)

    X = np.array(X)
    y = np.array(y)

    # 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 8. Train ThreatClassifier, evaluate, save
    classifier = ThreatClassifier()
    classifier.fit(X_train, y_train)
    
    y_pred = classifier.model.predict(X_test)
    
    # 9. Print final metrics
    # average="weighted" handles multi-class
    test_f1 = f1_score(y_test, y_pred, average="weighted")
    print(f"Threat Classifier — Test F1: {test_f1:.2f}")
    
    classifier.save()
    print("All models saved to data/models/")

if __name__ == "__main__":
    train_pipeline()
