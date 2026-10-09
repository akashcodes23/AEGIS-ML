# AEGIS-ML: Machine Learning & MLOps Pipeline Audit Report

**Date:** October 2026  
**Auditor:** Senior Machine Learning & MLOps Engineering Team  
**Repository:** [AEGIS-ML](https://github.com/akashcodes23/AEGIS-ML)  
**Status:** Audit Complete — Remediation in Progress

---

## 1. Executive Summary

AEGIS-ML aims to provide a real-time, multi-layer cybersecurity threat intelligence system combining signature, anomaly detection (Isolation Forest), behavioral profiling, and multi-class threat classification (Random Forest) mapped to MITRE ATT&CK kill-chain phases.

An exhaustive technical audit of the codebase revealed critical structural defects, data leakages, deceptive evaluation artifacts, and runtime discrepancies across the data ingestion, ML training, persistence, and FastAPI serving layers. The most severe issue identified was an inflated and invalid 0.98 test F1 score produced by applying SMOTE across the entire dataset prior to cross-validation, with zero evaluation support for the benign class, coupled with an API serving layer that bypassed the trained model using hardcoded random threat injection and synthetic ground-truth fallbacks.

This document details all root causes identified during the audit and defines the systematic remediation plan implemented across Phases 2 through 12.

---

## 2. Identified Issues & Root Cause Analysis

### 2.1 Git Repository & Source Code Integrity
- **Unresolved Merge Conflicts in Repository Files:**
  - `.gitignore`: Contained unresolved Git conflict markers (`<<<<<<< HEAD`, `=======`, `>>>>>>> 25e60573...`), breaking Git ignore patterns.
  - `backend/data_generator/attack_scenarios.py`: Contained multiple unresolved conflict markers (lines 11, 27, 165, 214), causing syntax errors (`SyntaxError: invalid decimal literal`) and preventing module imports.
  - `aegis_full_project.md`: Contained embedded conflict markers.
- **Architectural Discrepancy in Documentation:**
  - `README.md` documented a non-existent stack (Flask, Flask-SocketIO, Eventlet, PyTorch Temporal Graph Neural Network, Three.js 3D universe, OpenAI multi-agent debate), whereas the actual codebase is built on FastAPI, React/Vite, Cytoscape, scikit-learn, and NetworkX.

### 2.2 Model Directory & Path Resolution Inconsistencies
- **Ambiguous Relative Paths (`MODEL_DIR`):**
  - In `backend/core/config.py`, `MODEL_DIR = "data/models"`. When scripts were run from the repository root, artifacts were looked up in `<repo>/data/models/` (which only contained `.gitkeep`), while previously serialized models resided in `<repo>/backend/data/models/`.
  - When scripts ran from `backend/`, paths resolved to `backend/data/models/`. This caused models to appear missing or uninitialized depending on the current working directory.
- **Dependency & Serialization Inconsistencies:**
  - Serialized models (`threat_classifier.pkl`, `isolation_forest_network.pkl`) were pickled with scikit-learn 1.8.0, producing `InconsistentVersionWarning` when loaded under scikit-learn 1.7.x.
  - `imbalanced-learn` was declared in `backend/requirements.txt` but was missing from the environment.
  - Scipy 1.15.3 on macOS arm64 triggered a dynamic linker crash (`_spropack.cpython-310-darwin.so`) requiring pinning to a stable version.

### 2.3 Data Loading & Preprocessing Flaws (`load_flexible_dataset`)
- **Silent Classification of Unknown Labels as Benign:**
  - In `load_flexible_dataset()`, unmapped labels were silently cast to `'benign'` via `label_map.get(str(x).strip(), 'benign')`. Unmapped attacks (e.g., zero-day or unrecognized signatures) were treated as normal traffic without warning or logging.
- **Silent Record Dropping:**
  - `UnifiedEvent` parsing exceptions were caught with bare `except Exception: pass`, silently dropping invalid records without reporting loaded, transformed, rejected, and retained record counts.
- **Timestamp Defaulting:**
  - Missing timestamps defaulted to `datetime.now()` per row without tracking or logging, which distorted temporal features and rolling time windows in `calculate_failed_auth_rate()`.
- **Inconsistent Network Protocols & Units:**
  - CICIDS flow duration in microseconds was divided by 1000 to obtain milliseconds, but integer/float handling was inconsistent and did not validate negative durations.

### 2.4 Data Leakage & Flawed Evaluation Pipeline (`model_trainer.py`)
- **Catastrophic SMOTE Leakage:**
  - In `ThreatClassifier.fit()`, SMOTE was executed on the full dataset before model evaluation, synthesizing instances across the entire feature space. Cross-validation was run on resampled data, leading to severe synthetic data leakage across train/validation splits.
- **Zero Support for Benign Traffic in Training Evaluation:**
  - In the recorded `train_output.txt`, the benign class had a support of `0`. Precision, recall, and F1 for benign were `0.00` with `UndefinedMetricWarning`. The reported "0.98 Test F1" was actually evaluated on SMOTE-oversampled attack-only data, masking severe classification blindspots.
- **No Holdout Test Set Isolation:**
  - The final model metrics presented in `ThreatClassifier.fit()` were computed on the resampled training set (`y_pred = self.model.predict(X)`), reporting training fit rather than generalizable out-of-sample performance.
- **Lack of Baseline Benchmarks:**
  - No `DummyClassifier` or class-weighted non-resampled baseline was evaluated to determine if resampling or complex trees provided genuine lift.
- **Rare Class Crashing:**
  - Stratified splits crashed when classes had fewer than 2 instances.

### 2.5 Threat Classifier Vulnerabilities (`threat_classifier.py`)
- **Silent Benign Fallback on Unfitted/Missing Model:**
  - `predict()` silently returned `ThreatPrediction(threat_type="benign", confidence=1.0)` when `self.is_fitted` was False. If model loading failed in production, all threats were silently cleared as benign with 100% confidence.
- **No Input Validation:**
  - Feature vectors were not validated for expected length (15), NaN, Inf, or numeric types.
- **Uncalibrated Confidence & Flawed Severity Mapping:**
  - Random Forest probabilities (fraction of decision trees) were treated as calibrated probabilities.
  - Threat severity was derived purely from RF confidence (`conf >= 0.90 -> critical`, `conf >= 0.75 -> high`), confounding model prediction certainty with real-world threat impact.

### 2.6 Isolation Forest & Baseline Profiler Bugs
- **Missing State Persistence in Isolation Forest:**
  - `IsolationForestDetector.save()` only saved `network_model` and `endpoint_model`. It failed to serialize `payload_mean`, `payload_std`, and `port_freqs`. Upon reloading in inference, these stats reset to default values (`0.0`, `1.0`, `{}`), creating complete feature drift between training and serving.
- **Inverted / Uncalibrated Anomaly Score:**
  - `anomaly_score = 1.0 - (score + 0.5)` mapped average normal points (`score ~ -0.4`) to `0.9` (anomalous), causing massive false alarms against `ANOMALY_THRESHOLD = 0.65`.
- **Baseline Contamination:**
  - Baseline profiler included malicious attack events in entity baseline profiles, incorporating attacker behaviors into "normal" entity distributions.

### 2.7 Feature Extraction Drift Between Training & Serving
- **Feature Vector Discrepancy:**
  - `model_trainer.py` trained on 15 specific features. In contrast, `backend/api/main.py` extracted 10 completely different raw features and padded them with 5 zeros to match length 15! For example, feature 0 was trained as `if_anomaly_score` but passed as `math.log1p(bytes_sent)` during API serving.
- **Differing Normalization Logic:**
  - `normalizer.py` calculated `bytes_ratio = bytes_sent / (bytes_recv + 1)` and defaulted `port_risk` to `0.3`, while `model_trainer.py` calculated `bytes_ratio = log1p(tx) / log1p(rx + 1)` and defaulted `port_risk` to `0.0`.

### 2.8 API Serving & Deceptive Injection (`main.py`)
- **Artificial Threat Injection in Production Stream:**
  - `main.py` explicitly injected synthetic threats and randomly overrode labels with `random.random() < 0.05` and hardcoded severity mappings.
  - Predictions were overridden with ground-truth labels and faked random confidences (`random.uniform(0.85, 0.99)`).
- **Wildcard Permissive CORS:**
  - API configured `allow_origins=["*"]` with `allow_credentials=True`.

---

## 3. Remediation Matrix & Implementation Plan

| Phase | Component | Planned Fix |
|---|---|---|
| **Phase 2** | `load_flexible_dataset` & Normalizer | Support CSV/JSON/JSONL, validate schemas, strip whitespace, handle unknown labels explicitly, track loaded/rejected counts, unify duration/protocol transformations. |
| **Phase 3** | Data Splitting & Leakage Prevention | Strict train/validation/test split BEFORE preprocessing; ImbPipeline with SMOTE only on training folds; stratified splitting with rare class handling; baseline comparisons (`DummyClassifier`). |
| **Phase 4** | Reproducible Evaluation | Comprehensive metrics (per-class P/R/F1, Macro/Weighted F1, PR-AUC, Balanced Acc, FPR, Confusion Matrix, latency); machine-readable JSON artifacts; no fabricated metrics. |
| **Phase 5** | `ThreatClassifier` | Strict feature vector validation (15 features, NaN/Inf checks); explicit `NotFittedError` on unfitted calls; decoupled severity policy; metadata-rich persistence. |
| **Phase 6** | `IsolationForestDetector` & Baselines | Persist all feature statistics; standardize score scaling to [0, 1] using scikit-learn decision function; build baselines strictly on benign training data. |
| **Phase 7** | Feature Pipeline | Centralize unified feature extraction across training, evaluation, and API; handle zero-division and missing values safely. |
| **Phase 8** | FastAPI API (`main.py`) | Connect real model pipeline to streaming worker; remove artificial threat injection and random confidence; enforce secure CORS; validate inputs. |
| **Phase 9** | Automated Testing | Comprehensive unit and integration test suite with pytest covering dataset parsing, feature extraction, model inference, leak prevention, and API contracts. |
| **Phase 10** | Automation & Environment | Clean `.gitignore`, add `.env.example`, pinned `requirements.txt`, CLI training/eval entry points. |
| **Phase 11** | Documentation | Update `README.md` to accurately reflect implemented architecture, usage, and limitations. |
| **Phase 12** | Verification | Run full verification: syntax checks, pytest suite, model training, evaluation pipeline, API health checks. |
