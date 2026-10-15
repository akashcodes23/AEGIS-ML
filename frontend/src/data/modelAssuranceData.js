/**
 * AEGIS-ML Model Assurance & Empirical Evaluation Data Contract
 *
 * Source of Truth:
 * - docs/evaluation/results.json (Generated 2026-10-14T08:07:42Z)
 * - docs/evaluation/RESULTS.md
 * - docs/model-card.md
 * - docs/evaluation.md (Protocol version: 1.0.0-preregistered)
 *
 * NOTE: These figures are pre-registered frozen evaluation results on held-out test partitions.
 * They represent empirical measurements, NOT guarantees of real-world perfection.
 */

export function formatMetric(val, digits = 4, fallback = 'Unavailable') {
  if (val === undefined || val === null || Number.isNaN(Number(val))) {
    return fallback
  }
  return Number(val).toFixed(digits)
}

export const MODEL_ASSURANCE_METADATA = {
  protocol_version: '1.0.0-preregistered',
  protocol_path: 'docs/evaluation.md',
  model_card_path: 'docs/model-card.md',
  results_doc_path: 'docs/evaluation/RESULTS.md',
  evaluation_timestamp: '2026-10-14T08:07:42Z',
  primary_seed: 42,
  bootstrap_seed: 1337,
  bootstrap_iterations: 1000,
  dataset_name: 'behavioral_diversity_labeled.jsonl',
  dataset_sha256: '1a8967f3253bb6dfdd19d278a3f1f486759305fa447c5a84a4daafbb892ce352',
  dataset_total_records: 5717,
  python_version: '3.10.12',
  sklearn_version: '1.7.2',
  imblearn_version: '0.12.4',
  splits: {
    train_records: 4155,
    train_scenarios: 80,
    val_records: 676,
    val_scenarios: 17,
    test_records: 886,
    test_scenarios: 19,
    scenario_overlap: 0.0,
  },
}

export const HEADLINE_METRICS = {
  macro_f1: {
    value: 0.9866,
    ci_95_lower: 0.7803,
    ci_95_upper: 0.9987,
    mean: 0.9674,
    std: 0.0606,
    label: 'Macro F1 Score',
    description: 'Unweighted mean of per-class F1 scores across all 5 classes on held-out scenario test partition.',
  },
  benign_fpr: {
    value: 0.0024,
    ci_95_lower: 0.0000,
    ci_95_upper: 0.0097,
    mean: 0.0026,
    std: 0.0030,
    fp_count: 1,
    total_benign: 419,
    alerts_per_1m: 2386.63,
    label: 'Benign False-Positive Rate',
    description: '1 false alert out of 419 held-out benign network flows (2,386.63 alerts / 1,000,000 benign flows).',
  },
  ece: {
    value: 0.0011,
    ci_95_lower: 0.0003,
    ci_95_upper: 0.0120,
    mean: 0.0046,
    std: 0.0031,
    uncalibrated_ece: 0.1141,
    delta: -0.1130,
    label: 'Expected Calibration Error (ECE)',
    description: 'Expected absolute calibration discrepancy between empirical posterior confidence and observed accuracy across 10 confidence bins.',
  },
  brier_score: {
    value: 0.0109,
    ci_95_lower: 0.0028,
    ci_95_upper: 0.0270,
    uncalibrated_brier: 0.1144,
    delta: -0.1035,
    label: 'Multi-Class Brier Score',
    description: 'Mean squared probability error across one-hot class vectors (lower indicates tighter posterior probability calibration).',
  },
}

export const COMPARATIVE_BASELINES = [
  {
    model_id: 'baseline_majority_dummy',
    name: 'Majority Dummy Baseline',
    macro_f1: 0.1284,
    weighted_f1: 0.3037,
    benign_fpr: 0.0000,
    alerts_per_1m: 0.0,
    ece: 0.5271,
    brier: 1.0542,
    overall_accuracy: 0.4729,
    balanced_acc: 0.2000,
    notes: 'Trivial baseline predicting dominant benign class for all test flows.',
  },
  {
    model_id: 'baseline_logistic_regression',
    name: 'L2 Logistic Regression',
    macro_f1: 0.8147,
    weighted_f1: 0.9080,
    benign_fpr: 0.0883,
    alerts_per_1m: 88305.49,
    ece: 0.0905,
    brier: 0.1130,
    overall_accuracy: 0.8928,
    balanced_acc: 0.9069,
    notes: 'Linear baseline with standard L2 penalty and balanced class weights.',
  },
  {
    model_id: 'baseline_untuned_rf',
    name: 'Untuned Random Forest',
    macro_f1: 0.8703,
    weighted_f1: 0.9270,
    benign_fpr: 0.1957,
    alerts_per_1m: 195704.06,
    ece: 0.1060,
    brier: 0.1218,
    overall_accuracy: 0.9074,
    balanced_acc: 0.9609,
    notes: 'Default scikit-learn hyperparameters without tuning or probability calibration.',
  },
  {
    model_id: 'full_pipeline_uncalibrated',
    name: 'Optimized RF (Uncalibrated)',
    macro_f1: 0.8750,
    weighted_f1: 0.9310,
    benign_fpr: 0.1838,
    alerts_per_1m: 183770.88,
    ece: 0.1141,
    brier: 0.1144,
    overall_accuracy: 0.9131,
    balanced_acc: 0.9632,
    notes: 'SMOTE + class-weighted Random Forest prior to isotonic probability calibration.',
  },
  {
    model_id: 'full_pipeline_calibrated',
    name: 'Full AEGIS Model (Calibrated RF)',
    macro_f1: 0.9866,
    weighted_f1: 0.9943,
    benign_fpr: 0.0024,
    alerts_per_1m: 2386.63,
    ece: 0.0011,
    brier: 0.0109,
    overall_accuracy: 0.9944,
    balanced_acc: 0.9810,
    is_production: true,
    notes: 'SMOTE + RF + CalibratedClassifierCV (isotonic) evaluated on held-out test split.',
  },
]

export const PER_CLASS_METRICS = [
  { class_name: 'benign', label: 'Benign Traffic', support: 419, precision: 0.9929, recall: 0.9976, f1: 0.9952, pr_auc: 0.9929 },
  { class_name: 'brute_force', label: 'Brute Force', support: 238, precision: 1.0000, recall: 1.0000, f1: 1.0000, pr_auc: 1.0000 },
  { class_name: 'lateral_movement', label: 'Lateral Movement', support: 35, precision: 1.0000, recall: 0.9143, f1: 0.9552, pr_auc: 0.9177 },
  { class_name: 'data_exfiltration', label: 'Data Exfiltration', support: 147, precision: 0.9932, recall: 0.9932, f1: 0.9932, pr_auc: 0.9943 },
  { class_name: 'c2_beaconing', label: 'C2 Beaconing', support: 47, precision: 0.9792, recall: 1.0000, f1: 0.9895, pr_auc: 0.9792 },
]

export const RELIABILITY_BINS_CALIBRATED = [
  { bin_index: 1, bin_range: '[0.0, 0.1]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 2, bin_range: '[0.1, 0.2]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 3, bin_range: '[0.2, 0.3]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 4, bin_range: '[0.3, 0.4]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 5, bin_range: '[0.4, 0.5]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 6, bin_range: '[0.5, 0.6]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 7, bin_range: '[0.6, 0.7]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 8, bin_range: '[0.7, 0.8]', samples: 0, mean_confidence: 0.0000, observed_accuracy: 0.0000, calibration_gap: 0.0000 },
  { bin_index: 9, bin_range: '[0.8, 0.9]', samples: 1, mean_confidence: 0.8035, observed_accuracy: 0.0000, calibration_gap: 0.8035 },
  { bin_index: 10, bin_range: '[0.9, 1.0]', samples: 885, mean_confidence: 0.9957, observed_accuracy: 0.9955, calibration_gap: 0.0002 },
]

export const ZERO_DAY_GENERALIZATION = [
  {
    attack_category: 'Data Exfiltration',
    held_out_samples: 147,
    escape_to_benign_pct: 100.0,
    supervised_misclassifications: { benign: 147 },
    isolation_forest_recall_pct: 0.0,
    profiler_deviation_recall_pct: 0.0,
    defense_notes: 'Supervised classifier silently categorizes 100% of unobserved exfiltration as benign. Unsupervised layers showed 0% recall without endpoint volume thresholds.',
  },
  {
    attack_category: 'Lateral Movement',
    held_out_samples: 35,
    escape_to_benign_pct: 94.3,
    supervised_misclassifications: { benign: 33, c2_beaconing: 2 },
    isolation_forest_recall_pct: 0.0,
    profiler_deviation_recall_pct: 0.0,
    defense_notes: '33/35 flows escaped to benign. 2 flows misclassified as C2 beaconing. Unsupervised feature drift alone failed to alert.',
  },
  {
    attack_category: 'Brute Force',
    held_out_samples: 238,
    escape_to_benign_pct: 92.4,
    supervised_misclassifications: { benign: 220, c2_beaconing: 18 },
    isolation_forest_recall_pct: 0.0,
    profiler_deviation_recall_pct: 0.0,
    defense_notes: '220/238 flows escaped to benign. 18 flows triggered C2 beaconing signature due to high recurrence rates.',
  },
  {
    attack_category: 'C2 Beaconing',
    held_out_samples: 47,
    escape_to_benign_pct: 44.7,
    supervised_misclassifications: { benign: 21, data_exfiltration: 26 },
    isolation_forest_recall_pct: 0.0,
    profiler_deviation_recall_pct: 38.3,
    defense_notes: '21/47 escaped to benign, 26 misclassified as exfiltration. Profile deviation layer caught 38.3% independently through regularity metrics.',
  },
]

export const CICIDS_STATUS = {
  status: 'BLOCKED_AWAITING_LOCAL_COPY',
  reason: 'Interactive registration required by UNB; local raw dataset absent from offline environment; 35.4% feature schema discrepancy for endpoint process context.',
  fabricated_numbers: false,
}

export const CORRELATION_ENGINE_VALIDATION = {
  scenarios_evaluated: 12,
  fixture_events: 34,
  pairwise_cluster_f1: 1.0,
  merge_errors: 0,
  split_errors: 0,
  evidence_traceability_pct: 100.0,
  triage_reduction_pct: 44.12,
  disclaimer: 'Evaluates deterministic grouping heuristics against controlled synthetic test fixtures. Validates merge prevention, pivot linking, and deduplication logic, not real-world clustering accuracy.',
}
