import test from 'node:test'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import {
  MODEL_ASSURANCE_METADATA,
  HEADLINE_METRICS,
  COMPARATIVE_BASELINES,
  PER_CLASS_METRICS,
  RELIABILITY_BINS_CALIBRATED,
  ZERO_DAY_GENERALIZATION,
  CICIDS_STATUS,
  CORRELATION_ENGINE_VALIDATION,
} from './modelAssuranceData.js'

test('MODEL_ASSURANCE_METADATA matches Stage 6 results.json exactly', () => {
  const jsonPath = path.resolve(process.cwd(), 'docs/evaluation/results.json')
  assert.ok(fs.existsSync(jsonPath), 'results.json must exist in docs/evaluation/')
  
  const rawJson = JSON.parse(fs.readFileSync(jsonPath, 'utf8'))
  const meta = rawJson.metadata

  assert.strictEqual(MODEL_ASSURANCE_METADATA.protocol_version, '1.0.0-preregistered')
  assert.strictEqual(MODEL_ASSURANCE_METADATA.dataset_name, meta.dataset_name)
  assert.strictEqual(MODEL_ASSURANCE_METADATA.dataset_sha256, meta.dataset_sha256)
  assert.strictEqual(MODEL_ASSURANCE_METADATA.dataset_total_records, meta.dataset_total_records)
  assert.strictEqual(MODEL_ASSURANCE_METADATA.primary_seed, meta.primary_seed)
  assert.strictEqual(MODEL_ASSURANCE_METADATA.bootstrap_seed, meta.bootstrap_seed)

  // Split counts
  assert.strictEqual(MODEL_ASSURANCE_METADATA.splits.train_records, meta.splits.train_records)
  assert.strictEqual(MODEL_ASSURANCE_METADATA.splits.val_records, meta.splits.val_records)
  assert.strictEqual(MODEL_ASSURANCE_METADATA.splits.test_records, meta.splits.test_records)
  assert.strictEqual(
    MODEL_ASSURANCE_METADATA.splits.train_records +
    MODEL_ASSURANCE_METADATA.splits.val_records +
    MODEL_ASSURANCE_METADATA.splits.test_records,
    meta.dataset_total_records
  )
  assert.strictEqual(MODEL_ASSURANCE_METADATA.splits.scenario_overlap, 0.0)
})

test('HEADLINE_METRICS match Stage 6 reported values and 95% bootstrap CIs', () => {
  const jsonPath = path.resolve(process.cwd(), 'docs/evaluation/results.json')
  const rawJson = JSON.parse(fs.readFileSync(jsonPath, 'utf8'))

  const calibrated = rawJson.models.full_pipeline_calibrated
  const ci = rawJson.confidence_intervals_95

  // 1. Macro F1: 0.9866 [0.7803, 0.9987]
  assert.strictEqual(HEADLINE_METRICS.macro_f1.value, 0.9866)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.value, calibrated.macro_f1)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.ci_95_lower, 0.7803)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.ci_95_upper, 0.9987)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.ci_95_lower, ci.macro_f1.ci_95_lower)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.ci_95_upper, ci.macro_f1.ci_95_upper)

  // 2. Benign False-Positive Rate: 0.0024
  assert.strictEqual(HEADLINE_METRICS.benign_fpr.value, 0.0024)
  assert.strictEqual(HEADLINE_METRICS.benign_fpr.value, calibrated.benign_fpr)
  assert.strictEqual(HEADLINE_METRICS.benign_fpr.ci_95_lower, 0.0000)
  assert.strictEqual(HEADLINE_METRICS.benign_fpr.ci_95_upper, 0.0097)
  assert.strictEqual(HEADLINE_METRICS.benign_fpr.fp_count, 1)
  assert.strictEqual(HEADLINE_METRICS.benign_fpr.total_benign, 419)
  assert.strictEqual(HEADLINE_METRICS.benign_fpr.alerts_per_1m, 2386.63)

  // 3. Expected Calibration Error: 0.0011
  assert.strictEqual(HEADLINE_METRICS.ece.value, 0.0011)
  assert.strictEqual(HEADLINE_METRICS.ece.value, calibrated.ece)
  assert.strictEqual(HEADLINE_METRICS.ece.ci_95_lower, 0.0003)
  assert.strictEqual(HEADLINE_METRICS.ece.ci_95_upper, 0.0120)

  // Terminology check: ECE must not be described as accuracy
  assert.ok(
    !HEADLINE_METRICS.ece.label.toLowerCase().includes('accuracy'),
    'ECE must not be labeled accuracy'
  )
  assert.ok(
    HEADLINE_METRICS.ece.description.toLowerCase().includes('calibration'),
    'ECE description must refer to calibration'
  )

  // 4. Brier score
  assert.strictEqual(HEADLINE_METRICS.brier_score.value, 0.0109)
  assert.strictEqual(HEADLINE_METRICS.brier_score.value, calibrated.brier_score)
  assert.strictEqual(HEADLINE_METRICS.brier_score.ci_95_lower, 0.0028)
  assert.strictEqual(HEADLINE_METRICS.brier_score.ci_95_upper, 0.0270)
})

test('COMPARATIVE_BASELINES maintains integrity across 5 models', () => {
  assert.strictEqual(COMPARATIVE_BASELINES.length, 5)

  const dummy = COMPARATIVE_BASELINES.find(b => b.model_id === 'baseline_majority_dummy')
  assert.ok(dummy)
  assert.strictEqual(dummy.macro_f1, 0.1284)
  assert.strictEqual(dummy.ece, 0.5271)

  const lr = COMPARATIVE_BASELINES.find(b => b.model_id === 'baseline_logistic_regression')
  assert.ok(lr)
  assert.strictEqual(lr.macro_f1, 0.8147)

  const untuned = COMPARATIVE_BASELINES.find(b => b.model_id === 'baseline_untuned_rf')
  assert.ok(untuned)
  assert.strictEqual(untuned.macro_f1, 0.8703)

  const prod = COMPARATIVE_BASELINES.find(b => b.model_id === 'full_pipeline_calibrated')
  assert.ok(prod)
  assert.strictEqual(prod.macro_f1, 0.9866)
  assert.strictEqual(prod.ece, 0.0011)
  assert.strictEqual(prod.is_production, true)
})

test('ZERO_DAY_GENERALIZATION documents severe escape rates for novel categories', () => {
  assert.strictEqual(ZERO_DAY_GENERALIZATION.length, 4)

  const exfil = ZERO_DAY_GENERALIZATION.find(z => z.attack_category.includes('Exfiltration'))
  assert.ok(exfil)
  assert.strictEqual(exfil.escape_to_benign_pct, 100.0)

  const lateral = ZERO_DAY_GENERALIZATION.find(z => z.attack_category.includes('Lateral'))
  assert.ok(lateral)
  assert.strictEqual(lateral.escape_to_benign_pct, 94.3)

  const brute = ZERO_DAY_GENERALIZATION.find(z => z.attack_category.includes('Brute Force'))
  assert.ok(brute)
  assert.strictEqual(brute.escape_to_benign_pct, 92.4)

  const c2 = ZERO_DAY_GENERALIZATION.find(z => z.attack_category.includes('C2 Beaconing'))
  assert.ok(c2)
  assert.strictEqual(c2.escape_to_benign_pct, 44.7)
  assert.strictEqual(c2.profiler_deviation_recall_pct, 38.3)
})

test('CICIDS_STATUS records honest blocked state with zero fabricated figures', () => {
  assert.strictEqual(CICIDS_STATUS.status, 'BLOCKED_AWAITING_LOCAL_COPY')
  assert.strictEqual(CICIDS_STATUS.fabricated_numbers, false)
  assert.ok(CICIDS_STATUS.reason.includes('35.4% feature schema discrepancy') || CICIDS_STATUS.reason.includes('feature gap'))
})
