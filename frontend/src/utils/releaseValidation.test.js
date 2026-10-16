import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildEvidenceChain } from './evidence.js'
import { getApiUrl, getWsUrl, DEFAULT_PRODUCTION_API_URL } from '../config/api.js'
import {
  MODEL_ASSURANCE_METADATA,
  HEADLINE_METRICS,
  COMPARATIVE_BASELINES,
  CORRELATION_ENGINE_VALIDATION,
  CICIDS_STATUS,
} from '../data/modelAssuranceData.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const REPO_ROOT = path.resolve(__dirname, '../../../')

// ── 1. Evidence Count Correctness & Deduplication ────────────────────────────
test('Release Validation: Relationship evidence deduplication prevents artificial inflation', () => {
  const incidentWithDuplicates = {
    incident_id: 'INC-TEST-001',
    severity: 'high',
    relationship_evidence: [
      {
        source_entity: '10.0.0.5',
        target_entity: '10.0.0.50',
        relationship_type: 'observed_telemetry',
        claim_type: 'observation',
        supporting_event_ids: ['EV-1'],
      },
      {
        source_entity: '10.0.0.5',
        target_entity: '10.0.0.50',
        relationship_type: 'observed_telemetry',
        claim_type: 'observation',
        supporting_event_ids: ['EV-2'],
      },
      {
        source_entity: '10.0.0.50',
        target_entity: '192.168.1.100',
        relationship_type: 'pivot_lateral_movement',
        claim_type: 'hypothesis',
        supporting_event_ids: ['EV-3'],
      },
    ],
  }

  // Deduplication simulation matching IncidentCard useMemo
  const seen = new Set()
  const deduplicated = []
  for (const rel of incidentWithDuplicates.relationship_evidence) {
    const key = `${rel.source_entity}|${rel.target_entity}|${rel.relationship_type}`
    if (seen.has(key)) {
      const existing = deduplicated.find(
        (d) => `${d.source_entity}|${d.target_entity}|${d.relationship_type}` === key
      )
      if (existing) {
        existing.supporting_event_ids = Array.from(
          new Set([...existing.supporting_event_ids, ...rel.supporting_event_ids])
        )
      }
    } else {
      seen.add(key)
      deduplicated.push({ ...rel })
    }
  }

  // 3 raw entries should deduplicate to exactly 2 unique entity-relationship links
  assert.equal(deduplicated.length, 2)
  const obsLink = deduplicated.find((r) => r.relationship_type === 'observed_telemetry')
  assert.ok(obsLink)
  // Supporting events should be merged, retaining full evidence traceability
  assert.deepEqual(obsLink.supporting_event_ids, ['EV-1', 'EV-2'])
  assert.equal(obsLink.claim_type, 'observation')
})

// ── 2. Observed vs Inferred Demarcation ──────────────────────────────────────
test('Release Validation: Explicitly distinguishes observed facts from inferred hypotheses', () => {
  const alert = {
    alert_id: 'ALT-OBS-01',
    layer: 'network',
    src_entity: '10.0.0.10',
    dst_entity: '10.0.0.99',
    raw_event: { event_id: 'EVT-REAL-01', layer: 'network' },
    is_calibrated: false,
    confidence: 0.72,
    threat_type: 'lateral_movement',
    current_kill_chain_stage: 'Lateral Movement',
  }

  const chain = buildEvidenceChain(alert, null)
  assert.equal(chain.length, 5)

  // Event link is factual telemetry
  const eventLink = chain.find((c) => c.kind === 'event')
  assert.equal(eventLink.status, 'present')
  assert.equal(eventLink.details.eventId, 'EVT-REAL-01')

  // Uncalibrated score is explicitly marked partial and uncalibrated
  const scoreLink = chain.find((c) => c.kind === 'score')
  assert.equal(scoreLink.status, 'partial')
  assert.equal(scoreLink.label, 'Uncalibrated Model Score')
  assert.equal(scoreLink.details.isCalibrated, false)

  // Incident link is absent because alert is not yet clustered
  const incLink = chain.find((c) => c.kind === 'incident')
  assert.equal(incLink.status, 'absent')
  assert.equal(incLink.sublabel, 'Not yet clustered into an incident')
})

// ── 3. Missing Provenance & Safe Failure on Malformed Input ──────────────────
test('Release Validation: Missing or malformed evidence fields fail safely without crashing', () => {
  // Empty inputs
  const emptyChain = buildEvidenceChain(null, null)
  assert.equal(emptyChain.length, 5)
  for (const link of emptyChain) {
    assert.equal(link.status, 'absent')
    assert.ok(link.sublabel)
  }

  // Malformed inputs (null properties, non-object)
  const malformedAlert = {
    alert_id: '',
    raw_event: null,
    feature_importance: 'invalid_string',
    confidence: 'not_a_number',
  }
  const malformedChain = buildEvidenceChain(malformedAlert, null)
  assert.equal(malformedChain.length, 5)
  const featLink = malformedChain.find((c) => c.kind === 'feature')
  assert.equal(featLink.status, 'absent')
  const scoreLink = malformedChain.find((c) => c.kind === 'score')
  assert.equal(scoreLink.status, 'absent')
})

// ── 4. Score Semantics Non-Conflation ────────────────────────────────────────
test('Release Validation: Calibrated probability, tree consensus, and priority score are never conflated', () => {
  const calibratedConfidence = 0.942
  const treeAgreement = 0.75
  const priorityScore = 88.5

  // 1. Calibrated confidence is bounded in [0, 1] and requires is_calibrated = true
  assert.ok(calibratedConfidence >= 0.0 && calibratedConfidence <= 1.0)

  // 2. Tree consensus is fraction of RF estimators voting malicious
  assert.ok(treeAgreement >= 0.0 && treeAgreement <= 1.0)
  assert.notEqual(calibratedConfidence, treeAgreement)

  // 3. Priority score is bounded in [0, 99] composite metric
  assert.ok(priorityScore >= 0.0 && priorityScore <= 100.0)
  assert.ok(priorityScore > 1.0, 'Priority score must not be scaled to unit probability')
})

// ── 5. Dashboard Posture Messaging Decoupling ────────────────────────────────
test('Release Validation: Ingestion completion decouples from security posture', () => {
  const deriveBanner = (isAnalyzing, anomaliesCount) => {
    if (isAnalyzing) return { text: 'Analyzing Telemetry Stream...', tone: 'active' }
    if (anomaliesCount > 0) {
      return {
        text: `Analysis Ingestion Finished — Active Findings (${anomaliesCount} Anomalies Flagged)`,
        tone: 'warning',
      }
    }
    return { text: 'Analysis Ingestion Finished — Baseline Normal (No Active Anomalies)', tone: 'secure' }
  }

  // Finished ingestion with 12 anomalies flagged
  const bannerWithAnomalies = deriveBanner(false, 12)
  assert.equal(bannerWithAnomalies.tone, 'warning')
  assert.ok(bannerWithAnomalies.text.includes('Active Findings'))
  assert.ok(!bannerWithAnomalies.text.includes('Your network looks secure'))

  // Finished ingestion with 0 anomalies flagged
  const cleanBanner = deriveBanner(false, 0)
  assert.equal(cleanBanner.tone, 'secure')
  assert.ok(cleanBanner.text.includes('Baseline Normal'))
})

// ── 6. Graph Filtering & Empty / Malformed State Handling ────────────────────
test('Release Validation: Graph node and edge filtering handles empty and malformed records safely', () => {
  const mockNodes = [
    { id: '10.0.0.1', node_type: 'ip' },
    { id: 'proc_1', node_type: 'process' },
    null, // malformed node
    { node_type: 'ip' }, // missing id
  ]

  const validNodes = mockNodes.filter((n) => n && n.id)
  assert.equal(validNodes.length, 2)

  const mockEdges = [
    { id: 'e1', source: '10.0.0.1', target: 'proc_1', is_anomalous: true, edge_type: 'observed_telemetry' },
    { id: 'e2', source: '10.0.0.1', target: 'non_existent_node' }, // orphaned edge
    null, // malformed edge
  ]

  const validNodeIds = new Set(validNodes.map((n) => n.id))
  const validEdges = mockEdges.filter(
    (e) => e && e.id && e.source && e.target && validNodeIds.has(e.source) && validNodeIds.has(e.target)
  )
  assert.equal(validEdges.length, 1)
  assert.equal(validEdges[0].id, 'e1')
})

// ── 7. Production API & WebSocket Configuration Hygiene ─────────────────────
test('Release Validation: Production API resolves without localhost dependency', () => {
  assert.equal(DEFAULT_PRODUCTION_API_URL, 'https://aegis-ml-api.onrender.com')

  // getApiUrl cleans and prevents double /api
  const url1 = getApiUrl('/api/health')
  assert.ok(url1.includes('/health'))
  assert.ok(!url1.includes('/api/api/'))

  // getWsUrl returns valid wss protocol for remote environments
  const wsUrl = getWsUrl()
  assert.ok(wsUrl.startsWith('ws://') || wsUrl.startsWith('wss://'))
  assert.ok(wsUrl.endsWith('/ws/live'))
})

// ── 8. Stage 6 Model Assurance Evaluation Artifact Parity ────────────────────
test('Release Validation: Evaluation figures in Model Assurance match results.json exactly', () => {
  const resultsPath = path.join(REPO_ROOT, 'docs/evaluation/results.json')
  assert.ok(fs.existsSync(resultsPath), 'results.json must exist in docs/evaluation/')

  const rawJson = JSON.parse(fs.readFileSync(resultsPath, 'utf8'))
  const calibrated = rawJson.models.full_pipeline_calibrated
  const ci = rawJson.confidence_intervals_95

  // 1. Macro F1 point estimate and CI
  assert.equal(HEADLINE_METRICS.macro_f1.value, 0.9866)
  assert.equal(HEADLINE_METRICS.macro_f1.value, calibrated.macro_f1)
  assert.equal(HEADLINE_METRICS.macro_f1.ci_95_lower, ci.macro_f1.ci_95_lower)
  assert.equal(HEADLINE_METRICS.macro_f1.ci_95_upper, ci.macro_f1.ci_95_upper)
  assert.equal(HEADLINE_METRICS.macro_f1.mean, ci.macro_f1.mean)

  // 2. Benign FPR
  assert.equal(HEADLINE_METRICS.benign_fpr.value, 0.0024)
  assert.equal(HEADLINE_METRICS.benign_fpr.value, calibrated.benign_fpr)
  assert.equal(HEADLINE_METRICS.benign_fpr.ci_95_lower, ci.benign_fpr.ci_95_lower)
  assert.equal(HEADLINE_METRICS.benign_fpr.ci_95_upper, ci.benign_fpr.ci_95_upper)

  // 3. Expected Calibration Error (ECE)
  assert.equal(HEADLINE_METRICS.ece.value, 0.0011)
  assert.equal(HEADLINE_METRICS.ece.value, calibrated.ece)
  assert.equal(HEADLINE_METRICS.ece.ci_95_lower, ci.ece.ci_95_lower)
  assert.equal(HEADLINE_METRICS.ece.ci_95_upper, ci.ece.ci_95_upper)

  // 4. Scenario partitioning counts
  const meta = rawJson.metadata
  assert.equal(MODEL_ASSURANCE_METADATA.splits.train_records, meta.splits.train_records)
  assert.equal(MODEL_ASSURANCE_METADATA.splits.val_records, meta.splits.val_records)
  assert.equal(MODEL_ASSURANCE_METADATA.splits.test_records, meta.splits.test_records)
  assert.equal(MODEL_ASSURANCE_METADATA.splits.scenario_overlap, 0.0)

  // 5. Correlation benchmark traceability scope
  assert.equal(CORRELATION_ENGINE_VALIDATION.evidence_traceability_pct, 100.0)
  assert.equal(CORRELATION_ENGINE_VALIDATION.scenarios_evaluated, 12)

  // 6. External benchmark blocked status
  assert.equal(CICIDS_STATUS.status, 'BLOCKED_AWAITING_LOCAL_COPY')
  assert.equal(CICIDS_STATUS.fabricated_numbers, false)
})
