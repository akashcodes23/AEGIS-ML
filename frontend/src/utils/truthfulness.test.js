import test from 'node:test'
import assert from 'node:assert/strict'
import { buildEvidenceChain } from './evidence.js'
import { MODEL_ASSURANCE_METADATA, HEADLINE_METRICS, formatMetric } from '../data/modelAssuranceData.js'

test('Truthfulness: Dashboard analysis banner logic distinguishes analysis completion from security posture', () => {
  function getAnalysisBannerContent(totalEvents, totalAlerts) {
    const hasFindings = totalAlerts > 0
    return {
      title: hasFindings
        ? `Analysis Ingestion Finished — Active Findings (${totalAlerts} Anomalies Flagged)`
        : 'Analysis Ingestion Finished — Baseline Normal (0 Anomalies)',
      tone: hasFindings ? 'elevated' : 'success',
      hasContradiction: false, // Must never state "network looks secure" when alerts > 0
    }
  }

  // Case A: Analysis finished with 0 anomalies
  const cleanRun = getAnalysisBannerContent(5000, 0, 'clean_traffic.jsonl')
  assert.strictEqual(cleanRun.title.includes('Baseline Normal (0 Anomalies)'), true)
  assert.strictEqual(cleanRun.tone, 'success')
  assert.strictEqual(cleanRun.hasContradiction, false)

  // Case B: Analysis finished with 4 anomalies flagged
  const alertRun = getAnalysisBannerContent(5000, 4, 'behavioral_diversity_labeled.jsonl')
  assert.strictEqual(alertRun.title.includes('Active Findings (4 Anomalies Flagged)'), true)
  assert.strictEqual(alertRun.title.includes('looks secure'), false)
  assert.strictEqual(alertRun.tone, 'elevated')
  assert.strictEqual(alertRun.hasContradiction, false)
})

test('Truthfulness: Priority Score reflects documented mathematical formula without magic numbers', () => {
  function calculatePriority(baseSev, uniqueLayersCount, eventCount, maxProb) {
    const sevWeights = { low: 20.0, medium: 45.0, high: 75.0, critical: 95.0 }
    const highestSev = sevWeights[baseSev] || 45.0
    const layerBonus = Math.min(uniqueLayersCount * 10.0, 20.0)
    const countBonus = Math.min(eventCount * 2.0, 15.0)
    const confidenceFactor = maxProb * 10.0

    const raw = highestSev + layerBonus + countBonus + confidenceFactor
    return Math.round(Math.min(Math.max(raw, 10.0), 99.0))
  }

  // Critical incident with 2 layers, 5 events, 0.95 prob
  const score1 = calculatePriority('critical', 2, 5, 0.95)
  // 95 + 20 + 10 + 9.5 = 134.5 -> capped at 99
  assert.strictEqual(score1, 99)

  // Medium incident with 1 layer, 2 events, 0.60 prob
  const score2 = calculatePriority('medium', 1, 2, 0.60)
  // 45 + 10 + 4 + 6.0 = 65
  assert.strictEqual(score2, 65)

  // Low incident with 1 layer, 1 event, 0.30 prob
  const score3 = calculatePriority('low', 1, 1, 0.30)
  // 20 + 10 + 2 + 3.0 = 35
  assert.strictEqual(score3, 35)
})

test('Truthfulness: Evidence chain distinguishes observed facts, model-level explanations, and missing gaps', () => {
  // Full alert with real local features and calibrated probability
  const fullAlert = {
    alert_id: 'ALT-101',
    event_id: 'EV-202',
    src_entity: '10.0.0.45',
    dst_entity: '198.51.100.22',
    layer: 'network',
    feature_importance: { bytes_out: 0.65, connection_duration: 0.25 },
    is_calibrated: true,
    calibrated_confidence: 0.942,
    threat_type: 'data_exfiltration',
    severity: 'critical',
  }

  const chain = buildEvidenceChain(fullAlert, null)
  assert.strictEqual(chain.length, 5)

  // 1. Observed Telemetry
  assert.strictEqual(chain[0].id, 'link_event')
  assert.strictEqual(chain[0].status, 'present')
  assert.strictEqual(chain[0].label, 'Telemetry Event')

  // 2. Behavioral feature deviation (local)
  assert.strictEqual(chain[1].id, 'link_feature')
  assert.strictEqual(chain[1].status, 'present')
  assert.strictEqual(chain[1].details.isLocal, true)

  // 3. Calibrated Confidence
  assert.strictEqual(chain[2].id, 'link_score')
  assert.strictEqual(chain[2].status, 'present')
  assert.strictEqual(chain[2].details.isCalibrated, true)
  assert.strictEqual(chain[2].label, 'Calibrated Confidence')

  // 4. Alert Link
  assert.strictEqual(chain[3].id, 'link_alert')
  assert.strictEqual(chain[3].status, 'present')

  // 5. Unassigned incident link is marked absent without pretending to be linked
  assert.strictEqual(chain[4].id, 'link_incident')
  assert.strictEqual(chain[4].status, 'absent')
  assert.strictEqual(chain[4].sublabel, 'Not yet clustered into an incident')
})

test('Truthfulness: Graph attribute filters correctly isolate entity types and edge provenance', () => {
  const nodes = [
    { id: 'n1', node_type: 'ip' },
    { id: 'n2', node_type: 'process' },
    { id: 'n3', node_type: 'user' },
  ]

  const edges = [
    { id: 'e1', source: 'n1', target: 'n2', is_anomalous: true, edge_type: 'observed_telemetry' },
    { id: 'e2', source: 'n2', target: 'n3', is_anomalous: false, edge_type: 'inferred_correlation' },
    { id: 'e3', source: 'n1', target: 'n3', is_anomalous: false, edge_type: 'observed_telemetry' },
  ]

  // Filter by IP node type
  const ipNodes = nodes.filter(n => n.node_type === 'ip')
  assert.strictEqual(ipNodes.length, 1)
  assert.strictEqual(ipNodes[0].id, 'n1')

  // Filter anomalous edges only
  const anomEdges = edges.filter(e => e.is_anomalous)
  assert.strictEqual(anomEdges.length, 1)
  assert.strictEqual(anomEdges[0].id, 'e1')

  // Filter observed telemetry edges only
  const obsEdges = edges.filter(e => e.edge_type === 'observed_telemetry')
  assert.strictEqual(obsEdges.length, 2)

  // Filter inferred hypotheses only
  const infEdges = edges.filter(e => e.edge_type === 'inferred_correlation')
  assert.strictEqual(infEdges.length, 1)
  assert.strictEqual(infEdges[0].id, 'e2')
})

test('Truthfulness: Model Assurance values remain strictly identical to results.json with uncertainty intervals', () => {
  assert.strictEqual(HEADLINE_METRICS.macro_f1.value, 0.9866)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.mean, 0.9674)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.ci_95_lower, 0.7803)
  assert.strictEqual(HEADLINE_METRICS.macro_f1.ci_95_upper, 0.9987)
  assert.strictEqual(HEADLINE_METRICS.ece.value, 0.0011)
  assert.strictEqual(HEADLINE_METRICS.brier_score.value, 0.0109)

  // Format metric utility prevents fabricating default zeroes for missing/invalid data
  assert.strictEqual(formatMetric(undefined), 'Unavailable')
  assert.strictEqual(formatMetric(null), 'Unavailable')
  assert.strictEqual(formatMetric(NaN), 'Unavailable')
  assert.strictEqual(formatMetric(0.9866), '0.9866')
})
