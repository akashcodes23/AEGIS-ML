import test from 'node:test'
import assert from 'node:assert/strict'
import { buildEvidenceChain } from './evidence.js'

test('buildEvidenceChain: full chain with real calibrated alert and incident', () => {
  const alert = {
    alert_id: 'alt_991',
    event_id: 'evt_001',
    incident_id: 'inc_882',
    src_entity: '192.168.1.10',
    dst_entity: '10.0.0.50',
    layer: 'network',
    threat_type: 'Data Exfiltration Spike',
    severity: 'critical',
    current_kill_chain_stage: 'Exfiltration',
    is_calibrated: true,
    calibrated_confidence: 0.942,
    anomaly_score: 0.98,
    raw_event: {
      event_id: 'evt_001',
      layer: 'network',
      src_ip: '192.168.1.10',
      dst_ip: '10.0.0.50',
      timestamp: '2026-10-13T10:00:00Z',
    },
    feature_importance: {
      bytes_sent_log: 0.62,
      flow_duration_log: 0.28,
      port_entropy: 0.10,
    },
  }

  const incident = {
    incident_id: 'inc_882',
    title: 'Multi-Stage Data Exfiltration',
    matched_rules: ['RULE_4_HIGH_VOLUME_EXFIL'],
    relationship_evidence: [
      { source_entity: '192.168.1.10', target_entity: '10.0.0.50', relationship_type: 'observed_telemetry' }
    ],
    supporting_events: [alert.raw_event],
    alert_ids: ['alt_991'],
  }

  const chain = buildEvidenceChain(alert, incident)
  assert.equal(chain.length, 5)

  // 1. Event
  assert.equal(chain[0].kind, 'event')
  assert.equal(chain[0].status, 'present')
  assert.equal(chain[0].value, 'evt_001')

  // 2. Feature
  assert.equal(chain[1].kind, 'feature')
  assert.equal(chain[1].status, 'present')
  assert.equal(chain[1].label, 'Per-Alert Behavioral Deviation')
  assert.ok(chain[1].sublabel.includes('bytes_sent_log'))

  // 3. Score
  assert.equal(chain[2].kind, 'score')
  assert.equal(chain[2].status, 'present')
  assert.equal(chain[2].label, 'Calibrated Confidence')
  assert.equal(chain[2].value, 0.942)

  // 4. Alert
  assert.equal(chain[3].kind, 'alert')
  assert.equal(chain[3].status, 'present')
  assert.equal(chain[3].value, 'alt_991')

  // 5. Incident
  assert.equal(chain[4].kind, 'incident')
  assert.equal(chain[4].status, 'present')
  assert.equal(chain[4].value, 'inc_882')
})

test('buildEvidenceChain: global-only feature importance must be labeled model-level and partial', () => {
  const alert = {
    alert_id: 'alt_102',
    event_id: 'evt_102',
    threat_type: 'Port Scan',
    severity: 'medium',
    is_calibrated: false,
    confidence: 0.65,
    global_feature_importances: {
      port_entropy: 0.45,
      packet_rate: 0.35,
    },
    // No local feature_importance
  }

  const chain = buildEvidenceChain(alert, null)
  const featLink = chain.find(l => l.kind === 'feature')

  assert.ok(featLink)
  assert.equal(featLink.status, 'partial')
  assert.equal(featLink.label, 'Model-level feature importance (not specific to this alert)')
  assert.ok(featLink.details.disclaimer.includes('not specific to this event'))
})

test('buildEvidenceChain: uncalibrated confidence must be marked partial', () => {
  const alert = {
    alert_id: 'alt_103',
    threat_type: 'Heuristic Anomaly',
    severity: 'low',
    is_calibrated: false,
    confidence: 0.72,
    calibrated_confidence: null,
  }

  const chain = buildEvidenceChain(alert, null)
  const scoreLink = chain.find(l => l.kind === 'score')

  assert.ok(scoreLink)
  assert.equal(scoreLink.status, 'partial')
  assert.equal(scoreLink.label, 'Uncalibrated Model Score')
  assert.equal(scoreLink.value, 0.72)
})

test('buildEvidenceChain: missing links are marked absent and truthfully annotated', () => {
  const alert = {
    alert_id: 'alt_104',
    threat_type: 'Raw Log Anomaly',
    // Missing: event_id, raw_event, feature_importance, confidence, incident_id
  }

  const chain = buildEvidenceChain(alert, null)

  const eventLink = chain.find(l => l.kind === 'event')
  assert.equal(eventLink.status, 'absent')
  assert.equal(eventLink.value, null)
  assert.ok(eventLink.source.includes('(not recorded)'))

  const featLink = chain.find(l => l.kind === 'feature')
  assert.equal(featLink.status, 'absent')
  assert.equal(featLink.value, null)

  const scoreLink = chain.find(l => l.kind === 'score')
  assert.equal(scoreLink.status, 'absent')
  assert.equal(scoreLink.sublabel, 'No confidence reported')

  const incLink = chain.find(l => l.kind === 'incident')
  assert.equal(incLink.status, 'absent')
  assert.equal(incLink.value, null)
})

test('buildEvidenceChain: empty input returns 5 truthful absent links without fabricating', () => {
  const chain = buildEvidenceChain(null, null)
  assert.equal(chain.length, 5)
  chain.forEach(link => {
    assert.equal(link.status, 'absent')
    assert.equal(link.value, null)
  })
})
