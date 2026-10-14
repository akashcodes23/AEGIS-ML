import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildBriefingData,
  computeBriefingChecksum,
  CHECKSUM_LABEL,
  CHECKSUM_UNAVAILABLE_MESSAGE,
  SYNTHETIC_DISCLOSURE,
} from './briefing.js'

describe('briefing report engine', () => {
  const sampleIncident = {
    incident_id: 'INC-7001',
    threat_type: 'Multi-Stage Data Exfiltration',
    severity: 'critical',
    current_kill_chain_stage: 'Exfiltration',
    primary_attacker: '192.168.1.105',
    primary_target: 'srv-db-01',
    confidence: 0.94,
    calibrated_confidence: 0.91,
    is_calibrated: true,
    supporting_events: [
      { event_id: 'EVT-900', src_entity: '192.168.1.105', dst_entity: 'srv-db-01', layer: 'Network' },
    ],
    relationship_evidence: [
      { source_entity: '192.168.1.105', target_entity: 'srv-db-01', inferred: true },
    ],
  }

  test('builds briefing with evidence chain and confidence evaluation', () => {
    const briefing = buildBriefingData(sampleIncident, {
      isSynthetic: true,
      datasetName: 'behavioral_diversity_labeled.jsonl',
      sessionAlertsCount: 42,
    })

    assert.equal(briefing.incidentId, 'INC-7001')
    assert.equal(briefing.severity, 'critical')
    assert.equal(briefing.killChainStage, 'Exfiltration')
    assert.equal(briefing.disclosure, SYNTHETIC_DISCLOSURE)
    assert.equal(briefing.metadata.sessionAlertsCount, 42)
    assert.ok(Array.isArray(briefing.evidenceChain))
    assert.equal(briefing.evidenceChain.length, 5) // event, feature, score, alert, incident links
    assert.equal(briefing.confidence.isCalibrated, true)
    assert.equal(briefing.confidence.percentage, '91.0%')
  })

  test('handles synthetic disclosure vs real data disclosure truthfully', () => {
    const syntheticBriefing = buildBriefingData(sampleIncident, { isSynthetic: true })
    assert.equal(syntheticBriefing.disclosure, SYNTHETIC_DISCLOSURE)

    const realBriefing = buildBriefingData(sampleIncident, { isSynthetic: false })
    assert.equal(realBriefing.disclosure, null)
  })

  test('generates SHA-256 integrity checksum using SubtleCrypto when available', async () => {
    const content = 'canonical-incident-data-payload-hash-check'
    const checksum = await computeBriefingChecksum(content)

    // In modern Node, globalThis.crypto.subtle is available
    if (globalThis.crypto?.subtle) {
      assert.ok(checksum, 'Checksum was generated')
      assert.equal(checksum.length, 64)
      assert.match(checksum, /^[0-9a-f]{64}$/)
      assert.equal(CHECKSUM_LABEL, 'Integrity checksum (detects accidental changes; not a digital signature)')
    } else {
      assert.equal(checksum, null)
    }
  })

  test('handles unavailable SubtleCrypto environment gracefully', async () => {
    const originalSubtle = globalThis.crypto?.subtle
    Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true })

    try {
      const checksum = await computeBriefingChecksum('test-string')
      assert.equal(checksum, null)
      assert.equal(CHECKSUM_UNAVAILABLE_MESSAGE, 'Integrity checksum unavailable in this environment')
    } finally {
      Object.defineProperty(globalThis.crypto, 'subtle', { value: originalSubtle, configurable: true })
    }
  })

  test('flags evidence gaps and distinguishes observations vs hypotheses in timeline', () => {
    const incidentWithHypothesis = {
      ...sampleIncident,
      timeline: [
        { id: 't1', time: '10:00:00', type: 'observation', description: 'Firewall alert observed' },
        { id: 't2', time: '10:05:00', type: 'hypothesis', description: 'Lateral movement inferred by correlation engine' },
      ],
    }

    const briefing = buildBriefingData(incidentWithHypothesis)
    assert.equal(briefing.timeline[0].nature, 'Observation')
    assert.equal(briefing.timeline[0].isHypothesis, false)
    assert.equal(briefing.timeline[1].nature, 'Hypothesis')
    assert.equal(briefing.timeline[1].isHypothesis, true)

    // Verify evidence chain identifies absent links as gaps
    const gapLinks = briefing.evidenceChain.filter(l => l.status === 'absent')
    assert.ok(gapLinks.length > 0, 'Contains truthful evidence gap links')
  })

  test('verifies that downloadable canonical briefing bytes hash to the exact displayed checksum', async () => {
    const crypto = await import('node:crypto')
    const briefing = buildBriefingData(sampleIncident, { isSynthetic: true })

    assert.ok(briefing.canonicalString, 'Must produce canonicalString')
    assert.ok(briefing.canonicalPayload, 'Must produce canonicalPayload')

    // Verify all canonical fields are present
    const { CANONICAL_BRIEFING_FIELDS } = await import('./briefing.js')
    for (const field of CANONICAL_BRIEFING_FIELDS) {
      assert.ok(field in briefing.canonicalPayload, `Field ${field} must exist in canonicalPayload`)
    }

    // Compute checksum via computeBriefingChecksum (SubtleCrypto)
    const displayedChecksum = await computeBriefingChecksum(briefing.canonicalString)

    // Compute standard SHA-256 over the downloaded byte sequence using node:crypto (equivalent to CLI shasum -a 256)
    const nodeCliSha256 = crypto.createHash('sha256').update(briefing.canonicalString, 'utf8').digest('hex')

    assert.equal(displayedChecksum, nodeCliSha256, 'Displayed checksum must match CLI shasum -a 256 of downloaded bytes')
  })
})
