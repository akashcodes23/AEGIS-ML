/**
 * AEGIS-ML Briefing Report Data Builder & Integrity Checksum Engine
 * Zero external runtime dependencies.
 */

import { buildEvidenceChain } from './evidence.js'

export const CHECKSUM_LABEL = 'Integrity checksum (detects accidental changes; not a digital signature)'
export const CHECKSUM_UNAVAILABLE_MESSAGE = 'Integrity checksum unavailable in this environment'
export const SYNTHETIC_DISCLOSURE = 'Synthetic demo data. Results do not reflect real-world detection accuracy.'

/**
 * Resolves confidence according to Stage 2 calibrated confidence rules.
 */
export function resolveConfidence(item = {}) {
  const isCalibrated = Boolean(item.is_calibrated)
  const calibratedConfidence = typeof item.calibrated_confidence === 'number'
    ? item.calibrated_confidence
    : null
  const rawConfidence = typeof item.confidence === 'number'
    ? item.confidence
    : null

  if (isCalibrated && calibratedConfidence !== null) {
    return {
      tier: 'calibrated',
      value: calibratedConfidence,
      label: 'Calibrated Confidence',
      percentage: `${(calibratedConfidence * 100).toFixed(1)}%`,
      isCalibrated: true,
      description: 'Probability calibrated against historical true positive validation dataset',
    }
  }

  if (rawConfidence !== null) {
    return {
      tier: 'uncalibrated',
      value: rawConfidence,
      label: 'Uncalibrated Model Score',
      percentage: `${(rawConfidence * 100).toFixed(1)}%`,
      isCalibrated: false,
      description: 'Raw heuristic inference probability; unverified calibration artifact',
    }
  }

  return {
    tier: 'unassessed',
    value: null,
    label: 'Confidence Unassessed',
    percentage: 'N/A',
    isCalibrated: false,
    description: 'No calibrated model score or probability recorded for this item',
  }
}

/**
 * Computes a SHA-256 checksum of canonical content using SubtleCrypto.
 * Returns null if SubtleCrypto is unavailable in the environment.
 *
 * @param {string} content - Canonical text content
 * @returns {Promise<string|null>} 64-char hex string or null
 */
export async function computeBriefingChecksum(content) {
  if (typeof content !== 'string') return null

  const subtle = globalThis.crypto?.subtle
  if (!subtle || typeof subtle.digest !== 'function') {
    return null
  }

  try {
    const encoder = new TextEncoder()
    const data = encoder.encode(content)
    const hashBuffer = await subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  } catch (err) {
    console.warn('[AEGIS] SubtleCrypto checksum generation failed:', err)
    return null
  }
}

/**
 * Builds the structured data for an executive incident briefing.
 *
 * @param {Object} incident - Incident object from alertStore
 * @param {Object} context - Application environment and session context
 * @returns {Object} Structured briefing model
 */
export function buildBriefingData(incident, context = {}) {
  if (!incident) return null

  const {
    alerts = [],
    isSynthetic = true,
    datasetName = 'behavioral_diversity_labeled.jsonl',
    timestampBasis = 'Ingest/Event timestamp basis',
    sessionAlertsCount = 0,
    graphSnapshotUrl = null,
    gitCommit = '77c026e',
  } = context

  // 1. Evidence chain reconstruction from Stage 3
  const alertIds = incident.alert_ids || []
  const matchingAlert = alerts.find(a => alertIds.includes(a.alert_id || a.event_id)) || null
  const evidenceChain = buildEvidenceChain(matchingAlert, incident, context)

  // 2. Confidence representation from Stage 2
  const confResult = resolveConfidence(incident)

  // 3. Timeline extraction: observations vs hypotheses
  const timeline = []
  if (Array.isArray(incident.timeline)) {
    incident.timeline.forEach((item, idx) => {
      const isHypothesis = item.type === 'hypothesis' || item.inferred === true
      timeline.push({
        id: `tl-${idx}`,
        time: item.timestamp || item.time || 'Timestamp unrecorded',
        nature: isHypothesis ? 'Hypothesis' : 'Observation',
        isHypothesis,
        description: item.description || item.label || item.action || 'Telemetry event',
        source: item.source || 'telemetry',
        stage: item.stage || incident.current_kill_chain_stage || null,
      })
    })
  } else {
    // Derive from evidence chain and incident relationships
    evidenceChain.forEach((link, idx) => {
      const isHypothesis = link.kind === 'incident' && Boolean(incident.relationship_evidence?.some(r => r.inferred))
      timeline.push({
        id: `tl-${idx}`,
        time: incident.created_at || 'Session replay interval',
        nature: isHypothesis ? 'Hypothesis' : 'Observation',
        isHypothesis,
        description: `${link.label}: ${link.sublabel}`,
        source: link.source,
        stage: incident.current_kill_chain_stage || null,
      })
    })
  }

  // Count chain present and absent links
  const presentCount = evidenceChain.filter(l => l.status === 'present').length
  const gapCount = evidenceChain.filter(l => l.status === 'absent').length

  // Canonical string for deterministic integrity checksum
  const canonicalString = JSON.stringify({
    incident_id: incident.incident_id || incident.event_id || 'INC-UNKNOWN',
    threat_type: incident.threat_type || 'Unclassified Threat',
    severity: incident.severity || 'high',
    stage: incident.current_kill_chain_stage || 'Unknown',
    confidence_tier: confResult.tier,
    is_calibrated: confResult.isCalibrated,
    evidence_links_total: evidenceChain.length,
    evidence_links_present: presentCount,
    evidence_gaps_count: gapCount,
    timeline_count: timeline.length,
    is_synthetic: isSynthetic,
  })

  return {
    incidentId: incident.incident_id || incident.event_id || 'INC-UNKNOWN',
    title: incident.threat_type || incident.title || 'Security Incident Briefing',
    severity: incident.severity || 'high',
    killChainStage: incident.current_kill_chain_stage || 'Unknown',
    primaryAttacker: incident.primary_attacker || incident.src_entity || 'N/A',
    primaryTarget: incident.primary_target || incident.dst_entity || 'N/A',
    confidence: confResult,
    evidenceChain,
    timeline,
    graphSnapshotUrl,
    metadata: {
      generatedAt: new Date().toISOString(),
      isSynthetic,
      datasetName,
      timestampBasis,
      sessionAlertsCount,
      gitCommit,
    },
    canonicalString,
    disclosure: isSynthetic ? SYNTHETIC_DISCLOSURE : null,
  }
}
