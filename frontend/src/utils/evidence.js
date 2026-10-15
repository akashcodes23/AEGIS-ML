/**
 * Evidence Trail & Provenance Extraction
 * 
 * Builds an honest, unbroken or gap-annotated provenance chain from real event payloads:
 * Raw Supporting Event -> Feature Deviations -> Model Score & Calibration -> Alert -> Incident
 * 
 * Rules:
 * 1. NEVER fabricate a link or assume evidence exists.
 * 2. If a field is absent, mark status: 'absent' with source indicating '(not recorded)'.
 * 3. Never present global feature importance as per-alert local explanations.
 *    If only global importance is available, mark status: 'partial' and explicitly label:
 *    "Model-level feature importance (not specific to this alert)".
 * 4. Calibrated confidence is only claimed when is_calibrated is true.
 */

/**
 * Builds an ordered evidence trail for an alert or incident.
 *
 * @param {object|null} alert - Alert object (if alert selected or from incident)
 * @param {object|null} incident - Incident object (if incident selected or associated)
 * @param {object} [context={}] - Optional context (e.g. correlator rules, store state)
 * @returns {Array<{
 *   id: string,
 *   kind: 'event' | 'feature' | 'score' | 'alert' | 'incident',
 *   label: string,
 *   sublabel: string,
 *   value: any,
 *   source: string,
 *   status: 'present' | 'absent' | 'partial',
 *   details: object
 * }>}
 */
export function buildEvidenceChain(alert, incident, context = {}) {
  void context
  const chain = []

  // Resolve active alert and incident
  const activeAlert = alert || null
  const activeIncident = incident || null

  // ── 1. Supporting Event Link ──────────────────────────────────────────────
  const rawEvent = activeAlert?.raw_event ||
    (activeIncident?.supporting_events && activeIncident.supporting_events.length > 0
      ? activeIncident.supporting_events[0]
      : null)
  const eventId = activeAlert?.event_id || rawEvent?.event_id || null

  if (rawEvent || eventId) {
    const layer = activeAlert?.layer || rawEvent?.layer || 'telemetry'
    const src = activeAlert?.src_entity || rawEvent?.src_entity || rawEvent?.src_ip || 'unknown'
    const dst = activeAlert?.dst_entity || rawEvent?.dst_entity || rawEvent?.dst_ip || 'unknown'
    chain.push({
      id: 'link_event',
      kind: 'event',
      label: 'Telemetry Event',
      sublabel: `${src} → ${dst} (${layer})`,
      value: eventId || 'Observed Frame',
      source: activeAlert?.raw_event ? 'alert.raw_event' : 'incident.supporting_events[0]',
      status: 'present',
      details: {
        eventId,
        layer,
        src,
        dst,
        timestamp: activeAlert?.timestamp || rawEvent?.timestamp || null,
      },
    })
  } else {
    chain.push({
      id: 'link_event',
      kind: 'event',
      label: 'Telemetry Event',
      sublabel: 'Raw supporting event not recorded',
      value: null,
      source: 'supporting_events (not recorded)',
      status: 'absent',
      details: {},
    })
  }

  // ── 2. Feature Deviations Link ───────────────────────────────────────────
  const localFeatures = activeAlert?.feature_importance || activeIncident?.feature_importance || null
  const globalFeatures = activeAlert?.global_feature_importances || null

  if (localFeatures && typeof localFeatures === 'object' && Object.keys(localFeatures).length > 0) {
    const topFeat = Object.entries(localFeatures).sort((a, b) => b[1] - a[1])[0]
    chain.push({
      id: 'link_feature',
      kind: 'feature',
      label: 'Per-Alert Behavioral Deviation',
      sublabel: topFeat ? `Top factor: ${topFeat[0]} (${(topFeat[1] * 100).toFixed(1)}%)` : 'Local feature deviations',
      value: localFeatures,
      source: 'alert.feature_importance',
      status: 'present',
      details: {
        isLocal: true,
        features: localFeatures,
        featureCount: Object.keys(localFeatures).length,
      },
    })
  } else if (globalFeatures && typeof globalFeatures === 'object' && Object.keys(globalFeatures).length > 0) {
    const topGlobal = Object.entries(globalFeatures).sort((a, b) => b[1] - a[1])[0]
    chain.push({
      id: 'link_feature',
      kind: 'feature',
      label: 'Model-level feature importance (not specific to this alert)',
      sublabel: topGlobal ? `Global weight: ${topGlobal[0]} (${(topGlobal[1] * 100).toFixed(1)}%)` : 'Global tree weights',
      value: globalFeatures,
      source: 'alert.global_feature_importances',
      status: 'partial',
      details: {
        isLocal: false,
        features: globalFeatures,
        featureCount: Object.keys(globalFeatures).length,
        disclaimer: 'Model-level feature importance reflects training-time Gini impurity and is not specific to this event.',
      },
    })
  } else {
    chain.push({
      id: 'link_feature',
      kind: 'feature',
      label: 'Feature Explanations',
      sublabel: 'Feature importance not recorded',
      value: null,
      source: 'feature_importance (not recorded)',
      status: 'absent',
      details: {},
    })
  }

  // ── 3. Model Score & Calibration Link ────────────────────────────────────
  const isCalibrated = Boolean(activeAlert?.is_calibrated)
  const calibratedConfidence = typeof activeAlert?.calibrated_confidence === 'number'
    ? activeAlert.calibrated_confidence
    : null
  const rawConfidence = typeof activeAlert?.confidence === 'number'
    ? activeAlert.confidence
    : (typeof activeIncident?.confidence === 'number' ? activeIncident.confidence : null)
  const anomalyScore = typeof activeAlert?.anomaly_score === 'number'
    ? activeAlert.anomaly_score
    : (typeof activeIncident?.anomaly_score === 'number' ? activeIncident.anomaly_score : null)

  if (isCalibrated && calibratedConfidence !== null) {
    chain.push({
      id: 'link_score',
      kind: 'score',
      label: 'Calibrated Confidence',
      sublabel: `${(calibratedConfidence * 100).toFixed(1)}% calibrated certainty`,
      value: calibratedConfidence,
      source: 'alert.calibrated_confidence',
      status: 'present',
      details: {
        isCalibrated: true,
        calibratedConfidence,
        anomalyScore,
        rawProbability: rawConfidence,
      },
    })
  } else if (rawConfidence !== null) {
    chain.push({
      id: 'link_score',
      kind: 'score',
      label: 'Uncalibrated Model Score',
      sublabel: `${(rawConfidence * 100).toFixed(1)}% raw heuristic probability`,
      value: rawConfidence,
      source: activeAlert?.confidence !== undefined ? 'alert.confidence' : 'incident.confidence',
      status: 'partial',
      details: {
        isCalibrated: false,
        rawConfidence,
        anomalyScore,
      },
    })
  } else {
    chain.push({
      id: 'link_score',
      kind: 'score',
      label: 'Model Score',
      sublabel: 'No confidence reported',
      value: null,
      source: 'confidence (no confidence reported)',
      status: 'absent',
      details: {},
    })
  }

  // ── 4. Detection Alert Link ──────────────────────────────────────────────
  const alertId = activeAlert?.alert_id ||
    (activeIncident?.alert_ids && activeIncident.alert_ids.length > 0 ? activeIncident.alert_ids[0] : null)
  const threatType = activeAlert?.threat_type || activeIncident?.threat_type || null
  const severity = activeAlert?.severity || activeIncident?.severity || 'medium'
  const stage = activeAlert?.current_kill_chain_stage || activeIncident?.current_kill_chain_stage || null

  if (alertId || threatType) {
    chain.push({
      id: 'link_alert',
      kind: 'alert',
      label: 'Detection Alert',
      sublabel: `${threatType || 'Anomaly'} [${severity.toUpperCase()}]${stage ? ` · ${stage}` : ''}`,
      value: alertId || 'Triggered Alert',
      source: activeAlert?.alert_id ? 'alert.alert_id' : 'incident.alert_ids[0]',
      status: 'present',
      details: {
        alertId,
        threatType,
        severity,
        stage,
        mitreTechnique: activeAlert?.mitre_technique_id || null,
      },
    })
  } else {
    chain.push({
      id: 'link_alert',
      kind: 'alert',
      label: 'Detection Alert',
      sublabel: 'Alert record not available',
      value: null,
      source: 'alert_id (not recorded)',
      status: 'absent',
      details: {},
    })
  }

  // ── 5. Correlated Incident Link ──────────────────────────────────────────
  const incidentId = activeIncident?.incident_id || activeAlert?.incident_id || null
  const incidentTitle = activeIncident?.title || 'Correlated Network Threat'
  const matchedRules = activeIncident?.matched_rules || []
  const relCount = activeIncident?.relationship_evidence?.length || 0

  if (incidentId || activeIncident) {
    chain.push({
      id: 'link_incident',
      kind: 'incident',
      label: 'Correlated Incident',
      sublabel: `${incidentTitle} (${matchedRules[0] || 'Correlated Cluster'}${relCount > 0 ? ` · ${relCount} rels` : ''})`,
      value: incidentId || 'Correlated Entity',
      source: activeIncident?.incident_id ? 'incident.incident_id' : 'alert.incident_id',
      status: 'present',
      details: {
        incidentId,
        matchedRules,
        relationshipCount: relCount,
        affectedEntities: activeIncident?.affected_entities || [],
      },
    })
  } else {
    chain.push({
      id: 'link_incident',
      kind: 'incident',
      label: 'Correlated Incident',
      sublabel: 'Not yet clustered into an incident',
      value: null,
      source: 'incident_id (unassigned)',
      status: 'absent',
      details: {},
    })
  }

  return chain
}
