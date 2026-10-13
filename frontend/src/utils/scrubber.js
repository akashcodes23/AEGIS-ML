/**
 * Temporal Scrubber & Historical State Reconstruction
 * 
 * Computes network topology and alert feed as of time `t`.
 * 
 * Rules:
 * 1. Timestamp Basis: Primary is event timestamp (item.timestamp). Fallback is ingest/created_at time.
 * 2. Missing timestamps are NEVER guessed: excluded from historical replay and counted in excludedMissingCount.
 * 3. Out-of-order timestamps are sorted chronologically.
 * 4. Entities appear as their first evidence timestamp passes.
 */

/**
 * Extracts a normalized Unix millisecond timestamp from an alert, incident, or event.
 *
 * @param {object|null|undefined} item
 * @returns {{ timeMs: number | null, basis: 'event_time' | 'ingest_time' | 'none' }}
 */
export function extractTimestamp(item) {
  if (!item || typeof item !== 'object') {
    return { timeMs: null, basis: 'none' }
  }

  // 1. Primary: Explicit event time
  const eventTimeRaw = item.timestamp || item.raw_event?.timestamp
  if (eventTimeRaw) {
    const parsed = new Date(eventTimeRaw).getTime()
    if (!Number.isNaN(parsed)) {
      return { timeMs: parsed, basis: 'event_time' }
    }
  }

  // 2. Fallback: Ingest / Creation time
  const ingestTimeRaw = item.created_at || item.updated_at
  if (ingestTimeRaw) {
    const parsed = new Date(ingestTimeRaw).getTime()
    if (!Number.isNaN(parsed)) {
      return { timeMs: parsed, basis: 'ingest_time' }
    }
  }

  return { timeMs: null, basis: 'none' }
}

/**
 * Reconstructs system state (alerts, incidents, entities, edges) as of timestamp `t`.
 *
 * @param {Array<object>} alerts - All alerts in session
 * @param {Array<object>} incidents - All incidents in session
 * @param {number|Date|string} t - Target timestamp (ms, Date, or ISO string)
 * @param {object} [options={}] - Options
 * @returns {{
 *   alerts: Array<object>,
 *   incidents: Array<object>,
 *   visibleEntityIds: Set<string>,
 *   visibleEdges: Array<object>,
 *   excludedMissingCount: number,
 *   timeRange: { min: number, max: number, current: number },
 *   basis: 'event_time' | 'ingest_time' | 'mixed' | 'none'
 * }}
 */
export function stateAsOf(alerts = [], incidents = [], t, options = {}) {
  void options
  const targetMs = typeof t === 'number'
    ? t
    : (t instanceof Date ? t.getTime() : (typeof t === 'string' ? new Date(t).getTime() : Date.now()))

  const safeAlerts = Array.isArray(alerts) ? alerts : []
  const safeIncidents = Array.isArray(incidents) ? incidents : []

  let excludedCount = 0
  const validAlertsWithTime = []
  const bases = new Set()

  // 1. Process alerts
  for (const alert of safeAlerts) {
    const { timeMs, basis } = extractTimestamp(alert)
    if (timeMs === null) {
      excludedCount++
    } else {
      bases.add(basis)
      validAlertsWithTime.push({ alert, timeMs, basis })
    }
  }

  // 2. Process incidents
  const validIncidentsWithTime = []
  for (const inc of safeIncidents) {
    const { timeMs, basis } = extractTimestamp(inc)
    if (timeMs === null) {
      excludedCount++
    } else {
      bases.add(basis)
      validIncidentsWithTime.push({ inc, timeMs, basis })
    }
  }

  // Determine overall session time bounds across alerts, incidents, and relationships
  const allTimes = [
    ...validAlertsWithTime.map(a => a.timeMs),
    ...validIncidentsWithTime.map(i => i.timeMs),
  ]

  safeIncidents.forEach(inc => {
    if (Array.isArray(inc.relationship_evidence)) {
      inc.relationship_evidence.forEach(rel => {
        const { timeMs } = extractTimestamp(rel)
        if (timeMs !== null) allTimes.push(timeMs)
      })
    }
    if (Array.isArray(inc.timeline)) {
      inc.timeline.forEach(tEntry => {
        const { timeMs } = extractTimestamp(tEntry)
        if (timeMs !== null) allTimes.push(timeMs)
      })
    }
  })

  const minTime = allTimes.length > 0 ? Math.min(...allTimes) : targetMs
  const maxTime = allTimes.length > 0 ? Math.max(...allTimes) : targetMs
  const clampedTarget = Math.max(minTime, Math.min(maxTime, targetMs))

  // Filter alerts & incidents visible at targetMs
  const visibleAlerts = validAlertsWithTime
    .filter(a => a.timeMs <= clampedTarget)
    .sort((a, b) => b.timeMs - a.timeMs) // latest first
    .map(a => a.alert)

  const visibleIncidents = validIncidentsWithTime
    .filter(i => i.timeMs <= clampedTarget)
    .sort((a, b) => b.timeMs - a.timeMs)
    .map(i => i.inc)

  // Derive visible entities from active alerts & incidents
  const visibleEntityIds = new Set()
  visibleAlerts.forEach(a => {
    if (a.src_entity) visibleEntityIds.add(a.src_entity)
    if (a.dst_entity) visibleEntityIds.add(a.dst_entity)
    if (a.src_ip) visibleEntityIds.add(a.src_ip)
    if (a.dest_ip) visibleEntityIds.add(a.dest_ip)
  })

  visibleIncidents.forEach(inc => {
    if (inc.primary_attacker) visibleEntityIds.add(inc.primary_attacker)
    if (inc.primary_target) visibleEntityIds.add(inc.primary_target)
    if (Array.isArray(inc.affected_entities)) {
      inc.affected_entities.forEach(e => visibleEntityIds.add(e))
    }
  })

  // Derive visible edges backed by real relationship_evidence or alert interactions
  const visibleEdges = []
  const edgeSet = new Set()

  visibleIncidents.forEach(inc => {
    if (Array.isArray(inc.relationship_evidence)) {
      inc.relationship_evidence.forEach(rel => {
        const { timeMs } = extractTimestamp(rel)
        // If relationship has timestamp, honor it; else inherit from incident
        if (timeMs === null || timeMs <= clampedTarget) {
          const src = rel.source_entity
          const tgt = rel.target_entity
          if (src && tgt && visibleEntityIds.has(src) && visibleEntityIds.has(tgt)) {
            const key = `${src}->${tgt}`
            if (!edgeSet.has(key)) {
              edgeSet.add(key)
              visibleEdges.push({
                source: src,
                target: tgt,
                relationship_type: rel.relationship_type,
                claim_type: rel.claim_type,
                correlation_rule: rel.correlation_rule,
              })
            }
          }
        }
      })
    }
  })

  // Also include direct interaction edges from visible alerts
  visibleAlerts.forEach(a => {
    const src = a.src_entity || a.src_ip
    const dst = a.dst_entity || a.dest_ip
    if (src && dst && src !== dst) {
      const key = `${src}->${dst}`
      if (!edgeSet.has(key)) {
        edgeSet.add(key)
        visibleEdges.push({
          source: src,
          target: dst,
          relationship_type: 'observed_telemetry',
          claim_type: 'observation',
          is_anomalous: Boolean(a.anomaly_score && a.anomaly_score > 0.5),
        })
      }
    }
  })

  let basisSummary = 'none'
  if (bases.has('event_time') && bases.has('ingest_time')) basisSummary = 'mixed'
  else if (bases.has('event_time')) basisSummary = 'event_time'
  else if (bases.has('ingest_time')) basisSummary = 'ingest_time'

  return {
    alerts: visibleAlerts,
    incidents: visibleIncidents,
    visibleEntityIds,
    visibleEdges,
    excludedMissingCount: excludedCount,
    timeRange: {
      min: minTime,
      max: maxTime,
      current: clampedTarget,
    },
    basis: basisSummary,
  }
}
