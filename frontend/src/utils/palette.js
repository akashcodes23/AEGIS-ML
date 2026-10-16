/**
 * AEGIS-ML Command Palette Search and Ranking Engine
 * Pure, deterministic search and ranking with zero external runtime dependencies.
 */

const SEVERITY_WEIGHTS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

/**
 * Normalizes input string for search comparison.
 */
function normalize(str) {
  if (typeof str !== 'string') return ''
  return str.toLowerCase().trim()
}

/**
 * Calculates match score for a given item.
 * Higher is better. Returns 0 if no match.
 */
function scoreItem(item, query) {
  if (!query) return 1

  const q = normalize(query)
  const id = normalize(item.id)
  const label = normalize(item.label || item.name)
  const category = normalize(item.category)
  const subtitle = normalize(item.subtitle || item.threat_type || '')
  const description = normalize(item.description || '')
  const severity = normalize(item.severity || '')
  const stage = normalize(item.stage || item.kill_chain_stage || '')
  const entities = Array.isArray(item.entities)
    ? item.entities.map(normalize).join(' ')
    : normalize(item.entity || '')

  let score = 0

  // 1. Exact matches (highest priority)
  if (id === q || label === q) {
    score = 100
  } else if (id.startsWith(q) || label.startsWith(q)) {
    // 2. Prefix matches
    score = 75
  } else if (label.includes(q) || id.includes(q)) {
    // 3. Substring match on main label / id
    score = 50
  } else if (subtitle.includes(q) || stage.includes(q) || severity.includes(q) || entities.includes(q)) {
    // 4. Secondary field match
    score = 30
  } else if (category.includes(q) || description.includes(q)) {
    // 5. Category or description match
    score = 15
  }

  // Slight boost for severity if matched
  if (score > 0 && severity && SEVERITY_WEIGHTS[severity]) {
    score += SEVERITY_WEIGHTS[severity]
  }

  return score
}

/**
 * Pure search function for Command Palette.
 *
 * @param {string} query - The search query
 * @param {Object} sources - Collections of items to search across
 * @param {Array} [sources.routes] - Navigation routes
 * @param {Array} [sources.incidents] - Incidents from store
 * @param {Array} [sources.alerts] - Recent alerts from store
 * @param {Array} [sources.entities] - Entities from graph
 * @param {Array} [sources.actions] - Quick action commands (Time, Display)
 * @param {number} [limit=20] - Max items to return
 * @returns {{ results: Array, totalMatches: number, totalAvailable: number, query: string }}
 */
export function searchPalette(query = '', sources = {}, limit = 20) {
  const safeSources = {
    routes: Array.isArray(sources.routes) ? sources.routes : [],
    incidents: Array.isArray(sources.incidents) ? sources.incidents : [],
    alerts: Array.isArray(sources.alerts) ? sources.alerts : [],
    entities: Array.isArray(sources.entities) ? sources.entities : [],
    actions: Array.isArray(sources.actions) ? sources.actions : [],
  }

  // Canonicalize items across all categories
  const allItems = []

  // 1. Routes
  safeSources.routes.forEach(r => {
    allItems.push({
      id: `route-${r.id || r.name.toLowerCase().replace(/\s+/g, '-')}`,
      category: 'Navigate',
      label: r.name,
      subtitle: r.subtitle || 'View',
      description: r.description || `Switch to ${r.name} view`,
      type: 'route',
      target: r.target || r.name,
      hash: r.hash || '',
    })
  })

  // 2. Actions (Time / Display)
  safeSources.actions.forEach(a => {
    allItems.push({
      id: `action-${a.id}`,
      category: a.category || 'Action',
      label: a.label || a.name,
      subtitle: a.subtitle || 'Command',
      description: a.description || '',
      type: 'action',
      actionKey: a.actionKey || a.id,
    })
  })

  // 3. Incidents
  safeSources.incidents.forEach((inc, idx) => {
    const incId = inc.incident_id || inc.event_id || `inc-${idx}`
    const entities = inc.affected_entities || [inc.src_entity, inc.dst_entity].filter(Boolean)
    allItems.push({
      id: incId,
      category: 'Incidents',
      label: inc.threat_type || inc.title || `Incident ${incId}`,
      subtitle: incId,
      severity: inc.severity || 'high',
      stage: inc.current_kill_chain_stage || '',
      entities,
      description: `Severity: ${inc.severity || 'high'} | Stage: ${inc.current_kill_chain_stage || 'Unknown'} | Entities: ${entities.join(', ') || 'N/A'}`,
      type: 'incident',
      data: inc,
    })
  })

  // 4. Alerts
  safeSources.alerts.forEach((alert, idx) => {
    const alertId = alert.alert_id || alert.event_id || `alert-${idx}`
    const entities = [alert.src_entity, alert.dst_entity].filter(Boolean)
    allItems.push({
      id: alertId,
      category: 'Alerts',
      label: alert.threat_type || `Alert ${alertId}`,
      subtitle: alertId,
      severity: alert.severity || 'medium',
      stage: alert.mitre_technique_name || alert.layer || '',
      entities,
      description: `Severity: ${alert.severity || 'low'} | ${entities.join(' → ') || 'No entity link'}`,
      type: 'alert',
      data: alert,
    })
  })

  // 5. Entities
  safeSources.entities.forEach((ent, idx) => {
    const entId = typeof ent === 'string' ? ent : ent.id || `ent-${idx}`
    const entType = ent.node_type || ent.type || 'Entity'
    allItems.push({
      id: `entity-${entId}`,
      category: 'Entities',
      label: entId,
      subtitle: entType,
      stage: ent.kill_chain_stage || '',
      description: `Focus node in Entity Graph (${entType})`,
      type: 'entity',
      targetEntity: entId,
    })
  })

  const totalAvailable = allItems.length
  const q = normalize(query)

  if (!q) {
    // Default view: present balanced preview of top categories
    const results = allItems.slice(0, limit)
    return {
      results,
      totalMatches: totalAvailable,
      totalAvailable,
      query: '',
      hasQuery: false,
    }
  }

  // Score each item
  const scored = []
  for (let i = 0; i < allItems.length; i++) {
    const item = allItems[i]
    const score = scoreItem(item, q)
    if (score > 0) {
      scored.push({ item, score, originalIndex: i })
    }
  }

  // Deterministic sort:
  // 1. Score desc
  // 2. Original category order
  // 3. Alphabetical label
  // 4. Original index
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score
    const cmpLabel = (a.item.label || '').localeCompare(b.item.label || '')
    if (cmpLabel !== 0) return cmpLabel
    return a.originalIndex - b.originalIndex
  })

  const totalMatches = scored.length
  const results = scored.slice(0, limit).map(s => s.item)

  return {
    results,
    totalMatches,
    totalAvailable,
    query,
    hasQuery: true,
  }
}
