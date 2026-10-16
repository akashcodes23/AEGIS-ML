/**
 * AEGIS-ML Hunting-to-Focus Mapping Helper
 * Pure functions to derive graph focus scope and filter summaries from Threat Hunting state.
 */

/**
 * Builds a readable summary string of active Threat Hunting filters.
 */
export function buildHuntingFilterSummary({
  searchQuery = '',
  selectedSev = 'all',
  selectedLayer = 'all',
  selectedStatus = 'all',
  selectedThreatType = 'all',
} = {}) {
  const parts = []

  if (searchQuery && searchQuery.trim()) {
    parts.push(`query "${searchQuery.trim()}"`)
  }
  if (selectedSev && selectedSev !== 'all') {
    parts.push(`severity ${selectedSev}`)
  }
  if (selectedLayer && selectedLayer !== 'all') {
    parts.push(`layer ${selectedLayer}`)
  }
  if (selectedStatus && selectedStatus !== 'all') {
    parts.push(`status ${selectedStatus}`)
  }
  if (selectedThreatType && selectedThreatType !== 'all') {
    parts.push(`type ${selectedThreatType}`)
  }

  return parts.length > 0 ? parts.join(', ') : 'All alerts'
}

/**
 * Maps filtered alerts to graph entity focus state.
 *
 * @param {Array} filteredAlerts - Alerts after hunting filters are applied
 * @param {Array} allGraphNodes - All nodes currently in graph
 * @param {Object} filterOptions - Filter states
 * @returns {Object} focusState
 */
export function deriveHuntingFocus(filteredAlerts = [], allGraphNodes = [], filterOptions = {}) {
  const safeAlerts = Array.isArray(filteredAlerts) ? filteredAlerts : []
  const safeNodes = Array.isArray(allGraphNodes) ? allGraphNodes : []

  // Extract all unique entities mentioned in filtered alerts
  const matchedEntityIds = new Set()
  for (const alert of safeAlerts) {
    if (alert.src_entity) matchedEntityIds.add(alert.src_entity)
    if (alert.dst_entity) matchedEntityIds.add(alert.dst_entity)
  }

  const allNodeIds = new Set(safeNodes.map(n => (typeof n === 'string' ? n : n.id || n.data?.id)))
  const matchedInGraph = Array.from(matchedEntityIds).filter(id => allNodeIds.has(id))

  const filterSummary = buildHuntingFilterSummary(filterOptions)
  const isFiltered = filterSummary !== 'All alerts'

  return {
    active: isFiltered && safeAlerts.length > 0,
    filterSummary,
    matchedEntityIds: Array.from(matchedEntityIds),
    matchedInGraphCount: matchedInGraph.length,
    totalGraphNodesCount: safeNodes.length,
    hasMatches: matchedInGraph.length > 0,
    status:
      matchedInGraph.length === 0 && isFiltered
        ? 'no_match'
        : matchedInGraph.length < matchedEntityIds.size
          ? 'partial_graph_match'
          : 'full_match',
  }
}
