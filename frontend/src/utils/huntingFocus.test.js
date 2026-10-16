import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { buildHuntingFilterSummary, deriveHuntingFocus } from './huntingFocus.js'

describe('huntingFocus helper', () => {
  const mockNodes = [
    { id: '10.0.0.1' },
    { id: '10.0.0.2' },
    { id: '10.0.0.3' },
    { id: 'srv-db-01' },
  ]

  test('builds accurate human-readable filter summaries', () => {
    assert.equal(buildHuntingFilterSummary(), 'All alerts')
    assert.equal(
      buildHuntingFilterSummary({ selectedSev: 'critical' }),
      'severity critical'
    )
    assert.equal(
      buildHuntingFilterSummary({
        searchQuery: 'exfil',
        selectedSev: 'high',
        selectedLayer: 'Network',
      }),
      'query "exfil", severity high, layer Network'
    )
  })

  test('derives focus when all matched entities are present in graph (full match)', () => {
    const filteredAlerts = [
      { src_entity: '10.0.0.1', dst_entity: '10.0.0.2', severity: 'critical' },
    ]
    const res = deriveHuntingFocus(filteredAlerts, mockNodes, { selectedSev: 'critical' })

    assert.equal(res.active, true)
    assert.equal(res.hasMatches, true)
    assert.equal(res.matchedInGraphCount, 2)
    assert.equal(res.status, 'full_match')
    assert.equal(res.filterSummary, 'severity critical')
  })

  test('handles no matches scenario honestly without zooming or dimming graph', () => {
    const filteredAlerts = []
    const res = deriveHuntingFocus(filteredAlerts, mockNodes, { searchQuery: 'unknown-entity' })

    assert.equal(res.active, false)
    assert.equal(res.hasMatches, false)
    assert.equal(res.matchedInGraphCount, 0)
    assert.equal(res.status, 'no_match')
  })

  test('handles partial match when some alert entities are not in active topology graph', () => {
    const filteredAlerts = [
      { src_entity: '10.0.0.1', dst_entity: 'external-c2.evil.com', severity: 'high' },
    ]
    const res = deriveHuntingFocus(filteredAlerts, mockNodes, { selectedSev: 'high' })

    assert.equal(res.active, true)
    assert.equal(res.hasMatches, true)
    assert.equal(res.matchedInGraphCount, 1) // only 10.0.0.1 is in mockNodes
    assert.equal(res.matchedEntityIds.length, 2)
    assert.equal(res.status, 'partial_graph_match')
  })
})
