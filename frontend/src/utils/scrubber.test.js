import test from 'node:test'
import assert from 'node:assert/strict'
import { extractTimestamp, stateAsOf } from './scrubber.js'

test('extractTimestamp: prioritizes event timestamp over ingest time and handles fallback', () => {
  const itemWithBoth = {
    timestamp: '2026-10-13T10:00:00Z',
    created_at: '2026-10-13T10:05:00Z',
  }
  const resBoth = extractTimestamp(itemWithBoth)
  assert.equal(resBoth.basis, 'event_time')
  assert.equal(resBoth.timeMs, new Date('2026-10-13T10:00:00Z').getTime())

  const itemIngestOnly = {
    created_at: '2026-10-13T11:00:00Z',
  }
  const resIngest = extractTimestamp(itemIngestOnly)
  assert.equal(resIngest.basis, 'ingest_time')
  assert.equal(resIngest.timeMs, new Date('2026-10-13T11:00:00Z').getTime())

  const itemMissing = {
    threat_type: 'Unknown',
  }
  const resMissing = extractTimestamp(itemMissing)
  assert.equal(resMissing.basis, 'none')
  assert.equal(resMissing.timeMs, null)
})

test('stateAsOf: correctly filters alerts and incidents up to target time t', () => {
  const alerts = [
    { alert_id: 'a1', timestamp: '2026-10-13T10:00:00Z', src_entity: '10.0.0.1', dst_entity: '10.0.0.2' },
    { alert_id: 'a2', timestamp: '2026-10-13T10:10:00Z', src_entity: '10.0.0.2', dst_entity: '10.0.0.3' },
    { alert_id: 'a3', timestamp: '2026-10-13T10:20:00Z', src_entity: '10.0.0.3', dst_entity: '10.0.0.4' },
  ]
  const incidents = [
    { incident_id: 'inc1', created_at: '2026-10-13T10:05:00Z', affected_entities: ['10.0.0.1', '10.0.0.2'] },
    { incident_id: 'inc2', created_at: '2026-10-13T10:15:00Z', affected_entities: ['10.0.0.2', '10.0.0.3'] },
  ]

  // Query at 10:12:00Z -> should see a1, a2, and inc1, but NOT a3 or inc2
  const t = new Date('2026-10-13T10:12:00Z').getTime()
  const state = stateAsOf(alerts, incidents, t)

  assert.equal(state.alerts.length, 2)
  assert.equal(state.alerts.some(a => a.alert_id === 'a1'), true)
  assert.equal(state.alerts.some(a => a.alert_id === 'a2'), true)
  assert.equal(state.alerts.some(a => a.alert_id === 'a3'), false)

  assert.equal(state.incidents.length, 1)
  assert.equal(state.incidents[0].incident_id, 'inc1')

  assert.ok(state.visibleEntityIds.has('10.0.0.1'))
  assert.ok(state.visibleEntityIds.has('10.0.0.2'))
  assert.ok(state.visibleEntityIds.has('10.0.0.3'))
  assert.ok(!state.visibleEntityIds.has('10.0.0.4'))
})

test('stateAsOf: handles empty lists and out-of-order data gracefully', () => {
  const empty = stateAsOf([], [], 1000)
  assert.equal(empty.alerts.length, 0)
  assert.equal(empty.incidents.length, 0)
  assert.equal(empty.visibleEntityIds.size, 0)
  assert.equal(empty.visibleEdges.length, 0)
  assert.equal(empty.excludedMissingCount, 0)

  // Out of order timestamps
  const outOfOrder = [
    { alert_id: 'a3', timestamp: '2026-10-13T12:00:00Z' },
    { alert_id: 'a1', timestamp: '2026-10-13T10:00:00Z' },
    { alert_id: 'a2', timestamp: '2026-10-13T11:00:00Z' },
  ]
  const state = stateAsOf(outOfOrder, [], new Date('2026-10-13T11:30:00Z').getTime())
  assert.equal(state.alerts.length, 2)
  assert.equal(state.alerts[0].alert_id, 'a2') // sorted latest visible first
  assert.equal(state.alerts[1].alert_id, 'a1')
})

test('stateAsOf: excludes and counts items with missing timestamps without guessing', () => {
  const alerts = [
    { alert_id: 'a1', timestamp: '2026-10-13T10:00:00Z' },
    { alert_id: 'a_missing', timestamp: null, created_at: null },
    { alert_id: 'a_invalid', timestamp: 'not-a-valid-date' },
  ]
  const state = stateAsOf(alerts, [], new Date('2026-10-13T10:30:00Z').getTime())

  assert.equal(state.alerts.length, 1)
  assert.equal(state.alerts[0].alert_id, 'a1')
  assert.equal(state.excludedMissingCount, 2)
})

test('stateAsOf: relationship edges are visible only when real evidence supports them at time t', () => {
  const incidents = [
    {
      incident_id: 'inc1',
      created_at: '2026-10-13T10:00:00Z',
      relationship_evidence: [
        {
          source_entity: '10.0.1.1',
          target_entity: '10.0.1.2',
          relationship_type: 'direct_socket_binding',
          claim_type: 'observation',
          timestamp: '2026-10-13T10:00:00Z',
        },
        {
          source_entity: '10.0.1.2',
          target_entity: '10.0.1.3',
          relationship_type: 'pivot_lateral_movement',
          claim_type: 'hypothesis',
          timestamp: '2026-10-13T10:15:00Z',
        },
      ],
      affected_entities: ['10.0.1.1', '10.0.1.2', '10.0.1.3'],
    },
  ]

  // At 10:05:00Z: first relationship visible, second lateral movement edge NOT yet visible
  const stateEarly = stateAsOf([], incidents, new Date('2026-10-13T10:05:00Z').getTime())
  assert.equal(stateEarly.visibleEdges.length, 1)
  assert.equal(stateEarly.visibleEdges[0].source, '10.0.1.1')
  assert.equal(stateEarly.visibleEdges[0].target, '10.0.1.2')

  // At 10:20:00Z: both relationships visible
  const stateLate = stateAsOf([], incidents, new Date('2026-10-13T10:20:00Z').getTime())
  assert.equal(stateLate.visibleEdges.length, 2)
})
