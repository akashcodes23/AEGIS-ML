import test from 'node:test'
import assert from 'node:assert/strict'
import useAlertStore from './alertStore.js'

test('alertStore scrubber buffering: buffers incoming alerts during past replay and flushes on jumpToLatest', () => {
  // 1. Reset store
  useAlertStore.getState().clearAlerts()

  // 2. Add alert in live mode
  useAlertStore.getState().addAlert({ alert_id: 'a1', timestamp: '2026-10-13T10:00:00Z' })
  assert.equal(useAlertStore.getState().alerts.length, 1)
  assert.equal(useAlertStore.getState().liveAlertBuffer.length, 0)

  // 3. Pause scrubber at past time
  useAlertStore.getState().setScrubberTime(new Date('2026-10-13T09:30:00Z').getTime())
  assert.equal(useAlertStore.getState().scrubberTime !== null, true)

  // 4. Ingest new stream alerts while past time is active
  useAlertStore.getState().addAlert({ alert_id: 'a2', timestamp: '2026-10-13T10:05:00Z' })
  useAlertStore.getState().addAlert({ alert_id: 'a3', timestamp: '2026-10-13T10:06:00Z' })

  // Active past alerts must not be disrupted
  assert.equal(useAlertStore.getState().alerts.length, 1)
  // Incoming alerts must be safely buffered
  assert.equal(useAlertStore.getState().liveAlertBuffer.length, 2)
  assert.equal(useAlertStore.getState().liveAlertBuffer[0].alert_id, 'a3')
  assert.equal(useAlertStore.getState().liveAlertBuffer[1].alert_id, 'a2')

  // 5. Jump back to latest
  useAlertStore.getState().jumpToLatest()
  assert.equal(useAlertStore.getState().scrubberTime, null)
  assert.equal(useAlertStore.getState().liveAlertBuffer.length, 0)
  assert.equal(useAlertStore.getState().alerts.length, 3)
  assert.equal(useAlertStore.getState().alerts[0].alert_id, 'a3')
})
