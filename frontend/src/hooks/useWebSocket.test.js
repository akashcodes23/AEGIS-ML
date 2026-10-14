import test from 'node:test'
import assert from 'node:assert/strict'
import {
  calculateReconnectDelay,
  INITIAL_RECONNECT_DELAY_MS,
  MAX_RECONNECT_DELAY_MS,
  MAX_RECONNECT_ATTEMPTS,
} from './useWebSocket.js'

test('WebSocket Reconnect Backoff: calculates deterministic linear backoff bounded by max delay', () => {
  // Attempt 0: initial delay
  assert.equal(calculateReconnectDelay(0), INITIAL_RECONNECT_DELAY_MS)
  assert.equal(calculateReconnectDelay(0), 2000)

  // Attempt 1: 2000 + 500 = 2500ms
  assert.equal(calculateReconnectDelay(1), 2500)

  // Attempt 4: 2000 + 2000 = 4000ms
  assert.equal(calculateReconnectDelay(4), 4000)

  // Attempt 8: 2000 + 4000 = 6000ms (reaches MAX_RECONNECT_DELAY_MS)
  assert.equal(calculateReconnectDelay(8), MAX_RECONNECT_DELAY_MS)
  assert.equal(calculateReconnectDelay(8), 6000)

  // Attempt 20: capped at MAX_RECONNECT_DELAY_MS
  assert.equal(calculateReconnectDelay(20), 6000)

  // Max attempts constant check
  assert.equal(MAX_RECONNECT_ATTEMPTS, 60)
})
