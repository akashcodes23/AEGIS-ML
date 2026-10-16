import test from 'node:test'
import assert from 'node:assert/strict'
import {
  QUALITY_TIERS,
  evaluateQualityTier,
  DEGRADE_WINDOW_FRAMES,
  RECOVER_WINDOW_FRAMES,
} from './adaptiveQuality.js'

test('adaptiveQuality: defines 4 structured tiers from high to fallback', () => {
  assert.equal(QUALITY_TIERS.high.particleCount, 360)
  assert.equal(QUALITY_TIERS.high.dprCap, 1.75)
  assert.equal(QUALITY_TIERS.medium.particleCount, 200)
  assert.equal(QUALITY_TIERS.low.particleCount, 100)
  assert.equal(QUALITY_TIERS.fallback.particleCount, 0)
})

test('adaptiveQuality: holds current tier within neutral performance band (16.6ms)', () => {
  const result = evaluateQualityTier({
    currentTier: 'high',
    rollingAvgFrameTime: 16.6,
    consecutiveDegradeFrames: 0,
  })
  assert.equal(result.nextTier, 'high')
  assert.equal(result.consecutiveDegradeFrames, 0)
})

test('adaptiveQuality: degrades tier only after sustained poor frame times', () => {
  // Step 59: should not degrade yet
  let state = {
    currentTier: 'high',
    rollingAvgFrameTime: 28.0, // Slow
    consecutiveDegradeFrames: DEGRADE_WINDOW_FRAMES - 2,
    consecutiveRecoverFrames: 0,
  }
  let next = evaluateQualityTier(state)
  assert.equal(next.nextTier, 'high')
  assert.equal(next.consecutiveDegradeFrames, DEGRADE_WINDOW_FRAMES - 1)

  // Step 60: reaches degrade window, steps down to medium
  next = evaluateQualityTier({ ...next, rollingAvgFrameTime: 28.0 })
  assert.equal(next.nextTier, 'medium')
  assert.equal(next.consecutiveDegradeFrames, 0)

  // Further sustained degradation: medium -> low
  next = evaluateQualityTier({
    currentTier: 'medium',
    rollingAvgFrameTime: 30.0,
    consecutiveDegradeFrames: DEGRADE_WINDOW_FRAMES - 1,
  })
  assert.equal(next.nextTier, 'low')

  // Further sustained degradation: low -> fallback
  next = evaluateQualityTier({
    currentTier: 'low',
    rollingAvgFrameTime: 32.0,
    consecutiveDegradeFrames: DEGRADE_WINDOW_FRAMES - 1,
  })
  assert.equal(next.nextTier, 'fallback')
})

test('adaptiveQuality: hysteresis prevents oscillation between tiers', () => {
  // High frame time spike followed by quick recovery
  let state = {
    currentTier: 'high',
    rollingAvgFrameTime: 26.0,
    consecutiveDegradeFrames: 10,
    consecutiveRecoverFrames: 0,
  }

  // Frame time improves back to neutral 18ms
  state = evaluateQualityTier({
    ...state,
    rollingAvgFrameTime: 18.0,
  })
  // Counters reset to 0 in neutral band
  assert.equal(state.nextTier, 'high')
  assert.equal(state.consecutiveDegradeFrames, 0)
  assert.equal(state.consecutiveRecoverFrames, 0)

  // Upward recovery requires full RECOVER_WINDOW_FRAMES (180 frames)
  let recoveryState = {
    currentTier: 'low',
    rollingAvgFrameTime: 10.0, // Very fast
    consecutiveDegradeFrames: 0,
    consecutiveRecoverFrames: RECOVER_WINDOW_FRAMES - 1,
  }
  let recoveryNext = evaluateQualityTier(recoveryState)
  assert.equal(recoveryNext.nextTier, 'medium')
  assert.equal(recoveryNext.consecutiveRecoverFrames, 0)
})
