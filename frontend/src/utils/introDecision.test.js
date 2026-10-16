import test from 'node:test'
import assert from 'node:assert/strict'
import {
  shouldShowIntro,
  hasSeenIntro,
  markIntroSeen,
  INTRO_STORAGE_KEY,
} from './introDecision.js'

test('introDecision: shows intro on first visit to root route with standard settings', () => {
  const show = shouldShowIntro({
    pathname: '/',
    isFirstVisit: true,
    prefersReducedMotion: false,
    reduceVisualEffects: false,
    isLowResource: false,
    isE2E: false,
  })
  assert.equal(show, true)
})

test('introDecision: skips intro on repeat visit', () => {
  const show = shouldShowIntro({
    pathname: '/',
    isFirstVisit: false,
  })
  assert.equal(show, false)
})

test('introDecision: skips intro on deep links', () => {
  assert.equal(shouldShowIntro({ pathname: '/hunting', isFirstVisit: true }), false)
  assert.equal(shouldShowIntro({ pathname: '/graph', isFirstVisit: true }), false)
  assert.equal(shouldShowIntro({ pathname: '/reports', isFirstVisit: true }), false)
})

test('introDecision: skips intro under reduced motion or reduce visual effects', () => {
  assert.equal(shouldShowIntro({ prefersReducedMotion: true, isFirstVisit: true }), false)
  assert.equal(shouldShowIntro({ reduceVisualEffects: true, isFirstVisit: true }), false)
})

test('introDecision: skips intro on low resource devices or in E2E mode', () => {
  assert.equal(shouldShowIntro({ isLowResource: true, isFirstVisit: true }), false)
  assert.equal(shouldShowIntro({ isE2E: true, isFirstVisit: true }), false)
})

test('introDecision: replay mode ignores first visit and route, but respects reduced motion', () => {
  // Replay from any route should show intro
  assert.equal(shouldShowIntro({ pathname: '/reports', isReplay: true }), true)

  // Replay under reduced motion must be blocked
  assert.equal(shouldShowIntro({ isReplay: true, prefersReducedMotion: true }), false)
  assert.equal(shouldShowIntro({ isReplay: true, reduceVisualEffects: true }), false)
})

test('introDecision: hasSeenIntro and markIntroSeen handle storage safely', () => {
  // Node environment without window
  assert.equal(hasSeenIntro(), false)
  markIntroSeen() // Should not throw

  // Mock window.localStorage
  const mockStorage = {}
  globalThis.window = {
    localStorage: {
      getItem: (k) => mockStorage[k] || null,
      setItem: (k, v) => { mockStorage[k] = String(v) },
    },
  }

  assert.equal(hasSeenIntro(), false)
  markIntroSeen()
  assert.equal(hasSeenIntro(), true)
  assert.equal(mockStorage[INTRO_STORAGE_KEY], 'true')

  delete globalThis.window
})
