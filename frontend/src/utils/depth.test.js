import test from 'node:test'
import assert from 'node:assert/strict'
import {
  KILL_CHAIN_STAGES,
  KILL_CHAIN_DEPTH,
  confidenceToFocus,
  SEVERITY_TOKENS,
  isCrimsonReservedForCritical,
} from './depth.js'

test('KILL_CHAIN_STAGES defines 8 progressive stages', () => {
  assert.equal(KILL_CHAIN_STAGES.length, 8)
  assert.deepEqual(KILL_CHAIN_STAGES, [
    'Recon',
    'Weaponize',
    'Delivery',
    'Exploit',
    'Install',
    'C2',
    'Exfiltrate',
    'Impact',
  ])
})

test('KILL_CHAIN_DEPTH maps stages to correct spatial depth properties', () => {
  const recon = KILL_CHAIN_DEPTH.Recon
  assert.ok(recon)
  assert.equal(recon.index, 0)
  assert.equal(recon.normalized, 0.0)
  assert.equal(recon.zDistance, -70.0)
  assert.equal(recon.fogFactor, 0.85)

  const impact = KILL_CHAIN_DEPTH.Impact
  assert.ok(impact)
  assert.equal(impact.index, 7)
  assert.equal(impact.normalized, 1.0)
  assert.equal(impact.zDistance, 0.0)
  assert.equal(impact.fogFactor, 0.0)
})

test('confidenceToFocus maps high confidence to crisp rendering', () => {
  const focus = confidenceToFocus(1.0)
  assert.equal(focus.blurPx, 0)
  assert.equal(focus.opacity, 1.0)
  assert.equal(focus.saturation, 1.0)
  assert.equal(focus.filterString, 'blur(0px) opacity(1) saturate(1)')
})

test('confidenceToFocus maps low confidence to defocused rendering', () => {
  const focus = confidenceToFocus(0.0)
  assert.equal(focus.blurPx, 4.0)
  assert.equal(focus.opacity, 0.55)
  assert.equal(focus.saturation, 0.7)
  assert.equal(focus.filterString, 'blur(4px) opacity(0.55) saturate(0.7)')
})

test('confidenceToFocus gracefully handles null, undefined, and clamped values', () => {
  const focusNull = confidenceToFocus(null)
  assert.equal(focusNull.blurPx, 2.0)
  assert.equal(focusNull.opacity, 0.775)

  const focusHigh = confidenceToFocus(1.5)
  assert.equal(focusHigh.blurPx, 0)

  const focusLow = confidenceToFocus(-0.5)
  assert.equal(focusLow.blurPx, 4.0)
})

test('SEVERITY_TOKENS defines critical, high, medium, low, info with AA compliant tokens', () => {
  const required = ['critical', 'high', 'medium', 'low', 'info']
  for (const sev of required) {
    const token = SEVERITY_TOKENS[sev]
    assert.ok(token, `Missing token for ${sev}`)
    assert.ok(token.fg, `Missing fg for ${sev}`)
    assert.ok(token.bg, `Missing bg for ${sev}`)
    assert.ok(token.border, `Missing border for ${sev}`)
  }
})

test('Crimson rarity rule: crimson is strictly rejected for non-critical severities', () => {
  assert.equal(isCrimsonReservedForCritical('critical', '#ff3366'), true)
  assert.equal(isCrimsonReservedForCritical('critical', '#dc2626'), true)
  assert.equal(isCrimsonReservedForCritical('high', '#fb923c'), true)

  // Disallowed: crimson used on non-critical
  assert.equal(isCrimsonReservedForCritical('high', '#ff3366'), false)
  assert.equal(isCrimsonReservedForCritical('medium', '#dc2626'), false)
  assert.equal(isCrimsonReservedForCritical('info', '#e11d48'), false)
})
