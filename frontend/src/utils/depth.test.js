import test from 'node:test'
import assert from 'node:assert/strict'
import {
  KILL_CHAIN_STAGES,
  KILL_CHAIN_DEPTH,
  UNKNOWN_DEPTH,
  normalizeKillChainStage,
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
  assert.equal(recon.nodeSize, 26)
  assert.equal(recon.opacity, 0.65)
  assert.equal(recon.borderWidth, 1.5)
  assert.equal(recon.zIndex, 10)

  const impact = KILL_CHAIN_DEPTH.Impact
  assert.ok(impact)
  assert.equal(impact.index, 7)
  assert.equal(impact.normalized, 1.0)
  assert.equal(impact.zDistance, 0.0)
  assert.equal(impact.fogFactor, 0.0)
  assert.equal(impact.nodeSize, 48)
  assert.equal(impact.opacity, 1.0)
  assert.equal(impact.borderWidth, 3.5)
  assert.equal(impact.zIndex, 17)
})

test('UNKNOWN_DEPTH provides truthful neutral properties for unassigned nodes', () => {
  assert.equal(UNKNOWN_DEPTH.stage, 'Unknown')
  assert.equal(UNKNOWN_DEPTH.index, -1)
  assert.equal(UNKNOWN_DEPTH.nodeSize, 28)
  assert.equal(UNKNOWN_DEPTH.opacity, 0.70)
  assert.equal(UNKNOWN_DEPTH.borderWidth, 1.5)
  assert.equal(UNKNOWN_DEPTH.zIndex, 5)
})

test('normalizeKillChainStage maps valid stages and MITRE synonyms accurately', () => {
  assert.equal(normalizeKillChainStage('Recon').stage, 'Recon')
  assert.equal(normalizeKillChainStage('reconnaissance').stage, 'Recon')
  assert.equal(normalizeKillChainStage('Initial Access').stage, 'Delivery')
  assert.equal(normalizeKillChainStage('command and control').stage, 'C2')
  assert.equal(normalizeKillChainStage('c2_beaconing').stage, 'C2')
  assert.equal(normalizeKillChainStage('lateral_movement').stage, 'Install')
  assert.equal(normalizeKillChainStage('data_exfiltration').stage, 'Exfiltrate')
  assert.equal(normalizeKillChainStage('Impact').stage, 'Impact')
})

test('normalizeKillChainStage safely falls back to Unknown without guessing', () => {
  const unkNull = normalizeKillChainStage(null)
  assert.equal(unkNull.isKnown, false)
  assert.equal(unkNull.stage, 'Unknown')

  const unkAnomaly = normalizeKillChainStage('Anomaly')
  assert.equal(unkAnomaly.isKnown, false)
  assert.equal(unkAnomaly.stage, 'Unknown')

  const unkEmpty = normalizeKillChainStage('')
  assert.equal(unkEmpty.isKnown, false)
  assert.equal(unkEmpty.stage, 'Unknown')

  const unkInvalid = normalizeKillChainStage('random_unrecognized_string')
  assert.equal(unkInvalid.isKnown, false)
  assert.equal(unkInvalid.stage, 'Unknown')
})

test('confidenceToFocus handles calibrated confidence correctly', () => {
  const focusHigh = confidenceToFocus({ confidence: 0.95, isCalibrated: true })
  assert.equal(focusHigh.status, 'calibrated')
  assert.equal(focusHigh.isCalibrated, true)
  assert.equal(focusHigh.value, 0.95)
  assert.ok(focusHigh.decorationStyle.haloBlur < 1.0)
  assert.ok(focusHigh.decorationStyle.borderOpacity > 0.9)

  const focusLow = confidenceToFocus({ confidence: 0.20, isCalibrated: true })
  assert.equal(focusLow.status, 'calibrated')
  assert.ok(focusLow.decorationStyle.haloBlur > 4.0)
})

test('confidenceToFocus applies neutral treatment for uncalibrated scores', () => {
  const focusUncal = confidenceToFocus({ confidence: 0.85, isCalibrated: false })
  assert.equal(focusUncal.status, 'uncalibrated')
  assert.equal(focusUncal.isCalibrated, false)
  assert.equal(focusUncal.label, 'uncalibrated')
  assert.equal(focusUncal.value, 0.85)
  assert.equal(focusUncal.decorationStyle.haloBlur, 2.0)
  assert.equal(focusUncal.decorationStyle.saturation, 0.85)
})

test('confidenceToFocus handles missing confidence truthfully', () => {
  const focusMissing = confidenceToFocus({ confidence: null, isCalibrated: false })
  assert.equal(focusMissing.status, 'missing')
  assert.equal(focusMissing.label, 'no confidence reported')
  assert.equal(focusMissing.value, null)
  assert.equal(focusMissing.isCalibrated, false)
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
