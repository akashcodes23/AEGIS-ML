import test from 'node:test'
import assert from 'node:assert/strict'
import { isLowResourceDevice, shouldEnable3D } from './capabilities.js'

test('isLowResourceDevice identifies devices with low CPU cores or data saver', () => {
  assert.equal(isLowResourceDevice({ hardwareConcurrency: 2 }), true)
  assert.equal(isLowResourceDevice({ hardwareConcurrency: 8, deviceMemory: 2 }), true)
  assert.equal(isLowResourceDevice({ hardwareConcurrency: 8, connection: { saveData: true } }), true)
  assert.equal(isLowResourceDevice({ hardwareConcurrency: 8, deviceMemory: 16 }), false)
})

test('shouldEnable3D enables 3D when all conditions are satisfied', () => {
  const result = shouldEnable3D({
    featureFlag: true,
    reducedMotion: false,
    hasWebGL: true,
    isLowResource: false,
  })
  assert.equal(result.canRun, true)
})

test('shouldEnable3D disables 3D under reduced motion or low resources', () => {
  const rm = shouldEnable3D({ featureFlag: true, reducedMotion: true, hasWebGL: true, isLowResource: false })
  assert.equal(rm.canRun, false)
  assert.match(rm.reason, /reduced motion/i)

  const noGL = shouldEnable3D({ featureFlag: true, reducedMotion: false, hasWebGL: false, isLowResource: false })
  assert.equal(noGL.canRun, false)
  assert.match(noGL.reason, /WebGL/i)

  const flagOff = shouldEnable3D({ featureFlag: false, reducedMotion: false, hasWebGL: true, isLowResource: false })
  assert.equal(flagOff.canRun, false)
  assert.match(flagOff.reason, /Feature flag/i)
})
