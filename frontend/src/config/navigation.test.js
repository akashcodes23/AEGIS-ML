import test from 'node:test'
import assert from 'node:assert'
import { resolveTabFromLocation, NAV_TABS, TAB_ROUTES } from './navigation.js'

test('NAV_TABS defines all four required navigation items', () => {
  assert.deepStrictEqual(NAV_TABS, ['Dashboard', 'Threat Hunting', 'Entity Graph', 'Reports'])
})

test('TAB_ROUTES maps tabs to valid clean URLs', () => {
  assert.strictEqual(TAB_ROUTES['Dashboard'], '/')
  assert.strictEqual(TAB_ROUTES['Threat Hunting'], '/threat-hunting')
  assert.strictEqual(TAB_ROUTES['Entity Graph'], '/entity-graph')
  assert.strictEqual(TAB_ROUTES['Reports'], '/reports')
})

test('resolveTabFromLocation handles direct pathnames', () => {
  assert.strictEqual(resolveTabFromLocation({ pathname: '/' }), 'Dashboard')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/dashboard' }), 'Dashboard')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/threat-hunting' }), 'Threat Hunting')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/threat-hunting/' }), 'Threat Hunting')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/hunting' }), 'Threat Hunting')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/entity-graph' }), 'Entity Graph')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/graph' }), 'Entity Graph')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/reports' }), 'Reports')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/report' }), 'Reports')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/unknown-route' }), 'Dashboard')
})

test('resolveTabFromLocation handles hash routes', () => {
  assert.strictEqual(resolveTabFromLocation({ pathname: '/', hash: '#/threat-hunting' }), 'Threat Hunting')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/', hash: '#entity-graph' }), 'Entity Graph')
  assert.strictEqual(resolveTabFromLocation({ pathname: '/', hash: '#reports' }), 'Reports')
})
