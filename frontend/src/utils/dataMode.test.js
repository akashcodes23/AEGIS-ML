import test from 'node:test'
import assert from 'node:assert/strict'
import { isSyntheticData } from './dataMode.js'

test('isSyntheticData returns true when stats.is_synthetic is true', () => {
  assert.equal(isSyntheticData({ is_synthetic: true }), true)
})

test('isSyntheticData returns false when stats.is_synthetic is false', () => {
  assert.equal(isSyntheticData({ is_synthetic: false }), false)
})

test('isSyntheticData honors dataset_type flag', () => {
  assert.equal(isSyntheticData({ dataset_type: 'synthetic' }), true)
  assert.equal(isSyntheticData({ dataset_type: 'pcap' }), false)
  assert.equal(isSyntheticData({ dataset_type: 'live' }), false)
})

test('isSyntheticData inspects current file name when explicit flag is absent', () => {
  assert.equal(isSyntheticData({}, 'behavioral_diversity_labeled.jsonl'), true)
  assert.equal(isSyntheticData({}, 'synthetic_traffic.json'), true)
  assert.equal(isSyntheticData({}, 'Monday-WorkingHours.pcap_ISCX.csv'), false)
  assert.equal(isSyntheticData({}, 'live_traffic.pcap'), false)
})

test('isSyntheticData defaults to true on initial state without active file', () => {
  assert.equal(isSyntheticData(null, null), true)
  assert.equal(isSyntheticData({}, ''), true)
})
