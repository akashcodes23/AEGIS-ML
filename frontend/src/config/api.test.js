import test from 'node:test'
import assert from 'node:assert/strict'
import { getApiUrl, getWsUrl, DEFAULT_PRODUCTION_API_URL } from './api.js'

test('DEFAULT_PRODUCTION_API_URL points to Render backend', () => {
  assert.equal(DEFAULT_PRODUCTION_API_URL, 'https://aegis-ml-api.onrender.com')
})

test('getApiUrl handles clean relative endpoints', () => {
  const url = getApiUrl('/api/stats/summary')
  assert.match(url, /\/api\/stats\/summary$/)
})

test('getApiUrl prevents double /api prefix', () => {
  const url1 = getApiUrl('/api')
  assert.doesNotMatch(url1, /\/api\/api/)

  const url2 = getApiUrl('/api/analysis/files')
  assert.doesNotMatch(url2, /\/api\/api/)
})

test('getWsUrl returns valid wss protocol for production', () => {
  const ws = getWsUrl()
  assert.match(ws, /^wss?:\/\//)
  assert.match(ws, /\/ws\/live$/)
})
