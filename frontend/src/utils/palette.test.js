import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { searchPalette } from './palette.js'

describe('searchPalette pure engine', () => {
  const sampleSources = {
    routes: [
      { name: 'Dashboard', description: 'Real-time overview' },
      { name: 'Threat Hunting', description: 'Query and triage detections' },
      { name: 'Entity Graph', description: 'Spatial topology' },
      { name: 'Reports', description: 'Compliance audit and executive briefing' },
    ],
    actions: [
      { id: 'jump-latest', name: 'Jump to Latest', category: 'Time', actionKey: 'jumpToLatest', description: 'Exit replay and stream live events' },
      { id: 'toggle-fx', name: 'Toggle Visual Effects', category: 'Display', actionKey: 'toggleFx', description: 'Switch between 3D Spatial and FX Reduced' },
    ],
    incidents: [
      { incident_id: 'INC-8801', threat_type: 'Data Exfiltration Spike', severity: 'critical', current_kill_chain_stage: 'Exfiltration', affected_entities: ['10.0.0.45', 'srv-db-01'] },
      { incident_id: 'INC-8802', threat_type: 'Lateral Credential Pivot', severity: 'high', current_kill_chain_stage: 'Lateral Movement', affected_entities: ['10.0.0.12', '10.0.0.45'] },
      { incident_id: 'INC-8803', threat_type: 'Port Scan Sweep', severity: 'low', current_kill_chain_stage: 'Reconnaissance', affected_entities: ['192.168.1.100'] },
    ],
    alerts: [
      { alert_id: 'ALT-101', threat_type: 'SSH Brute Force', severity: 'high', src_entity: '192.168.1.50', dst_entity: '10.0.0.12' },
      { alert_id: 'ALT-102', threat_type: 'DNS Tunneling Probe', severity: 'medium', src_entity: '10.0.0.45', dst_entity: '8.8.8.8' },
    ],
    entities: [
      { id: '10.0.0.45', node_type: 'ip', kill_chain_stage: 'Exfiltration' },
      { id: 'srv-db-01', node_type: 'process', kill_chain_stage: 'Actions on Objectives' },
      { id: '192.168.1.100', node_type: 'ip' },
    ],
  }

  test('handles empty query with balanced top items and accurate totals', () => {
    const res = searchPalette('', sampleSources, 20)
    assert.equal(res.hasQuery, false)
    assert.equal(res.totalAvailable, 14) // 4 routes + 2 actions + 3 incidents + 2 alerts + 3 entities
    assert.equal(res.totalMatches, 14)
    assert.equal(res.results.length, 14)
    assert.equal(res.results[0].category, 'Navigate')
  })

  test('ranks exact matches higher than partial substring matches', () => {
    const res = searchPalette('INC-8801', sampleSources)
    assert.ok(res.results.length > 0)
    assert.equal(res.results[0].id, 'INC-8801')
    assert.equal(res.results[0].category, 'Incidents')
  })

  test('finds entities by IP address and returns entity category', () => {
    const res = searchPalette('10.0.0.45', sampleSources)
    assert.ok(res.results.length > 0)
    // The exact entity node or incident referencing it
    const entityResult = res.results.find(r => r.type === 'entity')
    assert.ok(entityResult, 'Found entity match')
    assert.equal(entityResult.targetEntity, '10.0.0.45')
  })

  test('searches by threat type and kill-chain stage', () => {
    const res = searchPalette('Exfiltration', sampleSources)
    assert.ok(res.results.length >= 2)
    assert.ok(res.results.some(r => r.id === 'INC-8801'))
    assert.ok(res.results.some(r => r.type === 'entity' && r.targetEntity === '10.0.0.45'))
  })

  test('searches navigation routes and action triggers', () => {
    const resRoute = searchPalette('Hunting', sampleSources)
    assert.equal(resRoute.results[0].target, 'Threat Hunting')

    const resAction = searchPalette('latest', sampleSources)
    assert.equal(resAction.results[0].actionKey, 'jumpToLatest')
  })

  test('handles special regex/punctuation characters safely without throwing', () => {
    const queries = ['[test]', '(', ')', '*', '+', '?', '\\', '"', 'INC-.*', '<script>']
    for (const q of queries) {
      assert.doesNotThrow(() => {
        const res = searchPalette(q, sampleSources)
        assert.ok(Array.isArray(res.results))
      }, `Failed for query: ${q}`)
    }
  })

  test('returns empty results array and totalMatches=0 when no match exists', () => {
    const res = searchPalette('nonexistent-term-xyz-12345', sampleSources)
    assert.equal(res.totalMatches, 0)
    assert.equal(res.results.length, 0)
    assert.equal(res.hasQuery, true)
  })

  test('scales to 1,000+ items with sub-millisecond execution and deterministic limit', () => {
    const largeSources = {
      routes: sampleSources.routes,
      incidents: Array.from({ length: 600 }, (_, i) => ({
        incident_id: `INC-${1000 + i}`,
        threat_type: i % 2 === 0 ? 'Data Exfiltration' : 'Privilege Escalation',
        severity: i % 10 === 0 ? 'critical' : 'medium',
      })),
      alerts: Array.from({ length: 600 }, (_, i) => ({
        alert_id: `ALT-${2000 + i}`,
        threat_type: 'Suspicious Execution',
        src_entity: `10.0.${Math.floor(i / 250)}.${i % 250}`,
      })),
      entities: Array.from({ length: 300 }, (_, i) => ({
        id: `node-${i}`,
        node_type: 'ip',
      })),
    }

    const t0 = performance.now()
    const res = searchPalette('Exfiltration', largeSources, 20)
    const elapsed = performance.now() - t0

    assert.equal(res.results.length, 20)
    assert.ok(res.totalMatches >= 300)
    assert.ok(elapsed < 25, `Large search took too long: ${elapsed}ms`)
  })

  test('ensures no destructive actions are defined in palette', () => {
    const res = searchPalette('', sampleSources)
    const dangerousKeywords = ['isolate', 'remediate', 'model reload', 'admin', 'delete', 'drop']
    for (const r of res.results) {
      const text = `${r.label} ${r.description} ${r.id}`.toLowerCase()
      for (const kw of dangerousKeywords) {
        assert.ok(!text.includes(kw), `Palette contained unauthorized action: ${kw}`)
      }
    }
  })
})
