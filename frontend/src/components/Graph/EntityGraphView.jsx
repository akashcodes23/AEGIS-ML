import { memo } from 'react'
import { Network, ShieldAlert, Cpu, Share2, Layers } from 'lucide-react'
import AttackGraph from './AttackGraph'
import useAlertStore from '../../store/alertStore'

export default memo(function EntityGraphView() {
  const graphData = useAlertStore(s => s.graphData)
  const nodes = graphData?.nodes || []
  const edges = graphData?.edges || []

  const nodeCount = nodes.length
  const edgeCount = edges.length
  const anomalousCount = edges.filter(e => {
    const isAnom = e.is_anomalous || e.data?.is_anomalous
    return Boolean(isAnom)
  }).length
  const compromisedCount = nodes.filter(n => {
    const isComp = n.is_compromised || n.data?.is_compromised
    return Boolean(isComp)
  }).length

  return (
    <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ── Header Card ──────────────────────────────────────────────── */}
      <div className="glass-panel" style={{ padding: '24px 32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
              <div style={{
                width: 38, height: 38, borderRadius: 12,
                background: 'rgba(79, 70, 229, 0.1)', color: 'var(--accent-brand)',
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }}>
                <Network size={22} />
              </div>
              <h1 style={{ fontSize: 22, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
                Entity Threat Topology
              </h1>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', maxWidth: 780, lineHeight: 1.5 }}>
              Interactive entity topology mapping observed layer telemetry and multi-stage lateral pivot hypotheses. 
              Nodes represent interacting network hosts, system processes, and user identities.
            </p>
          </div>

          {/* Quick Metrics */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <div style={{
              padding: '10px 18px', borderRadius: 14, background: 'var(--bg-page)',
              border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: 10
            }}>
              <Share2 size={16} color="var(--accent-info)" />
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Entities</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>{nodeCount}</div>
              </div>
            </div>

            <div style={{
              padding: '10px 18px', borderRadius: 14, background: 'var(--bg-page)',
              border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: 10
            }}>
              <Layers size={16} color="var(--accent-brand)" />
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Active Links</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>{edgeCount}</div>
              </div>
            </div>

            <div style={{
              padding: '10px 18px', borderRadius: 14, background: 'var(--bg-page)',
              border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: 10
            }}>
              <ShieldAlert size={16} color="var(--accent-critical)" />
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Anomalous Edges</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--accent-critical)' }}>{anomalousCount}</div>
              </div>
            </div>

            <div style={{
              padding: '10px 18px', borderRadius: 14, background: 'var(--bg-page)',
              border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: 10
            }}>
              <Cpu size={16} color={compromisedCount > 0 ? 'var(--accent-critical)' : 'var(--accent-success)'} />
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Compromised</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: compromisedCount > 0 ? 'var(--accent-critical)' : 'var(--accent-success)' }}>
                  {compromisedCount}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Main Graph Container ───────────────────────────────────────── */}
      <div className="glass-panel" style={{ height: 720, overflow: 'hidden', padding: 8 }}>
        <AttackGraph />
      </div>
    </div>
  )
})
