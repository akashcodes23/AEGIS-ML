import { memo, useState } from 'react'
import { BellRing, ShieldAlert, ArrowRight, Shield, Zap, Database, ShieldCheck, ChevronLeft, ChevronRight } from 'lucide-react'
import useAlertStore from '../../store/alertStore'

const SEV_STYLE = {
  critical: { bg: 'rgba(220, 38, 38, 0.06)', color: 'var(--accent-critical)', dot: 'var(--accent-critical)' },
  high:     { bg: 'rgba(217, 119, 6, 0.06)',  color: 'var(--accent-high)',     dot: 'var(--accent-high)' },
  medium:   { bg: 'rgba(79, 70, 229, 0.06)',  color: 'var(--accent-brand)',    dot: 'var(--accent-brand)' },
  low:      { bg: 'rgba(5, 150, 105, 0.06)',  color: 'var(--accent-success)',  dot: 'var(--accent-success)' },
}

function SeverityBadge({ severity }) {
  const s = SEV_STYLE[severity] || SEV_STYLE.low
  return (
    <div style={{
      background: s.bg, color: s.color,
      borderRadius: 16, padding: '4px 10px',
      fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase',
      display: 'flex', alignItems: 'center', gap: 6,
    }}>
      <div style={{ width: 6, height: 6, borderRadius: '50%', background: s.dot, flexShrink: 0 }} />
      {severity}
    </div>
  )
}

function AlertRow({ alert, index }) {
  const selectIncident = useAlertStore(s => s.selectIncident)
  const ts = new Date(alert.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  
  // Staggered animation delay
  const delay = Math.min(index * 50, 500)

  return (
    <div
      className="glass-panel animate-slide-up"
      onClick={() => (alert.incident_id || alert.alert_id || alert.event_id) && selectIncident(alert.incident_id || alert.alert_id || alert.event_id)}
      style={{
        padding: '16px 20px', 
        cursor: (alert.incident_id || alert.alert_id) ? 'pointer' : 'default',
        marginBottom: 12,
        animationDelay: `${delay}ms`,
        display: 'grid',
        gridTemplateColumns: 'auto 1fr',
        gap: 16,
        alignItems: 'start'
      }}
    >
      <div style={{
        marginTop: 2,
        width: 32, height: 32, borderRadius: 10,
        background: SEV_STYLE[alert.severity || 'low'].bg,
        color: SEV_STYLE[alert.severity || 'low'].color,
        display: 'flex', alignItems: 'center', justifyContent: 'center'
      }}>
        {alert.severity === 'critical' ? <ShieldAlert size={16} /> : <Zap size={16} />}
      </div>

      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <SeverityBadge severity={alert.severity || 'low'} />
          <div className="mono-font" style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{ts}</div>
        </div>

        <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, letterSpacing: '-0.3px' }}>
          {alert.threat_type?.replace(/_/g, ' ').toUpperCase() || 'ANOMALY DETECTED'}
        </div>

        <div style={{ 
          display: 'flex', alignItems: 'center', gap: 10, 
          background: 'var(--bg-page)', padding: '8px 12px', borderRadius: 8,
          border: '1px solid var(--border-light)'
        }}>
          <span className="mono-font" style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600 }}>{alert.src_entity}</span>
          <ArrowRight size={14} color="var(--text-tertiary)" />
          <span className="mono-font" style={{ fontSize: 11, color: 'var(--text-primary)', fontWeight: 600 }}>{alert.dst_entity}</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-tertiary)' }}>
            {alert.source_file && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <Database size={12} />
                {alert.source_file.replace('.pcap_ISCX.csv', '')}
              </span>
            )}
            {alert.is_synthetic && (
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 8,
                background: 'rgba(147, 51, 234, 0.1)', color: '#9333ea',
                border: '1px solid rgba(147, 51, 234, 0.2)'
              }}>
                Synthetic
              </span>
            )}
          </div>
          <div style={{ fontSize: 11, color: 'var(--accent-info)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4 }}>
            <Shield size={12} />
            {alert.classifier_probability != null
              ? `${Math.round(alert.classifier_probability * 100)}% Consensus`
              : (alert.anomaly_score ? `Score ${Number(alert.anomaly_score).toFixed(2)}` : `${Math.round((alert.confidence || 0) * 100)}% Risk`)}
          </div>
        </div>
      </div>
    </div>
  )
}

const MemoizedAlertRow = memo(AlertRow, (prev, next) => prev.alert.event_id === next.alert.event_id)

export default function AlertFeed() {
  const alerts = useAlertStore(s => s.alerts)
  const clearAlerts = useAlertStore(s => s.clearAlerts)
  const [page, setPage] = useState(1)

  const itemsPerPage = 8
  const totalPages = Math.max(1, Math.ceil(alerts.length / itemsPerPage))
  
  // Ensure page is valid if alerts shrink
  if (page > totalPages) setPage(totalPages)

  const visibleAlerts = alerts.slice().reverse().slice((page - 1) * itemsPerPage, page * itemsPerPage)

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{
        padding: '24px 28px',
        borderBottom: '1px solid var(--border-light)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: 'rgba(255, 255, 255, 0.4)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: 'rgba(79, 70, 229, 0.08)', color: 'var(--accent-brand)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <BellRing size={18} strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>Threat Log</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Real-time telemetry</div>
          </div>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Pagination Controls */}
          {alerts.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-page)', padding: '4px', borderRadius: 20 }}>
              <button 
                onClick={() => setPage(p => Math.max(1, p - 1))} 
                disabled={page === 1}
                style={{ background: 'none', border: 'none', cursor: page === 1 ? 'default' : 'pointer', opacity: page === 1 ? 0.3 : 1, display: 'flex', alignItems: 'center', padding: 2 }}
              ><ChevronLeft size={16} /></button>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)' }}>{page} / {totalPages}</span>
              <button 
                onClick={() => setPage(p => Math.min(totalPages, p + 1))} 
                disabled={page === totalPages}
                style={{ background: 'none', border: 'none', cursor: page === totalPages ? 'default' : 'pointer', opacity: page === totalPages ? 0.3 : 1, display: 'flex', alignItems: 'center', padding: 2 }}
              ><ChevronRight size={16} /></button>
            </div>
          )}
          
          <div style={{
            fontSize: 11, fontWeight: 700, padding: '4px 12px',
            borderRadius: 20, background: 'var(--bg-page)', color: 'var(--text-secondary)'
          }}>
            {alerts.length} Total
          </div>
          <button
            onClick={() => { clearAlerts(); setPage(1); }}
            style={{
              padding: '6px 14px', borderRadius: 20, fontSize: 11, fontWeight: 700,
              color: 'var(--accent-critical)', background: 'rgba(220, 38, 38, 0.06)',
              border: '1px solid rgba(220, 38, 38, 0.2)', cursor: 'pointer',
              transition: 'all 0.2s',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(220, 38, 38, 0.1)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(220, 38, 38, 0.06)'}
          >
            Clear Log
          </button>
        </div>
      </div>

      {/* Feed List */}
      <div style={{
        flex: 1, overflowY: 'auto', padding: '20px 24px',
        background: 'rgba(250, 249, 246, 0.3)'
      }}>
        {alerts.length === 0 ? (
          <div style={{
            height: '100%', display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 16
          }} className="animate-slide-up">
            <div style={{
              width: 64, height: 64, borderRadius: 20,
              background: 'var(--bg-page)', color: 'var(--text-tertiary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.02)'
            }}>
              <ShieldCheck size={32} strokeWidth={1.5} />
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>All Clear</div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Waiting for incoming events...</div>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {visibleAlerts.map((a, i) => (
              <MemoizedAlertRow key={a.event_id || i} alert={a} index={i} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
