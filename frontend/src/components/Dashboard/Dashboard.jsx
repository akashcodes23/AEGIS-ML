import { useCallback, useEffect, useState, useRef } from 'react'
import { ShieldCheck, Activity, Bell, AlertTriangle, Server, Database, CheckCircle } from 'lucide-react'
import useAlertStore from '../../store/alertStore'
import useWebSocket from '../../hooks/useWebSocket'
import AlertFeed from './AlertFeed'
import AttackGraph from './AttackGraph'
import IncidentCard from './IncidentCard'
import { getApiUrl } from '../../config/api'
import { resolveTabFromLocation, TAB_ROUTES, NAV_TABS } from '../../config/navigation'
import ThreatHunting from '../ThreatHunting/ThreatHunting'
import EntityGraphView from '../Graph/EntityGraphView'
import Reports from '../Reports/Reports'

/* ── Stat card ────────────────────────────────────────────────────────────── */
function StatCard({ label, value, unit = '', accentVar, icon: Icon, delay = 0 }) {
  return (
    <div 
      className="glass-panel animate-slide-up"
      style={{
        padding: '24px 28px',
        display: 'flex', gap: 20, alignItems: 'center',
        animationDelay: `${delay}ms`
      }}
    >
      <div style={{
        width: 52, height: 52, borderRadius: 16, flexShrink: 0,
        background: `var(${accentVar})`,
        opacity: 0.1,
        position: 'absolute'
      }} />
      <div style={{
        width: 52, height: 52, borderRadius: 16, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: `var(${accentVar})`,
        zIndex: 1
      }}>
        <Icon size={24} strokeWidth={2.5} />
      </div>
      <div>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 6 }}>
          {label}
        </div>
        <div style={{ fontSize: 32, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1, letterSpacing: '-0.5px' }}>
          {value}
          {unit && <span style={{ fontSize: 14, color: 'var(--text-tertiary)', marginLeft: 6, fontWeight: 600 }}>{unit}</span>}
        </div>
      </div>
    </div>
  )
}

/* ── Dataset files mini-panel ─────────────────────────────────────────────── */
function DatasetPanel({ currentFile }) {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchFiles = useCallback(() => {
    setLoading(true)
    setError(null)
    fetch(getApiUrl('/api/analysis/files'))
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(d => {
        setFiles(d.files || [])
        setError(null)
      })
      .catch(err => {
        console.error('[AEGIS] Dataset fetch failed:', err)
        setError(err.message)
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    fetchFiles()
  }, [fetchFiles])

  return (
    <div className="glass-panel animate-slide-up" style={{
      padding: '16px 24px',
      gridColumn: '1 / -1',
      display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap',
      animationDelay: '100ms'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)' }}>
        <Database size={16} />
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', flexShrink: 0 }}>Active Datasets</span>
      </div>
      <div style={{ width: 1, height: 20, background: 'var(--border-light)' }} />
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', flex: 1, alignItems: 'center' }}>
        {loading && (
          <span style={{ fontSize: 12, color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="animate-spin" style={{ display: 'inline-block', width: 10, height: 10, border: '2px solid var(--text-tertiary)', borderTopColor: 'transparent', borderRadius: '50%' }} />
            Discovering datasets...
          </span>
        )}
        {!loading && error && (
          <span style={{ fontSize: 12, color: 'var(--accent-critical)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Failed to load datasets ({error})</span>
            <button
              onClick={fetchFiles}
              style={{
                fontSize: 11, padding: '2px 8px', borderRadius: 6,
                background: 'rgba(220, 38, 38, 0.1)', color: 'var(--accent-critical)',
                border: '1px solid rgba(220, 38, 38, 0.2)', cursor: 'pointer'
              }}
            >
              Retry
            </button>
          </span>
        )}
        {!loading && !error && files.map(f => {
          const isSynth = f.is_synthetic || f.name.includes('.jsonl') || f.name.includes('synthetic') || f.name.includes('combined_labeled')
          const isSelected = currentFile === f.name
          return (
            <span key={f.name} style={{
              fontSize: 12,
              padding: '6px 14px', borderRadius: 24,
              background: isSelected ? 'rgba(79, 70, 229, 0.08)' : 'transparent',
              border: `1px solid ${isSelected ? 'rgba(79, 70, 229, 0.3)' : 'var(--border-light)'}`,
              color: isSelected ? 'var(--accent-brand)' : 'var(--text-secondary)',
              fontWeight: isSelected ? 600 : 500,
              transition: 'all 0.3s ease',
              display: 'flex', alignItems: 'center', gap: 8
            }}>
              {isSelected && <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-brand)' }} className="animate-pulse-slow" />}
              <span>{f.name.replace('.pcap_ISCX.csv', '')}</span>
              <span style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>({f.size_mb}MB)</span>
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 10,
                background: isSynth ? 'rgba(147, 51, 234, 0.1)' : 'rgba(5, 150, 105, 0.1)',
                color: isSynth ? '#9333ea' : 'var(--accent-success)',
                border: `1px solid ${isSynth ? 'rgba(147, 51, 234, 0.25)' : 'rgba(5, 150, 105, 0.25)'}`,
                textTransform: 'uppercase', letterSpacing: 0.5
              }}>
                {isSynth ? 'Synthetic Demo' : 'Real PCAP'}
              </span>
            </span>
          )
        })}
        {!loading && !error && files.length === 0 && (
          <span style={{ fontSize: 13, color: 'var(--text-tertiary)' }}>No analysis files available in datasets.</span>
        )}
      </div>
    </div>
  )
}

/* ── Main Dashboard ───────────────────────────────────────────────────────── */
export default function Dashboard() {
  const stats = useAlertStore(s => s.stats)
  const simulationRunning = useAlertStore(s => s.simulationRunning)
  const setSimulationRunning = useAlertStore(s => s.setSimulationRunning)
  const alerts = useAlertStore(s => s.alerts)
  const incidents = useAlertStore(s => s.incidents)
  const { connected, connecting, error: wsError, reconnect } = useWebSocket()
  const [activeTab, setActiveTab] = useState(() => resolveTabFromLocation())
  const [actionError, setActionError] = useState(null)

  const navigateTo = useCallback((tab) => {
    setActiveTab(tab)
    const targetPath = TAB_ROUTES[tab] || '/'
    if (typeof window !== 'undefined' && window.location.pathname !== targetPath) {
      window.history.pushState({ tab }, '', targetPath)
    }
  }, [])

  useEffect(() => {
    const handleLocationChange = () => {
      setActiveTab(resolveTabFromLocation())
    }
    window.addEventListener('popstate', handleLocationChange)
    window.addEventListener('hashchange', handleLocationChange)
    return () => {
      window.removeEventListener('popstate', handleLocationChange)
      window.removeEventListener('hashchange', handleLocationChange)
    }
  }, [])

  const [bruteForceWarning, setBruteForceWarning] = useState(null)
  const prevAlertCount = useRef(0)

  useEffect(() => {
    if (alerts.length > prevAlertCount.current) {
      const newAlerts = alerts.slice(prevAlertCount.current)
      const bfAlert = newAlerts.find(a => a.threat_type === 'brute_force')
      if (bfAlert) {
        setBruteForceWarning(bfAlert)
        setTimeout(() => setBruteForceWarning(null), 7000)
      }
      prevAlertCount.current = alerts.length
    }
  }, [alerts])

  const currentFile = stats.current_file || null
  const analysisComplete = stats.analysis_complete || false

  // Initial stats, alerts, and incidents sync on mount
  useEffect(() => {
    fetch(getApiUrl('/api/stats/summary'))
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(d => {
        if (d && typeof d.total_events === 'number') {
          useAlertStore.getState().updateStats(d)
          if (d.analysis_running) {
            setSimulationRunning(true)
          } else {
            setSimulationRunning(false)
          }
        }
      })
      .catch(err => console.debug('[AEGIS] Stats summary sync failed:', err))

    fetch(getApiUrl('/api/alerts'))
      .then(r => r.ok ? r.json() : [])
      .then(alertsData => {
        if (Array.isArray(alertsData) && alertsData.length > 0) {
          const currentAlerts = useAlertStore.getState().alerts
          if (currentAlerts.length === 0) {
            useAlertStore.getState().setAlerts(alertsData)
          }
        }
      })
      .catch(err => console.debug('[AEGIS] Alerts initial sync failed:', err))

    fetch(getApiUrl('/api/incidents'))
      .then(r => r.ok ? r.json() : [])
      .then(incidentsData => {
        if (Array.isArray(incidentsData) && incidentsData.length > 0) {
          const currentIncidents = useAlertStore.getState().incidents
          if (currentIncidents.length === 0) {
            useAlertStore.getState().setIncidents(incidentsData)
          }
        }
      })
      .catch(err => console.debug('[AEGIS] Incidents initial sync failed:', err))
  }, [setSimulationRunning])

  const startAnalysis = useCallback(async () => {
    setActionError(null)
    try {
      const res = await fetch(getApiUrl('/api/analysis/start'), { method: 'POST' })
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        const msg = errData.detail || errData.message || `HTTP ${res.status}: ${res.statusText}`
        setActionError(`Failed to start analysis: ${msg}`)
        console.error('[AEGIS] Start analysis failed:', res.status, res.statusText)
        return
      }
      setSimulationRunning(true)
    } catch (err) {
      setActionError(`Network error starting analysis: ${err.message}`)
      console.error('[AEGIS] Failed to start analysis:', err)
    }
  }, [setSimulationRunning])

  const stopAnalysis = useCallback(async () => {
    setActionError(null)
    try {
      const res = await fetch(getApiUrl('/api/analysis/stop'), { method: 'POST' })
      if (!res.ok) {
        console.error('[AEGIS] Stop analysis failed:', res.status, res.statusText)
      }
    } catch (err) {
      console.error('[AEGIS] Failed to stop analysis:', err)
    } finally {
      setSimulationRunning(false)
    }
  }, [setSimulationRunning])

  const hasFpr = stats.false_positive_rate !== null && stats.false_positive_rate !== undefined
  const falsePosValue = hasFpr ? ((stats.false_positive_rate) * 100).toFixed(1) : 'N/A'
  const falsePosUnit = hasFpr ? '%' : ''

  return (
    <div style={{
      minHeight: '100vh',
      display: 'grid',
      gridTemplateRows: 'auto auto 1fr auto',
      gap: 24,
      padding: 32,
      maxWidth: 1600,
      margin: '0 auto'
    }}>

      {/* ── Row 0: Header ─────────────────────────────────────────────── */}
      <header className="glass-panel" style={{
        padding: '16px 32px',
        display: 'grid',
        gridTemplateColumns: 'auto 1fr auto',
        alignItems: 'center',
        gap: 32,
      }}>
        {/* Brand */}
        <div
          onClick={() => navigateTo('Dashboard')}
          style={{ display:'flex', alignItems:'center', gap:16, cursor: 'pointer' }}
          title="Return to AEGIS Dashboard"
        >
          <div style={{
            width: 48, height: 48, borderRadius: 16,
            background: 'var(--text-primary)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#fff', boxShadow: '0 8px 24px rgba(31, 41, 55, 0.15)',
          }}>
            <ShieldCheck size={26} strokeWidth={2.5} />
          </div>
          <div>
            <div style={{
              fontSize: 24, fontWeight: 800, letterSpacing: '-0.5px', color: 'var(--text-primary)',
            }}>AEGIS</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', letterSpacing: 1, textTransform: 'uppercase', fontWeight: 600 }}>
              Network Intelligence
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div style={{ display:'flex', gap:8, justifyContent:'center' }}>
          {NAV_TABS.map((tab) => {
            const isActive = activeTab === tab
            const tabId = `nav-${tab.toLowerCase().replace(/\s+/g, '-')}`
            return (
              <button
                key={tab}
                id={tabId}
                type="button"
                onClick={() => navigateTo(tab)}
                style={{
                  padding: '8px 20px', borderRadius: 24, fontSize: 14,
                  fontWeight: isActive ? 700 : 500,
                  background: isActive ? 'var(--bg-page)' : 'transparent',
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  border: `1px solid ${isActive ? 'var(--border-light)' : 'transparent'}`,
                  cursor: 'pointer', transition: 'all 0.2s',
                  outline: 'none',
                }}
                onMouseEnter={e => { if (!isActive) e.currentTarget.style.color = 'var(--text-primary)' }}
                onMouseLeave={e => { if (!isActive) e.currentTarget.style.color = 'var(--text-secondary)' }}
              >
                {tab}
              </button>
            )
          })}
        </div>

        {/* Controls */}
        <div style={{ display:'flex', alignItems:'center', gap:20 }}>
          {/* Status Badge */}
          <div
            onClick={!connected ? reconnect : undefined}
            title={!connected ? "Click to retry connecting to backend stream" : "Live WebSocket connected"}
            style={{
              display:'flex', alignItems:'center', gap:8,
              padding: '6px 16px', borderRadius: 24,
              cursor: !connected ? 'pointer' : 'default',
              background: connected ? 'rgba(5, 150, 105, 0.08)' : connecting ? 'rgba(217, 119, 6, 0.08)' : 'rgba(220, 38, 38, 0.08)',
              border: `1px solid ${connected ? 'rgba(5, 150, 105, 0.2)' : connecting ? 'rgba(217, 119, 6, 0.2)' : 'rgba(220, 38, 38, 0.2)'}`
            }}
          >
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: connected ? 'var(--accent-success)' : connecting ? 'var(--accent-high)' : 'var(--accent-critical)',
              boxShadow: `0 0 12px ${connected ? 'var(--accent-success)' : connecting ? 'var(--accent-high)' : 'var(--accent-critical)'}`
            }} className={(connected || connecting) ? 'animate-pulse-slow' : ''} />
            <span style={{ fontSize:12, fontWeight:700, color: connected ? 'var(--accent-success)' : connecting ? 'var(--accent-high)' : 'var(--accent-critical)', letterSpacing: 0.5 }}>
              {connected ? 'System Online' : connecting ? 'Connecting...' : 'Offline (Retry)'}
            </span>
          </div>

          <div style={{ width: 1, height: 32, background: 'var(--border-light)' }} />

          {/* Action Buttons */}
          <button onClick={startAnalysis} disabled={simulationRunning} style={{
            padding: '10px 24px', borderRadius: 12,
            fontSize: 14, fontWeight: 700,
            cursor: simulationRunning ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
            background: simulationRunning ? 'var(--bg-page)' : 'var(--text-primary)',
            color: simulationRunning ? 'var(--text-tertiary)' : '#fff',
            border: `1px solid ${simulationRunning ? 'var(--border-light)' : 'transparent'}`,
            boxShadow: simulationRunning ? 'none' : '0 8px 24px rgba(31, 41, 55, 0.2)',
            display: 'flex', alignItems: 'center', gap: 8
          }}>
            <Activity size={18} />
            {simulationRunning ? 'Analyzing...' : 'Start Analysis'}
          </button>

          <button onClick={stopAnalysis} disabled={!simulationRunning} style={{
            padding: '10px 24px', borderRadius: 12,
            fontSize: 14, fontWeight: 700,
            cursor: !simulationRunning ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s',
            background: 'transparent',
            color: !simulationRunning ? 'var(--text-tertiary)' : 'var(--text-primary)',
            border: `1px solid ${!simulationRunning ? 'var(--border-light)' : 'var(--text-primary)'}`,
          }}>
            Stop
          </button>
        </div>
      </header>

      {/* ── Action Error Banner ─────────────────────────────────────────── */}
      {actionError && (
        <div className="animate-slide-up" style={{
          gridColumn: '1 / -1',
          background: 'rgba(220, 38, 38, 0.08)',
          border: '1px solid rgba(220, 38, 38, 0.3)',
          color: 'var(--accent-critical)',
          padding: '12px 20px', borderRadius: 12,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
          fontSize: 13, fontWeight: 600,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={18} />
            <span>{actionError}</span>
          </div>
          <button
            onClick={() => setActionError(null)}
            style={{
              background: 'transparent', border: 'none', color: 'var(--accent-critical)',
              cursor: 'pointer', fontWeight: 700, fontSize: 13,
            }}
          >
            ✕ Dismiss
          </button>
        </div>
      )}

      {/* ── Brute Force Toast popup ────────────────────────────────────── */}
      {bruteForceWarning && (
        <div className="animate-slide-up" style={{
          position: 'fixed', top: 32, right: 32, zIndex: 9999,
          background: 'var(--accent-high)', color: '#fff',
          padding: '16px 24px', borderRadius: 12,
          boxShadow: '0 12px 40px rgba(217, 119, 6, 0.4)',
          display: 'flex', alignItems: 'center', gap: 12,
          fontWeight: 600, fontSize: 14
        }}>
          <AlertTriangle size={24} />
          <div>
            <div style={{fontWeight: 800, fontSize: 15, marginBottom: 2}}>BRUTE FORCE DETECTED</div>
            <div style={{opacity: 0.9}}>Source: {bruteForceWarning.src_entity}</div>
          </div>
        </div>
      )}

      {/* ── Tab Views ─────────────────────────────────────────────────── */}
      {activeTab === 'Dashboard' && (
        <>
          {/* ── Datasets ──────────────────────────────────────────────────────── */}
          <DatasetPanel currentFile={currentFile} />

          {/* ── Analysis Complete Banner ─────────────────────────────────────── */}
          {analysisComplete && (
            <div className="glass-panel animate-slide-up" style={{
              padding: '24px 32px', gridColumn: '1 / -1',
              display: 'flex', alignItems: 'center', gap: 20,
              background: 'rgba(5, 150, 105, 0.04)',
              borderColor: 'rgba(5, 150, 105, 0.2)',
            }}>
              <CheckCircle size={32} color="var(--accent-success)" strokeWidth={2} />
              <div>
                <div style={{ fontWeight: 700, fontSize: 18, color: 'var(--text-primary)', marginBottom: 4 }}>
                  Analysis finished. Your network looks secure.
                </div>
                <div style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                  Successfully processed <span className="mono-font" style={{fontWeight: 600, color: 'var(--text-primary)'}}>{stats.total_events?.toLocaleString() || 0}</span> events. We detected {stats.total_alerts ?? alerts.length} anomalies across your infrastructure.
                </div>
              </div>
            </div>
          )}

          {/* ── Row 1: Stats ──────────────────────────────────────────────── */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:24 }}>
            <StatCard delay={150} icon={Activity} label="Network Pulse" value={stats.events_per_second || 0} unit="eps" accentVar="--accent-brand" />
            <StatCard delay={200} icon={Server} label="Events Processed" value={stats.total_events?.toLocaleString() || 0} accentVar="--accent-info" />
            <StatCard delay={250} icon={Bell} label="Correlated Incidents" value={stats.total_incidents !== undefined && stats.total_incidents !== null ? stats.total_incidents : (incidents.length || (alerts.length > 0 ? 1 : 0))} unit={alerts.length ? `(${alerts.length} alerts)` : ''} accentVar="--accent-high" />
            <StatCard delay={300} icon={AlertTriangle} label="False Positives (Unlabelled)" value={falsePosValue} unit={falsePosUnit} accentVar="--accent-critical" />
          </div>

          {/* ── Row 2: Main ───────────────────────────────────────────────── */}
          <div style={{ display:'grid', gridTemplateColumns:'60fr 40fr', gap:24, minHeight: 600 }}>
            <AttackGraph />
            <AlertFeed />
          </div>

          {/* ── Row 3: Incident detail ────────────────────────────────────── */}
          <IncidentCard />
        </>
      )}

      {activeTab === 'Threat Hunting' && <ThreatHunting />}

      {activeTab === 'Entity Graph' && <EntityGraphView />}

      {activeTab === 'Reports' && <Reports />}
    </div>
  )
}
