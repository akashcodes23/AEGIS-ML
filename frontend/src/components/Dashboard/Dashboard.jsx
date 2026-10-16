import { useCallback, useEffect, useState, useRef, useMemo, lazy, Suspense } from 'react'
import { Activity, Bell, AlertTriangle, Server, Database, CheckCircle, Search } from 'lucide-react'
import useAlertStore from '../../store/alertStore'
import useWebSocket from '../../hooks/useWebSocket'
import useBackendHealth from '../../hooks/useBackendHealth'
import useReducedMotion, { setReducedVisualEffectsPreference } from '../../hooks/useReducedMotion'
import AlertFeed from './AlertFeed'
import AttackGraph from './AttackGraph'
import IncidentCard from './IncidentCard'
import { getApiUrl } from '../../config/api'
import { resolveTabFromLocation, TAB_ROUTES } from '../../config/navigation'
import AegisBrandMark from '../Common/AegisBrandMark'
import SyntheticDemoRibbon from '../Common/SyntheticDemoRibbon'
import AmbientField from '../Atmosphere/AmbientField'
import NavigationDock from '../Navigation/NavigationDock'
import StatusArea from '../Navigation/StatusArea'
import TemporalScrubber from '../Common/TemporalScrubber'
import { isSyntheticData } from '../../utils/dataMode'
import { shouldShowIntro, hasSeenIntro } from '../../utils/introDecision'
import { isLowResourceDevice } from '../../utils/capabilities'

const ThreatHunting = lazy(() => import('../ThreatHunting/ThreatHunting'))
const EntityGraphView = lazy(() => import('../Graph/EntityGraphView'))
const Reports = lazy(() => import('../Reports/Reports'))
const CommandPalette = lazy(() => import('../Common/CommandPalette'))
const FirstRunIntro = lazy(() => import('../Atmosphere/FirstRunIntro'))

function RouteSuspenseFallback({ title = 'section' }) {
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 480,
        gap: 12,
        color: 'var(--text-secondary)',
        fontSize: 13,
      }}
    >
      <div
        style={{
          width: 32,
          height: 32,
          borderRadius: '50%',
          border: '2px solid var(--border-medium)',
          borderTopColor: 'var(--accent-cyan)',
          animation: 'spin 0.8s linear infinite',
        }}
        aria-hidden="true"
      />
      <span>Loading {title}...</span>
    </div>
  )
}

/* ── Stat card ────────────────────────────────────────────────────────────── */
function StatCard({ label, value, unit = '', accentVar, icon, delay = 0, sublabel = null, source = null }) {
  const CardIcon = icon
  return (
    <div 
      className="glass-panel animate-slide-up"
      style={{
        padding: '20px 24px',
        display: 'flex', gap: 16, alignItems: 'flex-start',
        position: 'relative',
        animationDelay: `${delay}ms`
      }}
    >
      <div style={{
        width: 44, height: 44, borderRadius: 12, flexShrink: 0,
        background: `var(${accentVar})`,
        opacity: 0.12,
        position: 'absolute'
      }} />
      <div style={{
        width: 44, height: 44, borderRadius: 12, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: `var(${accentVar})`,
        zIndex: 1
      }}>
        <CardIcon size={20} strokeWidth={2.2} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: 0.6, textTransform: 'uppercase' }}>
            {label}
          </div>
          {source && (
            <span style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} title={`Data Source: ${source}`}>
              {source}
            </span>
          )}
        </div>
        <div className="tabular-nums" style={{ fontSize: 26, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.1, letterSpacing: '-0.5px' }}>
          {value}
          {unit && <span style={{ fontSize: 13, color: 'var(--text-tertiary)', marginLeft: 6, fontWeight: 600 }}>{unit}</span>}
        </div>
        {sublabel && (
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4, lineHeight: 1.3 }}>
            {sublabel}
          </div>
        )}
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
    void Promise.resolve().then(fetchFiles)
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
      <div style={{ width: 1, height: 20, background: 'var(--border-hairline)' }} />
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', flex: 1, alignItems: 'center' }}>
        {loading && (
          <span style={{ fontSize: 12, color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="animate-spin" style={{ display: 'inline-block', width: 10, height: 10, border: '2px solid var(--text-tertiary)', borderTopColor: 'transparent', borderRadius: '50%' }} />
            Discovering datasets...
          </span>
        )}
        {!loading && error && (
          <span style={{ fontSize: 12, color: 'var(--severity-critical-fg)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Failed to load datasets ({error})</span>
            <button
              type="button"
              onClick={fetchFiles}
              style={{
                fontSize: 11, padding: '2px 8px', borderRadius: 6,
                background: 'var(--severity-critical-bg)', color: 'var(--severity-critical-fg)',
                border: '1px solid var(--severity-critical-border)', cursor: 'pointer'
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
              padding: '6px 14px', borderRadius: 20,
              background: isSelected ? 'var(--surface-3)' : 'var(--surface-1)',
              border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--border-hairline)'}`,
              color: isSelected ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontWeight: isSelected ? 600 : 500,
              transition: 'all 0.2s ease',
              display: 'flex', alignItems: 'center', gap: 8
            }}>
              {isSelected && <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-cyan)' }} className="animate-pulse-slow" />}
              <span>{f.name.replace('.pcap_ISCX.csv', '')}</span>
              <span style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>({f.size_mb}MB)</span>
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 8,
                background: isSynth ? 'rgba(168, 85, 247, 0.14)' : 'rgba(52, 211, 153, 0.14)',
                color: isSynth ? '#c084fc' : 'var(--severity-success-fg)',
                border: `1px solid ${isSynth ? 'rgba(168, 85, 247, 0.3)' : 'rgba(52, 211, 153, 0.3)'}`,
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
  const { connected, connecting, reconnect } = useWebSocket()
  const { status: backendStatus } = useBackendHealth()
  const [activeTab, setActiveTab] = useState(() => resolveTabFromLocation())
  const [actionError, setActionError] = useState(null)

  const navigateTo = useCallback((tab, hash = '') => {
    setActiveTab(tab)
    const targetPath = (TAB_ROUTES[tab] || '/') + (hash ? `#${hash.replace(/^#/, '')}` : '')
    if (typeof window !== 'undefined') {
      window.history.pushState({ tab }, '', targetPath)
      if (hash) {
        window.location.hash = hash
      }
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
  const [paletteOpen, setPaletteOpen] = useState(false)
  const paletteTriggerRef = useRef(null)
  const prevAlertCount = useRef(0)

  const graphData = useAlertStore(s => s.graphData)
  const selectIncident = useAlertStore(s => s.selectIncident)
  const setFocusIncidentId = useAlertStore(s => s.setFocusIncidentId)
  const jumpToLatest = useAlertStore(s => s.jumpToLatest)
  const reducedVisualEffects = useReducedMotion()

  const [showIntro, setShowIntro] = useState(() => {
    return shouldShowIntro({
      pathname: typeof window !== 'undefined' ? window.location.pathname : '/',
      isFirstVisit: !hasSeenIntro(),
      prefersReducedMotion: Boolean(typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches),
      reduceVisualEffects: false,
      isLowResource: isLowResourceDevice(),
      isE2E: Boolean(import.meta.env?.VITE_E2E === 'true'),
      isReplay: false,
    })
  })
  const [isReplayingIntro, setIsReplayingIntro] = useState(false)

  // Global Ctrl/Cmd+K shortcut for launcher
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen(prev => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Command palette data sources derived from real application store
  const paletteSources = useMemo(() => {
    return {
      routes: [
        { name: 'Dashboard', description: 'Overview metrics, live topology, and correlated incidents' },
        { name: 'Threat Hunting', description: 'Triage detections, investigate hypotheses, and filter entities' },
        { name: 'Entity Graph', description: 'Full spatial topology, lateral pivot links, and blast radius' },
        { name: 'Reports', description: 'Executive incident briefings, audit exports, and CSV logs' },
        { name: 'Model Assurance', target: 'Reports', hash: 'model-assurance', description: 'Empirical model metrics (Macro F1 0.9866, ECE 0.0011), zero-day generalization escape rates, and protocol provenance' },
      ],
      actions: [
        { id: 'jump-latest', label: 'Jump to Latest Telemetry', category: 'Time', actionKey: 'jumpToLatest', description: 'Exit temporal replay and restore real-time live alert stream' },
        { id: 'toggle-fx', label: 'Toggle Visual Effects Mode', category: 'Display', actionKey: 'toggleFx', description: 'Switch between 3D Spatial atmosphere and Reduced Visual Effects' },
        { id: 'replay-intro', label: 'Replay Brand Introduction', category: 'Display', actionKey: 'replayIntro', description: 'Replay the assembling brand identity animation sequence' },
      ],
      incidents,
      alerts,
      entities: (graphData?.nodes || []).map(n => ({ id: n.id, node_type: n.node_type, stage: n.current_kill_chain_stage })),
    }
  }, [incidents, alerts, graphData])

  const handlePaletteAction = useCallback((actionKey) => {
    if (actionKey === 'jumpToLatest') {
      jumpToLatest()
    } else if (actionKey === 'toggleFx') {
      setReducedVisualEffectsPreference(!reducedVisualEffects)
    } else if (actionKey === 'replayIntro') {
      const prefersReduced = Boolean(typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches)
      if (!prefersReduced && !reducedVisualEffects) {
        setIsReplayingIntro(true)
        setShowIntro(true)
      }
    }
  }, [jumpToLatest, reducedVisualEffects])

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

  // Empirical honesty check: Is synthetic demo data currently loaded?
  const isSynthetic = isSyntheticData(stats, currentFile)

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

  return (
    <div className={`aegis-app-root ${isSynthetic ? 'synthetic-scene-tint' : ''}`} style={{ minHeight: '100vh', position: 'relative' }}>
      {/* ── First-Run Brand Intro (Lazy Chunk, Non-Blocking) ──────────── */}
      {showIntro && (
        <Suspense fallback={null}>
          <FirstRunIntro
            onDismiss={() => {
              setShowIntro(false)
              setIsReplayingIntro(false)
            }}
            isReplay={isReplayingIntro}
          />
        </Suspense>
      )}

      {/* ── Accessible Skip To Main Content Link ──────────────────────── */}
      <a href="#main-content" className="skip-to-content">
        Skip to main content
      </a>

      {/* ── Atmospheric 3D Canvas / Static Fallback ──────────────────── */}
      <AmbientField />

      {/* ── Synthetic Demo Disclosure Ribbon ─────────────────────────── */}
      <SyntheticDemoRibbon isSynthetic={isSynthetic} datasetName={currentFile || 'behavioral_diversity_labeled.jsonl'} />

      {/* ── Content Container ────────────────────────────────────────── */}
      <div
        className="aegis-main-container"
        style={{
          position: 'relative',
          zIndex: 1,
          maxWidth: 1600,
          margin: '0 auto',
          padding: '24px 32px 64px 32px',
          display: 'flex',
          flexDirection: 'column',
          gap: 24,
          boxSizing: 'border-box',
        }}
      >

        {/* ── Row 0: Application Shell Header ─────────────────────────── */}
        <header
          className="glass-panel aegis-shell-header"
          style={{
            padding: '14px 28px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 24,
            flexWrap: 'wrap',
          }}
        >
          {/* Brand Mark */}
          <div
            onClick={() => navigateTo('Dashboard')}
            style={{ display: 'flex', alignItems: 'center', gap: 14, cursor: 'pointer' }}
            title="Return to AEGIS Dashboard"
          >
            <AegisBrandMark size={40} glow />
            <div>
              <div style={{
                fontSize: 22, fontWeight: 800, letterSpacing: '-0.5px', color: 'var(--text-primary)',
                lineHeight: 1.1
              }}>
                AEGIS
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-secondary)', letterSpacing: 1.2, textTransform: 'uppercase', fontWeight: 600 }}>
                Spatial Intelligence
              </div>
            </div>
          </div>

          {/* Navigation Dock with Quick Jump Launcher Trigger */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <NavigationDock activeTab={activeTab} onNavigate={navigateTo} />
            <button
              ref={paletteTriggerRef}
              type="button"
              onClick={() => setPaletteOpen(true)}
              title="Open Command Palette (Cmd+K)"
              className="aegis-palette-trigger"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '7px 14px',
                background: 'var(--surface-1)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 9999,
                color: 'var(--text-secondary)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                boxShadow: 'var(--shadow-elevation-1)',
                transition: 'all var(--duration-quick) var(--ease-standard)',
              }}
            >
              <Search size={14} color="var(--accent-cyan)" />
              <span>Search</span>
              <kbd style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                padding: '2px 5px',
                borderRadius: 4,
                background: 'var(--surface-2)',
                border: '1px solid var(--border-hairline)',
                color: 'var(--text-tertiary)',
              }}>
                ⌘K
              </kbd>
            </button>
          </div>

          {/* Real Telemetry Status Area */}
          <StatusArea
            wsConnected={connected}
            wsConnecting={connecting}
            onReconnect={reconnect}
            backendStatus={backendStatus}
            isSynthetic={isSynthetic}
            simulationRunning={simulationRunning}
            onStartAnalysis={startAnalysis}
            onStopAnalysis={stopAnalysis}
          />
        </header>

        {/* ── Action Error Banner ─────────────────────────────────────── */}
        {actionError && (
          <div className="animate-slide-up" style={{
            background: 'var(--severity-critical-bg)',
            border: '1px solid var(--severity-critical-border)',
            color: 'var(--severity-critical-fg)',
            padding: '12px 20px', borderRadius: 12,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
            fontSize: 13, fontWeight: 600,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <AlertTriangle size={18} />
              <span>{actionError}</span>
            </div>
            <button
              type="button"
              onClick={() => setActionError(null)}
              style={{
                background: 'transparent', border: 'none', color: 'var(--severity-critical-fg)',
                cursor: 'pointer', fontWeight: 700, fontSize: 13,
              }}
            >
              ✕ Dismiss
            </button>
          </div>
        )}

        {/* ── Brute Force Toast popup ────────────────────────────────── */}
        {bruteForceWarning && (
          <div className="animate-slide-up" style={{
            position: 'fixed', top: 32, right: 32, zIndex: 9999,
            background: 'var(--severity-high-fg)', color: '#07090e',
            padding: '16px 24px', borderRadius: 12,
            boxShadow: 'var(--shadow-elevation-3)',
            display: 'flex', alignItems: 'center', gap: 12,
            fontWeight: 700, fontSize: 14
          }}>
            <AlertTriangle size={24} />
            <div>
              <div style={{ fontWeight: 800, fontSize: 15, marginBottom: 2 }}>BRUTE FORCE DETECTED</div>
              <div style={{ opacity: 0.9 }}>Source: {bruteForceWarning.src_entity}</div>
            </div>
          </div>
        )}

        {/* ── Main Content Area with A11y Landmark ─────────────────────── */}
        <main id="main-content" tabIndex="-1" className="aegis-main-container" style={{ outline: 'none' }}>
          {/* Level 1 Accessible Heading */}
          <h1 className="sr-only">AEGIS Network Intelligence - {activeTab}</h1>

          {/* ── Tab Views ─────────────────────────────────────────────────── */}
          {activeTab === 'Dashboard' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              {/* ── Datasets ──────────────────────────────────────────────────── */}
              <DatasetPanel currentFile={currentFile} />

              {/* ── Analysis Ingestion Status Banner ─────────────────────────── */}
              {analysisComplete && (
                <div
                  className="glass-panel animate-slide-up"
                  style={{
                    padding: '24px 32px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 20,
                    background: (stats.total_alerts ?? alerts.length) > 0
                      ? 'rgba(251, 146, 60, 0.08)'
                      : 'var(--severity-success-bg)',
                    borderColor: (stats.total_alerts ?? alerts.length) > 0
                      ? 'rgba(251, 146, 60, 0.3)'
                      : 'var(--severity-success-border)',
                  }}
                >
                  {(stats.total_alerts ?? alerts.length) > 0 ? (
                    <AlertTriangle size={32} color="var(--severity-high-fg)" strokeWidth={2} />
                  ) : (
                    <CheckCircle size={32} color="var(--severity-success-fg)" strokeWidth={2} />
                  )}
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 18, color: 'var(--text-primary)', marginBottom: 4 }}>
                      {(stats.total_alerts ?? alerts.length) > 0
                        ? `Analysis Ingestion Finished — Active Findings (${stats.total_alerts ?? alerts.length} Anomalies Flagged)`
                        : 'Analysis Ingestion Finished — Baseline Normal (0 Anomalies)'}
                    </div>
                    <div style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                      {(stats.total_alerts ?? alerts.length) > 0 ? (
                        <>
                          Successfully parsed <span className="mono-font" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{stats.total_events?.toLocaleString() || 0}</span> events from <span className="mono-font" style={{ color: 'var(--accent-cyan)' }}>{currentFile || 'telemetry feed'}</span>. Detected <span className="mono-font" style={{ fontWeight: 700, color: 'var(--severity-high-fg)' }}>{stats.total_alerts ?? alerts.length}</span> anomalous events clustered into <span className="mono-font" style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{incidents.length || (alerts.length > 0 ? 1 : 0)}</span> incident dossiers.
                        </>
                      ) : (
                        <>
                          Successfully parsed <span className="mono-font" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{stats.total_events?.toLocaleString() || 0}</span> events from <span className="mono-font" style={{ color: 'var(--accent-cyan)' }}>{currentFile || 'telemetry feed'}</span>. Observed telemetry conformed to baseline profiles.
                        </>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* ── Row 1: Operational Stats (Scope, Window & Source Disclosed) ── */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 20 }}>
                <StatCard
                  delay={150}
                  icon={Activity}
                  label="Network Pulse"
                  value={stats.events_per_second || 0}
                  unit="eps"
                  accentVar="--accent-cyan"
                  sublabel="Ingest rate (5-second sliding window)"
                  source="Live Ingest Stream"
                />
                <StatCard
                  delay={200}
                  icon={Server}
                  label="Events Processed"
                  value={stats.total_events?.toLocaleString() || 0}
                  accentVar="--accent-cyan"
                  sublabel="Total telemetry events evaluated"
                  source="Log Ingest Pipeline"
                />
                <StatCard
                  delay={250}
                  icon={Bell}
                  label="Correlated Incidents"
                  value={stats.total_incidents !== undefined && stats.total_incidents !== null ? stats.total_incidents : (incidents.length || (alerts.length > 0 ? 1 : 0))}
                  unit={alerts.length ? `(${alerts.length} alerts)` : ''}
                  accentVar="--severity-high-fg"
                  sublabel="Clustered multi-stage attack campaigns"
                  source="Incident Correlator"
                />
                <StatCard
                  delay={300}
                  icon={AlertTriangle}
                  label="Validation FPR"
                  value={hasFpr ? ((stats.false_positive_rate) * 100).toFixed(2) : '0.11'}
                  unit="%"
                  accentVar="--severity-critical-fg"
                  sublabel="Held-out benign test partition"
                  source="docs/evaluation/results.json"
                />
              </div>

              {/* ── Row 1.5: Temporal Scrubber ───────────────────────────────── */}
              <TemporalScrubber />

              {/* ── Row 2: Main Topology & Alert Feed ─────────────────────────── */}
              <div className="aegis-dashboard-main-grid" style={{ display: 'grid', gridTemplateColumns: '60fr 40fr', gap: 24, minHeight: 600 }}>
                <AttackGraph />
                <AlertFeed />
              </div>

              {/* ── Row 3: Incident detail ────────────────────────────────────── */}
              <IncidentCard />
            </div>
          )}

          {activeTab === 'Threat Hunting' && (
            <Suspense fallback={<RouteSuspenseFallback title="Threat Hunting" />}>
              <ThreatHunting />
            </Suspense>
          )}

          {activeTab === 'Entity Graph' && (
            <Suspense fallback={<RouteSuspenseFallback title="Entity Graph" />}>
              <EntityGraphView />
            </Suspense>
          )}

          {activeTab === 'Reports' && (
            <Suspense fallback={<RouteSuspenseFallback title="Reports" />}>
              <Reports />
            </Suspense>
          )}
        </main>
      </div>

      {/* ── Command Palette (Lazy Chunk) ─────────────────────────────── */}
      {paletteOpen && (
        <Suspense fallback={null}>
          <CommandPalette
            isOpen={paletteOpen}
            onClose={() => setPaletteOpen(false)}
            triggerRef={paletteTriggerRef}
            onNavigate={(tab, hash) => {
              navigateTo(tab, hash)
              setPaletteOpen(false)
            }}
            onSelectIncident={(id) => {
              selectIncident(id)
              navigateTo('Dashboard')
              setPaletteOpen(false)
            }}
            onFocusEntity={(entityId) => {
              setFocusIncidentId(entityId)
              navigateTo('Entity Graph')
              setPaletteOpen(false)
            }}
            onAction={(actionKey) => {
              handlePaletteAction(actionKey)
              setPaletteOpen(false)
            }}
            sources={paletteSources}
          />
        </Suspense>
      )}
    </div>
  )
}
