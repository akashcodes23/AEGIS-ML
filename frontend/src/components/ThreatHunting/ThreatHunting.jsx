import { useState, useMemo } from 'react'
import {
  Crosshair, Search, Filter, ShieldAlert, AlertTriangle, ArrowRight,
  Clock, Server, Shield, CheckCircle2, Ban, Eye, Activity, RefreshCw
} from 'lucide-react'
import useAlertStore from '../../store/alertStore'
import KillChainViewer from '../Incident/KillChainViewer'
import { getApiUrl } from '../../config/api'

const SEV_STYLE = {
  critical: { bg: 'rgba(220, 38, 38, 0.08)', color: 'var(--accent-critical)', border: 'rgba(220, 38, 38, 0.25)' },
  high:     { bg: 'rgba(217, 119, 6, 0.08)',  color: 'var(--accent-high)',     border: 'rgba(217, 119, 6, 0.25)' },
  medium:   { bg: 'rgba(79, 70, 229, 0.08)',  color: 'var(--accent-brand)',    border: 'rgba(79, 70, 229, 0.25)' },
  low:      { bg: 'rgba(5, 150, 105, 0.08)',  color: 'var(--accent-success)',  border: 'rgba(5, 150, 105, 0.25)' },
}

export default function ThreatHunting() {
  const alerts = useAlertStore(s => s.alerts)
  const incidents = useAlertStore(s => s.incidents)
  const updateAlertStatus = useAlertStore(s => s.updateAlertStatus)

  const [searchQuery, setSearchQuery] = useState('')
  const [selectedSev, setSelectedSev] = useState('all')
  const [selectedLayer, setSelectedLayer] = useState('all')
  const [selectedStatus, setSelectedStatus] = useState('all')
  const [selectedThreatType, setSelectedThreatType] = useState('all')
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [remediating, setRemediating] = useState(false)
  const [actionFeedback, setActionFeedback] = useState(null)

  // Extract available threat types dynamically from alerts
  const availableThreatTypes = useMemo(() => {
    const types = new Set(alerts.map(a => a.threat_type).filter(Boolean))
    return ['all', ...Array.from(types)]
  }, [alerts])

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      // Query search
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim()
        const matchSrc = (a.src_entity || '').toLowerCase().includes(q)
        const matchDst = (a.dst_entity || '').toLowerCase().includes(q)
        const matchType = (a.threat_type || '').toLowerCase().includes(q)
        const matchId = (a.event_id || a.alert_id || '').toLowerCase().includes(q)
        const matchMitre = (a.mitre_technique_name || a.mitre_technique_id || '').toLowerCase().includes(q)
        if (!matchSrc && !matchDst && !matchType && !matchId && !matchMitre) {
          return false
        }
      }

      // Severity filter
      if (selectedSev !== 'all' && (a.severity || 'low').toLowerCase() !== selectedSev.toLowerCase()) {
        return false
      }

      // Layer filter
      if (selectedLayer !== 'all' && (a.layer || '').toLowerCase() !== selectedLayer.toLowerCase()) {
        return false
      }

      // Status filter
      if (selectedStatus !== 'all' && (a.status || 'open').toLowerCase() !== selectedStatus.toLowerCase()) {
        return false
      }

      // Threat type filter
      if (selectedThreatType !== 'all' && a.threat_type !== selectedThreatType) {
        return false
      }

      return true
    })
  }, [alerts, searchQuery, selectedSev, selectedLayer, selectedStatus, selectedThreatType])

  // Active selected alert (default to first matching)
  const activeAlert = useMemo(() => {
    if (!filteredAlerts.length) return null
    if (selectedAlertId) {
      const found = filteredAlerts.find(a => (a.alert_id || a.event_id) === selectedAlertId)
      if (found) return found
    }
    return filteredAlerts[0]
  }, [filteredAlerts, selectedAlertId])

  // Associate incident if available
  const associatedIncident = useMemo(() => {
    if (!activeAlert) return null
    const targetIncId = activeAlert.incident_id
    if (targetIncId) {
      return incidents.find(i => i.incident_id === targetIncId) || null
    }
    return null
  }, [activeAlert, incidents])

  const handleTriageAction = async (newStatus) => {
    if (!activeAlert) return
    const eventId = activeAlert.event_id || activeAlert.alert_id
    updateAlertStatus(eventId, newStatus)
    activeAlert.status = newStatus

    // If isolating, call remediation endpoint if incident exists
    if (newStatus === 'isolated' && activeAlert.incident_id) {
      setRemediating(true)
      try {
        const res = await fetch(getApiUrl(`/api/incident/${activeAlert.incident_id}/remediate`), {
          method: 'POST'
        })
        if (res.ok) {
          setActionFeedback(`Remediation executed: Entity ${activeAlert.src_entity} isolated at firewall.`)
        }
      } catch (err) {
        console.error('[AEGIS] Remediation failed:', err)
      } finally {
        setRemediating(false)
        setTimeout(() => setActionFeedback(null), 5000)
      }
    } else {
      setActionFeedback(`Alert status updated to ${newStatus}.`)
      setTimeout(() => setActionFeedback(null), 4000)
    }
  }

  return (
    <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="glass-panel" style={{ padding: '24px 32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
              <div style={{
                width: 38, height: 38, borderRadius: 12,
                background: 'rgba(217, 119, 6, 0.1)', color: 'var(--accent-high)',
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }}>
                <Crosshair size={22} />
              </div>
              <h1 style={{ fontSize: 22, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
                Threat Hunting & Telemetry Investigation
              </h1>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', maxWidth: 840, lineHeight: 1.5 }}>
              Query and triage multi-stage network attacks, statistical anomalies, and MITRE ATT&amp;CK kill chain progression.
              Inspect raw model features, outlier distributions, and calibrated probabilities in real time.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <div style={{
              padding: '10px 18px', borderRadius: 14, background: 'var(--bg-page)',
              border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: 10
            }}>
              <ShieldAlert size={16} color="var(--accent-critical)" />
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Total Alerts</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>{alerts.length}</div>
              </div>
            </div>

            <div style={{
              padding: '10px 18px', borderRadius: 14, background: 'var(--bg-page)',
              border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: 10
            }}>
              <Filter size={16} color="var(--accent-brand)" />
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Filtered</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>{filteredAlerts.length}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Filter Bar ─────────────────────────────────────────────────── */}
      <div className="glass-panel" style={{ padding: '16px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Search box */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10, background: 'var(--bg-page)',
            border: '1px solid var(--border-light)', borderRadius: 12, padding: '8px 14px', flex: '1 1 280px'
          }}>
            <Search size={16} color="var(--text-tertiary)" />
            <input
              type="text"
              id="threat-search-input"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search by IP, event ID, technique, or threat..."
              style={{
                border: 'none', background: 'transparent', outline: 'none',
                width: '100%', fontSize: 13, color: 'var(--text-primary)',
                fontFamily: 'inherit'
              }}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-tertiary)', fontSize: 12 }}
              >
                ✕
              </button>
            )}
          </div>

          {/* Severity filter pills */}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginRight: 4 }}>Severity:</span>
            {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSev(sev)}
                style={{
                  padding: '5px 12px', borderRadius: 16, fontSize: 11, fontWeight: 700,
                  border: `1px solid ${selectedSev === sev ? 'var(--text-primary)' : 'var(--border-light)'}`,
                  background: selectedSev === sev ? 'var(--text-primary)' : 'transparent',
                  color: selectedSev === sev ? '#fff' : 'var(--text-secondary)',
                  cursor: 'pointer', textTransform: 'capitalize', transition: 'all 0.15s'
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Layer filter pills */}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginRight: 4 }}>Layer:</span>
            {['all', 'network', 'endpoint', 'application'].map(layer => (
              <button
                key={layer}
                onClick={() => setSelectedLayer(layer)}
                style={{
                  padding: '5px 12px', borderRadius: 16, fontSize: 11, fontWeight: 700,
                  border: `1px solid ${selectedLayer === layer ? 'var(--accent-brand)' : 'var(--border-light)'}`,
                  background: selectedLayer === layer ? 'rgba(79, 70, 229, 0.1)' : 'transparent',
                  color: selectedLayer === layer ? 'var(--accent-brand)' : 'var(--text-secondary)',
                  cursor: 'pointer', textTransform: 'capitalize', transition: 'all 0.15s'
                }}
              >
                {layer}
              </button>
            ))}
          </div>
        </div>

        {/* Secondary filters row */}
        <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap', borderTop: '1px solid var(--border-light)', paddingTop: 12 }}>
          {/* Status filter */}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginRight: 4 }}>Status:</span>
            {['all', 'open', 'investigating', 'resolved', 'isolated'].map(st => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                style={{
                  padding: '4px 10px', borderRadius: 14, fontSize: 11, fontWeight: 600,
                  border: `1px solid ${selectedStatus === st ? 'var(--accent-info)' : 'var(--border-light)'}`,
                  background: selectedStatus === st ? 'rgba(2, 132, 199, 0.1)' : 'transparent',
                  color: selectedStatus === st ? 'var(--accent-info)' : 'var(--text-secondary)',
                  cursor: 'pointer', textTransform: 'capitalize'
                }}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Threat Type select */}
          {availableThreatTypes.length > 2 && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginLeft: 'auto' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Threat Type:</span>
              <select
                value={selectedThreatType}
                onChange={e => setSelectedThreatType(e.target.value)}
                style={{
                  padding: '5px 12px', borderRadius: 10, fontSize: 12,
                  background: 'var(--bg-page)', border: '1px solid var(--border-light)',
                  color: 'var(--text-primary)', outline: 'none', cursor: 'pointer'
                }}
              >
                {availableThreatTypes.map(t => (
                  <option key={t} value={t}>{t === 'all' ? 'All Types' : t.replace(/_/g, ' ').toUpperCase()}</option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* ── Action Feedback Toast ─────────────────────────────────────── */}
      {actionFeedback && (
        <div className="glass-panel animate-slide-up" style={{
          padding: '12px 20px', background: 'rgba(5, 150, 105, 0.08)',
          borderColor: 'rgba(5, 150, 105, 0.3)', color: 'var(--accent-success)',
          display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, fontWeight: 600
        }}>
          <CheckCircle2 size={18} />
          <span>{actionFeedback}</span>
        </div>
      )}

      {/* ── Main Two-Column Hunting Console ───────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '55fr 45fr', gap: 24, minHeight: 650 }}>
        {/* Left Column: Alerts Feed List */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-secondary)', letterSpacing: 0.5, textTransform: 'uppercase' }}>
              Observed Threat Stream ({filteredAlerts.length})
            </div>
            {filteredAlerts.length > 0 && (
              <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>Click alert to inspect dossier</span>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, overflowY: 'auto', maxHeight: 600, paddingRight: 4 }}>
            {filteredAlerts.length === 0 && (
              <div style={{
                textAlign: 'center', padding: '60px 20px', color: 'var(--text-tertiary)',
                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12
              }}>
                <Search size={36} strokeWidth={1.5} />
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)' }}>
                  {alerts.length === 0 ? 'No alerts captured yet' : 'No alerts match your filter criteria'}
                </div>
                <div style={{ fontSize: 12, maxWidth: 360 }}>
                  {alerts.length === 0
                    ? 'Start analysis using the button in the header to stream live events and evaluate ML threat classifiers.'
                    : 'Clear or reset your query and severity filters to inspect other telemetry records.'}
                </div>
              </div>
            )}

            {filteredAlerts.map(alert => {
              const alertKey = alert.alert_id || alert.event_id
              const isSelected = activeAlert && (activeAlert.alert_id || activeAlert.event_id) === alertKey
              const sev = alert.severity || 'low'
              const style = SEV_STYLE[sev] || SEV_STYLE.low
              const timeStr = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Recent'

              return (
                <div
                  key={alertKey}
                  onClick={() => setSelectedAlertId(alertKey)}
                  style={{
                    padding: '12px 16px', borderRadius: 14,
                    background: isSelected ? 'rgba(79, 70, 229, 0.06)' : 'var(--bg-page)',
                    border: `1px solid ${isSelected ? 'var(--accent-brand)' : 'var(--border-light)'}`,
                    cursor: 'pointer', transition: 'all 0.15s',
                    display: 'flex', flexDirection: 'column', gap: 8
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{
                        padding: '2px 8px', borderRadius: 12, fontSize: 10, fontWeight: 800,
                        background: style.bg, color: style.color, border: `1px solid ${style.border}`,
                        textTransform: 'uppercase'
                      }}>
                        {sev}
                      </span>
                      <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                        {alert.threat_type ? alert.threat_type.replace(/_/g, ' ').toUpperCase() : 'ANOMALY'}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-tertiary)' }}>
                      <Clock size={12} />
                      <span>{timeStr}</span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
                      <span className="mono-font" style={{ fontWeight: 600 }}>{alert.src_entity || 'unknown'}</span>
                      <ArrowRight size={12} color="var(--text-tertiary)" />
                      <span className="mono-font" style={{ fontWeight: 600 }}>{alert.dst_entity || 'unknown'}</span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>Conf:</span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)' }}>
                        {((alert.calibrated_confidence ?? alert.confidence ?? 0.5) * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Column: Deep-Dive Telemetry Dossier */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: 20 }}>
          {!activeAlert ? (
            <div style={{
              textAlign: 'center', padding: '100px 20px', color: 'var(--text-tertiary)',
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12
            }}>
              <Shield size={40} strokeWidth={1.5} />
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)' }}>No alert selected</div>
              <div style={{ fontSize: 12 }}>Select any observed threat event on the left to inspect its ML telemetry.</div>
            </div>
          ) : (
            <>
              {/* Dossier Header */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                  <div>
                    <span style={{
                      fontSize: 10, fontWeight: 800, padding: '3px 8px', borderRadius: 8,
                      background: (SEV_STYLE[activeAlert.severity] || SEV_STYLE.low).bg,
                      color: (SEV_STYLE[activeAlert.severity] || SEV_STYLE.low).color,
                      textTransform: 'uppercase'
                    }}>
                      {activeAlert.severity || 'low'} Severity
                    </span>
                    <h2 style={{ fontSize: 18, fontWeight: 800, margin: '8px 0 4px', color: 'var(--text-primary)' }}>
                      {activeAlert.threat_type ? activeAlert.threat_type.replace(/_/g, ' ').toUpperCase() : 'STATISTICAL ANOMALY'}
                    </h2>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                      <span>Layer: <strong style={{ color: 'var(--text-primary)' }}>{activeAlert.layer || 'network'}</strong></span>
                      <span>Status: <strong style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{activeAlert.status || 'open'}</strong></span>
                      {activeAlert.incident_id && (
                        <span>Incident: <strong style={{ color: 'var(--accent-brand)' }}>{activeAlert.incident_id}</strong></span>
                      )}
                    </div>
                  </div>

                  {/* Triage Actions */}
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      onClick={() => handleTriageAction('investigating')}
                      style={{
                        padding: '6px 12px', borderRadius: 10, fontSize: 11, fontWeight: 700,
                        background: 'rgba(2, 132, 199, 0.1)', color: 'var(--accent-info)',
                        border: '1px solid rgba(2, 132, 199, 0.25)', cursor: 'pointer',
                        display: 'flex', alignItems: 'center', gap: 4
                      }}
                    >
                      <Eye size={12} /> Investigate
                    </button>
                    <button
                      onClick={() => handleTriageAction('resolved')}
                      style={{
                        padding: '6px 12px', borderRadius: 10, fontSize: 11, fontWeight: 700,
                        background: 'rgba(5, 150, 105, 0.1)', color: 'var(--accent-success)',
                        border: '1px solid rgba(5, 150, 105, 0.25)', cursor: 'pointer',
                        display: 'flex', alignItems: 'center', gap: 4
                      }}
                    >
                      <CheckCircle2 size={12} /> Resolve
                    </button>
                    <button
                      onClick={() => handleTriageAction('isolated')}
                      disabled={remediating}
                      style={{
                        padding: '6px 12px', borderRadius: 10, fontSize: 11, fontWeight: 700,
                        background: 'rgba(220, 38, 38, 0.1)', color: 'var(--accent-critical)',
                        border: '1px solid rgba(220, 38, 38, 0.25)', cursor: remediating ? 'wait' : 'pointer',
                        display: 'flex', alignItems: 'center', gap: 4
                      }}
                    >
                      <Ban size={12} /> Isolate IP
                    </button>
                  </div>
                </div>
              </div>

              {/* Entity Flow Card */}
              <div style={{
                padding: '14px 18px', borderRadius: 14, background: 'var(--bg-page)',
                border: '1px solid var(--border-light)', display: 'grid', gridTemplateColumns: '1fr auto 1fr',
                alignItems: 'center', gap: 12
              }}>
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Source Entity</div>
                  <div className="mono-font" style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                    {activeAlert.src_entity || 'unknown'}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <ArrowRight size={16} color="var(--accent-brand)" />
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Destination Target</div>
                  <div className="mono-font" style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                    {activeAlert.dst_entity || 'unknown'}
                  </div>
                </div>
              </div>

              {/* Model Confidence & Scoring Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                <div style={{ padding: '10px 14px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
                  <div style={{ fontSize: 9, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Confidence</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--accent-brand)', marginTop: 2 }}>
                    {((activeAlert.calibrated_confidence ?? activeAlert.confidence ?? 0.5) * 100).toFixed(1)}%
                  </div>
                </div>

                <div style={{ padding: '10px 14px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
                  <div style={{ fontSize: 9, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Outlier Score</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--accent-critical)', marginTop: 2 }}>
                    {(activeAlert.anomaly_score ?? 0).toFixed(3)}
                  </div>
                </div>

                <div style={{ padding: '10px 14px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
                  <div style={{ fontSize: 9, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Base Deviation</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--accent-high)', marginTop: 2 }}>
                    {(activeAlert.baseline_deviation ?? 0).toFixed(3)}
                  </div>
                </div>

                <div style={{ padding: '10px 14px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
                  <div style={{ fontSize: 9, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Calibrated</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: activeAlert.is_calibrated ? 'var(--accent-success)' : 'var(--text-secondary)', marginTop: 2 }}>
                    {activeAlert.is_calibrated ? 'Yes' : 'No'}
                  </div>
                </div>
              </div>

              {/* Local Explanations & Feature Deviations */}
              {activeAlert.feature_importance && Object.keys(activeAlert.feature_importance).length > 0 && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 800, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 8 }}>
                    Primary Deviating Features (SHAP / Tree Deviation)
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {Object.entries(activeAlert.feature_importance).slice(0, 5).map(([feat, imp]) => {
                      const pct = Math.min(Math.abs(Number(imp) || 0) * 100, 100)
                      return (
                        <div key={feat} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                            <span className="mono-font" style={{ color: 'var(--text-primary)' }}>{feat}</span>
                            <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{Number(imp).toFixed(3)}</span>
                          </div>
                          <div style={{ height: 4, borderRadius: 2, background: 'var(--bg-page)', overflow: 'hidden' }}>
                            <div style={{ width: `${pct}%`, height: '100%', background: 'var(--accent-brand)', borderRadius: 2 }} />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Kill Chain Stage Tracking */}
              <div>
                <KillChainViewer
                  currentStage={activeAlert.current_kill_chain_stage || 'c2'}
                  predictedNext={activeAlert.predicted_next_stage || 'lateral'}
                />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
