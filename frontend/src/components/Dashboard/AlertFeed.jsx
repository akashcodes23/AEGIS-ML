import { memo, useState } from 'react'
import {
  BellRing,
  ShieldAlert,
  ArrowRight,
  Shield,
  Zap,
  Database,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Info,
} from 'lucide-react'
import useAlertStore from '../../store/alertStore'
import useReducedMotion from '../../hooks/useReducedMotion'
import { SEVERITY_TOKENS, confidenceToFocus } from '../../utils/depth'

/* ── Severity Badge ───────────────────────────────────────────────────────── */
function SeverityBadge({ severity }) {
  const token = SEVERITY_TOKENS[severity] || SEVERITY_TOKENS.low
  return (
    <div
      style={{
        background: token.bg,
        color: token.fg,
        border: `1px solid ${token.border}`,
        borderRadius: 14,
        padding: '3px 10px',
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: 0.6,
        textTransform: 'uppercase',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
      }}
    >
      <div
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: token.fg,
          flexShrink: 0,
        }}
        aria-hidden="true"
      />
      <span>{token.label}</span>
    </div>
  )
}

/* ── Alert Row Component ──────────────────────────────────────────────────── */
function AlertRow({ alert, index }) {
  const selectIncident = useAlertStore(s => s.selectIncident)
  const reducedMotion = useReducedMotion()
  const rawTs = alert.timestamp || alert.created_at
  const ts = rawTs
    ? new Date(rawTs).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '--:--:--'

  // Staggered animation delay
  const delay = Math.min(index * 40, 400)

  // Calibrated vs Uncalibrated vs Missing confidence focus calculation
  const hasCalibrated = Boolean(alert.is_calibrated && alert.calibrated_confidence != null)
  const rawScore = alert.calibrated_confidence != null
    ? alert.calibrated_confidence
    : alert.classifier_probability != null
      ? alert.classifier_probability
      : alert.confidence

  const focusInfo = confidenceToFocus({
    confidence: rawScore,
    isCalibrated: hasCalibrated,
  })

  const sevToken = SEVERITY_TOKENS[alert.severity] || SEVERITY_TOKENS.low

  return (
    <div
      className="glass-panel animate-slide-up"
      onClick={() => (alert.incident_id || alert.alert_id || alert.event_id) && selectIncident(alert.incident_id || alert.alert_id || alert.event_id)}
      style={{
        padding: '16px 20px',
        cursor: (alert.incident_id || alert.alert_id || alert.event_id) ? 'pointer' : 'default',
        marginBottom: 12,
        animationDelay: `${delay}ms`,
        display: 'grid',
        gridTemplateColumns: 'auto 1fr',
        gap: 16,
        alignItems: 'start',
        position: 'relative',
        background: 'var(--surface-1)',
        // Apply confidence focus ONLY to non-text decoration (border and glow)
        borderColor: `rgba(255, 255, 255, ${focusInfo.decorationStyle.borderOpacity})`,
        boxShadow: reducedMotion ? 'var(--shadow-elevation-1)' : focusInfo.decorationStyle.glowBoxShadow,
        transition: reducedMotion ? 'none' : 'box-shadow var(--duration-smooth) ease, border-color var(--duration-smooth) ease',
      }}
    >
      {/* Severity Icon with non-text focus halo */}
      <div style={{ position: 'relative' }}>
        {/* Decorative confidence focus halo ring behind icon (never blurs text/icon itself) */}
        {!reducedMotion && focusInfo.isCalibrated && (
          <div
            aria-hidden="true"
            style={{
              position: 'absolute',
              inset: -3,
              borderRadius: 14,
              background: sevToken.fg,
              filter: `blur(${focusInfo.decorationStyle.haloBlur}px)`,
              opacity: focusInfo.decorationStyle.haloOpacity,
              pointerEvents: 'none',
            }}
          />
        )}
        <div
          style={{
            position: 'relative',
            marginTop: 2,
            width: 34,
            height: 34,
            borderRadius: 10,
            background: sevToken.bg,
            border: `1px solid ${sevToken.border}`,
            color: sevToken.fg,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          {alert.severity === 'critical' ? <ShieldAlert size={16} /> : <Zap size={16} />}
        </div>
      </div>

      {/* Content Body: All text is 100% crisp without blur */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <SeverityBadge severity={alert.severity || 'low'} />
          <div className="tabular-nums" style={{ fontSize: 11, color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
            {ts}
          </div>
        </div>

        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, letterSpacing: '-0.2px' }}>
          {alert.threat_type?.replace(/_/g, ' ').toUpperCase() || 'ANOMALY DETECTED'}
        </div>

        {/* Entity path */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          background: 'var(--surface-2)',
          padding: '8px 12px',
          borderRadius: 8,
          border: '1px solid var(--border-hairline)',
        }}>
          <span className="mono-font" style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600 }}>
            {alert.src_entity || 'Unknown Source'}
          </span>
          <ArrowRight size={14} color="var(--text-tertiary)" />
          <span className="mono-font" style={{ fontSize: 11, color: 'var(--text-primary)', fontWeight: 600 }}>
            {alert.dst_entity || 'Unknown Destination'}
          </span>
        </div>

        {/* Footer: Metadata & Honest Confidence Text */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12, flexWrap: 'wrap', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-tertiary)' }}>
            {alert.source_file && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <Database size={12} />
                <span>{alert.source_file.replace('.pcap_ISCX.csv', '')}</span>
              </span>
            )}
            {alert.is_synthetic && (
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 6,
                background: 'rgba(168, 85, 247, 0.12)', color: '#c084fc',
                border: '1px solid rgba(168, 85, 247, 0.3)',
                textTransform: 'uppercase', letterSpacing: 0.5
              }}>
                Synthetic
              </span>
            )}
            {hasCalibrated && (
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 6,
                background: 'rgba(52, 211, 153, 0.12)', color: 'var(--severity-success-fg)',
                border: '1px solid rgba(52, 211, 153, 0.3)',
                textTransform: 'uppercase', letterSpacing: 0.5
              }}>
                Calibrated
              </span>
            )}
            {!hasCalibrated && rawScore != null && (
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 6,
                background: 'rgba(148, 163, 184, 0.12)', color: 'var(--text-secondary)',
                border: '1px solid var(--border-subtle)',
                textTransform: 'uppercase', letterSpacing: 0.5
              }}>
                Uncalibrated
              </span>
            )}
          </div>

          {/* Truthful Confidence Metric Display */}
          <div style={{
            fontSize: 11,
            fontWeight: 700,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 5,
            fontFamily: 'var(--font-mono)',
            color: hasCalibrated ? 'var(--accent-cyan)' : 'var(--text-secondary)'
          }}>
            <Shield size={12} aria-hidden="true" />
            {hasCalibrated ? (
              <span title="Isotonically calibrated posterior probability (synthetic benchmark evaluated; not real-world ground truth)">
                {Math.round(alert.calibrated_confidence * 100)}% Calibrated Conf.
              </span>
            ) : rawScore != null ? (
              <span title="Raw model classification score (uncalibrated probability)">
                {Math.round(rawScore * 100)}% Uncalibrated Score
              </span>
            ) : (
              <span style={{ color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
                No confidence reported
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

const MemoizedAlertRow = memo(AlertRow, (prev, next) => prev.alert.event_id === next.alert.event_id)

/* ── Main AlertFeed Component ─────────────────────────────────────────────── */
export default function AlertFeed() {
  const alerts = useAlertStore(s => s.alerts)
  const clearAlerts = useAlertStore(s => s.clearAlerts)
  const [page, setPage] = useState(1)

  const itemsPerPage = 8
  const totalPages = Math.max(1, Math.ceil(alerts.length / itemsPerPage))

  if (page > totalPages) setPage(totalPages)

  const visibleAlerts = alerts.slice().reverse().slice((page - 1) * itemsPerPage, page * itemsPerPage)

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{
        padding: '18px 24px',
        borderBottom: '1px solid var(--border-hairline)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'var(--surface-1)',
        flexWrap: 'wrap',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: 'rgba(0, 240, 255, 0.1)', color: 'var(--accent-cyan)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <BellRing size={18} strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>
              Threat Log
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              Real-time telemetry stream
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Pagination Controls */}
          {alerts.length > 0 && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--surface-2)', padding: '3px 8px', borderRadius: 20,
              border: '1px solid var(--border-hairline)'
            }}>
              <button
                type="button"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                aria-label="Previous alerts page"
                style={{
                  background: 'none', border: 'none',
                  cursor: page === 1 ? 'default' : 'pointer',
                  opacity: page === 1 ? 0.3 : 1,
                  display: 'flex', alignItems: 'center', padding: 2,
                  color: 'var(--text-primary)',
                }}
              >
                <ChevronLeft size={16} />
              </button>
              <span className="tabular-nums" style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)' }}>
                {page} / {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                aria-label="Next alerts page"
                style={{
                  background: 'none', border: 'none',
                  cursor: page === totalPages ? 'default' : 'pointer',
                  opacity: page === totalPages ? 0.3 : 1,
                  display: 'flex', alignItems: 'center', padding: 2,
                  color: 'var(--text-primary)',
                }}
              >
                <ChevronRight size={16} />
              </button>
            </div>
          )}

          <div className="tabular-nums" style={{
            fontSize: 11, fontWeight: 700, padding: '4px 12px',
            borderRadius: 20, background: 'var(--surface-2)', color: 'var(--text-secondary)',
            border: '1px solid var(--border-hairline)'
          }}>
            {alerts.length} Total
          </div>

          <button
            type="button"
            onClick={() => { clearAlerts(); setPage(1); }}
            style={{
              padding: '6px 14px', borderRadius: 20, fontSize: 11, fontWeight: 700,
              color: 'var(--severity-critical-fg)',
              background: 'var(--severity-critical-bg)',
              border: '1px solid var(--severity-critical-border)',
              cursor: 'pointer',
              transition: 'all var(--duration-quick) ease',
            }}
          >
            Clear Log
          </button>
        </div>
      </div>

      {/* Confidence Focus Explanatory Legend */}
      <div style={{
        padding: '7px 20px',
        background: 'var(--surface-1)',
        borderBottom: '1px solid var(--border-hairline)',
        fontSize: 10,
        color: 'var(--text-secondary)',
        display: 'flex',
        alignItems: 'center',
        gap: 6,
      }}>
        <Info size={12} color="var(--accent-cyan)" aria-hidden="true" />
        <span>
          <strong>Focus Encoding:</strong> Crisper card halo indicates higher calibrated confidence. Uncalibrated alerts receive neutral treatment. Visuals reflect model certainty, not ground-truth detection accuracy.
        </span>
      </div>

      {/* Feed List */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '16px 20px',
        background: 'var(--surface-0)',
      }}>
        {alerts.length === 0 ? (
          <div style={{
            height: '100%', display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 14
          }} className="animate-slide-up">
            <div style={{
              width: 56, height: 56, borderRadius: 18,
              background: 'var(--surface-1)', color: 'var(--text-tertiary)',
              border: '1px solid var(--border-hairline)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <ShieldCheck size={28} strokeWidth={1.5} />
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 3 }}>
                All Clear
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Waiting for incoming stream telemetry...
              </div>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {visibleAlerts.map((a, i) => (
              <MemoizedAlertRow key={a.event_id || a.alert_id || i} alert={a} index={i} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
