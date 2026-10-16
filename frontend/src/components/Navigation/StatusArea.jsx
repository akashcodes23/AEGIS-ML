import React from 'react'
import { Activity, Sparkles, SlidersHorizontal, RefreshCw } from 'lucide-react'
import useReducedMotion, { setReducedVisualEffectsPreference } from '../../hooks/useReducedMotion'

/**
 * StatusArea
 * 
 * Strict Requirement:
 * Displays only real application telemetry:
 * - Real WebSocket connection state
 * - Real backend health endpoint response
 * - Real data mode (Synthetic demo vs Live stream)
 * - Visual effects user control toggle
 * 
 * Never fabricates reassuring defaults.
 */
export default function StatusArea({
  wsConnected,
  wsConnecting,
  onReconnect,
  backendStatus,
  isSynthetic,
  simulationRunning,
  onStartAnalysis,
  onStopAnalysis,
}) {
  const reducedVisualEffects = useReducedMotion()

  const handleToggleFX = () => {
    setReducedVisualEffectsPreference(!reducedVisualEffects)
  }

  // Real backend health color and label mapping
  const healthLabel = backendStatus === 'live' ? 'API: Live' : backendStatus === 'offline' ? 'API: Offline' : 'API: Unknown'
  const healthColor = backendStatus === 'live' ? 'var(--severity-success-fg)' : backendStatus === 'offline' ? 'var(--severity-critical-fg)' : 'var(--text-tertiary)'

  // Real WebSocket status
  const wsLabel = wsConnected ? 'WS: Stream Live' : wsConnecting ? 'WS: Connecting...' : 'WS: Offline'
  const wsColor = wsConnected ? 'var(--severity-success-fg)' : wsConnecting ? 'var(--severity-high-fg)' : 'var(--severity-critical-fg)'

  return (
    <div
      className="aegis-status-area"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        flexWrap: 'wrap',
      }}
    >
      {/* ── Real Status Indicators Group ─────────────────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '4px 12px',
          background: 'var(--surface-1)',
          border: '1px solid var(--border-hairline)',
          borderRadius: 9999,
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
        }}
      >
        {/* WebSocket Stream Indicator */}
        <button
          type="button"
          onClick={!wsConnected ? onReconnect : undefined}
          title={!wsConnected ? "Click to retry connecting to WebSocket stream" : "Live WebSocket connected"}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            background: 'transparent',
            border: 'none',
            color: wsColor,
            fontWeight: 600,
            cursor: !wsConnected ? 'pointer' : 'default',
            padding: 0,
            outline: 'none',
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: wsColor,
              boxShadow: wsConnected ? `0 0 8px ${wsColor}` : 'none',
            }}
            aria-hidden="true"
          />
          <span>{wsLabel}</span>
          {!wsConnected && <RefreshCw size={10} aria-hidden="true" />}
        </button>

        <span style={{ color: 'var(--border-subtle)' }} aria-hidden="true">|</span>

        {/* Backend Health Indicator */}
        <div
          title={`Backend Health Endpoint: ${backendStatus}`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            color: healthColor,
            fontWeight: 600,
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: healthColor,
            }}
            aria-hidden="true"
          />
          <span>{healthLabel}</span>
        </div>

        <span style={{ color: 'var(--border-subtle)' }} aria-hidden="true">|</span>

        {/* Real Data Mode Pill */}
        <div
          title={isSynthetic ? "Synthetic or simulated dataset in memory" : "Real live network telemetry"}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            color: isSynthetic ? '#c084fc' : 'var(--accent-cyan)',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.4px',
            fontSize: 10,
          }}
        >
          <span>{isSynthetic ? 'Synthetic' : 'Live Data'}</span>
        </div>
      </div>

      {/* ── User Visual Effects Toggle ──────────────────────── */}
      <button
        type="button"
        onClick={handleToggleFX}
        title={reducedVisualEffects ? "Visual effects are reduced. Click to enable 3D atmosphere." : "3D atmosphere is enabled. Click to reduce visual effects."}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '6px 12px',
          borderRadius: 8,
          background: reducedVisualEffects ? 'rgba(168, 85, 247, 0.12)' : 'var(--surface-1)',
          border: `1px solid ${reducedVisualEffects ? 'rgba(168, 85, 247, 0.3)' : 'var(--border-hairline)'}`,
          color: reducedVisualEffects ? '#c084fc' : 'var(--text-secondary)',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          cursor: 'pointer',
          transition: 'all var(--duration-quick) ease',
        }}
      >
        <Sparkles size={12} aria-hidden="true" />
        <span>{reducedVisualEffects ? 'FX: Reduced' : 'FX: Spatial 3D'}</span>
      </button>

      {/* ── Analysis Controls ────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button
          type="button"
          onClick={onStartAnalysis}
          disabled={simulationRunning}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            padding: '7px 16px',
            borderRadius: 8,
            fontSize: 12,
            fontWeight: 700,
            cursor: simulationRunning ? 'not-allowed' : 'pointer',
            transition: 'all var(--duration-quick) var(--ease-standard)',
            background: simulationRunning ? 'var(--surface-2)' : 'var(--accent-cyan)',
            color: simulationRunning ? 'var(--text-tertiary)' : '#07090e',
            border: `1px solid ${simulationRunning ? 'var(--border-hairline)' : 'var(--accent-cyan)'}`,
            boxShadow: simulationRunning ? 'none' : 'var(--glow-primary)',
          }}
        >
          <Activity size={14} aria-hidden="true" />
          <span>{simulationRunning ? 'Analyzing...' : 'Start Analysis'}</span>
        </button>

        <button
          type="button"
          onClick={onStopAnalysis}
          disabled={!simulationRunning}
          style={{
            padding: '7px 14px',
            borderRadius: 8,
            fontSize: 12,
            fontWeight: 600,
            cursor: !simulationRunning ? 'not-allowed' : 'pointer',
            transition: 'all var(--duration-quick) var(--ease-standard)',
            background: 'transparent',
            color: !simulationRunning ? 'var(--text-tertiary)' : 'var(--text-primary)',
            border: `1px solid ${!simulationRunning ? 'var(--border-hairline)' : 'var(--border-subtle)'}`,
          }}
        >
          Stop
        </button>
      </div>
    </div>
  )
}
