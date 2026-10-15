import React, { memo, useState } from 'react'
import { buildEvidenceChain } from '../../utils/evidence.js'
import { CheckCircle2, AlertTriangle, AlertCircle, Info, ChevronDown, ChevronUp } from 'lucide-react'

/**
 * EvidenceTrail: Visual SVG Filament + Semantic Accessible List
 * 
 * Demonstrates the full provenance chain leading to a detection:
 * Supporting Events → Feature Deviations → Model Score & Calibration → Alert → Incident
 * 
 * Enforces strict honesty:
 * - Links with absent data render as a dashed, labeled gap ("not recorded").
 * - Model-level importance is explicitly labeled "Model-level feature importance (not specific to this alert)".
 * - Calibrated score is labeled calibrated only when is_calibrated is true.
 * - Text is 100% sharp; SVG is purely decorative (aria-hidden).
 */
export default memo(function EvidenceTrail({ alert, incident }) {
  const chain = buildEvidenceChain(alert, incident)
  const [expandedIndex, setExpandedIndex] = useState(null)

  const toggleExpand = (idx) => {
    setExpandedIndex(prev => prev === idx ? null : idx)
  }

  return (
    <div
      className="glass-panel"
      style={{
        padding: '16px 20px',
        margin: '12px 0',
        borderRadius: 14,
        background: 'var(--surface-1)',
        border: '1px solid var(--border-hairline)',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: 'var(--accent-cyan)',
              boxShadow: '0 0 8px var(--accent-cyan)',
            }}
            aria-hidden="true"
          />
          <div
            style={{ margin: 0, fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: 0.8 }}
          >
            Evidence Provenance Trail
          </div>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-tertiary)', display: 'inline-flex', gap: 6, alignItems: 'center' }}>
          <span>{chain.filter(c => c.status === 'present').length}/{chain.length} links recorded</span>
          <span style={{ color: 'var(--border-subtle)' }}>•</span>
          <span style={{ color: 'var(--accent-cyan)' }}>{chain.filter(c => c.status === 'present').length} observed</span>
          {chain.filter(c => c.status === 'partial').length > 0 && (
            <>
              <span style={{ color: 'var(--border-subtle)' }}>•</span>
              <span style={{ color: 'var(--severity-high-fg)' }}>{chain.filter(c => c.status === 'partial').length} inferred</span>
            </>
          )}
          {chain.filter(c => c.status === 'absent').length > 0 && (
            <>
              <span style={{ color: 'var(--border-subtle)' }}>•</span>
              <span style={{ color: 'var(--text-muted)' }}>{chain.filter(c => c.status === 'absent').length} missing</span>
            </>
          )}
        </span>
      </div>

      {/* ── 1. Visual SVG Filament (Decorative Overlay) ── */}
      <div
        aria-hidden="true"
        style={{
          position: 'relative',
          width: '100%',
          height: 60,
          marginBottom: 10,
          overflow: 'hidden',
        }}
      >
        <svg
          width="100%"
          height="60"
          viewBox="0 0 500 60"
          preserveAspectRatio="none"
          style={{ overflow: 'visible' }}
        >
          <defs>
            <filter id="cyan-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Draw connecting filament segments */}
          {chain.map((link, idx) => {
            if (idx === chain.length - 1) return null
            const nextLink = chain[idx + 1]
            const x1 = 50 + idx * 100
            const x2 = 50 + (idx + 1) * 100
            const isBroken = link.status === 'absent' || nextLink.status === 'absent'
            const isPartial = link.status === 'partial' || nextLink.status === 'partial'

            return (
              <g key={`filament_${idx}`}>
                <line
                  x1={x1}
                  y1={30}
                  x2={x2}
                  y2={30}
                  stroke={
                    isBroken
                      ? 'var(--border-subtle)'
                      : isPartial
                        ? 'var(--severity-high-fg)'
                        : 'var(--accent-cyan)'
                  }
                  strokeWidth={isBroken ? 1.5 : 2.5}
                  strokeDasharray={isBroken ? '4 4' : undefined}
                  filter={!isBroken && !isPartial ? 'url(#cyan-glow)' : undefined}
                  opacity={isBroken ? 0.45 : 0.85}
                />
                {isBroken && (
                  <text
                    x={(x1 + x2) / 2}
                    y={22}
                    textAnchor="middle"
                    fill="var(--text-muted)"
                    fontSize="9"
                    fontFamily="var(--font-mono)"
                    fontWeight="600"
                  >
                    not recorded
                  </text>
                )}
              </g>
            )
          })}

          {/* Draw Nodes along filament */}
          {chain.map((link, idx) => {
            const cx = 50 + idx * 100
            const cy = 30
            const isPresent = link.status === 'present'
            const isPartial = link.status === 'partial'

            return (
              <g key={`node_${idx}`}>
                {/* Outer halo */}
                <circle
                  cx={cx}
                  cy={cy}
                  r={isPresent ? 12 : 9}
                  fill={
                    isPresent
                      ? 'rgba(0, 240, 255, 0.15)'
                      : isPartial
                        ? 'rgba(251, 146, 60, 0.15)'
                        : 'rgba(148, 163, 184, 0.08)'
                  }
                  stroke={
                    isPresent
                      ? 'var(--accent-cyan)'
                      : isPartial
                        ? 'var(--severity-high-fg)'
                        : 'var(--border-subtle)'
                  }
                  strokeWidth={isPresent ? 2 : 1.2}
                />
                {/* Core dot */}
                <circle
                  cx={cx}
                  cy={cy}
                  r={isPresent ? 4 : 2.5}
                  fill={
                    isPresent
                      ? 'var(--accent-cyan)'
                      : isPartial
                        ? 'var(--severity-high-fg)'
                        : 'var(--text-muted)'
                  }
                />
              </g>
            )
          })}
        </svg>
      </div>

      {/* ── 2. Accessible Ordered List (Primary Screen-Reader & Operator View) ── */}
      <ol
        role="list"
        aria-label="Ordered Evidence Provenance Steps"
        style={{
          listStyle: 'none',
          padding: 0,
          margin: 0,
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        {chain.map((link, idx) => {
          const isExpanded = expandedIndex === idx
          const isPresent = link.status === 'present'
          const isPartial = link.status === 'partial'

          return (
            <li
              key={link.id}
              style={{
                borderRadius: 8,
                background: isExpanded ? 'var(--surface-2)' : 'transparent',
                border: isExpanded ? '1px solid var(--border-subtle)' : '1px solid transparent',
                transition: 'background var(--duration-quick) ease',
              }}
            >
              <button
                type="button"
                onClick={() => toggleExpand(idx)}
                aria-expanded={isExpanded}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  textAlign: 'left',
                  borderRadius: 8,
                  outline: 'none',
                }}
                onFocus={(e) => { e.currentTarget.style.boxShadow = '0 0 0 2px var(--border-focus)' }}
                onBlur={(e) => { e.currentTarget.style.boxShadow = 'none' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {/* Status Indicator Icon */}
                  {isPresent ? (
                    <CheckCircle2 size={16} color="var(--accent-cyan)" aria-hidden="true" />
                  ) : isPartial ? (
                    <AlertTriangle size={16} color="var(--severity-high-fg)" aria-hidden="true" />
                  ) : (
                    <AlertCircle size={16} color="var(--text-muted)" aria-hidden="true" />
                  )}

                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: isPresent ? 'var(--text-primary)' : isPartial ? 'var(--severity-high-fg)' : 'var(--text-secondary)' }}>
                      {idx + 1}. {link.label}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 1 }}>
                      {link.sublabel}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      padding: '2px 8px',
                      borderRadius: 4,
                      background: isPresent
                        ? 'rgba(0, 240, 255, 0.1)'
                        : isPartial
                          ? 'rgba(251, 146, 60, 0.1)'
                          : 'rgba(148, 163, 184, 0.1)',
                      color: isPresent
                        ? 'var(--accent-cyan)'
                        : isPartial
                          ? 'var(--severity-high-fg)'
                          : 'var(--text-secondary)',
                      border: `1px solid ${isPresent ? 'rgba(0, 240, 255, 0.25)' : isPartial ? 'rgba(251, 146, 60, 0.25)' : 'var(--border-subtle)'}`,
                    }}
                  >
                    {isPresent ? 'Observed Telemetry' : isPartial ? 'Inferred Hypothesis' : 'Missing Evidence'}
                  </span>
                  {isExpanded ? <ChevronUp size={14} color="var(--text-tertiary)" /> : <ChevronDown size={14} color="var(--text-tertiary)" />}
                </div>
              </button>

              {/* Expanded Provenance Dossier */}
              {isExpanded && (
                <div
                  style={{
                    padding: '8px 12px 12px 38px',
                    fontSize: 11,
                    color: 'var(--text-secondary)',
                    borderTop: '1px solid var(--border-hairline)',
                  }}
                >
                  <div style={{ marginBottom: 4 }}>
                    <strong style={{ color: 'var(--text-tertiary)' }}>Source Field: </strong>
                    <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                      {link.source}
                    </code>
                  </div>
                  {link.details?.disclaimer && (
                    <div style={{ color: 'var(--severity-high-fg)', marginTop: 4, fontStyle: 'italic' }}>
                      ⚠ {link.details.disclaimer}
                    </div>
                  )}
                  {link.details?.features && (
                    <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 3 }}>
                      <strong style={{ color: 'var(--text-tertiary)' }}>Feature Contributions:</strong>
                      {Object.entries(link.details.features).slice(0, 4).map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                          <span>{k}</span>
                          <span style={{ color: 'var(--text-primary)' }}>{(Number(v) * 100).toFixed(1)}%</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </li>
          )
        })}
      </ol>
    </div>
  )
})
