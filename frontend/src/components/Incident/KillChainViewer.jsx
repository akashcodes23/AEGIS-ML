import { useState } from 'react'

/* ── Stage definitions ────────────────────────────────────────────────────── */
const STAGES = [
  { id: 'initial',   icon: '🔓', label: 'Initial Access' },
  { id: 'execution', icon: '⚙️', label: 'Execution' },
  { id: 'c2',        icon: '📡', label: 'C2' },
  { id: 'lateral',   icon: '↔️', label: 'Lateral Move' },
  { id: 'collect',   icon: '📦', label: 'Collection' },
  { id: 'exfil',     icon: '🚨', label: 'Exfiltration' },
]

const PREEMPTIVE = {
  initial:   ['Enforce MFA on all remote access.', 'Block known phishing domains at DNS.'],
  execution: ['Restrict macro execution in Office suite.', 'Enable PowerShell script block logging.'],
  c2:        ['Block known C2 IP ranges at perimeter.', 'Monitor unusual outbound HTTPS traffic.'],
  lateral:   ['Block SMB ports (445) between workstations.', 'Monitor PsExec and WMI remote execution.'],
  collect:   ['Alert on large archive creation (.zip/.rar).', 'Monitor access to sensitive file shares.'],
  exfil:     ['Block large outbound transfers > 50 MB.', 'Alert on unusual cloud storage uploads.'],
}

/* ── Stage status helpers ─────────────────────────────────────────────────── */
function resolveStatuses(stages, currentStage, predictedNext) {
  const currentIdx  = STAGES.findIndex(s => s.id === currentStage)
  const predictedIdx = STAGES.findIndex(s => s.id === predictedNext)

  return STAGES.map((s, i) => {
    if (i < currentIdx)  return 'passed'
    if (i === currentIdx) return 'detected'
    if (i === predictedIdx) return 'predicted'
    return 'future'
  })
}

/* ── Colors & styles per status ──────────────────────────────────────────── */
const STATUS = {
  detected:  { bg: '#10b981', border: '#059669', text: '#fff', shadow: 'rgba(16,185,129,0.4)' },
  predicted: { bg: '#f97316', border: '#ea580c', text: '#fff', shadow: 'rgba(249,115,22,0.4)' },
  passed:    { bg: '#94a3b8', border: '#64748b', text: '#fff', shadow: 'none' },
  future:    { bg: '#f0f6ff', border: 'rgba(96,165,250,0.3)', text: '#a0bdd4', shadow: 'none' },
}

/* ── Connecting line ──────────────────────────────────────────────────────── */
function Connector({ leftStatus, rightStatus }) {
  const isGreen  = leftStatus === 'passed' || leftStatus === 'detected'
  const isOrange = leftStatus === 'detected' && rightStatus === 'predicted'

  let style = {
    height: 3, flex: 1, alignSelf: 'center', marginBottom: 24,
    borderRadius: 4,
  }

  if (isOrange) {
    style = {
      ...style,
      background: 'repeating-linear-gradient(90deg, #f97316 0 8px, transparent 8px 16px)',
      animation: 'kc-dash 1s linear infinite',
    }
  } else if (isGreen) {
    style = { ...style, background: '#10b981' }
  } else {
    style = { ...style, background: 'rgba(59,130,246,0.1)' }
  }

  return <div style={style} />
}

/* ── Stage node ───────────────────────────────────────────────────────────── */
function StageNode({ stage, status, showTooltip, onHover }) {
  const s = STATUS[status]
  const isPredicted = status === 'predicted'
  const isDetected  = status === 'detected'

  return (
    <div
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, position: 'relative', cursor: 'default' }}
    >
      {/* Circle */}
      <div style={{
        width: 48, height: 48, borderRadius: '50%',
        background: s.bg,
        border: `2.5px solid ${s.border}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 18, position: 'relative',
        boxShadow: s.shadow !== 'none' ? `0 0 16px ${s.shadow}` : 'none',
        animation: isPredicted ? 'kc-pulse 1.5s ease-in-out infinite' : 'none',
        transition: 'box-shadow 0.2s',
      }}>
        {stage.icon}

        {/* Checkmark badge for detected */}
        {isDetected && (
          <span style={{
            position: 'absolute', bottom: -4, right: -4,
            width: 18, height: 18, borderRadius: '50%',
            background: '#059669', border: '2px solid #fff',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 9, color: '#fff', fontWeight: 900,
          }}>✓</span>
        )}

        {/* Warning badge for predicted */}
        {isPredicted && (
          <span style={{
            position: 'absolute', bottom: -4, right: -4,
            width: 18, height: 18, borderRadius: '50%',
            background: '#ea580c', border: '2px solid #fff',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 9, color: '#fff',
          }}>⚠</span>
        )}
      </div>

      {/* Label */}
      <div style={{ textAlign: 'center' }}>
        <div style={{
          fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-ui)',
          color: status === 'future' ? 'var(--text-tertiary)' : 'var(--text-primary)',
          whiteSpace: 'nowrap',
        }}>
          {stage.label}
        </div>
        <div style={{
          fontSize: 9, letterSpacing: 1, textTransform: 'uppercase',
          color: status === 'future' ? 'var(--text-secondary)' : s.border, fontWeight: 600, marginTop: 2,
        }}>
          {status}
        </div>
      </div>

      {/* Predicted tooltip */}
      {isPredicted && showTooltip && (
        <div style={{
          position: 'absolute', top: '110%', left: '50%', transform: 'translateX(-50%)',
          zIndex: 100, minWidth: 240, marginTop: 8,
          background: 'rgba(255,255,255,0.97)',
          backdropFilter: 'blur(12px)',
          border: '1px solid rgba(249,115,22,0.3)',
          borderRadius: 12,
          padding: '12px 16px',
          boxShadow: '0 8px 28px rgba(249,115,22,0.12)',
          fontFamily: "'Sora', sans-serif",
          animation: 'fadeSlideIn 0.15s ease-out',
        }}>
          {/* Arrow */}
          <div style={{
            position: 'absolute', top: -6, left: '50%',
            width: 12, height: 12,
            background: 'rgba(255,255,255,0.97)',
            border: '1px solid rgba(249,115,22,0.3)',
            borderRight: 'none', borderBottom: 'none',
            transform: 'translateX(-50%) rotate(45deg)',
          }}/>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
            <span style={{
              background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.3)',
              color: '#ea580c', fontSize: 9, fontWeight: 800, letterSpacing: 1,
              padding: '2px 8px', borderRadius: 20, textTransform: 'uppercase',
            }}>⚠ Predicted Next</span>
          </div>

          <div style={{ fontSize: 12, fontWeight: 700, color: '#1e3a5f', marginBottom: 8 }}>
            {stage.label} likely next
          </div>

          <div style={{ fontSize: 10, color: '#6b8cae', fontWeight: 600, marginBottom: 6, letterSpacing: 1, textTransform: 'uppercase' }}>
            Pre-emptive Actions:
          </div>
          {(PREEMPTIVE[stage.id] || []).map((action, i) => (
            <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 5, fontSize: 11, color: '#334155', alignItems: 'flex-start' }}>
              <span style={{ color: '#f97316', fontWeight: 800, flexShrink: 0 }}>→</span>
              {action}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/* ── Main export ──────────────────────────────────────────────────────────── */
export default function KillChainViewer({ stages, currentStage, predictedNext }) {
  const [hoveredIdx, setHoveredIdx] = useState(null)

  // Fallback demo values if no props
  const cur  = currentStage  || 'c2'
  const pred = predictedNext || 'lateral'

  const statuses = resolveStatuses(stages, cur, pred)

  const detected  = STAGES.find(s => s.id === cur)
  const predicted = STAGES.find(s => s.id === pred)

  return (
    <div style={{
      background: 'var(--surface-1)',
      backdropFilter: 'var(--glass-blur)',
      WebkitBackdropFilter: 'var(--glass-blur)',
      border: '1px solid var(--border-hairline)',
      borderRadius: 18,
      boxShadow: 'var(--shadow-elevation-1)',
      padding: '20px 24px',
      fontFamily: 'var(--font-ui)',
    }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <div style={{ fontWeight: 800, fontSize: 14, color: 'var(--text-primary)' }}>Kill Chain Progress</div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', letterSpacing: 1, textTransform: 'uppercase', marginTop: 2 }}>
            MITRE ATT&amp;CK · Live Tracking
          </div>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          {[
            ['#10b981', 'Detected'],
            ['#f97316', 'Predicted'],
            ['#94a3b8', 'Passed'],
          ].map(([color, label]) => (
            <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-secondary)' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }}/>
              {label}
            </span>
          ))}
        </div>
      </div>

      {/* Chain */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 0, overflow: 'visible', paddingBottom: 8 }}>
        {STAGES.map((stage, i) => (
          <div key={stage.id} style={{ display: 'contents' }}>
            <StageNode
              stage={stage}
              status={statuses[i]}
              showTooltip={hoveredIdx === i}
              onHover={(on) => setHoveredIdx(on ? i : null)}
            />
            {i < STAGES.length - 1 && (
              <Connector leftStatus={statuses[i]} rightStatus={statuses[i + 1]} />
            )}
          </div>
        ))}
      </div>

      {/* Summary bar */}
      <div style={{
        marginTop: 20, padding: '12px 16px', borderRadius: 12,
        background: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.25)',
        display: 'flex', gap: 24, alignItems: 'center',
      }}>
        <div>
          <div style={{ fontSize: 9, color: 'var(--text-secondary)', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 3 }}>Current Stage</div>
          <div style={{ fontWeight: 800, color: 'var(--severity-success-fg)', fontSize: 13 }}>{detected?.icon} {detected?.label}</div>
        </div>
        <div style={{ width: 1, height: 30, background: 'var(--border-hairline)' }}/>
        <div>
          <div style={{ fontSize: 9, color: 'var(--text-secondary)', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 3 }}>Predicted Next</div>
          <div style={{ fontWeight: 800, color: 'var(--severity-high-fg)', fontSize: 13 }}>{predicted?.icon} {predicted?.label}</div>
        </div>
        <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-secondary)' }}>
          Hover on <span style={{ color: 'var(--severity-high-fg)', fontWeight: 700 }}>⚠ Predicted</span> node for pre-emptive actions
        </div>
      </div>

      <style>{`
        @keyframes kc-pulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(249,115,22,0.5); }
          50%       { box-shadow: 0 0 0 8px rgba(249,115,22,0); }
        }
        @keyframes kc-dash {
          from { background-position: 0 0; }
          to   { background-position: 32px 0; }
        }
        @keyframes fadeSlideIn {
          from { opacity:0; transform:translateX(-50%) translateY(4px); }
          to   { opacity:1; transform:translateX(-50%) translateY(0); }
        }
      `}</style>
    </div>
  )
}
