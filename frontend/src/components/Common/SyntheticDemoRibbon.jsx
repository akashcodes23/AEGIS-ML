import React from 'react'
import { AlertCircle, Database } from 'lucide-react'

/**
 * Synthetic Demo Ribbon
 * 
 * Strict Requirement:
 * Wherever synthetic or replayed data is displayed, a visible disclosure
 * must remain on screen. Nothing in the UI may imply synthetic results
 * establish real-world detection accuracy.
 * 
 * Non-dismissible while synthetic or replayed data is active.
 */
export default function SyntheticDemoRibbon({ isSynthetic = true, datasetName = '' }) {
  if (!isSynthetic) return null

  return (
    <aside
      aria-label="Synthetic Data Disclosure"
      className="synthetic-ribbon"
      style={{
        width: '100%',
        background: 'linear-gradient(90deg, rgba(168, 85, 247, 0.12) 0%, rgba(18, 25, 39, 0.95) 50%, rgba(168, 85, 247, 0.12) 100%)',
        borderBottom: '1px solid rgba(168, 85, 247, 0.3)',
        boxShadow: '0 2px 12px rgba(0, 0, 0, 0.4)',
        padding: '6px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 12,
        fontSize: 12,
        color: 'var(--text-secondary)',
        zIndex: 50,
        position: 'relative',
        letterSpacing: '0.2px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#c084fc', fontWeight: 700 }}>
        <AlertCircle size={14} strokeWidth={2.5} aria-hidden="true" />
        <span style={{ textTransform: 'uppercase', letterSpacing: '0.8px', fontSize: 10 }}>Notice</span>
      </div>

      <span style={{ color: 'var(--border-subtle)' }} aria-hidden="true">|</span>

      <span style={{ fontWeight: 500, color: '#e2e8f0' }}>
        Synthetic demo data. Results do not reflect real-world detection accuracy.
      </span>

      {datasetName && (
        <span style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
          fontSize: 11,
          padding: '2px 8px',
          borderRadius: 6,
          background: 'rgba(255, 255, 255, 0.05)',
          border: '1px solid var(--border-hairline)',
          color: 'var(--text-secondary)',
          fontFamily: 'var(--font-mono)'
        }}>
          <Database size={11} aria-hidden="true" />
          <span>{datasetName}</span>
        </span>
      )}
    </aside>
  )
}
