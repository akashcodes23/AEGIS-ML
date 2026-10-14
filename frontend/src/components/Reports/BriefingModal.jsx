import { useEffect, useState, useRef } from 'react'
import { createPortal } from 'react-dom'
import {
  Printer,
  X,
  ShieldAlert,
  AlertTriangle,
  Clock,
  Fingerprint,
  Layers,
  CheckCircle2,
  Info,
} from 'lucide-react'
import {
  buildBriefingData,
  computeBriefingChecksum,
  CHECKSUM_LABEL,
  CHECKSUM_UNAVAILABLE_MESSAGE,
} from '../../utils/briefing'
import useReducedMotion from '../../hooks/useReducedMotion'

/**
 * BriefingModal
 *
 * Dedicated executive incident briefing view and print layout.
 * Features:
 * - @media print styles for zero-dependency high-fidelity PDF/printing
 * - Prominent synthetic data disclosure on cover and every printed page
 * - Stage 3 evidence chain showing present links and dashed gaps
 * - Stage 2 calibrated confidence evaluation
 * - SHA-256 integrity checksum labeled strictly per specification
 */
export default function BriefingModal({
  isOpen,
  onClose,
  incident,
  alerts = [],
  isSynthetic = true,
  datasetName = 'behavioral_diversity_labeled.jsonl',
  sessionAlertsCount = 0,
  graphSnapshot = null,
}) {
  const [checksum, setChecksum] = useState(null)
  const [checksumLoading, setChecksumLoading] = useState(true)
  const reducedMotion = useReducedMotion()
  const modalRef = useRef(null)

  // Build canonical briefing data model
  const briefing = buildBriefingData(incident, {
    alerts,
    isSynthetic,
    datasetName,
    timestampBasis: 'Ingest/Event timestamp basis',
    sessionAlertsCount,
    graphSnapshotUrl: graphSnapshot,
    gitCommit: '77c026e',
  })

  const canonicalString = briefing?.canonicalString || ''

  // Compute integrity checksum asynchronously
  useEffect(() => {
    let isMounted = true
    if (isOpen && canonicalString) {
      computeBriefingChecksum(canonicalString).then((hash) => {
        if (isMounted) {
          setChecksum(hash)
          setChecksumLoading(false)
        }
      })
    }
    return () => {
      isMounted = false
    }
  }, [isOpen, canonicalString])

  // Keyboard navigation: Escape closes modal
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen || !briefing) return null

  const handlePrint = () => {
    window.print()
  }

  const modalContent = (
    <div
      role="presentation"
      className="briefing-modal-overlay"
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 99999,
        background: 'rgba(5, 7, 12, 0.82)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px 16px',
        animation: reducedMotion ? 'none' : 'fadeIn 120ms ease-out',
        overflowY: 'auto',
      }}
    >
      {/* ── Briefing Container ────────────────────────────────────────── */}
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Executive Incident Briefing: ${briefing.title}`}
        onClick={(e) => e.stopPropagation()}
        className="briefing-document-container"
        style={{
          width: '100%',
          maxWidth: 920,
          background: 'var(--surface-3)',
          border: '1px solid var(--border-medium)',
          borderRadius: 16,
          boxShadow: 'var(--shadow-elevation-4)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '90vh',
          animation: reducedMotion ? 'none' : 'slideUp 160ms var(--ease-standard)',
        }}
      >
        {/* ── Modal Top Action Bar (hidden in print) ──────────────────── */}
        <div
          className="no-print"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '14px 24px',
            borderBottom: '1px solid var(--border-hairline)',
            background: 'var(--surface-2)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span
              style={{
                fontSize: 11,
                fontFamily: 'var(--font-mono)',
                color: 'var(--accent-cyan)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: 0.8,
              }}
            >
              AEGIS Executive Briefing
            </span>
            <span style={{ color: 'var(--border-subtle)' }}>|</span>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {briefing.incidentId}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button
              type="button"
              onClick={handlePrint}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '7px 16px',
                borderRadius: 8,
                background: 'var(--accent-cyan)',
                color: '#07090e',
                fontWeight: 700,
                fontSize: 12,
                border: 'none',
                cursor: 'pointer',
                boxShadow: '0 2px 8px rgba(0, 240, 255, 0.25)',
              }}
            >
              <Printer size={15} />
              <span>Print / Save as PDF</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              aria-label="Close briefing"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 32,
                height: 32,
                borderRadius: 8,
                background: 'var(--surface-1)',
                border: '1px solid var(--border-hairline)',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* ── Document Content (Printable) ────────────────────────────── */}
        <div
          tabIndex="0"
          aria-label="Briefing document content"
          className="briefing-print-body"
          style={{
            padding: '36px 44px',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: 28,
            fontFamily: 'var(--font-ui)',
            color: 'var(--text-primary)',
            outline: 'none',
          }}
        >
          {/* Cover Header */}
          <div style={{ borderBottom: '2px solid var(--border-medium)', paddingBottom: 20 }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                flexWrap: 'wrap',
                gap: 16,
                marginBottom: 12,
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: 12,
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-secondary)',
                    letterSpacing: 1.2,
                    textTransform: 'uppercase',
                    marginBottom: 6,
                  }}
                >
                  AEGIS Network Intelligence · Incident Briefing
                </div>
                <h1
                  style={{
                    fontSize: 26,
                    fontWeight: 800,
                    margin: 0,
                    color: 'var(--text-primary)',
                    letterSpacing: '-0.5px',
                  }}
                >
                  {briefing.title}
                </h1>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span
                  style={{
                    padding: '6px 14px',
                    borderRadius: 8,
                    fontSize: 12,
                    fontWeight: 800,
                    letterSpacing: 0.6,
                    textTransform: 'uppercase',
                    background:
                      briefing.severity === 'critical'
                        ? 'var(--severity-critical-bg)'
                        : 'var(--severity-high-bg)',
                    color:
                      briefing.severity === 'critical'
                        ? '#ff5277'
                        : 'var(--severity-high-fg)',
                    border: `1px solid ${
                      briefing.severity === 'critical'
                        ? 'var(--severity-critical-border)'
                        : 'var(--severity-high-border)'
                    }`,
                  }}
                >
                  {briefing.severity} Severity
                </span>

                <span
                  style={{
                    padding: '6px 14px',
                    borderRadius: 8,
                    fontSize: 12,
                    fontWeight: 700,
                    background: 'rgba(0, 240, 255, 0.1)',
                    color: 'var(--accent-cyan)',
                    border: '1px solid rgba(0, 240, 255, 0.25)',
                  }}
                >
                  Stage: {briefing.killChainStage}
                </span>
              </div>
            </div>

            {/* Synthetic Demo Mandatory Cover Disclosure */}
            {briefing.disclosure && (
              <div
                className="briefing-synthetic-cover-banner"
                style={{
                  marginTop: 16,
                  padding: '12px 18px',
                  borderRadius: 8,
                  background: 'rgba(168, 85, 247, 0.12)',
                  border: '1px solid rgba(168, 85, 247, 0.35)',
                  color: '#d8b4fe',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  fontSize: 13,
                  fontWeight: 700,
                }}
              >
                <Info size={18} flexShrink={0} />
                <span>{briefing.disclosure}</span>
              </div>
            )}
          </div>

          {/* Metadata Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: 16,
              background: 'var(--surface-2)',
              padding: '16px 20px',
              borderRadius: 12,
              border: '1px solid var(--border-hairline)',
              fontSize: 12,
            }}
          >
            <div>
              <div
                style={{
                  fontSize: 10,
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  fontWeight: 700,
                  marginBottom: 2,
                }}
              >
                Incident Identifier
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                }}
              >
                {briefing.incidentId}
              </div>
            </div>

            <div>
              <div
                style={{
                  fontSize: 10,
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  fontWeight: 700,
                  marginBottom: 2,
                }}
              >
                Primary Attacker
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: 'var(--severity-critical-fg)',
                }}
              >
                {briefing.primaryAttacker}
              </div>
            </div>

            <div>
              <div
                style={{
                  fontSize: 10,
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  fontWeight: 700,
                  marginBottom: 2,
                }}
              >
                Primary Target
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: 'var(--accent-cyan)',
                }}
              >
                {briefing.primaryTarget}
              </div>
            </div>

            <div>
              <div
                style={{
                  fontSize: 10,
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  fontWeight: 700,
                  marginBottom: 2,
                }}
              >
                Session Scope
              </div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                {briefing.metadata.sessionAlertsCount} alerts held in session
              </div>
            </div>

            <div>
              <div
                style={{
                  fontSize: 10,
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  fontWeight: 700,
                  marginBottom: 2,
                }}
              >
                Timestamp Basis
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>
                {briefing.metadata.timestampBasis}
              </div>
            </div>

            <div>
              <div
                style={{
                  fontSize: 10,
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  fontWeight: 700,
                  marginBottom: 2,
                }}
              >
                Report Generated
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>
                {new Date(briefing.metadata.generatedAt).toLocaleString()}
              </div>
            </div>
          </div>

          {/* Model Confidence Evaluation (Stage 2 Rules) */}
          <div
            style={{
              padding: '16px 20px',
              borderRadius: 12,
              background: briefing.confidence.isCalibrated
                ? 'rgba(0, 240, 255, 0.06)'
                : 'var(--surface-1)',
              border: `1px solid ${
                briefing.confidence.isCalibrated
                  ? 'rgba(0, 240, 255, 0.25)'
                  : 'var(--border-hairline)'
              }`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 12,
            }}
          >
            <div>
              <div
                style={{
                  fontSize: 11,
                  textTransform: 'uppercase',
                  letterSpacing: 0.8,
                  fontWeight: 700,
                  color: briefing.confidence.isCalibrated
                    ? 'var(--accent-cyan)'
                    : 'var(--text-secondary)',
                  marginBottom: 4,
                }}
              >
                {briefing.confidence.label}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                {briefing.confidence.description}
              </div>
            </div>

            <div
              className="tabular-nums"
              style={{
                fontSize: 26,
                fontWeight: 800,
                color: briefing.confidence.isCalibrated
                  ? 'var(--accent-cyan)'
                  : 'var(--text-primary)',
              }}
            >
              {briefing.confidence.percentage}
            </div>
          </div>

          {/* Topology Graph Snapshot (if available) */}
          {briefing.graphSnapshotUrl && (
            <div>
              <h2
                style={{
                  fontSize: 15,
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  marginBottom: 10,
                }}
              >
                Spatial Threat Topology Snapshot
              </h2>
              <div
                style={{
                  borderRadius: 12,
                  border: '1px solid var(--border-medium)',
                  overflow: 'hidden',
                  background: '#07090e',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <img
                  src={briefing.graphSnapshotUrl}
                  alt={`Entity topology snapshot for ${briefing.incidentId}`}
                  style={{ width: '100%', maxHeight: 300, objectFit: 'contain' }}
                />
              </div>
            </div>
          )}

          {/* Stage 3 Evidence Trail & Gaps */}
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 12,
              }}
            >
              <h2 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Auditable Evidence Provenance Chain
              </h2>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                {briefing.evidenceChain.filter((l) => l.status === 'present').length} verified links ·{' '}
                {briefing.evidenceChain.filter((l) => l.status === 'absent').length} evidence gaps
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {briefing.evidenceChain.map((link, idx) => {
                const isAbsent = link.status === 'absent'
                const isPartial = link.status === 'partial'

                return (
                  <div
                    key={link.id || idx}
                    style={{
                      padding: '12px 18px',
                      borderRadius: 10,
                      background: isAbsent ? 'transparent' : 'var(--surface-1)',
                      border: isAbsent
                        ? '1px dashed var(--border-medium)'
                        : `1px solid ${isPartial ? 'rgba(217, 119, 6, 0.4)' : 'var(--border-subtle)'}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 14,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div
                        style={{
                          width: 24,
                          height: 24,
                          borderRadius: '50%',
                          background: isAbsent
                            ? 'rgba(148, 163, 184, 0.1)'
                            : 'rgba(0, 240, 255, 0.12)',
                          color: isAbsent ? 'var(--text-tertiary)' : 'var(--accent-cyan)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: 11,
                          fontWeight: 700,
                        }}
                      >
                        {idx + 1}
                      </div>

                      <div>
                        <div
                          style={{
                            fontWeight: 700,
                            fontSize: 13,
                            color: isAbsent ? 'var(--text-tertiary)' : 'var(--text-primary)',
                          }}
                        >
                          {link.label}
                        </div>
                        <div
                          style={{
                            fontSize: 11,
                            color: isAbsent ? 'var(--text-tertiary)' : 'var(--text-secondary)',
                          }}
                        >
                          {link.sublabel}
                        </div>
                      </div>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '3px 8px',
                          borderRadius: 6,
                          background: isAbsent
                            ? 'rgba(148, 163, 184, 0.1)'
                            : isPartial
                              ? 'rgba(217, 119, 6, 0.12)'
                              : 'rgba(5, 150, 105, 0.12)',
                          color: isAbsent
                            ? 'var(--text-tertiary)'
                            : isPartial
                              ? 'var(--severity-high-fg)'
                              : 'var(--severity-success-fg)',
                        }}
                      >
                        {isAbsent ? 'Gap (Absent)' : isPartial ? 'Partial' : 'Verified'}
                      </span>
                      <div
                        style={{
                          fontSize: 10,
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-tertiary)',
                          marginTop: 3,
                        }}
                      >
                        Source: {link.source}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Timeline: Observations vs Hypotheses */}
          <div>
            <h2
              style={{
                fontSize: 15,
                fontWeight: 700,
                color: 'var(--text-primary)',
                marginBottom: 12,
              }}
            >
              Timeline Sequence (Observations vs. Hypotheses)
            </h2>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                borderLeft: '2px solid var(--border-medium)',
                marginLeft: 10,
                paddingLeft: 18,
              }}
            >
              {briefing.timeline.map((item) => (
                <div
                  key={item.id}
                  style={{
                    position: 'relative',
                    padding: '8px 12px',
                    borderRadius: 8,
                    background: item.isHypothesis ? 'rgba(168, 85, 247, 0.08)' : 'var(--surface-1)',
                    border: `1px solid ${
                      item.isHypothesis ? 'rgba(168, 85, 247, 0.25)' : 'var(--border-hairline)'
                    }`,
                  }}
                >
                  <div
                    style={{
                      position: 'absolute',
                      left: -24,
                      top: 14,
                      width: 10,
                      height: 10,
                      borderRadius: '50%',
                      background: item.isHypothesis ? 'var(--accent-violet)' : 'var(--accent-cyan)',
                      border: '2px solid var(--surface-3)',
                    }}
                  />

                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginBottom: 4,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 800,
                        textTransform: 'uppercase',
                        letterSpacing: 0.6,
                        color: item.isHypothesis ? '#d8b4fe' : 'var(--accent-cyan)',
                      }}
                    >
                      {item.nature}
                    </span>
                    <span
                      style={{
                        fontSize: 11,
                        color: 'var(--text-tertiary)',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      {item.time}
                    </span>
                  </div>

                  <div style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
                    {item.description}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Cryptographic Integrity Checksum Section */}
          <div
            style={{
              marginTop: 12,
              padding: '16px 20px',
              borderRadius: 12,
              background: 'var(--surface-2)',
              border: '1px solid var(--border-hairline)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <Fingerprint size={16} color="var(--accent-cyan)" />
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: 'var(--text-secondary)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.6,
                }}
              >
                {CHECKSUM_LABEL}
              </div>
            </div>

            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                wordBreak: 'break-all',
                color: checksum ? 'var(--text-primary)' : 'var(--text-tertiary)',
                background: 'var(--surface-1)',
                padding: '8px 12px',
                borderRadius: 6,
                border: '1px solid var(--border-hairline)',
              }}
            >
              {checksumLoading
                ? 'Computing SHA-256 digest via SubtleCrypto...'
                : checksum
                  ? `SHA-256: ${checksum}`
                  : CHECKSUM_UNAVAILABLE_MESSAGE}
            </div>

            <div style={{ fontSize: 10, color: 'var(--text-tertiary)', marginTop: 6 }}>
              Computed over canonical incident attributes, evidence nodes, confidence evaluation, and session metadata.
            </div>
          </div>

          {/* Printed Page Repeated Footer (handled via CSS @media print) */}
          <div
            className="briefing-print-page-footer"
            style={{
              borderTop: '1px solid var(--border-hairline)',
              paddingTop: 12,
              marginTop: 12,
              display: 'flex',
              justifyContent: 'space-between',
              fontSize: 10,
              color: 'var(--text-tertiary)',
            }}
          >
            <div>AEGIS-ML · Commit {briefing.metadata.gitCommit}</div>
            {briefing.disclosure && <div>{briefing.disclosure}</div>}
            <div>Page Footer · {new Date().toLocaleDateString()}</div>
          </div>
        </div>
      </div>
    </div>
  )

  if (typeof document !== 'undefined' && document.body) {
    return createPortal(modalContent, document.body)
  }

  return modalContent
}
