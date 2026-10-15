import { useState } from 'react'
import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Download,
  Info,
  Layers,
  Activity,
  Cpu,
  Lock,
  ExternalLink,
  ChevronRight,
  GitCommit,
  Hash,
} from 'lucide-react'
import {
  MODEL_ASSURANCE_METADATA,
  HEADLINE_METRICS,
  COMPARATIVE_BASELINES,
  PER_CLASS_METRICS,
  RELIABILITY_BINS_CALIBRATED,
  ZERO_DAY_GENERALIZATION,
  CICIDS_STATUS,
  CORRELATION_ENGINE_VALIDATION,
  formatMetric,
} from '../../data/modelAssuranceData'

export default function ModelAssuranceView() {
  const [selectedBaseline, setSelectedBaseline] = useState('full_pipeline_calibrated')
  const [showFullReliability, setShowFullReliability] = useState(false)

  const exportEvaluationJson = () => {
    const payload = {
      model_assurance_export: {
        exported_at: new Date().toISOString(),
        protocol: MODEL_ASSURANCE_METADATA,
        headline_metrics: HEADLINE_METRICS,
        comparative_baselines: COMPARATIVE_BASELINES,
        per_class_evaluation: PER_CLASS_METRICS,
        zero_day_generalization_escape: ZERO_DAY_GENERALIZATION,
        external_benchmark_status: CICIDS_STATUS,
        correlation_validation: CORRELATION_ENGINE_VALIDATION,
      },
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `AEGIS-Model-Assurance-Report-${MODEL_ASSURANCE_METADATA.protocol_version}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ── Governance Header ────────────────────────────────────────────── */}
      <div className="glass-panel" style={{ padding: '28px 32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 20 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
              <div
                style={{
                  width: 42,
                  height: 42,
                  borderRadius: 14,
                  background: 'rgba(0, 240, 255, 0.1)',
                  color: 'var(--accent-cyan)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: '1px solid rgba(0, 240, 255, 0.25)',
                }}
              >
                <ShieldCheck size={24} />
              </div>
              <div>
                <h2 style={{ fontSize: 22, fontWeight: 800, margin: 0, color: 'var(--text-primary)', letterSpacing: '-0.5px' }}>
                  Model Assurance &amp; Empirical Evaluation
                </h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
                  <span
                    className="mono-font"
                    style={{
                      fontSize: 11,
                      padding: '2px 8px',
                      borderRadius: 6,
                      background: 'rgba(0, 240, 255, 0.12)',
                      color: 'var(--accent-cyan)',
                      border: '1px solid rgba(0, 240, 255, 0.3)',
                      fontWeight: 700,
                    }}
                  >
                    Protocol {MODEL_ASSURANCE_METADATA.protocol_version}
                  </span>
                  <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>•</span>
                  <span className="mono-font" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    Evaluated: {MODEL_ASSURANCE_METADATA.evaluation_timestamp.replace('T', ' ').replace('Z', ' UTC')}
                  </span>
                  <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>•</span>
                  <span className="mono-font" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    Primary Seed: {MODEL_ASSURANCE_METADATA.primary_seed}
                  </span>
                </div>
              </div>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', maxWidth: 860, lineHeight: 1.5 }}>
              Frozen empirical verification of the AEGIS detection engine across leak-free scenario partitions.
              Metrics are pre-registered and validated with 1,000 bootstrap iterations; figures strictly reflect
              measured evidence without synthetic inflation or optimistic claims of real-world perfection.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={exportEvaluationJson}
              id="export-assurance-json"
              style={{
                padding: '10px 18px',
                borderRadius: 12,
                fontSize: 13,
                fontWeight: 700,
                background: 'var(--surface-3)',
                color: 'var(--accent-cyan)',
                border: '1px solid var(--border-medium)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                transition: 'all 0.2s',
              }}
            >
              <Download size={16} /> Export Evaluation Protocol (JSON)
            </button>
          </div>
        </div>
      </div>

      {/* ── Mandatory Synthetic Disclosure & Methodology Banner ──────────── */}
      <div
        className="glass-panel"
        style={{
          padding: '16px 20px',
          borderRadius: 12,
          background: 'rgba(234, 179, 8, 0.05)',
          border: '1px solid rgba(234, 179, 8, 0.25)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 14,
        }}
      >
        <AlertTriangle size={20} color="var(--accent-high)" style={{ flexShrink: 0, marginTop: 2 }} />
        <div style={{ fontSize: 12, lineHeight: 1.55, color: 'var(--text-secondary)' }}>
          <strong style={{ color: 'var(--accent-high)' }}>Methodological Scope &amp; Uncertainty Disclosure:</strong>{' '}
          All measurements derive from controlled, scenario-partitioned synthetic test flows. Synthetic evaluation results
          validate architectural correctness and calibration under controlled assumptions; they do{' '}
          <strong>not</strong> constitute proof of equal efficacy against unconstrained enterprise adversaries.
          Expected Calibration Error (ECE) quantifies posterior probability alignment across confidence bins, not classification accuracy.
          Confidence scores reflect model-calibrated posterior probabilities under the observed feature distribution, not guaranteed ground truth.
        </div>
      </div>

      {/* ── Key Verified Metrics Scorecards (95% Bootstrap CIs) ─────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 20 }}>
        {/* Macro F1 */}
        <div className="glass-panel" style={{ padding: '22px 24px', position: 'relative' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>
            {HEADLINE_METRICS.macro_f1.label}
          </div>
          <div className="tabular-nums mono-font" style={{ fontSize: 32, fontWeight: 800, color: 'var(--accent-cyan)', lineHeight: 1.1 }}>
            {formatMetric(HEADLINE_METRICS.macro_f1.value)}
          </div>
          <div style={{ fontSize: 12, marginTop: 8, color: 'var(--text-secondary)' }}>
            95% Bootstrap CI:{' '}
            <span className="mono-font" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              [{formatMetric(HEADLINE_METRICS.macro_f1.ci_95_lower)}, {formatMetric(HEADLINE_METRICS.macro_f1.ci_95_upper)}]
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4, lineHeight: 1.4 }}>
            Mean: {formatMetric(HEADLINE_METRICS.macro_f1.mean)} · Std: ±{formatMetric(HEADLINE_METRICS.macro_f1.std)} (N=1,000)
          </div>
        </div>

        {/* Benign FPR */}
        <div className="glass-panel" style={{ padding: '22px 24px', position: 'relative' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>
            {HEADLINE_METRICS.benign_fpr.label}
          </div>
          <div className="tabular-nums mono-font" style={{ fontSize: 32, fontWeight: 800, color: 'var(--accent-success)', lineHeight: 1.1 }}>
            {formatMetric(HEADLINE_METRICS.benign_fpr.value)}
          </div>
          <div style={{ fontSize: 12, marginTop: 8, color: 'var(--text-secondary)' }}>
            95% Bootstrap CI:{' '}
            <span className="mono-font" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              [{formatMetric(HEADLINE_METRICS.benign_fpr.ci_95_lower)}, {formatMetric(HEADLINE_METRICS.benign_fpr.ci_95_upper)}]
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4, lineHeight: 1.4 }}>
            {HEADLINE_METRICS.benign_fpr.fp_count} FP / {HEADLINE_METRICS.benign_fpr.total_benign} flows ({HEADLINE_METRICS.benign_fpr.alerts_per_1m.toLocaleString()} alerts / 1M flows)
          </div>
        </div>

        {/* ECE */}
        <div className="glass-panel" style={{ padding: '22px 24px', position: 'relative' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>
            {HEADLINE_METRICS.ece.label}
          </div>
          <div className="tabular-nums mono-font" style={{ fontSize: 32, fontWeight: 800, color: 'var(--accent-brand)', lineHeight: 1.1 }}>
            {formatMetric(HEADLINE_METRICS.ece.value)}
          </div>
          <div style={{ fontSize: 12, marginTop: 8, color: 'var(--text-secondary)' }}>
            95% Bootstrap CI:{' '}
            <span className="mono-font" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              [{formatMetric(HEADLINE_METRICS.ece.ci_95_lower)}, {formatMetric(HEADLINE_METRICS.ece.ci_95_upper)}]
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--accent-success)', marginTop: 4, lineHeight: 1.4, fontWeight: 600 }}>
            ↓ {formatMetric(Math.abs(HEADLINE_METRICS.ece.delta))} reduction from raw RF (0.1141)
          </div>
        </div>

        {/* Brier Score */}
        <div className="glass-panel" style={{ padding: '22px 24px', position: 'relative' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>
            {HEADLINE_METRICS.brier_score.label}
          </div>
          <div className="tabular-nums mono-font" style={{ fontSize: 32, fontWeight: 800, color: 'var(--accent-cyan)', lineHeight: 1.1 }}>
            {formatMetric(HEADLINE_METRICS.brier_score.value)}
          </div>
          <div style={{ fontSize: 12, marginTop: 8, color: 'var(--text-secondary)' }}>
            95% Bootstrap CI:{' '}
            <span className="mono-font" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              [{formatMetric(HEADLINE_METRICS.brier_score.ci_95_lower)}, {formatMetric(HEADLINE_METRICS.brier_score.ci_95_upper)}]
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--accent-success)', marginTop: 4, lineHeight: 1.4, fontWeight: 600 }}>
            ↓ {formatMetric(Math.abs(HEADLINE_METRICS.brier_score.delta))} reduction from raw RF (0.1144)
          </div>
        </div>
      </div>

      {/* ── Section 1: Comparative Model Baselines ───────────────────────── */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Activity size={20} color="var(--accent-cyan)" />
            <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
              Empirical Baseline Comparison on Held-Out Test Split (N=886 flows)
            </h3>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
            Evaluated on identical frozen test split (19 scenarios)
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }} aria-label="Model Baselines Comparison Table">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-light)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>MODEL / PIPELINE</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>MACRO F1</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>BENIGN FPR</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>ALERTS / 1M BENIGN</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>ECE (CALIB GAP)</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>BRIER SCORE</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>ROLE / NOTES</th>
              </tr>
            </thead>
            <tbody>
              {COMPARATIVE_BASELINES.map((b) => {
                const isSelected = selectedBaseline === b.model_id
                return (
                  <tr
                    key={b.model_id}
                    onClick={() => setSelectedBaseline(b.model_id)}
                    style={{
                      borderBottom: '1px solid var(--border-light)',
                      background: b.is_production ? 'rgba(0, 240, 255, 0.05)' : isSelected ? 'var(--surface-2)' : 'transparent',
                      cursor: 'pointer',
                      transition: 'background 0.15s ease',
                    }}
                  >
                    <td style={{ padding: '12px', fontWeight: 700, color: b.is_production ? 'var(--accent-cyan)' : 'var(--text-primary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {b.is_production && (
                          <span
                            style={{
                              fontSize: 10,
                              fontWeight: 800,
                              textTransform: 'uppercase',
                              padding: '2px 6px',
                              borderRadius: 4,
                              background: 'var(--accent-cyan)',
                              color: '#07090e',
                            }}
                          >
                            Production
                          </span>
                        )}
                        <span>{b.name}</span>
                      </div>
                    </td>
                    <td className="mono-font" style={{ padding: '12px', fontWeight: 700 }}>
                      {formatMetric(b.macro_f1)}
                    </td>
                    <td className="mono-font" style={{ padding: '12px', color: b.benign_fpr > 0.1 ? 'var(--accent-critical)' : 'inherit' }}>
                      {b.benign_fpr !== undefined ? `${(Number(b.benign_fpr) * 100).toFixed(2)}%` : 'Unavailable'}
                    </td>
                    <td className="mono-font" style={{ padding: '12px', color: b.alerts_per_1m > 10000 ? 'var(--accent-critical)' : 'inherit' }}>
                      {b.alerts_per_1m !== undefined ? b.alerts_per_1m.toLocaleString(undefined, { maximumFractionDigits: 1 }) : 'Unavailable'}
                    </td>
                    <td className="mono-font" style={{ padding: '12px', color: b.ece < 0.05 ? 'var(--accent-success)' : 'inherit' }}>
                      {formatMetric(b.ece)}
                    </td>
                    <td className="mono-font" style={{ padding: '12px' }}>
                      {formatMetric(b.brier)}
                    </td>
                    <td style={{ padding: '12px', fontSize: 12, color: 'var(--text-secondary)' }}>
                      {b.notes}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Section 2: Scenario-Grouped Partitioning & Data Leakage Safeguards ── */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <Lock size={20} color="var(--accent-brand)" />
          <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
            Scenario-Grouped Partitioning &amp; Data Leakage Safeguards
          </h3>
        </div>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 20 }}>
          To prevent synthetic record leakage, splits were grouped strictly by campaign scenario identifier rather than
          naive random shuffling. All records originating from a given simulation scenario reside exclusively in exactly one partition.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
          <div style={{ padding: '16px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Train Split</div>
            <div className="mono-font" style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', marginTop: 4 }}>
              {MODEL_ASSURANCE_METADATA.splits.train_records.toLocaleString()} flows
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              {MODEL_ASSURANCE_METADATA.splits.train_scenarios} independent scenarios
            </div>
          </div>

          <div style={{ padding: '16px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Validation Split</div>
            <div className="mono-font" style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', marginTop: 4 }}>
              {MODEL_ASSURANCE_METADATA.splits.val_records.toLocaleString()} flows
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              {MODEL_ASSURANCE_METADATA.splits.val_scenarios} scenarios (calibration fitting)
            </div>
          </div>

          <div style={{ padding: '16px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Held-Out Test Split</div>
            <div className="mono-font" style={{ fontSize: 22, fontWeight: 800, color: 'var(--accent-cyan)', marginTop: 4 }}>
              {MODEL_ASSURANCE_METADATA.splits.test_records.toLocaleString()} flows
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              {MODEL_ASSURANCE_METADATA.splits.test_scenarios} scenarios (final evaluation)
            </div>
          </div>

          <div style={{ padding: '16px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Scenario Overlap</div>
            <div className="mono-font" style={{ fontSize: 22, fontWeight: 800, color: 'var(--accent-success)', marginTop: 4 }}>
              0.0% overlap
            </div>
            <div style={{ fontSize: 12, color: 'var(--accent-success)', marginTop: 2, fontWeight: 600 }}>
              ✓ Strict group partition isolation
            </div>
          </div>
        </div>
      </div>

      {/* ── Section 3: Zero-Day Attack Generalization (Documented Limitations) ── */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={20} color="var(--accent-high)" />
            <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
              Zero-Day Attack Generalization &amp; Escape Rates (Leave-One-Attack-Type-Out)
            </h3>
          </div>
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              padding: '3px 8px',
              borderRadius: 6,
              background: 'rgba(239, 68, 68, 0.1)',
              color: 'var(--accent-critical)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
            }}
          >
            Known Architectural Limitation
          </span>
        </div>

        <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 16 }}>
          When tested against entirely unobserved attack categories, the supervised Random Forest silently misclassifies
          between <strong>44.7% and 100.0%</strong> of attack flows as benign. This empirical reality demonstrates why
          supervised classification cannot operate alone and mandates AEGIS's multi-tiered architecture (Supervised + Anomaly Detection + Correlation Engine).
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }} aria-label="Zero-Day Generalization Matrix">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-light)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>HELD-OUT ATTACK CATEGORY</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>TEST FLOWS</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>ESCAPE TO BENIGN RATE</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>SUPERVISED MISCLASSIFICATION</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>ANOMALY PROFILER RECALL</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>ARCHITECTURAL MITIGATION</th>
              </tr>
            </thead>
            <tbody>
              {ZERO_DAY_GENERALIZATION.map((z) => (
                <tr key={z.attack_category} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={{ padding: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {z.attack_category}
                  </td>
                  <td className="mono-font" style={{ padding: '12px' }}>
                    {z.held_out_samples}
                  </td>
                  <td className="mono-font" style={{ padding: '12px', fontWeight: 700, color: z.escape_to_benign_pct > 80 ? 'var(--accent-critical)' : 'var(--accent-high)' }}>
                    {z.escape_to_benign_pct.toFixed(1)}%
                  </td>
                  <td style={{ padding: '12px', fontSize: 12, color: 'var(--text-secondary)' }}>
                    {Object.entries(z.supervised_misclassifications).map(([k, v]) => `${v} → ${k}`).join(', ')}
                  </td>
                  <td className="mono-font" style={{ padding: '12px', color: z.profiler_deviation_recall_pct > 0 ? 'var(--accent-success)' : 'var(--text-tertiary)' }}>
                    {z.profiler_deviation_recall_pct > 0 ? `${z.profiler_deviation_recall_pct.toFixed(1)}%` : '0.0% (missed)'}
                  </td>
                  <td style={{ padding: '12px', fontSize: 12, color: 'var(--text-secondary)' }}>
                    {z.defense_notes}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Section 4: 10-Bin Calibration Reliability Table ──────────────── */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Layers size={20} color="var(--accent-brand)" />
            <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
              Probability Calibration: 10-Bin Reliability Partition (ECE = 0.0011)
            </h3>
          </div>
          <button
            type="button"
            onClick={() => setShowFullReliability(prev => !prev)}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              fontSize: 12,
              fontWeight: 600,
              background: 'transparent',
              color: 'var(--accent-cyan)',
              border: '1px solid var(--border-light)',
              cursor: 'pointer',
            }}
          >
            {showFullReliability ? 'Collapse Empty Bins' : 'Show All 10 Bins'}
          </button>
        </div>

        <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 16 }}>
          Probability calibration was fitted using isotonic regression (`CalibratedClassifierCV`) on the validation partition.
          The calibration gap represents the absolute delta between the model&apos;s mean predicted confidence and empirical observed accuracy.
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }} aria-label="Calibration Reliability Bins Table">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-light)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>BIN</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>CONFIDENCE RANGE</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>SAMPLES</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>MEAN POSTERIOR CONFIDENCE</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>OBSERVED EMPIRICAL ACCURACY</th>
                <th style={{ padding: '10px 12px', fontWeight: 700 }}>CALIBRATION GAP (|CONF - ACC|)</th>
              </tr>
            </thead>
            <tbody>
              {(showFullReliability ? RELIABILITY_BINS_CALIBRATED : RELIABILITY_BINS_CALIBRATED.filter(b => b.samples > 0)).map((b) => (
                <tr key={b.bin_index} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td className="mono-font" style={{ padding: '12px', fontWeight: 600 }}>
                    Bin {b.bin_index}
                  </td>
                  <td className="mono-font" style={{ padding: '12px' }}>
                    {b.bin_range}
                  </td>
                  <td className="mono-font" style={{ padding: '12px', fontWeight: b.samples > 0 ? 700 : 400 }}>
                    {b.samples}
                  </td>
                  <td className="mono-font" style={{ padding: '12px' }}>
                    {formatMetric(b.mean_confidence)}
                  </td>
                  <td className="mono-font" style={{ padding: '12px' }}>
                    {formatMetric(b.observed_accuracy)}
                  </td>
                  <td className="mono-font" style={{ padding: '12px', fontWeight: 700, color: b.calibration_gap < 0.01 ? 'var(--accent-success)' : 'var(--accent-high)' }}>
                    {formatMetric(b.calibration_gap)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Section 5: Provenance, External Benchmarks & Artifact Integrity ── */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <Hash size={20} color="var(--accent-cyan)" />
          <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
            Artifact Provenance &amp; External Benchmark Status
          </h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
          <div style={{ padding: '16px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Evaluation Dataset Hash</div>
            <div className="mono-font" style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent-cyan)', marginTop: 4, wordBreak: 'break-all' }}>
              SHA-256: {MODEL_ASSURANCE_METADATA.dataset_sha256}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
              File: <span className="mono-font">{MODEL_ASSURANCE_METADATA.dataset_name}</span> ({MODEL_ASSURANCE_METADATA.dataset_total_records.toLocaleString()} records)
            </div>
          </div>

          <div style={{ padding: '16px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>CIC-IDS2017 Benchmark Status</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
              <span
                className="mono-font"
                style={{
                  fontSize: 11,
                  fontWeight: 800,
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: 'rgba(234, 179, 8, 0.15)',
                  color: 'var(--accent-high)',
                }}
              >
                {CICIDS_STATUS.status}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.4 }}>
              {CICIDS_STATUS.reason}
            </div>
          </div>

          <div style={{ padding: '16px', borderRadius: 12, background: 'var(--bg-page)', border: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Correlation Heuristic Validation</div>
            <div className="mono-font" style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-success)', marginTop: 4 }}>
              {CORRELATION_ENGINE_VALIDATION.scenarios_evaluated} Scenarios Validated (0 Merge / 0 Split Errors)
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
              Triage Reduction: <span className="mono-font">{CORRELATION_ENGINE_VALIDATION.triage_reduction_pct}%</span> · Evidence Traceability: 100.0%
            </div>
          </div>
        </div>

        {/* Documentation Links */}
        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-light)', display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <FileCode size={14} color="var(--accent-cyan)" />
            <span>Detailed Documentation &amp; Artifact References:</span>
          </div>
          <span className="mono-font" style={{ fontSize: 12, color: 'var(--accent-cyan)' }}>
            {MODEL_ASSURANCE_METADATA.protocol_path}
          </span>
          <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>•</span>
          <span className="mono-font" style={{ fontSize: 12, color: 'var(--accent-cyan)' }}>
            {MODEL_ASSURANCE_METADATA.model_card_path}
          </span>
          <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>•</span>
          <span className="mono-font" style={{ fontSize: 12, color: 'var(--accent-cyan)' }}>
            {MODEL_ASSURANCE_METADATA.results_doc_path}
          </span>
        </div>
      </div>
    </div>
  )
}
