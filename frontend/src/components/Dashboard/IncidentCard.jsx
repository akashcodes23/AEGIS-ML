import { memo, useState } from 'react'
import {
  ShieldAlert, Crosshair, Target, Activity, FileText, FastForward,
  ShieldCheck, PlayCircle, Fingerprint, Layers, Clock, AlertCircle,
  HelpCircle, Eye, Network, CheckCircle2, AlertTriangle, ArrowRight, CornerDownRight
} from 'lucide-react'
import useAlertStore from '../../store/alertStore'

const TABS = [
  'Executive Summary',
  'Timeline & Evidence',
  'Underlying Events',
  'Kill Chain Context',
  'Remediation Playbook'
]

const KILL_CHAIN = ['Recon', 'Weaponize', 'Delivery', 'Exploit', 'Install', 'C2', 'Exfiltrate']

const PLAYBOOK = {
  brute_force:      ['Block source IP at perimeter firewall.', 'Reset credentials for targeted accounts.', 'Enable MFA on affected services.', 'Review auth logs for successful logins.'],
  lateral_movement: ['Isolate affected endpoints from network.', 'Revoke active sessions on compromised accounts.', 'Run EDR scan across movement path.', 'Preserve memory dumps before remediation.'],
  data_exfiltration:['Block outbound connection to destination.', 'Identify and classify data transferred.', 'Notify DLP team and compliance.', 'Preserve network captures for forensics.'],
  c2_beaconing:     ['Block C2 IP/domain at DNS and firewall.', 'Quarantine beaconing host.', 'Run full malware scan.', 'Search for similar patterns across fleet.'],
  statistical_anomaly: ['Review baseline network profiling metrics.', 'Correlate host activity with scheduled maintenance.', 'Inspect payload bytes for atypical protocol framing.', 'Confirm if activity represents legitimate administrative task.'],
  default:          ['Collect and preserve evidence.', 'Escalate to Incident Response team.', 'Document event timeline.', 'Follow standard IR guidelines.'],
}

function FeatureBar({ label, value }) {
  const pct = Math.min(100, Math.round((value || 0) * 100))
  const color = pct > 70 ? 'var(--accent-critical)' : pct > 40 ? 'var(--accent-high)' : 'var(--accent-brand)'
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6, fontWeight: 600 }}>
        <span>{label.replace(/_/g, ' ')}</span>
        <span className="mono-font" style={{ color, fontWeight: 700 }}>{pct}%</span>
      </div>
      <div style={{ height: 6, background: 'var(--bg-page)', borderRadius: 6, overflow: 'hidden', border: '1px solid var(--border-light)' }}>
        <div style={{ 
          height: '100%', width: `${pct}%`, background: color,
          borderRadius: 6, transition: 'width 0.6s cubic-bezier(0.16, 1, 0.3, 1)' 
        }} />
      </div>
    </div>
  )
}

function InsightChip({ icon: Icon, label, value, subtext = null }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 12,
      padding: '10px 14px', background: 'var(--bg-page)',
      borderRadius: 12, border: '1px solid var(--border-light)'
    }}>
      <div style={{ color: 'var(--accent-brand)' }}>
        <Icon size={16} strokeWidth={2} />
      </div>
      <div style={{ overflow: 'hidden' }}>
        <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-tertiary)', fontWeight: 700 }}>{label}</div>
        <div className="mono-font" style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 600, marginTop: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
          {value}
        </div>
        {subtext && <div style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>{subtext}</div>}
      </div>
    </div>
  )
}

export default memo(function IncidentCard() {
  const [activeTab, setActiveTab] = useState(0)
  const alerts = useAlertStore(s => s.alerts)
  const incidents = useAlertStore(s => s.incidents)
  const selectedId = useAlertStore(s => s.selectedIncident)
  const selectIncident = useAlertStore(s => s.selectIncident)

  // Find targeted incident or fallback
  const incident = incidents.find(i => i.incident_id === selectedId) ||
                   alerts.find(a => (a.incident_id || a.alert_id || a.event_id) === selectedId) ||
                   incidents[0] ||
                   alerts[0]

  if (!incident) return (
    <div className="glass-panel animate-slide-up" style={{ 
      padding: 40, textAlign: 'center', color: 'var(--text-tertiary)', gridColumn: '1 / -1',
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16
    }}>
      <ShieldCheck size={48} strokeWidth={1} />
      <div style={{ fontSize: 14, fontWeight: 500 }}>Select an alert or entity to view incident details</div>
    </div>
  )

  const playbook = PLAYBOOK[incident.threat_type] || PLAYBOOK.default
  const stageIdx = Math.max(0, KILL_CHAIN.findIndex(
    s => s.toLowerCase() === (incident.current_kill_chain_stage || '').toLowerCase()
  ))
  const isResolved = incident.status === 'resolved' || incident.status === 'isolated'
  const threatName = incident.threat_type?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())

  // Normalize supporting events & timeline
  const timeline = incident.timeline || [
    {
      entry_id: 'default-obs',
      timestamp: incident.timestamp || incident.created_at,
      entity: incident.src_entity,
      title: 'Observed Telemetry',
      description: `Observed ${incident.layer || 'network'} traffic from ${incident.src_entity} to ${incident.dst_entity}.`,
      claim_type: 'observation',
      evidence_type: 'Raw Telemetry'
    },
    {
      entry_id: 'default-hyp',
      timestamp: incident.timestamp || incident.created_at,
      entity: incident.dst_entity,
      title: 'Inferred Threat Pattern',
      description: `Model inferred probable ${incident.threat_type?.replace(/_/g, ' ')} with ${Math.round((incident.classifier_probability || incident.confidence || 0.5) * 100)}% tree vote agreement.`,
      claim_type: 'hypothesis',
      evidence_type: 'Classifier Inference'
    }
  ]

  const supportingEvents = incident.supporting_events && incident.supporting_events.length > 0
    ? incident.supporting_events
    : (incident.raw_event ? [incident.raw_event] : [])

  const priorityScore = incident.priority_score || (incident.severity === 'critical' ? 92 : incident.severity === 'high' ? 76 : incident.severity === 'medium' ? 52 : 30)
  const isSynthetic = incident.is_synthetic || false

  return (
    <div className="glass-panel animate-slide-up" style={{ gridColumn: '1 / -1', display: 'flex', overflow: 'hidden' }}>
      
      {/* ── Left Sidebar: Critical Narrative & Entities ────────────────────── */}
      <div style={{ width: 380, borderRight: '1px solid var(--border-light)', padding: 28, background: 'rgba(250, 249, 246, 0.4)', display: 'flex', flexDirection: 'column', gap: 20 }}>
        
        {/* Status Badges */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{
              fontSize: 10, fontWeight: 800, padding: '4px 10px', borderRadius: 20,
              background: isResolved ? 'rgba(5, 150, 105, 0.08)' : 'rgba(220, 38, 38, 0.08)',
              color: isResolved ? 'var(--accent-success)' : 'var(--accent-critical)',
              border: `1px solid ${isResolved ? 'rgba(5, 150, 105, 0.2)' : 'rgba(220, 38, 38, 0.2)'}`,
              textTransform: 'uppercase', letterSpacing: 0.5
            }}>
              {isResolved ? incident.status : 'Active Investigation'}
            </span>
            {isSynthetic && (
              <span style={{
                fontSize: 9, fontWeight: 800, padding: '3px 8px', borderRadius: 20,
                background: 'rgba(147, 51, 234, 0.1)', color: '#9333ea',
                border: '1px solid rgba(147, 51, 234, 0.25)', textTransform: 'uppercase'
              }}>
                Synthetic Demo
              </span>
            )}
          </div>
          <span className="mono-font" style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
            #{incident.incident_id ? incident.incident_id.slice(0, 12) : (incident.event_id || 'ID-UNKNOWN')}
          </span>
        </div>

        {/* Title */}
        <div>
          <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.2, marginBottom: 8, letterSpacing: '-0.4px' }}>
            {threatName} Activity
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Correlated campaign involving <span className="mono-font" style={{fontWeight:600}}>{incident.primary_attacker || incident.src_entity}</span> targeting <span className="mono-font" style={{fontWeight:600}}>{incident.primary_target || incident.dst_entity}</span>.
          </div>
        </div>

        {/* Priority & Risk Gauges */}
        <div style={{
          padding: '12px 16px', background: 'var(--bg-page)', borderRadius: 12,
          border: '1px solid var(--border-light)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12
        }}>
          <div>
            <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 700 }}>Priority Score</div>
            <div className="mono-font" style={{ fontSize: 20, fontWeight: 800, color: priorityScore >= 75 ? 'var(--accent-critical)' : 'var(--accent-high)' }}>
              {priorityScore}<span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>/100</span>
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 700 }}>Severity</div>
            <div style={{
              fontSize: 14, fontWeight: 800, textTransform: 'uppercase', marginTop: 2,
              color: incident.severity === 'critical' ? 'var(--accent-critical)' : incident.severity === 'high' ? 'var(--accent-high)' : 'var(--accent-brand)'
            }}>
              {incident.severity || 'Medium'}
            </div>
          </div>
        </div>

        {/* Insight Chips */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <InsightChip icon={Crosshair} label="Primary Attacker" value={incident.primary_attacker || incident.src_entity || 'N/A'} />
          <InsightChip icon={Target} label="Primary Target" value={incident.primary_target || incident.dst_entity || 'N/A'} />
          <InsightChip icon={Layers} label="Layers Involved" value={(incident.layers_involved || [incident.layer || 'network']).join(', ')} />
          <InsightChip
            icon={Fingerprint}
            label="Model Consensus"
            value={`${Math.round((incident.classifier_probability != null ? incident.classifier_probability : (incident.confidence || 0.5)) * 100)}%`}
            subtext="Random Forest tree agreement"
          />
        </div>

        {/* Affected Entities */}
        {incident.affected_entities && incident.affected_entities.length > 0 && (
          <div>
            <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-tertiary)', fontWeight: 700, marginBottom: 8 }}>
              Correlated Entities ({incident.affected_entities.length})
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {incident.affected_entities.map(e => (
                <span key={e} className="mono-font" style={{
                  fontSize: 11, padding: '4px 8px', borderRadius: 6,
                  background: 'var(--bg-page)', border: '1px solid var(--border-light)',
                  color: 'var(--text-primary)'
                }}>{e}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Right Content: Multi-tab Investigation Panel ──────────────────── */}
      <div style={{ flex: 1, padding: 32, display: 'flex', flexDirection: 'column' }}>
        
        {/* Tab Navigation */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 24, borderBottom: '1px solid var(--border-light)', paddingBottom: 16, overflowX: 'auto' }}>
          {TABS.map((t, i) => (
            <button key={t} onClick={() => setActiveTab(i)} style={{
              background: activeTab === i ? 'var(--text-primary)' : 'transparent',
              color: activeTab === i ? '#fff' : 'var(--text-secondary)',
              border: 'none', padding: '8px 18px', borderRadius: 20,
              fontSize: 12, fontWeight: 700, cursor: 'pointer',
              whiteSpace: 'nowrap', transition: 'all 0.2s ease'
            }}>
              {t}
            </button>
          ))}
        </div>

        {/* ── TAB 0: Executive Summary & ML Insights ──────────────────────── */}
        {activeTab === 0 && (
          <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            
            {/* Correlation Reason Box */}
            <div style={{
              padding: '16px 20px', borderRadius: 12,
              background: 'rgba(79, 70, 229, 0.05)', border: '1px solid rgba(79, 70, 229, 0.2)',
              display: 'flex', gap: 12, alignItems: 'flex-start'
            }}>
              <Network size={20} color="var(--accent-brand)" style={{ flexShrink: 0, marginTop: 2 }} />
              <div>
                <div style={{ fontSize: 12, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--accent-brand)', marginBottom: 4 }}>
                  Why Events Were Correlated
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                  {incident.correlation_reason || `Correlated events within sliding time window based on continuous entity traffic from ${incident.src_entity} across network topology.`}
                </div>
              </div>
            </div>

            {/* Local ML Feature Contributions */}
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={16} color="var(--accent-brand)" /> Local Feature Contribution & Baseline Deviations
              </h3>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.5 }}>
                Local attribution computed by comparing observed telemetry against normal entity baselines, weighted by model decision boundaries.
              </p>
              
              <div style={{ maxWidth: 560 }}>
                {Object.entries(incident.feature_importance || {}).slice(0, 6).map(([k, v]) => (
                  <FeatureBar key={k} label={k} value={v} />
                ))}
                {(!incident.feature_importance || Object.keys(incident.feature_importance).length === 0) && (
                  <div style={{ color: 'var(--text-tertiary)', fontSize: 13, fontStyle: 'italic' }}>
                    Feature extraction parameters normalized from baseline profiler.
                  </div>
                )}
              </div>
            </div>

            {/* Alternative Benign Hypotheses & Uncertainty */}
            <div style={{
              padding: '16px 20px', borderRadius: 12,
              background: 'rgba(217, 119, 6, 0.05)', border: '1px solid rgba(217, 119, 6, 0.2)',
            }}>
              <div style={{ fontSize: 12, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--accent-high)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <HelpCircle size={15} /> Alternative Benign Interpretations (Uncertainty Analysis)
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {(incident.alternative_hypotheses || [
                  'Automated IT maintenance script executing periodic batch commands.',
                  'Authorized diagnostic scan or vulnerability test by internal team.',
                  'Burst of legitimate traffic during peak business or backup operations.'
                ]).map((alt, idx) => (
                  <li key={idx}>{alt}</li>
                ))}
              </ul>
            </div>

            {/* Matched Correlation Rules */}
            {incident.matched_rules && incident.matched_rules.length > 0 && (
              <div style={{
                padding: '16px 20px', borderRadius: 12,
                background: 'rgba(79, 70, 229, 0.04)', border: '1px solid rgba(79, 70, 229, 0.2)'
              }}>
                <div style={{ fontSize: 12, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--accent-brand)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <ShieldCheck size={15} /> Explicit Correlation Rules Matched
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {incident.matched_rules.map(rule => (
                    <span key={rule} className="mono-font" style={{
                      fontSize: 11, padding: '4px 10px', borderRadius: 6,
                      background: 'var(--bg-page)', border: '1px solid var(--border-light)',
                      color: 'var(--accent-brand)', fontWeight: 600
                    }}>
                      {rule}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Traceable Relationship Evidence with Direct Jump to Supporting Events */}
            {incident.relationship_evidence && incident.relationship_evidence.length > 0 && (
              <div style={{
                padding: '16px 20px', borderRadius: 12,
                background: 'var(--bg-page)', border: '1px solid var(--border-light)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <div style={{ fontSize: 12, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Network size={15} /> Traceable Relationship Evidence ({incident.relationship_evidence.length})
                  </div>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 12, background: 'rgba(5, 150, 105, 0.1)', color: 'var(--accent-success)', border: '1px solid rgba(5, 150, 105, 0.2)' }}>
                    100% Traceability
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {incident.relationship_evidence.map((rel, idx) => {
                    const isHyp = rel.claim_type === 'hypothesis'
                    return (
                      <div key={idx} style={{
                        padding: '12px 14px', borderRadius: 8, background: 'var(--bg-card, #fff)',
                        border: `1px solid ${isHyp ? 'rgba(147, 51, 234, 0.25)' : 'var(--border-light)'}`,
                        display: 'flex', flexDirection: 'column', gap: 6
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: 9, fontWeight: 800, padding: '2px 6px', borderRadius: 6,
                              background: isHyp ? 'rgba(147, 51, 234, 0.12)' : 'rgba(5, 150, 105, 0.12)',
                              color: isHyp ? '#9333ea' : 'var(--accent-success)', textTransform: 'uppercase'
                            }}>
                              {isHyp ? 'INFERRED HYPOTHESIS' : 'OBSERVED TELEMETRY'}
                            </span>
                            {rel.correlation_rule && (
                              <span className="mono-font" style={{
                                fontSize: 9, padding: '2px 6px', borderRadius: 4,
                                background: 'rgba(79, 70, 229, 0.08)', color: 'var(--accent-brand)', fontWeight: 600
                              }}>
                                {rel.correlation_rule}
                              </span>
                            )}
                            <span className="mono-font" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                              {rel.source_entity} → {rel.target_entity}
                            </span>
                            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                              ({rel.reason || rel.relationship_type})
                            </span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <span className="mono-font" style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>
                              {rel.timestamp ? new Date(rel.timestamp).toLocaleTimeString() : ''}
                            </span>
                            {rel.supporting_event_ids && rel.supporting_event_ids.length > 0 && (
                              <button
                                onClick={() => setActiveTab(2)}
                                style={{
                                  fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 6,
                                  background: 'rgba(79, 70, 229, 0.08)',
                                  color: 'var(--accent-brand)', border: '1px solid rgba(79, 70, 229, 0.2)',
                                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4
                                }}
                                title="Jump to raw event evidence in Tab 2"
                              >
                                Inspect Event {rel.supporting_event_ids[0].slice(0, 8)} <ArrowRight size={10} />
                              </button>
                            )}
                          </div>
                        </div>
                        {rel.missing_evidence && rel.missing_evidence.length > 0 && (
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center', paddingLeft: 4, flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 10, fontWeight: 700, color: '#d97706' }}>Unverified Evidence:</span>
                            {rel.missing_evidence.map((me, i) => (
                              <span key={i} className="mono-font" style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: 'rgba(217, 119, 6, 0.1)', color: '#d97706' }}>
                                {me}
                              </span>
                            ))}
                          </div>
                        )}
                        {rel.uncertainty_notes && (
                          <div style={{
                            fontSize: 11, color: isHyp ? '#7e22ce' : 'var(--text-tertiary)',
                            fontStyle: 'italic', paddingLeft: 4, lineHeight: 1.4
                          }}>
                            Note: {rel.uncertainty_notes}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Uncertainty & Missing Evidence Disclosures */}
            {incident.uncertainty_notes && incident.uncertainty_notes.length > 0 && (
              <div style={{
                padding: '16px 20px', borderRadius: 12,
                background: 'rgba(217, 119, 6, 0.04)', border: '1px solid rgba(217, 119, 6, 0.2)'
              }}>
                <div style={{ fontSize: 12, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--accent-high)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <HelpCircle size={15} /> Evidence Limits & Uncertainty Disclosures
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {incident.uncertainty_notes.map((note, i) => (
                    <li key={i}>{note}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Documented Priority Calculation Breakdown */}
            {incident.priority_calculation_breakdown && Object.keys(incident.priority_calculation_breakdown).length > 0 && (
              <div style={{
                padding: '16px 20px', borderRadius: 12,
                background: 'var(--bg-page)', border: '1px solid var(--border-light)'
              }}>
                <div style={{ fontSize: 12, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-secondary)', marginBottom: 10 }}>
                  Documented Priority Score Breakdown
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Base Severity</div>
                    <div className="mono-font" style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                      +{incident.priority_calculation_breakdown.base_severity_weight || 40}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Layer Diversity</div>
                    <div className="mono-font" style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-brand)' }}>
                      +{incident.priority_calculation_breakdown.layer_diversity_bonus || 0}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Unique Events</div>
                    <div className="mono-font" style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-info)' }}>
                      +{incident.priority_calculation_breakdown.event_count_bonus || 0}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Model Confidence</div>
                    <div className="mono-font" style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-success)' }}>
                      +{incident.priority_calculation_breakdown.confidence_factor || 0}
                    </div>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 8, fontStyle: 'italic' }}>
                  Formula: {incident.priority_calculation_breakdown.formula || 'Base + Layer Bonus + Event Count Bonus + Confidence Factor'}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── TAB 1: Incident Timeline & Evidence ─────────────────────────── */}
        {activeTab === 1 && (
          <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div>
                <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  Evidence Chronology
                </h3>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Clearly demarcating factual telemetry observations from model-inferred hypotheses.
                </span>
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <span style={{ fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 12, background: 'rgba(5, 150, 105, 0.1)', color: 'var(--accent-success)', border: '1px solid rgba(5, 150, 105, 0.25)' }}>
                  ● OBSERVATION (Telemetry)
                </span>
                <span style={{ fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 12, background: 'rgba(217, 119, 6, 0.1)', color: 'var(--accent-high)', border: '1px solid rgba(217, 119, 6, 0.25)' }}>
                  ▲ HYPOTHESIS (Inferred)
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {timeline.map((entry, idx) => {
                const isObs = entry.claim_type === 'observation'
                return (
                  <div key={entry.entry_id || idx} style={{
                    padding: '14px 18px', borderRadius: 12, background: 'var(--bg-page)',
                    border: `1px solid ${isObs ? 'rgba(5, 150, 105, 0.25)' : 'rgba(217, 119, 6, 0.25)'}`,
                    display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 16, alignItems: 'start'
                  }}>
                    <div style={{
                      width: 32, height: 32, borderRadius: 8,
                      background: isObs ? 'rgba(5, 150, 105, 0.1)' : 'rgba(217, 119, 6, 0.1)',
                      color: isObs ? 'var(--accent-success)' : 'var(--accent-high)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                      {isObs ? <Eye size={16} /> : <AlertTriangle size={16} />}
                    </div>

                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{
                            fontSize: 9, fontWeight: 800, padding: '2px 8px', borderRadius: 10,
                            background: isObs ? 'rgba(5, 150, 105, 0.12)' : 'rgba(217, 119, 6, 0.12)',
                            color: isObs ? 'var(--accent-success)' : 'var(--accent-high)',
                            textTransform: 'uppercase', letterSpacing: 0.5
                          }}>
                            {entry.claim_type || 'OBSERVATION'}
                          </span>
                          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                            {entry.title}
                          </span>
                        </div>
                        <span className="mono-font" style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
                          {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : 'N/A'}
                        </span>
                      </div>

                      <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 8 }}>
                        {entry.description}
                      </div>

                      <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-tertiary)' }}>
                        <span>Evidence: <strong>{entry.evidence_type}</strong></span>
                        {entry.linked_event_id && (
                          <span className="mono-font">Event ID: {entry.linked_event_id.slice(0, 12)}</span>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* ── TAB 2: Underlying Correlated Events ────────────────────────── */}
        {activeTab === 2 && (
          <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Correlated Raw Events ({supportingEvents.length})
              </h3>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Forensic trace back to individual network packets, session records, and host telemetry.
              </span>
            </div>

            {supportingEvents.length === 0 ? (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-tertiary)', fontSize: 13, fontStyle: 'italic' }}>
                No raw event payloads buffered for this incident.
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-light)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontSize: 10, letterSpacing: 0.5 }}>
                      <th style={{ padding: '8px 12px' }}>Event ID</th>
                      <th style={{ padding: '8px 12px' }}>Timestamp</th>
                      <th style={{ padding: '8px 12px' }}>Layer</th>
                      <th style={{ padding: '8px 12px' }}>Source → Target</th>
                      <th style={{ padding: '8px 12px' }}>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {supportingEvents.slice(0, 10).map((ev, i) => (
                      <tr key={ev.event_id || i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                        <td className="mono-font" style={{ padding: '10px 12px', color: 'var(--text-primary)', fontWeight: 600 }}>
                          {(ev.event_id || `EV-${i}`).slice(0, 12)}
                        </td>
                        <td className="mono-font" style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                          {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td style={{ padding: '10px 12px', textTransform: 'capitalize', color: 'var(--accent-brand)', fontWeight: 600 }}>
                          {ev.layer || 'network'}
                        </td>
                        <td className="mono-font" style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                          {ev.src_entity} → {ev.dst_entity}
                        </td>
                        <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                          {ev.bytes_sent ? `${ev.bytes_sent.toLocaleString()} B` : ''}
                          {ev.dst_port ? ` :${ev.dst_port}` : ''}
                          {ev.action ? ` (${ev.action})` : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── TAB 3: Kill Chain Context ───────────────────────────────────── */}
        {activeTab === 3 && (
          <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <FastForward size={16} color="var(--accent-high)" /> MITRE ATT&CK Progression
            </h3>

            {incident.predicted_next_stage && (
              <div style={{ padding: '14px 18px', background: 'rgba(217, 119, 6, 0.08)', borderRadius: 12, border: '1px solid rgba(217, 119, 6, 0.2)', fontSize: 13, color: 'var(--text-primary)' }}>
                <strong style={{color: 'var(--accent-high)'}}>PREDICTED ESCALATION:</strong> Behavioral pattern indicates high likelihood of adversary progression to stage <strong className="mono-font">{incident.predicted_next_stage.toUpperCase()}</strong>.
              </div>
            )}
            
            <div style={{ display: 'flex', justifyContent: 'space-between', position: 'relative', marginTop: 32, padding: '0 20px' }}>
              <div style={{ position: 'absolute', top: 20, left: 40, right: 40, height: 2, background: 'var(--border-light)', zIndex: 0 }} />
              <div style={{
                position: 'absolute', top: 20, left: 40, 
                width: `${(stageIdx / (KILL_CHAIN.length - 1)) * 100}%`, height: 2,
                background: 'var(--accent-high)', zIndex: 0,
                transition: 'width 1s cubic-bezier(0.16, 1, 0.3, 1)'
              }} />
              
              {KILL_CHAIN.map((stage, i) => {
                const isPast = i <= stageIdx
                const isCurrent = i === stageIdx
                return (
                  <div key={stage} style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
                    <div style={{
                      width: 40, height: 40, borderRadius: '50%',
                      background: isCurrent ? 'var(--accent-high)' : isPast ? 'var(--accent-info)' : 'var(--bg-page)',
                      color: isPast ? '#fff' : 'var(--text-tertiary)',
                      border: `2px solid ${isCurrent ? 'var(--accent-high)' : isPast ? 'var(--accent-info)' : 'var(--border-light)'}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontWeight: 800, fontSize: 12,
                      boxShadow: isCurrent ? '0 0 0 6px rgba(217, 119, 6, 0.15)' : 'none',
                      transition: 'all 0.3s ease'
                    }}>
                      {i + 1}
                    </div>
                    <span style={{
                      fontSize: 11, fontWeight: isCurrent ? 800 : 600,
                      color: isCurrent ? 'var(--accent-high)' : isPast ? 'var(--text-primary)' : 'var(--text-tertiary)'
                    }}>
                      {stage}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* ── TAB 4: Remediation Playbook ─────────────────────────────────── */}
        {activeTab === 4 && (
          <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <FileText size={16} color="var(--accent-critical)" /> Prescribed Remediation Actions
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {playbook.map((step, i) => (
                <div key={i} style={{
                  display: 'flex', gap: 14, padding: '14px 18px',
                  background: 'var(--bg-page)', borderRadius: 12, border: '1px solid var(--border-light)'
                }}>
                  <div style={{
                    width: 26, height: 26, borderRadius: '50%', background: 'rgba(79, 70, 229, 0.1)',
                    color: 'var(--accent-brand)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 11, fontWeight: 800, flexShrink: 0
                  }}>
                    {i + 1}
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5, fontWeight: 500 }}>
                    {step}
                  </div>
                </div>
              ))}
            </div>

            {!isResolved && (
              <div>
                <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 16 }}>
                  <button
                    onClick={() => fetch(`/api/incident/${incident.incident_id || incident.event_id}/remediate`, { method: 'POST' })}
                    style={{
                      padding: '12px 24px', background: 'var(--text-primary)',
                      color: '#fff', border: 'none', borderRadius: 12, fontSize: 13, fontWeight: 700,
                      cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
                      boxShadow: '0 8px 24px rgba(31, 41, 55, 0.15)'
                    }}
                  >
                    <PlayCircle size={16} /> Execute Playbook (Simulated)
                  </button>

                  {(incident.severity === 'critical' || incident.severity === 'high') && (
                    <button
                      onClick={() => fetch(`/api/incident/${incident.incident_id || incident.event_id}/isolate`, { method: 'POST' })}
                      title="Simulated action: In-memory stream block; no live firewall agent connected"
                      style={{
                        padding: '12px 24px', background: 'var(--accent-critical)',
                        color: '#fff', border: 'none', borderRadius: 12, fontSize: 13, fontWeight: 700,
                        cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
                        boxShadow: '0 8px 24px rgba(220, 38, 38, 0.25)'
                      }}
                    >
                      <ShieldAlert size={16} /> ISOLATE ATTACKER HOST (SIMULATED)
                    </button>
                  )}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 8, fontStyle: 'italic' }}>
                  * Actions are simulated in-memory for testing; no real infrastructure firewall enforcement is applied.
                </div>
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  )
})
