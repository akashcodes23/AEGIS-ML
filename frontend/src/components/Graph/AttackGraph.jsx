import { useEffect, useRef, useState, useCallback, memo } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import useAlertStore from '../../store/alertStore'
import useReducedMotion from '../../hooks/useReducedMotion'
import {
  KILL_CHAIN_STAGES,
  KILL_CHAIN_DEPTH,
  UNKNOWN_DEPTH,
  normalizeKillChainStage,
} from '../../utils/depth'
import { stateAsOf } from '../../utils/scrubber'

cytoscape.use(dagre)

/* ── Risk & Severity color mapping (Crimson strictly for Critical) ────────── */
function riskColor(score, isCompromised = false) {
  if (isCompromised || score > 0.8) return 'var(--severity-critical-fg)' // Crimson strictly for Critical/Compromised
  if (score > 0.5) return 'var(--severity-high-fg)'     // Amber
  if (score > 0.2) return 'var(--severity-medium-fg)'   // Yellow
  return 'var(--accent-cyan)'                           // Cyan
}

function riskBorderColor(score, isCompromised = false) {
  if (isCompromised || score > 0.8) return 'var(--severity-critical-fg)'
  if (score > 0.5) return 'var(--severity-high-fg)'
  if (score > 0.2) return 'var(--severity-medium-fg)'
  return 'var(--border-subtle)'
}

/* ── Cytoscape stylesheet (Spatial Intelligence Theme) ───────────────────── */
const CY_STYLE = [
  // ── Base node ──
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'text-valign': 'bottom',
      'text-margin-y': 7,
      'font-size': 10,
      'font-family': "var(--font-mono)",
      'font-weight': 600,
      'color': '#f8fafc',
      'background-color': 'rgba(18, 25, 39, 0.85)',
      'border-width': 'data(depth_border_width)',
      'border-color': 'data(depth_border_color)',
      'width': 'data(node_size)',
      'height': 'data(node_size)',
      'opacity': 'data(depth_opacity)',
      'z-index': 'data(depth_z_index)',
    },
  },
  // ── Node shapes by type ──
  {
    selector: 'node[node_type="ip"]',
    style: {
      'shape': 'ellipse',
    },
  },
  {
    selector: 'node[node_type="process"]',
    style: {
      'shape': 'diamond',
    },
  },
  {
    selector: 'node[node_type="user"]',
    style: {
      'shape': 'round-rectangle',
      'corner-radius': 6,
    },
  },
  // ── Compromised nodes (Crimson strictly reserved) ──
  {
    selector: 'node[?is_compromised]',
    style: {
      'border-width': 3.5,
      'border-color': '#ff3366',
      'background-color': 'rgba(255, 51, 102, 0.18)',
      'shadow-blur': 16,
      'shadow-color': 'rgba(255, 51, 102, 0.45)',
      'shadow-opacity': 0.8,
    },
  },
  // ── Selected ──
  {
    selector: ':selected',
    style: {
      'border-color': 'var(--accent-cyan)',
      'border-width': 3.5,
      'shadow-blur': 18,
      'shadow-color': 'rgba(0, 240, 255, 0.6)',
      'shadow-opacity': 0.9,
    },
  },
  // ── Base edge ──
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': 'rgba(148, 163, 184, 0.3)',
      'target-arrow-color': 'rgba(148, 163, 184, 0.5)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'opacity': 0.75,
    },
  },
  // ── Inferred lateral pivot edge ──
  {
    selector: 'edge[edge_type="inferred_correlation"]',
    style: {
      'line-color': 'rgba(168, 85, 247, 0.6)',
      'target-arrow-color': 'rgba(168, 85, 247, 0.8)',
      'line-style': 'dashed',
      'line-dash-pattern': [6, 3],
      'width': 2,
    },
  },
  // ── Anomalous edge ──
  {
    selector: 'edge[?is_anomalous]',
    style: {
      'line-color': 'var(--severity-critical-fg)',
      'target-arrow-color': 'var(--severity-critical-fg)',
      'line-style': 'dashed',
      'line-dash-pattern': [6, 3],
      'width': 2.5,
      'opacity': 0.9,
    },
  },
  // ── Hover ──
  {
    selector: 'node.hovered',
    style: {
      'border-color': 'var(--accent-cyan)',
      'border-width': 3,
      'z-index': 9999,
    },
  },
]

/* ── Node Dossier Tooltip Component ───────────────────────────────────────── */
function Tooltip({ node, position }) {
  if (!node) return null
  const { label, ip, risk_score, event_count, is_compromised, node_type, kill_chain_stage, is_stage_known } = node
  const riskLabel = risk_score > 0.8 ? 'Critical' : risk_score > 0.5 ? 'High' : risk_score > 0.2 ? 'Medium' : 'Low'
  const riskCol = riskColor(risk_score || 0, is_compromised)

  return (
    <div
      role="tooltip"
      aria-live="polite"
      style={{
        position: 'fixed',
        left: position.x + 14,
        top: position.y - 10,
        zIndex: 99999,
        pointerEvents: 'none',
        background: 'var(--surface-3)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 14,
        padding: '14px 18px',
        boxShadow: 'var(--shadow-elevation-3)',
        minWidth: 240,
        fontFamily: 'var(--font-ui)',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <span style={{ fontSize: 16 }}>
          {node_type === 'process' ? '⚙️' : node_type === 'user' ? '👤' : '🌐'}
        </span>
        <div>
          <div style={{ fontWeight: 800, fontSize: 13, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {label || ip || 'Unknown'}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.8 }}>
            {node_type || 'ip'} entity
          </div>
        </div>
        {is_compromised && (
          <span style={{
            marginLeft: 'auto',
            background: 'var(--severity-critical-bg)',
            border: '1px solid var(--severity-critical-border)',
            color: 'var(--severity-critical-fg)',
            fontSize: 9, fontWeight: 800, letterSpacing: 0.8,
            padding: '2px 8px', borderRadius: 12, textTransform: 'uppercase',
          }}>
            Compromised
          </span>
        )}
      </div>

      {/* Kill Chain Stage Notice (Truthful: never guesses) */}
      <div style={{
        marginBottom: 10,
        padding: '6px 10px',
        borderRadius: 8,
        background: is_stage_known ? 'rgba(0, 240, 255, 0.08)' : 'rgba(148, 163, 184, 0.08)',
        border: `1px solid ${is_stage_known ? 'rgba(0, 240, 255, 0.25)' : 'var(--border-hairline)'}`,
        fontSize: 11,
      }}>
        <div style={{ fontSize: 9, color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: 0.6 }}>
          Kill-Chain Progression
        </div>
        <div style={{
          fontWeight: 700,
          color: is_stage_known ? 'var(--accent-cyan)' : 'var(--text-secondary)',
          display: 'flex', alignItems: 'center', gap: 6, marginTop: 2
        }}>
          <span>{is_stage_known ? `${kill_chain_stage}` : 'Unknown Stage'}</span>
          <span style={{ fontSize: 10, color: 'var(--text-tertiary)', fontWeight: 500 }}>
            {is_stage_known ? `(Depth ${KILL_CHAIN_DEPTH[kill_chain_stage]?.index + 1}/8)` : '(No alert stage)'}
          </span>
        </div>
      </div>

      {/* Stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 14px' }}>
        {[
          ['IP Address', ip || label || '—'],
          ['Risk Score', (risk_score || 0).toFixed(3)],
          ['Severity Tier', riskLabel],
          ['Correlated Events', event_count ?? '—'],
        ].map(([k, v], i) => (
          <div key={i}>
            <div style={{ fontSize: 9, color: 'var(--text-tertiary)', letterSpacing: 0.8, textTransform: 'uppercase', marginBottom: 1 }}>{k}</div>
            <div className="tabular-nums" style={{
              fontSize: 11, fontWeight: 700,
              color: k === 'Risk Score' || k === 'Severity Tier' ? riskCol : 'var(--text-primary)',
            }}>{v}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Compact Spatial Depth Legend Component ───────────────────────────────── */
function DepthLegend() {
  return (
    <div
      aria-label="Spatial Depth Scale Legend"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 8,
        padding: '8px 14px',
        background: 'var(--surface-1)',
        border: '1px solid var(--border-hairline)',
        borderRadius: 10,
        fontSize: 11,
        color: 'var(--text-secondary)',
        fontFamily: 'var(--font-ui)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: 'var(--text-tertiary)' }}>
          Depth Scale:
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Atmospheric Fog (Recon) → Crisp Foreground (Impact)</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {KILL_CHAIN_STAGES.map((stg) => {
          const depth = KILL_CHAIN_DEPTH[stg]
          return (
            <div
              key={stg}
              title={`${stg}: Depth Tier ${depth.index + 1}/8, Size ${depth.nodeSize}px, Opacity ${depth.opacity}`}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                padding: '2px 6px',
                borderRadius: 6,
                background: 'var(--surface-2)',
                border: '1px solid var(--border-hairline)',
                fontSize: 10,
              }}
            >
              <span
                style={{
                  width: Math.round(depth.nodeSize * 0.22),
                  height: Math.round(depth.nodeSize * 0.22),
                  borderRadius: '50%',
                  background: 'var(--accent-cyan)',
                  opacity: depth.opacity,
                  display: 'inline-block',
                }}
                aria-hidden="true"
              />
              <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{stg}</span>
            </div>
          )
        })}

        {/* Unknown Stage Neutral Indicator */}
        <div
          title="Unknown Stage: Entities with unassigned or missing alert kill-chain stages"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            padding: '2px 6px',
            borderRadius: 6,
            background: 'var(--surface-2)',
            border: '1px solid var(--border-subtle)',
            fontSize: 10,
            color: 'var(--text-muted)',
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--text-muted)',
              display: 'inline-block',
            }}
            aria-hidden="true"
          />
          <span>Unknown</span>
        </div>
      </div>
    </div>
  )
}

/* ── Main Component ───────────────────────────────────────────────────────── */
export default memo(function AttackGraph() {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const graphData = useAlertStore(s => s.graphData)
  const alerts = useAlertStore(s => s.alerts)
  const incidents = useAlertStore(s => s.incidents)
  const selectedIncidentId = useAlertStore(s => s.selectedIncident || s.focusIncidentId)
  const scrubberTime = useAlertStore(s => s.scrubberTime)
  const selectIncident = useAlertStore(s => s.selectIncident)
  const setFocusIncidentId = useAlertStore(s => s.setFocusIncidentId)
  const reducedMotion = useReducedMotion()

  const [tooltip, setTooltip] = useState(null)
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)
  const [anomalousCount, setAnomalousCount] = useState(0)

  /* Node stage resolver: derives real kill-chain stage without guessing */
  const resolveNodeStage = useCallback((n) => {
    // 1. Direct stage on node
    if (n.current_kill_chain_stage) return n.current_kill_chain_stage
    if (n.stage) return n.stage

    // 2. Matching alert stage (highest progression)
    const matchingAlerts = alerts.filter(a => a.src_entity === n.id || a.dst_entity === n.id)
    if (matchingAlerts.length > 0) {
      for (const a of matchingAlerts) {
        if (a.current_kill_chain_stage) return a.current_kill_chain_stage
        if (a.threat_type) {
          const norm = normalizeKillChainStage(a.threat_type)
          if (norm.isKnown) return norm.stage
        }
      }
    }

    // 3. Matching incident stage
    const matchingInc = incidents.find(inc => inc.affected_entities && inc.affected_entities.includes(n.id))
    if (matchingInc && matchingInc.current_kill_chain_stage) {
      return matchingInc.current_kill_chain_stage
    }

    return null
  }, [alerts, incidents])

  /* Applies per-node Depth is Data spatial styling */
  const applyDynamicStyles = useCallback((cy) => {
    cy.nodes().forEach(node => {
      const data = node.data()
      const rawStage = resolveNodeStage(data)
      const norm = normalizeKillChainStage(rawStage)
      const depth = norm.isKnown ? norm.depth : UNKNOWN_DEPTH

      const isCompromised = Boolean(data.is_compromised)
      const borderCol = riskBorderColor(data.risk_score || 0, isCompromised)
      const bgCol = isCompromised ? 'rgba(255, 51, 102, 0.2)' : 'rgba(18, 25, 39, 0.88)'

      node.data({
        ...data,
        kill_chain_stage: norm.stage,
        is_stage_known: norm.isKnown,
        node_size: depth.nodeSize,
        depth_opacity: depth.opacity,
        depth_border_width: depth.borderWidth,
        depth_z_index: depth.zIndex,
        depth_border_color: borderCol,
      })

      node.style({
        'background-color': bgCol,
        'border-color': borderCol,
        'border-width': depth.borderWidth,
        'width': depth.nodeSize,
        'height': depth.nodeSize,
        'opacity': depth.opacity,
        'z-index': depth.zIndex,
      })
    })

    // Edge styling
    cy.edges().forEach(edge => {
      const freq = edge.data('frequency') || 1
      const w = Math.min(4, Math.max(1.2, freq * 0.4))
      const isAnomalous = Boolean(edge.data('is_anomalous'))
      const isHypothesis = edge.data('edge_type') === 'inferred_correlation'

      edge.style({
        'width': w,
        'line-color': isAnomalous
          ? '#ff3366'
          : isHypothesis
            ? 'rgba(168, 85, 247, 0.65)'
            : 'rgba(148, 163, 184, 0.3)',
        'target-arrow-color': isAnomalous
          ? '#ff3366'
          : isHypothesis
            ? 'rgba(168, 85, 247, 0.8)'
            : 'rgba(148, 163, 184, 0.5)',
      })
    })
  }, [resolveNodeStage])

  /* Initialize Cytoscape */
  useEffect(() => {
    if (!containerRef.current) return

    const cy = cytoscape({
      container: containerRef.current,
      style: CY_STYLE,
      layout: { name: 'preset' },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      minZoom: 0.2,
      maxZoom: 4,
      hideEdgesOnViewport: true,
      textureOnViewport: true,
    })
    cyRef.current = cy
    if (typeof window !== 'undefined') {
      window.__cytoscape_instance__ = cy
    }

    /* Node click → tooltip */
    cy.on('tap', 'node', (evt) => {
      const node = evt.target
      const rendered = node.renderedPosition()
      const container = containerRef.current.getBoundingClientRect()
      setTooltip({
        node: node.data(),
        position: { x: container.left + rendered.x, y: container.top + rendered.y },
      })
      node.select()
    })

    /* Click canvas → close tooltip */
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setTooltip(null)
        cy.nodes().unselect()
      }
    })

    /* Hover */
    cy.on('mouseover', 'node', (evt) => evt.target.addClass('hovered'))
    cy.on('mouseout', 'node', (evt) => evt.target.removeClass('hovered'))

    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [])

  /* Update graph when Zustand graphData changes */
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    const nodes = graphData?.nodes || []
    const edges = graphData?.edges || []

    if (!nodes.length && !edges.length) return

    cy.batch(() => {
      nodes.forEach(n => {
        if (!cy.getElementById(n.id).length) {
          const rawStage = resolveNodeStage(n)
          const norm = normalizeKillChainStage(rawStage)
          const depth = norm.isKnown ? norm.depth : UNKNOWN_DEPTH

          cy.add({
            group: 'nodes',
            data: {
              id: n.id,
              label: n.label || n.ip || n.id,
              ip: n.ip,
              node_type: n.node_type || 'ip',
              risk_score: n.risk_score || 0,
              event_count: n.event_count || 0,
              is_compromised: n.is_compromised || false,
              role: n.role,
              kill_chain_stage: norm.stage,
              is_stage_known: norm.isKnown,
              node_size: depth.nodeSize,
              depth_opacity: depth.opacity,
              depth_border_width: depth.borderWidth,
              depth_z_index: depth.zIndex,
              depth_border_color: riskBorderColor(n.risk_score || 0, n.is_compromised),
            },
          })
        } else {
          cy.getElementById(n.id).data(n)
        }
      })

      edges.forEach(e => {
        if (!cy.getElementById(e.id).length) {
          cy.add({
            group: 'edges',
            data: {
              id: e.id,
              source: e.source,
              target: e.target,
              is_anomalous: e.is_anomalous || false,
              frequency: e.frequency || 1,
              label: e.label || '',
              edge_type: e.edge_type || 'observed_telemetry',
            },
          })
        }
      })
    })

    applyDynamicStyles(cy)

    /* Hierarchical Dagre layout */
    cy.layout({
      name: 'dagre',
      rankDir: 'LR',
      nodeSep: 60,
      rankSep: 110,
      edgeSep: 14,
      animate: !reducedMotion,
      animationDuration: reducedMotion ? 0 : 380,
      fit: true,
      padding: 24,
    }).run()

    setNodeCount(cy.nodes().length)
    setEdgeCount(cy.edges().length)
    setAnomalousCount(cy.edges().filter('[?is_anomalous]').length)
  }, [graphData, applyDynamicStyles, reducedMotion, resolveNodeStage])

  /* ── Camera Glide & Focus on Incident Selection ── */
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    if (!selectedIncidentId) {
      applyDynamicStyles(cy)
      return
    }

    const inc = incidents.find(i =>
      i.incident_id === selectedIncidentId ||
      i.event_id === selectedIncidentId ||
      (Array.isArray(i.alert_ids) && i.alert_ids.includes(selectedIncidentId))
    )

    if (!inc) return

    const involved = new Set(
      inc.affected_entities ||
      [inc.src_entity, inc.dst_entity, inc.primary_attacker, inc.primary_target].filter(Boolean)
    )

    if (Array.isArray(inc.relationship_evidence)) {
      inc.relationship_evidence.forEach(r => {
        if (r.source_entity) involved.add(r.source_entity)
        if (r.target_entity) involved.add(r.target_entity)
      })
    }

    const targetNodes = cy.nodes().filter(n => involved.has(n.id()))
    if (targetNodes.length > 0) {
      // 1. Camera Glide
      if (reducedMotion) {
        cy.fit(targetNodes, 40)
      } else {
        cy.animate({
          fit: { eles: targetNodes, padding: 50 },
          duration: 420,
          easing: 'ease-in-out-cubic',
        })
      }

      // 2. Dim unrelated nodes and highlight involved nodes
      cy.batch(() => {
        cy.nodes().forEach(n => {
          if (involved.has(n.id())) {
            n.style({ opacity: 1.0, 'border-width': 3.5 })
          } else {
            n.style({ opacity: 0.18 })
          }
        })

        // 3. Highlight only edges backed by real relationship evidence or direct entity interaction
        const relPairs = new Set()
        if (Array.isArray(inc.relationship_evidence)) {
          inc.relationship_evidence.forEach(r => {
            if (r.source_entity && r.target_entity) {
              relPairs.add(`${r.source_entity}->${r.target_entity}`)
            }
          })
        }

        cy.edges().forEach(e => {
          const pair = `${e.source().id()}->${e.target().id()}`
          const isDirectInvolved = involved.has(e.source().id()) && involved.has(e.target().id())
          if (relPairs.has(pair) || isDirectInvolved) {
            e.style({ opacity: 1.0, width: 3.0 })
          } else {
            e.style({ opacity: 0.08 })
          }
        })
      })
    }
  }, [selectedIncidentId, incidents, reducedMotion, applyDynamicStyles])

  /* ── Historical Scrubber Filtering Effect ── */
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    if (scrubberTime === null) {
      cy.batch(() => {
        cy.nodes().style('display', 'element')
        cy.edges().style('display', 'element')
      })
      setNodeCount(cy.nodes().length)
      setEdgeCount(cy.edges().length)
      return
    }

    const historical = stateAsOf(alerts, incidents, scrubberTime)
    cy.batch(() => {
      cy.nodes().forEach(n => {
        if (historical.visibleEntityIds.has(n.id())) {
          n.style('display', 'element')
        } else {
          n.style('display', 'none')
        }
      })

      const visibleEdgeKeys = new Set(
        historical.visibleEdges.map(e => `${e.source}->${e.target}`)
      )
      cy.edges().forEach(e => {
        const key = `${e.source().id()}->${e.target().id()}`
        if (visibleEdgeKeys.has(key) ||
            (historical.visibleEntityIds.has(e.source().id()) && historical.visibleEntityIds.has(e.target().id()))) {
          e.style('display', 'element')
        } else {
          e.style('display', 'none')
        }
      })
    })

    setNodeCount(cy.nodes(':visible').length)
    setEdgeCount(cy.edges(':visible').length)
  }, [scrubberTime, alerts, incidents])

  /* Graph controls */
  const fitGraph = useCallback(() => {
    if (cyRef.current) cyRef.current.fit(undefined, 30)
  }, [])

  const resetZoom = useCallback(() => {
    if (cyRef.current) cyRef.current.zoom(1)
  }, [])

  /* Mock data generator demonstrating known stages and an explicit unknown node */
  const injectMockData = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return

    cy.add([
      { group: 'nodes', data: { id: 'att1', label: '198.51.100.11', ip: '198.51.100.11', node_type: 'ip', risk_score: 0.95, event_count: 52, is_compromised: true, role: 'attacker', stage: 'Weaponize' } },
      { group: 'nodes', data: { id: 'srv1', label: '10.0.0.50', ip: '10.0.0.50', node_type: 'ip', risk_score: 0.65, event_count: 14, is_compromised: true, role: 'server', stage: 'Delivery' } },
      { group: 'nodes', data: { id: 'p1',   label: 'powershell.exe', node_type: 'process', risk_score: 0.82, event_count: 8, stage: 'Install' } },
      { group: 'nodes', data: { id: 'c2',   label: '203.0.113.19', ip: '203.0.113.19', node_type: 'ip', risk_score: 0.91, event_count: 22, stage: 'C2' } },
      { group: 'nodes', data: { id: 'exf',  label: '192.0.2.77', ip: '192.0.2.77', node_type: 'ip', risk_score: 0.98, event_count: 18, is_compromised: true, stage: 'Exfiltrate' } },
      // Deliberately unknown stage entity demonstrating empirical honesty
      { group: 'nodes', data: { id: 'unk_host', label: '10.0.1.99 (Unknown)', ip: '10.0.1.99', node_type: 'ip', risk_score: 0.15, event_count: 2, stage: null } },
      { group: 'edges', data: { id: 'e1', source: 'att1', target: 'srv1', is_anomalous: true, frequency: 12 } },
      { group: 'edges', data: { id: 'e2', source: 'srv1', target: 'p1',   is_anomalous: true, frequency: 6 } },
      { group: 'edges', data: { id: 'e3', source: 'p1',   target: 'c2',   is_anomalous: true, frequency: 15 } },
      { group: 'edges', data: { id: 'e4', source: 'c2',   target: 'exf',  is_anomalous: true, frequency: 24 } },
      { group: 'edges', data: { id: 'e5', source: 'srv1', target: 'unk_host', is_anomalous: false, frequency: 1 } },
    ])

    applyDynamicStyles(cy)
    cy.layout({
      name: 'dagre',
      rankDir: 'LR',
      nodeSep: 60,
      rankSep: 110,
      animate: !reducedMotion,
      animationDuration: reducedMotion ? 0 : 380,
      fit: true,
      padding: 30,
    }).run()

    setNodeCount(cy.nodes().length)
    setEdgeCount(cy.edges().length)
    setAnomalousCount(cy.edges().filter('[?is_anomalous]').length)
  }, [applyDynamicStyles, reducedMotion])

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* ── Top Bar: Metrics & Controls ── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
        padding: '8px 12px',
        background: 'var(--surface-1)',
        border: '1px solid var(--border-hairline)',
        borderRadius: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.8 }}>
            Topology Projection
          </span>
          <span style={{ color: 'var(--border-subtle)' }}>|</span>
          <div className="tabular-nums" style={{ display: 'flex', gap: 10, fontSize: 11, color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
            <span>Nodes: <strong style={{ color: 'var(--text-primary)' }}>{nodeCount}</strong></span>
            <span>Edges: <strong style={{ color: 'var(--text-primary)' }}>{edgeCount}</strong></span>
            <span>Anomalies: <strong style={{ color: anomalousCount > 0 ? 'var(--severity-critical-fg)' : 'var(--text-primary)' }}>{anomalousCount}</strong></span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 6 }}>
          {selectedIncidentId && (
            <button
              type="button"
              onClick={() => {
                selectIncident(null)
                setFocusIncidentId(null)
                if (cyRef.current) {
                  applyDynamicStyles(cyRef.current)
                  cyRef.current.fit(undefined, 30)
                }
              }}
              style={{
                background: 'rgba(251, 146, 60, 0.15)',
                border: '1px solid rgba(251, 146, 60, 0.35)',
                color: 'var(--severity-high-fg)',
                borderRadius: 8,
                padding: '5px 12px',
                fontSize: 11,
                fontWeight: 600,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                transition: 'all var(--duration-quick) ease',
              }}
            >
              <span>✕</span>
              <span>Reset Focus</span>
            </button>
          )}
          <button
            type="button"
            onClick={fitGraph}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--border-hairline)',
              color: 'var(--accent-cyan)',
              borderRadius: 8,
              padding: '5px 12px',
              fontSize: 11,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              transition: 'all var(--duration-quick) ease',
            }}
          >
            <span>⊡</span>
            <span>Fit</span>
          </button>
          <button
            type="button"
            onClick={resetZoom}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--border-hairline)',
              color: 'var(--accent-cyan)',
              borderRadius: 8,
              padding: '5px 12px',
              fontSize: 11,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              transition: 'all var(--duration-quick) ease',
            }}
          >
            <span>◎</span>
            <span>1x</span>
          </button>
          <button
            type="button"
            onClick={injectMockData}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--border-hairline)',
              color: 'var(--accent-cyan)',
              borderRadius: 8,
              padding: '5px 12px',
              fontSize: 11,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              transition: 'all var(--duration-quick) ease',
            }}
          >
            <span>⚡</span>
            <span>Mock Scenarios</span>
          </button>
        </div>
      </div>

      {/* ── Spatial Depth Scale Legend ── */}
      <DepthLegend />

      {/* ── Canvas Container ── */}
      <div
        ref={containerRef}
        role="region"
        aria-label="Interactive Cytoscape Entity Graph"
        tabIndex="0"
        style={{
          flex: 1,
          width: '100%',
          minHeight: 460,
          background: 'var(--surface-0)',
          borderRadius: 12,
          border: '1px solid var(--border-hairline)',
          position: 'relative',
          overflow: 'hidden',
        }}
      />

      {/* ── Tooltip Dossier ── */}
      <Tooltip node={tooltip?.node} position={tooltip?.position || { x: 0, y: 0 }} />
    </div>
  )
})
