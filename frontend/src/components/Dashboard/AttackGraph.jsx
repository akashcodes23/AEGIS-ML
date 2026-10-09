import { useEffect, useRef, memo } from 'react'
import cytoscape from 'cytoscape'
import { Network, Activity } from 'lucide-react'
import useAlertStore from '../../store/alertStore'

export default memo(function AttackGraph() {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const graphData = useAlertStore(s => s.graphData)

  useEffect(() => {
    if (!containerRef.current) return
    
    // Custom styling utilizing the new soft UI aesthetic
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#FAF9F6', // Off-white
            'border-width': 2,
            'border-color': '#1F2937', 
            'label': 'data(label)',
            'color': '#6B7280',
            'font-size': 10,
            'font-family': "'JetBrains Mono', monospace",
            'font-weight': 600,
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'width': 36,
            'height': 36,
            'transition-property': 'background-color, border-color',
            'transition-duration': 300
          },
        },
        {
          selector: 'node[type="ip"]',
          style: {
            'border-color': '#4F46E5', // brand
            'border-width': 2,
          }
        },
        {
          selector: 'node[?is_compromised]',
          style: {
            'background-color': '#FEF2F2',
            'border-color': '#DC2626', // critical red
            'border-width': 3,
            'color': '#DC2626',
            'shadow-blur': 15,
            'shadow-color': '#DC2626',
            'shadow-opacity': 0.15
          },
        },
        {
          selector: 'node[risk_score < 0.5][!is_compromised]',
          style: {
            'border-color': '#059669', // success green
          }
        },
        {
          selector: 'node[risk_score >= 0.5][risk_score < 0.8][!is_compromised]',
          style: {
            'border-color': '#D97706', // amber warning
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': 'rgba(107, 114, 128, 0.2)',
            'target-arrow-color': 'rgba(107, 114, 128, 0.4)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(threat_type)',
            'font-size': 9,
            'font-family': "'JetBrains Mono', monospace",
            'text-margin-y': -8,
            'color': '#9CA3AF',
            'text-rotation': 'autorotate',
            'transition-property': 'line-color',
            'transition-duration': 300
          },
        },
        {
          selector: 'edge[?is_anomalous]',
          style: {
            'line-color': 'rgba(220, 38, 38, 0.4)',
            'target-arrow-color': 'rgba(220, 38, 38, 0.6)',
            'width': 2,
            'line-style': 'dashed',
            'color': '#DC2626',
          },
        },
        {
          selector: 'edge[edge_type = "inferred_correlation"]',
          style: {
            'line-color': 'rgba(139, 92, 246, 0.7)',
            'target-arrow-color': 'rgba(139, 92, 246, 0.9)',
            'width': 2,
            'line-style': 'dotted',
            'color': '#8B5CF6',
          },
        },
      ],
      layout: { name: 'cose', animate: false },
      userZoomingEnabled: true, userPanningEnabled: true,
      wheelSensitivity: 0.1
    })
    
    return () => { cyRef.current?.destroy(); cyRef.current = null }
  }, [])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy || (!graphData?.nodes?.length && !graphData?.edges?.length)) return
    
    let needsLayout = false
    cy.batch(() => {
      // Add or update nodes
      graphData.nodes.forEach(n => { 
        const existing = cy.getElementById(n.id)
        if (!existing.length) {
          cy.add({ group: 'nodes', data: n })
          needsLayout = true
        } else {
          existing.data(n) // update stats quietly
        }
      })
      // Add or update edges
      graphData.edges.forEach(e => { 
        const edgeId = e.source + '-' + e.target + (e.edge_type ? '-' + e.edge_type : '')
        const existing = cy.getElementById(edgeId)
        if (!existing.length) {
          cy.add({ group: 'edges', data: { id: edgeId, ...e } })
          needsLayout = true
        } else {
          existing.data({ id: edgeId, ...e })
        }
      })
    })
    
    // Smooth organic layout ONLY if fundamental topology changed
    if (needsLayout) {
      cy.layout({ 
        name: 'cose', 
        animate: true, 
        animationDuration: 300, // Reduced duration to prevent queue piling
        animationEasing: 'cubic-bezier(0.16, 1, 0.3, 1)',
        nodeDimensionsIncludeLabels: true,
        idealEdgeLength: 100,
        nodeOverlap: 20
      }).run()
    }
  }, [graphData])

  return (
    <div className="glass-panel animate-slide-up" style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      
      {/* Editorial Header */}
      <div style={{
        padding: '24px 28px', borderBottom: '1px solid var(--border-light)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: 'rgba(255, 255, 255, 0.4)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: 'rgba(79, 70, 229, 0.08)', color: 'var(--accent-brand)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Network size={18} strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>Threat Topology</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Live geographical tracing</div>
          </div>
        </div>
        
        {/* Soft UI Legend */}
        <div style={{ display: 'flex', gap: 16, background: 'var(--bg-page)', padding: '6px 16px', borderRadius: 20, border: '1px solid var(--border-light)' }}>
          {[
            ['var(--accent-critical)', 'Compromised Host'],
            ['var(--accent-brand)', 'Observed Flow'],
            ['#8B5CF6', 'Inferred Pivot']
          ].map(([color, label]) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600 }}>
              <div style={{ width: 8, height: 8, background: color, borderRadius: '50%', boxShadow: `0 0 8px ${color}44` }} />
              {label}
            </div>
          ))}
        </div>
      </div>

      {/* Graph Area */}
      <div style={{ flex: 1, position: 'relative', background: 'rgba(250, 249, 246, 0.3)' }}>
        <div ref={containerRef} style={{ width: '100%', height: '100%' }} />
        
        {!graphData?.nodes?.length && (
          <div className="animate-slide-up" style={{ 
            position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', 
            pointerEvents: 'none', gap: 16
          }}>
            <div style={{
              width: 64, height: 64, borderRadius: 20,
              background: 'var(--bg-page)', color: 'var(--text-tertiary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.02)'
            }}>
              <Activity size={32} strokeWidth={1.5} />
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>Graph Idle</div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Topology will generate upon active telemetry</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
})
