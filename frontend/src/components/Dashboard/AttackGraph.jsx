import { memo } from 'react'
import AttackGraphCore from '../Graph/AttackGraph'

/**
 * Dashboard AttackGraph Wrapper
 * Employs the canonical Cytoscape spatial depth projection component.
 */
export default memo(function AttackGraph() {
  return (
    <div className="glass-panel animate-slide-up" style={{ height: '100%', minHeight: 560, padding: 12, overflow: 'hidden' }}>
      <AttackGraphCore />
    </div>
  )
})
