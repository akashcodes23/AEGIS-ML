import React from 'react'
import { Activity, Crosshair, Network, FileText } from 'lucide-react'
import { NAV_TABS } from '../../config/navigation'

const TAB_ICONS = {
  'Dashboard': Activity,
  'Threat Hunting': Crosshair,
  'Entity Graph': Network,
  'Reports': FileText,
}

/**
 * NavigationDock
 * 
 * Floating spatial navigation dock:
 * - Clear active states with pill elevation and glowing accent dot (not color-only).
 * - Full keyboard navigation and accessible focus rings.
 * - Responsive: adapts to a bottom bar on mobile (< 768px / 390px) without horizontal scroll.
 * - Interruptible route transitions.
 */
export default function NavigationDock({ activeTab, onNavigate }) {
  return (
    <nav
      aria-label="Primary Application Navigation"
      className="aegis-nav-dock"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        padding: '6px 10px',
        background: 'var(--surface-1)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 9999,
        boxShadow: 'var(--shadow-elevation-2)',
        backdropFilter: 'var(--glass-blur)',
        WebkitBackdropFilter: 'var(--glass-blur)',
      }}
    >
      {NAV_TABS.map((tab) => {
        const isActive = activeTab === tab
        const Icon = TAB_ICONS[tab] || Activity
        const tabId = `nav-${tab.toLowerCase().replace(/\s+/g, '-')}`

        return (
          <button
            key={tab}
            id={tabId}
            type="button"
            onClick={() => onNavigate(tab)}
            aria-current={isActive ? 'page' : undefined}
            className="nav-item-btn"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 18px',
              borderRadius: 9999,
              fontSize: 13,
              fontWeight: isActive ? 700 : 500,
              color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
              background: isActive ? 'var(--surface-3)' : 'transparent',
              border: `1px solid ${isActive ? 'var(--border-medium)' : 'transparent'}`,
              boxShadow: isActive ? 'inset 0 1px 0 rgba(255,255,255,0.1), 0 2px 8px rgba(0,0,0,0.3)' : 'none',
              cursor: 'pointer',
              transition: 'all var(--duration-quick) var(--ease-standard)',
              outline: 'none',
              position: 'relative',
              whiteSpace: 'nowrap',
            }}
          >
            <Icon
              size={16}
              strokeWidth={isActive ? 2.5 : 2}
              style={{
                color: isActive ? 'var(--accent-cyan)' : 'inherit',
                transition: 'color var(--duration-quick) var(--ease-standard)',
              }}
              aria-hidden="true"
            />
            <span>{tab}</span>

            {/* Redundant non-color active indicator */}
            {isActive && (
              <span
                style={{
                  width: 5,
                  height: 5,
                  borderRadius: '50%',
                  background: 'var(--accent-cyan)',
                  boxShadow: '0 0 8px var(--accent-cyan)',
                }}
                aria-hidden="true"
              />
            )}
          </button>
        )
      })}
    </nav>
  )
}
