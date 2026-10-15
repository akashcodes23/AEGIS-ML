import { useEffect, useRef, useState, useCallback, useId } from 'react'
import {
  Search,
  Compass,
  AlertTriangle,
  Bell,
  Network,
  Clock,
  Sparkles,
  ArrowRight,
  CornerDownLeft,
  X,
} from 'lucide-react'
import { searchPalette } from '../../utils/palette'
import useReducedMotion from '../../hooks/useReducedMotion'

const CATEGORY_ICONS = {
  Navigate: Compass,
  Incidents: AlertTriangle,
  Alerts: Bell,
  Entities: Network,
  Time: Clock,
  Display: Sparkles,
  Action: Sparkles,
}

const SEVERITY_COLORS = {
  critical: 'var(--severity-critical-fg)',
  high: 'var(--severity-high-fg)',
  medium: 'var(--severity-medium-fg)',
  low: 'var(--severity-low-fg)',
}

/**
 * AEGIS Command Palette
 *
 * Implements WAI-ARIA 1.2 Combobox with Listbox Popup & Dialog pattern:
 * - role="dialog", aria-modal="true"
 * - role="combobox" with aria-activedescendant and aria-controls
 * - Keyboard navigation: ArrowUp/Down, Home, End, Enter, Escape
 * - Focus trap & focus restoration to trigger
 * - Polite screen reader announcement of search results count
 * - Elevation 4 design tokens & reduced motion compliance
 */
export default function CommandPalette({
  isOpen,
  onClose,
  triggerRef,
  onNavigate,
  onSelectIncident,
  onFocusEntity,
  onAction,
  sources,
}) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef(null)
  const listboxRef = useRef(null)
  const dialogRef = useRef(null)
  const reducedMotion = useReducedMotion()
  const baseId = useId()

  // Execute pure search query
  const searchResult = searchPalette(query, sources, 20)
  const { results, totalMatches, totalAvailable, hasQuery } = searchResult

  // Focus input on open, restore focus on close
  useEffect(() => {
    if (isOpen) {
      const timer = setTimeout(() => {
        setQuery('')
        setSelectedIndex(0)
        if (inputRef.current) {
          inputRef.current.focus()
        }
      }, 0)
      return () => clearTimeout(timer)
    } else if (triggerRef && triggerRef.current) {
      triggerRef.current.focus()
    }
  }, [isOpen, triggerRef])

  // Scroll active option into view
  useEffect(() => {
    if (isOpen && listboxRef.current) {
      const activeElement = listboxRef.current.querySelector('[aria-selected="true"]')
      if (activeElement && activeElement.scrollIntoView) {
        activeElement.scrollIntoView({ block: 'nearest' })
      }
    }
  }, [selectedIndex, isOpen])

  // Handle execution of selected item
  const executeItem = useCallback((item) => {
    if (!item) return
    onClose()

    switch (item.type) {
      case 'route':
        if (onNavigate) onNavigate(item.target, item.hash)
        break
      case 'incident':
        if (onSelectIncident) {
          onSelectIncident(item.id)
        }
        break
      case 'alert':
        if (onNavigate) {
          onNavigate('Threat Hunting')
        }
        break
      case 'entity':
        if (onFocusEntity) {
          onFocusEntity(item.targetEntity)
        }
        break
      case 'action':
        if (onAction) {
          onAction(item.actionKey)
        }
        break
      default:
        break
    }
  }, [onClose, onNavigate, onSelectIncident, onFocusEntity, onAction])

  // Keyboard navigation
  const handleKeyDown = (e) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
      return
    }

    if (results.length === 0) return

    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex((prev) => (prev + 1) % results.length)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex((prev) => (prev - 1 + results.length) % results.length)
    } else if (e.key === 'Home') {
      e.preventDefault()
      setSelectedIndex(0)
    } else if (e.key === 'End') {
      e.preventDefault()
      setSelectedIndex(results.length - 1)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (results[selectedIndex]) {
        executeItem(results[selectedIndex])
      }
    } else if (e.key === 'Tab') {
      // Focus trap within dialog
      e.preventDefault()
    }
  }

  if (!isOpen) return null

  const activeOptionId = results[selectedIndex]
    ? `${baseId}-opt-${selectedIndex}`
    : undefined

  return (
    <div
      role="presentation"
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 99999,
        background: 'rgba(5, 7, 12, 0.72)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '80px 16px 24px 16px',
        animation: reducedMotion ? 'none' : 'fadeIn 120ms ease-out',
      }}
    >
      {/* ── Dialog Container ────────────────────────────────────────── */}
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Command Palette"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: 680,
          background: 'var(--surface-3)',
          border: '1px solid var(--border-medium)',
          borderRadius: 16,
          boxShadow: 'var(--shadow-elevation-4)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '80vh',
          animation: reducedMotion ? 'none' : 'slideUp 160ms var(--ease-standard)',
        }}
      >
        {/* ── Search Input Header ─────────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '16px 20px',
            borderBottom: '1px solid var(--border-hairline)',
            background: 'var(--surface-2)',
          }}
        >
          <Search size={18} color="var(--accent-cyan)" aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-autocomplete="list"
            aria-expanded="true"
            aria-controls={`${baseId}-results`}
            aria-activedescendant={activeOptionId}
            aria-label="Search actions, views, entities, and incidents"
            placeholder="Type a command, route, entity IP, or incident..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setSelectedIndex(0)
            }}
            onKeyDown={handleKeyDown}
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--text-primary)',
              fontSize: 15,
              fontWeight: 500,
              fontFamily: 'var(--font-ui)',
            }}
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
              aria-label="Clear query"
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-tertiary)',
                cursor: 'pointer',
                padding: 4,
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <X size={14} />
            </button>
          )}
          <kbd
            style={{
              padding: '2px 7px',
              borderRadius: 6,
              background: 'var(--surface-1)',
              border: '1px solid var(--border-hairline)',
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-tertiary)',
            }}
          >
            ESC
          </kbd>
        </div>

        {/* ── Accessible Live Status for Screen Readers ──────────────── */}
        <div role="status" aria-live="polite" className="sr-only">
          {hasQuery
            ? `Showing ${results.length} of ${totalMatches} matching results for ${query}`
            : `Showing ${results.length} initial navigation and quick actions`}
        </div>

        {/* ── Results Listbox ─────────────────────────────────────────── */}
        <div
          id={`${baseId}-results`}
          ref={listboxRef}
          role="listbox"
          aria-label="Command palette suggestions"
          style={{
            padding: '8px',
            overflowY: 'auto',
            maxHeight: 420,
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
          }}
        >
          {results.length === 0 ? (
            <div
              style={{
                padding: '36px 20px',
                textAlign: 'center',
                color: 'var(--text-tertiary)',
                fontSize: 13,
              }}
            >
              No matching commands or entities found for &ldquo;{query}&rdquo;
            </div>
          ) : (
            results.map((item, index) => {
              const isSelected = index === selectedIndex
              const Icon = CATEGORY_ICONS[item.category] || Compass
              const optionId = `${baseId}-opt-${index}`
              const sevColor = item.severity ? SEVERITY_COLORS[item.severity] : null

              return (
                <div
                  key={item.id}
                  id={optionId}
                  role="option"
                  aria-selected={isSelected}
                  onClick={() => executeItem(item)}
                  onMouseEnter={() => setSelectedIndex(index)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '10px 14px',
                    borderRadius: 8,
                    cursor: 'pointer',
                    background: isSelected ? 'var(--surface-1)' : 'transparent',
                    border: `1px solid ${isSelected ? 'var(--border-medium)' : 'transparent'}`,
                    outline: 'none',
                    transition: 'all 60ms ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0, flex: 1 }}>
                    <div
                      style={{
                        width: 32,
                        height: 32,
                        borderRadius: 8,
                        background: isSelected ? 'rgba(0, 240, 255, 0.12)' : 'var(--surface-2)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: isSelected ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                        flexShrink: 0,
                      }}
                      aria-hidden="true"
                    >
                      <Icon size={16} />
                    </div>

                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span
                          style={{
                            fontSize: 13,
                            fontWeight: isSelected ? 700 : 600,
                            color: 'var(--text-primary)',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {item.label}
                        </span>

                        {sevColor && (
                          <span
                            style={{
                              fontSize: 10,
                              textTransform: 'uppercase',
                              fontWeight: 800,
                              color: sevColor,
                              letterSpacing: 0.5,
                              background: '#07090e',
                              padding: '2px 6px',
                              borderRadius: 4,
                              border: '1px solid rgba(255, 255, 255, 0.08)',
                            }}
                          >
                            {item.severity}
                          </span>
                        )}

                        {item.subtitle && (
                          <span
                            style={{
                              fontSize: 11,
                              color: 'var(--text-tertiary)',
                              fontFamily: 'var(--font-mono)',
                            }}
                          >
                            {item.subtitle}
                          </span>
                        )}
                      </div>

                      <div
                        style={{
                          fontSize: 11,
                          color: 'var(--text-secondary)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          marginTop: 2,
                        }}
                      >
                        {item.description}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    <span
                      style={{
                        fontSize: 10,
                        textTransform: 'uppercase',
                        padding: '2px 6px',
                        borderRadius: 4,
                        background: 'var(--surface-2)',
                        color: 'var(--text-tertiary)',
                        fontWeight: 600,
                      }}
                    >
                      {item.category}
                    </span>
                    {isSelected && (
                      <CornerDownLeft size={13} color="var(--accent-cyan)" aria-hidden="true" />
                    )}
                  </div>
                </div>
              )
            })
          )}
        </div>

        {/* ── Footer / Scope Metadata ─────────────────────────────────── */}
        <div
          style={{
            padding: '10px 18px',
            background: 'var(--surface-1)',
            borderTop: '1px solid var(--border-hairline)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 11,
            color: 'var(--text-tertiary)',
            flexWrap: 'wrap',
            gap: 8,
          }}
        >
          <div>
            {hasQuery
              ? `Showing ${results.length} of ${totalMatches} results`
              : `Showing top ${results.length} of ${totalAvailable} available commands`}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span>
              <kbd style={{ fontFamily: 'var(--font-mono)' }}>↑↓</kbd> Navigate
            </span>
            <span>
              <kbd style={{ fontFamily: 'var(--font-mono)' }}>↵</kbd> Select
            </span>
            <span>
              <kbd style={{ fontFamily: 'var(--font-mono)' }}>ESC</kbd> Close
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
