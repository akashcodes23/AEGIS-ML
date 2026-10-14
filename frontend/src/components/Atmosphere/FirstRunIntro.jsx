import { useCallback, useEffect, useRef } from 'react'
import { markIntroSeen } from '../../utils/introDecision.js'

/**
 * FirstRunIntro
 *
 * A brief (~2.4s), skippable, non-blocking brand moment for first-time visitors.
 * Features:
 * - Pure SVG & CSS animation (no Three.js or heavy dependencies)
 * - Zero status/boot text or fake terminal logs
 * - Immediately skippable via Escape, Enter, click, or visible Skip button
 * - Focus managed: auto-focuses Skip, restores focus to main content on dismiss
 * - Non-blocking: background application mounts and streams telemetry underneath
 */
export default function FirstRunIntro({ onDismiss, isReplay = false }) {
  const skipBtnRef = useRef(null)
  const prevFocusRef = useRef(null)

  const handleDismiss = useCallback(() => {
    if (!isReplay) {
      markIntroSeen()
    }
    if (onDismiss) {
      onDismiss()
    }
    // Restore focus cleanly
    requestAnimationFrame(() => {
      const mainTarget = document.getElementById('aegis-main-content') ||
        document.querySelector('main') ||
        prevFocusRef.current
      if (mainTarget && typeof mainTarget.focus === 'function') {
        mainTarget.focus()
      }
    })
  }, [isReplay, onDismiss])

  useEffect(() => {
    // Record previously active element to restore focus on dismiss
    if (typeof document !== 'undefined') {
      prevFocusRef.current = document.activeElement
    }

    // Auto-focus skip button for immediate accessibility
    skipBtnRef.current?.focus()

    // Auto-dismiss after 2.5s if not skipped
    const timer = setTimeout(() => {
      handleDismiss()
    }, 2500)

    const handleKeyDown = (e) => {
      if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        handleDismiss()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => {
      clearTimeout(timer)
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [handleDismiss])

  return (
    <div
      role="region"
      aria-label="Brand introduction"
      onClick={handleDismiss}
      className="aegis-first-run-intro"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 999999,
        background: 'rgba(7, 9, 14, 0.94)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        cursor: 'pointer',
        animation: 'introFadeOut 0.4s ease-out 2.1s forwards',
      }}
    >
      {/* Skip Button */}
      <div
        style={{
          position: 'absolute',
          top: 24,
          right: 28,
          zIndex: 2,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <button
          ref={skipBtnRef}
          type="button"
          onClick={handleDismiss}
          aria-label="Skip brand introduction"
          style={{
            padding: '7px 16px',
            borderRadius: 20,
            background: 'rgba(255, 255, 255, 0.08)',
            border: '1px solid var(--border-medium)',
            color: 'var(--text-secondary)',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.15s ease',
            outline: 'none',
          }}
          onFocus={(e) => {
            e.currentTarget.style.borderColor = 'var(--accent-cyan)'
            e.currentTarget.style.color = 'var(--text-primary)'
            e.currentTarget.style.boxShadow = '0 0 10px rgba(0, 240, 255, 0.3)'
          }}
          onBlur={(e) => {
            e.currentTarget.style.borderColor = 'var(--border-medium)'
            e.currentTarget.style.color = 'var(--text-secondary)'
            e.currentTarget.style.boxShadow = 'none'
          }}
        >
          Skip <span style={{ opacity: 0.6, fontSize: 10, marginLeft: 4 }}>[Esc]</span>
        </button>
      </div>

      {/* Decorative Assembling Brand Emblem */}
      <div
        aria-hidden="true"
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 20,
          pointerEvents: 'none',
        }}
      >
        <svg
          width="120"
          height="120"
          viewBox="0 0 120 120"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          style={{
            filter: 'drop-shadow(0 0 24px rgba(0, 240, 255, 0.35))',
          }}
        >
          {/* Shield Outline Path */}
          <path
            d="M60 12 L100 30 V68 C100 92 60 110 60 110 C60 110 20 92 20 68 V30 L60 12 Z"
            stroke="var(--accent-cyan)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{
              strokeDasharray: 320,
              strokeDashoffset: 320,
              animation: 'introDrawShield 1.4s cubic-bezier(0.16, 1, 0.3, 1) 0.1s forwards',
            }}
          />

          {/* Internal Constellation Filaments */}
          <line
            x1="60"
            y1="34"
            x2="38"
            y2="64"
            stroke="rgba(0, 240, 255, 0.6)"
            strokeWidth="1.5"
            style={{
              strokeDasharray: 60,
              strokeDashoffset: 60,
              animation: 'introDrawLine 0.8s ease-out 0.6s forwards',
            }}
          />
          <line
            x1="60"
            y1="34"
            x2="82"
            y2="64"
            stroke="rgba(0, 240, 255, 0.6)"
            strokeWidth="1.5"
            style={{
              strokeDasharray: 60,
              strokeDashoffset: 60,
              animation: 'introDrawLine 0.8s ease-out 0.6s forwards',
            }}
          />
          <line
            x1="38"
            y1="64"
            x2="60"
            y2="88"
            stroke="rgba(168, 85, 247, 0.7)"
            strokeWidth="1.5"
            style={{
              strokeDasharray: 60,
              strokeDashoffset: 60,
              animation: 'introDrawLine 0.8s ease-out 0.9s forwards',
            }}
          />
          <line
            x1="82"
            y1="64"
            x2="60"
            y2="88"
            stroke="rgba(168, 85, 247, 0.7)"
            strokeWidth="1.5"
            style={{
              strokeDasharray: 60,
              strokeDashoffset: 60,
              animation: 'introDrawLine 0.8s ease-out 0.9s forwards',
            }}
          />

          {/* Constellation Nodes */}
          <circle
            cx="60"
            cy="34"
            r="4.5"
            fill="var(--accent-cyan)"
            style={{ animation: 'introNodePop 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.5s both' }}
          />
          <circle
            cx="38"
            cy="64"
            r="4"
            fill="var(--accent-cyan)"
            style={{ animation: 'introNodePop 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.7s both' }}
          />
          <circle
            cx="82"
            cy="64"
            r="4"
            fill="var(--accent-cyan)"
            style={{ animation: 'introNodePop 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.7s both' }}
          />
          <circle
            cx="60"
            cy="88"
            r="5"
            fill="var(--accent-violet)"
            style={{ animation: 'introNodePop 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) 1.0s both' }}
          />
        </svg>

        {/* Brand Title (strictly product identity, zero status/progress text) */}
        <div
          style={{
            fontFamily: 'var(--font-ui)',
            fontSize: 22,
            fontWeight: 800,
            letterSpacing: 4,
            textTransform: 'uppercase',
            color: 'var(--text-primary)',
            animation: 'introTextFade 0.8s ease-out 0.8s both',
          }}
        >
          AEGIS
        </div>
      </div>
    </div>
  )
}
