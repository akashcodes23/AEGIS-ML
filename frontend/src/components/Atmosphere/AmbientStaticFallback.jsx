import React from 'react'

/**
 * Ambient Static Fallback
 * 
 * Rendered when:
 * - User enables "Reduce visual effects"
 * - System prefers-reduced-motion is detected
 * - WebGL is unavailable or fails
 * - Device has constrained resources (CPU <= 2 cores or low memory)
 * - VITE_ENABLE_3D=false
 * 
 * Provides an obsidian spatial atmosphere using pure CSS radial gradients
 * and a lightweight SVG node constellation pattern with zero CPU/GPU overhead.
 */
export default function AmbientStaticFallback() {
  return (
    <div
      aria-hidden="true"
      className="ambient-static-fallback"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
        overflow: 'hidden',
        background: `
          radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0, 240, 255, 0.05), transparent 70%),
          radial-gradient(ellipse 60% 40% at 85% 90%, rgba(168, 85, 247, 0.04), transparent 60%),
          radial-gradient(circle at 15% 75%, rgba(14, 23, 42, 0.6), transparent 50%),
          var(--surface-0)
        `,
      }}
    >
      {/* Decorative static SVG node constellation */}
      <svg
        width="100%"
        height="100%"
        xmlns="http://www.w3.org/2000/svg"
        style={{ opacity: 0.18 }}
      >
        <defs>
          <pattern id="static-nodes-pattern" width="160" height="160" patternUnits="userSpaceOnUse">
            <circle cx="20" cy="20" r="1.5" fill="#00f0ff" opacity="0.6" />
            <circle cx="120" cy="50" r="1" fill="#a855f7" opacity="0.4" />
            <circle cx="80" cy="110" r="1.2" fill="#38bdf8" opacity="0.5" />
            <circle cx="150" cy="140" r="0.8" fill="#ffffff" opacity="0.3" />
            <line x1="20" y1="20" x2="80" y2="110" stroke="rgba(0, 240, 255, 0.12)" strokeWidth="0.75" />
            <line x1="80" y1="110" x2="120" y2="50" stroke="rgba(168, 85, 247, 0.1)" strokeWidth="0.75" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#static-nodes-pattern)" />
      </svg>
    </div>
  )
}
