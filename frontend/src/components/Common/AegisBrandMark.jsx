import React from 'react'

/**
 * Original AEGIS Brand Mark
 * Geometric spatial intelligence crest with precision hairlines,
 * aperture facet geometry, and electric cyan/plasma violet accents.
 * 
 * Replaces generic stock shield clip-art.
 */
export default function AegisBrandMark({ size = 36, className = '', glow = false }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
      style={glow ? { filter: 'drop-shadow(0 0 10px rgba(0, 240, 255, 0.45))' } : undefined}
    >
      <defs>
        <linearGradient id="aegis-grad-primary" x1="4" y1="4" x2="44" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00f0ff" />
          <stop offset="100%" stopColor="#a855f7" />
        </linearGradient>
        <linearGradient id="aegis-grad-facet" x1="24" y1="6" x2="24" y2="42" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#101724" stopOpacity="0.3" />
        </linearGradient>
        <radialGradient id="aegis-core-glow" cx="24" cy="24" r="16" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#00f0ff" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Ambient Core Glow */}
      <circle cx="24" cy="24" r="18" fill="url(#aegis-core-glow)" />

      {/* Hexagonal Outer Perimeter (Hairline Chassis) */}
      <polygon
        points="24,4 42,14 42,34 24,44 6,34 6,14"
        stroke="url(#aegis-grad-primary)"
        strokeWidth="1.75"
        strokeLinejoin="round"
        fill="rgba(8, 11, 17, 0.75)"
      />

      {/* Internal Angular Facets (Aperture Geometry) */}
      <polygon
        points="24,11 36,18 36,30 24,37 12,30 12,18"
        stroke="rgba(255, 255, 255, 0.22)"
        strokeWidth="1.2"
        strokeLinejoin="round"
        fill="url(#aegis-grad-facet)"
      />

      {/* Central Spatial Monogram Core (The Vector Vertex) */}
      <path
        d="M24 16L30 27H18L24 16Z"
        fill="url(#aegis-grad-primary)"
        stroke="#00f0ff"
        strokeWidth="1"
        strokeLinejoin="round"
      />
      
      {/* Central Node Dot */}
      <circle cx="24" cy="24" r="2" fill="#ffffff" />

      {/* Orthogonal Telemetry Accents */}
      <line x1="24" y1="4" x2="24" y2="10" stroke="#00f0ff" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="6" y1="14" x2="11" y2="17" stroke="rgba(255, 255, 255, 0.4)" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="42" y1="14" x2="37" y2="17" stroke="rgba(255, 255, 255, 0.4)" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  )
}
