/**
 * AEGIS-ML Spatial Intelligence Core Utilities
 * "Depth is Data" Philosophy
 */

/**
 * Standard 8-stage Kill-Chain progression sequence.
 * In the spatial intelligence view, earlier stages recede into background fog (deep z-plane),
 * while later stages advance into the foreground crisp plane.
 */
export const KILL_CHAIN_STAGES = [
  'Recon',
  'Weaponize',
  'Delivery',
  'Exploit',
  'Install',
  'C2',
  'Exfiltrate',
  'Impact',
]

/**
 * Kill-chain depth scale mappings.
 * Stage 1 foundation deliverable: Typed constant not yet bound to live alert graph.
 * 
 * Properties per stage:
 * - index: 0 (earliest) to 7 (latest impact)
 * - normalized: 0.0 (receded) to 1.0 (foreground)
 * - zDistance: spatial coordinates in 3D scene units (negative is deep in canvas)
 * - fogFactor: 0.0 (crisp, zero fog) to 0.85 (veiled in atmospheric depth)
 */
export const KILL_CHAIN_DEPTH = Object.freeze(
  KILL_CHAIN_STAGES.reduce((acc, stage, index) => {
    const total = KILL_CHAIN_STAGES.length - 1
    const normalized = Number((index / total).toFixed(3))
    // Receding z-plane: Recon sits at -70, Impact sits at 0 (nearest camera)
    const zDistance = Number((-70 * (1 - normalized)).toFixed(1))
    // Atmospheric fog attenuation
    const fogFactor = Number((0.85 * (1 - normalized)).toFixed(3))

    acc[stage] = Object.freeze({
      stage,
      index,
      normalized,
      zDistance,
      fogFactor,
      label: stage.toUpperCase(),
    })
    return acc
  }, {})
)

/**
 * Focus = Confidence Utility
 * 
 * Encodes model confidence into spatial visual focus:
 * - High confidence (1.0) -> razor sharp (0px blur, 100% opacity, 100% saturation)
 * - Low confidence (0.0) -> softly defocused (4px blur, 55% opacity, 70% saturation)
 *
 * @param {number|null|undefined} confidence - Calibrated confidence value between 0.0 and 1.0
 * @returns {{ blurPx: number, opacity: number, saturation: number, filterString: string }}
 */
export function confidenceToFocus(confidence) {
  // Graceful fallback for missing or uncalibrated confidence
  const num = typeof confidence === 'number' && !Number.isNaN(confidence) ? confidence : 0.5
  const clamped = Math.max(0, Math.min(1, num))

  // Invert confidence for blur: 0 confidence -> 4.0px blur, 1 confidence -> 0.0px blur
  const blurPx = Number(((1 - clamped) * 4.0).toFixed(2))

  // Opacity: 0 confidence -> 0.55, 1 confidence -> 1.00
  const opacity = Number((0.55 + clamped * 0.45).toFixed(3))

  // Saturation: 0 confidence -> 0.70, 1 confidence -> 1.00
  const saturation = Number((0.70 + clamped * 0.30).toFixed(3))

  const filterString = `blur(${blurPx}px) opacity(${opacity}) saturate(${saturation})`

  return {
    blurPx,
    opacity,
    saturation,
    filterString,
  }
}

/**
 * Severity token taxonomy and rules.
 * "Crimson is Rare": Crimson (#ff3366) is strictly reserved for critical severity.
 */
export const SEVERITY_TOKENS = Object.freeze({
  critical: Object.freeze({
    key: 'critical',
    label: 'Critical',
    fg: '#ff3366',
    bg: 'rgba(255, 51, 102, 0.12)',
    border: 'rgba(255, 51, 102, 0.35)',
    icon: 'AlertOctagon',
  }),
  high: Object.freeze({
    key: 'high',
    label: 'High',
    fg: '#fb923c',
    bg: 'rgba(251, 146, 60, 0.12)',
    border: 'rgba(251, 146, 60, 0.35)',
    icon: 'AlertTriangle',
  }),
  medium: Object.freeze({
    key: 'medium',
    label: 'Medium',
    fg: '#facc15',
    bg: 'rgba(250, 204, 21, 0.12)',
    border: 'rgba(250, 204, 21, 0.35)',
    icon: 'AlertCircle',
  }),
  low: Object.freeze({
    key: 'low',
    label: 'Low',
    fg: '#38bdf8',
    bg: 'rgba(56, 189, 248, 0.12)',
    border: 'rgba(56, 189, 248, 0.35)',
    icon: 'Info',
  }),
  info: Object.freeze({
    key: 'info',
    label: 'Info',
    fg: '#818cf8',
    bg: 'rgba(129, 140, 248, 0.12)',
    border: 'rgba(129, 140, 248, 0.35)',
    icon: 'HelpCircle',
  }),
})

/**
 * Validates that a color is not crimson unless the severity is explicitly critical.
 * Lint/test guardrail.
 */
export function isCrimsonReservedForCritical(severity, colorHex) {
  const isCrimsonHex = /^#?(ff3366|dc2626|e11d48|f43f5e)/i.test(colorHex.toLowerCase())
  if (isCrimsonHex && severity !== 'critical') {
    return false
  }
  return true
}
