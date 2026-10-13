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
 * Neutral depth definition for entities with missing, unassigned, or unrecognized stages.
 * Never guesses an attack stage.
 */
export const UNKNOWN_DEPTH = Object.freeze({
  stage: 'Unknown',
  index: -1,
  normalized: 0.35,
  zDistance: -45.0,
  fogFactor: 0.55,
  label: 'UNKNOWN STAGE',
  nodeSize: 28,
  opacity: 0.70,
  borderWidth: 1.5,
  zIndex: 5,
})

/**
 * Kill-chain depth scale mappings.
 * 
 * Properties per stage:
 * - index: 0 (earliest) to 7 (latest impact)
 * - normalized: 0.0 (receded) to 1.0 (foreground)
 * - zDistance: spatial coordinates in 3D scene units (negative is deep in canvas)
 * - fogFactor: 0.0 (crisp, zero fog) to 0.85 (veiled in atmospheric depth)
 * - nodeSize: 26px to 48px
 * - opacity: 0.65 to 1.0
 * - borderWidth: 1.5px to 3.5px
 * - zIndex: 10 to 17 (later stages render above earlier ones)
 */
export const KILL_CHAIN_DEPTH = Object.freeze(
  KILL_CHAIN_STAGES.reduce((acc, stage, index) => {
    const total = KILL_CHAIN_STAGES.length - 1
    const normalized = Number((index / total).toFixed(3))
    // Receding z-plane: Recon sits at -70, Impact sits at 0 (nearest camera)
    const zDistance = Number((-70 * (1 - normalized)).toFixed(1))
    // Atmospheric fog attenuation
    const fogFactor = Number((0.85 * (1 - normalized)).toFixed(3))

    // Visual attributes for 2D Cytoscape spatial depth projection
    const nodeSize = Math.round(26 + normalized * 22) // 26px -> 48px
    const opacity = Number((0.65 + normalized * 0.35).toFixed(2)) // 0.65 -> 1.0
    const borderWidth = Number((1.5 + normalized * 2.0).toFixed(1)) // 1.5px -> 3.5px
    const zIndex = 10 + index

    acc[stage] = Object.freeze({
      stage,
      index,
      normalized,
      zDistance,
      fogFactor,
      label: stage.toUpperCase(),
      nodeSize,
      opacity,
      borderWidth,
      zIndex,
    })
    return acc
  }, {})
)

/**
 * Stage synonym mapping dictionary for robust normalization from backend payloads.
 */
const STAGE_SYNONYMS = {
  // Recon
  'recon': 'Recon',
  'reconnaissance': 'Recon',
  'discovery': 'Recon',
  // Weaponize
  'weaponize': 'Weaponize',
  'weaponization': 'Weaponize',
  'brute_force': 'Weaponize',
  // Delivery
  'delivery': 'Delivery',
  'initial access': 'Delivery',
  'initial_access': 'Delivery',
  // Exploit
  'exploit': 'Exploit',
  'exploitation': 'Exploit',
  'execution': 'Exploit',
  // Install
  'install': 'Install',
  'installation': 'Install',
  'persistence': 'Install',
  'lateral_movement': 'Install',
  'privilege escalation': 'Install',
  'privilege_escalation': 'Install',
  // C2
  'c2': 'C2',
  'c2_beaconing': 'C2',
  'command and control': 'C2',
  'command & control': 'C2',
  // Exfiltrate
  'exfiltrate': 'Exfiltrate',
  'exfiltration': 'Exfiltrate',
  'data_exfiltration': 'Exfiltrate',
  // Impact
  'impact': 'Impact',
}

/**
 * Normalizes backend kill-chain stage strings to the canonical 8-stage depth keys.
 * Never guesses a stage. Unrecognized or missing strings map to UNKNOWN_DEPTH.
 *
 * @param {string|null|undefined} stageString
 * @returns {{ stage: string, isKnown: boolean, depth: object, label: string }}
 */
export function normalizeKillChainStage(stageString) {
  if (typeof stageString !== 'string' || !stageString.trim()) {
    return {
      stage: 'Unknown',
      isKnown: false,
      depth: UNKNOWN_DEPTH,
      label: 'UNKNOWN STAGE',
    }
  }

  const clean = stageString.trim().toLowerCase()
  const matched = STAGE_SYNONYMS[clean]

  if (matched && KILL_CHAIN_DEPTH[matched]) {
    return {
      stage: matched,
      isKnown: true,
      depth: KILL_CHAIN_DEPTH[matched],
      label: matched.toUpperCase(),
    }
  }

  return {
    stage: 'Unknown',
    isKnown: false,
    depth: UNKNOWN_DEPTH,
    label: 'UNKNOWN STAGE',
  }
}

/**
 * Focus = Confidence Utility
 * 
 * Strict Requirement:
 * - NEVER BLUR TEXT. Text stays sharp at all confidence levels.
 * - Calibrated confidence applies only when isCalibrated is true.
 * - Uncalibrated scores receive a neutral visual treatment (neither sharpened nor defocused).
 * - Missing confidence reports "no confidence reported".
 *
 * @param {object|number} param - Either a numeric confidence or options object { confidence, isCalibrated }
 * @returns {{
 *   status: 'calibrated' | 'uncalibrated' | 'missing',
 *   label: string,
 *   isCalibrated: boolean,
 *   value: number | null,
 *   decorationStyle: object,
 *   filterString: string
 * }}
 */
export function confidenceToFocus(param) {
  let conf = null
  let isCalibrated = false

  if (typeof param === 'number') {
    conf = param
    isCalibrated = true // legacy signature fallback
  } else if (param && typeof param === 'object') {
    conf = typeof param.confidence === 'number' && !Number.isNaN(param.confidence) ? param.confidence : null
    isCalibrated = Boolean(param.isCalibrated)
  }

  // 1. Missing confidence
  if (conf === null) {
    return {
      status: 'missing',
      label: 'no confidence reported',
      isCalibrated: false,
      value: null,
      decorationStyle: {
        haloBlur: 0,
        haloOpacity: 0,
        borderOpacity: 0.4,
        saturation: 0.8,
        glowBoxShadow: 'none',
      },
      filterString: 'blur(0px) opacity(0.7) saturate(0.8)',
    }
  }

  const clamped = Math.max(0, Math.min(1, conf))

  // 2. Uncalibrated score (neutral visual treatment)
  if (!isCalibrated) {
    return {
      status: 'uncalibrated',
      label: 'uncalibrated',
      isCalibrated: false,
      value: clamped,
      decorationStyle: {
        haloBlur: 2.0,
        haloOpacity: 0.25,
        borderOpacity: 0.6,
        saturation: 0.85,
        glowBoxShadow: '0 0 12px rgba(148, 163, 184, 0.2)',
      },
      filterString: 'blur(0px) opacity(0.85) saturate(0.85)',
    }
  }

  // 3. Calibrated confidence (crisp halo for high, defocused halo for low)
  // High confidence (1.0) -> halo 1px, opacity 1.0, saturation 1.0
  // Low confidence (0.0) -> halo 6px soft blur, opacity 0.55, saturation 0.70
  const haloBlur = Number(((1 - clamped) * 6.0).toFixed(2))
  const borderOpacity = Number((0.4 + clamped * 0.6).toFixed(3))
  const saturation = Number((0.70 + clamped * 0.30).toFixed(3))

  return {
    status: 'calibrated',
    label: 'calibrated',
    isCalibrated: true,
    value: clamped,
    decorationStyle: {
      haloBlur,
      haloOpacity: Number((0.2 + clamped * 0.6).toFixed(2)),
      borderOpacity,
      saturation,
      glowBoxShadow: clamped > 0.75
        ? '0 0 16px -2px rgba(0, 240, 255, 0.35)'
        : '0 0 8px rgba(0, 240, 255, 0.12)',
    },
    // For decorative elements ONLY; never apply blur filter to text elements!
    filterString: `blur(${Number(((1 - clamped) * 4.0).toFixed(2))}px) opacity(${borderOpacity}) saturate(${saturation})`,
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
