/**
 * AEGIS-ML Adaptive Quality Tier Engine for Ambient 3D Atmosphere
 * Pure functional state machine with hysteresis to prevent oscillation.
 */

export const QUALITY_TIERS = Object.freeze({
  high: Object.freeze({ id: 'high', particleCount: 360, dprCap: 1.75, linkDistance: 50 }),
  medium: Object.freeze({ id: 'medium', particleCount: 200, dprCap: 1.25, linkDistance: 35 }),
  low: Object.freeze({ id: 'low', particleCount: 100, dprCap: 1.0, linkDistance: 20 }),
  fallback: Object.freeze({ id: 'fallback', particleCount: 0, dprCap: 1.0, linkDistance: 0 }),
})

export const DEGRADE_FRAME_TIME_MS = 24.0 // ~41 FPS
export const RECOVER_FRAME_TIME_MS = 14.0 // ~71 FPS
export const DEGRADE_WINDOW_FRAMES = 60
export const RECOVER_WINDOW_FRAMES = 180

/**
 * Pure evaluation function for adaptive graphics quality.
 * Uses strict hysteresis: wide neutral band (14ms - 24ms) and asymmetric
 * window sizes (60 frames to degrade, 180 frames to recover) to eliminate oscillation.
 *
 * @param {Object} state
 * @returns {Object} next state
 */
export function evaluateQualityTier({
  currentTier = 'high',
  rollingAvgFrameTime = 16.6,
  consecutiveDegradeFrames = 0,
  consecutiveRecoverFrames = 0,
} = {}) {
  // If performance degrades (rolling avg exceeds 24ms / below ~41 FPS)
  if (rollingAvgFrameTime > DEGRADE_FRAME_TIME_MS) {
    const newDegradeCount = consecutiveDegradeFrames + 1
    if (newDegradeCount >= DEGRADE_WINDOW_FRAMES) {
      if (currentTier === 'high') {
        return { nextTier: 'medium', consecutiveDegradeFrames: 0, consecutiveRecoverFrames: 0 }
      }
      if (currentTier === 'medium') {
        return { nextTier: 'low', consecutiveDegradeFrames: 0, consecutiveRecoverFrames: 0 }
      }
      if (currentTier === 'low') {
        return { nextTier: 'fallback', consecutiveDegradeFrames: 0, consecutiveRecoverFrames: 0 }
      }
    }
    return { nextTier: currentTier, consecutiveDegradeFrames: newDegradeCount, consecutiveRecoverFrames: 0 }
  }

  // If performance is exceptionally fast (rolling avg below 14ms / above ~71 FPS)
  if (rollingAvgFrameTime < RECOVER_FRAME_TIME_MS) {
    const newRecoverCount = consecutiveRecoverFrames + 1
    if (newRecoverCount >= RECOVER_WINDOW_FRAMES) {
      if (currentTier === 'low') {
        return { nextTier: 'medium', consecutiveDegradeFrames: 0, consecutiveRecoverFrames: 0 }
      }
      if (currentTier === 'medium') {
        return { nextTier: 'high', consecutiveDegradeFrames: 0, consecutiveRecoverFrames: 0 }
      }
    }
    return { nextTier: currentTier, consecutiveDegradeFrames: 0, consecutiveRecoverFrames: newRecoverCount }
  }

  // Neutral zone: 14.0ms <= frameTime <= 24.0ms. Hysteresis locks in current tier.
  return { nextTier: currentTier, consecutiveDegradeFrames: 0, consecutiveRecoverFrames: 0 }
}
