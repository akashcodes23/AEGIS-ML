/**
 * AEGIS-ML First-Run Intro Decision Engine
 *
 * Rules:
 * - Shown ONLY on first visit to the root route ('/')
 * - Never on deep links (/hunting, /graph, /reports)
 * - Never in E2E/test builds
 * - Never when prefers-reduced-motion is true
 * - Never when Reduce Visual Effects is active
 * - Never on low-resource devices or with data-saver
 * - User-initiated replay ignores first-visit flag, but still respects reduced motion
 */

export const INTRO_STORAGE_KEY = 'aegis_intro_seen_v1'

export function hasSeenIntro() {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return false
    return window.localStorage.getItem(INTRO_STORAGE_KEY) === 'true'
  } catch {
    return false
  }
}

export function markIntroSeen() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(INTRO_STORAGE_KEY, 'true')
    }
  } catch {
    // Gracefully handle storage disabled or quotas
  }
}

export function shouldShowIntro({
  pathname = '/',
  isFirstVisit = true,
  prefersReducedMotion = false,
  reduceVisualEffects = false,
  isLowResource = false,
  isE2E = false,
  isReplay = false,
} = {}) {
  // Replay is user-initiated: ignores first visit & route, but respects motion preferences
  if (isReplay) {
    if (prefersReducedMotion || reduceVisualEffects) {
      return false
    }
    return true
  }

  // E2E / Automated test mode disables intro immediately
  if (isE2E) return false

  // Motion and device guardrails
  if (prefersReducedMotion) return false
  if (reduceVisualEffects) return false
  if (isLowResource) return false

  // Route check: root route only
  const cleanPath = (pathname || '/').replace(/\/+$/, '') || '/'
  if (cleanPath !== '/') return false

  // First visit check
  if (!isFirstVisit) return false

  return true
}
