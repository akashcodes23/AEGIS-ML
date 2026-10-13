import { useState, useEffect } from 'react'

const STORAGE_KEY = 'aegis_reduce_visual_effects'

/**
 * Retrieves the stored user preference with safe error handling
 */
function getStoredPreference() {
  if (typeof window === 'undefined') return null
  try {
    const val = localStorage.getItem(STORAGE_KEY)
    if (val === 'true') return true
    if (val === 'false') return false
    return null
  } catch {
    return null
  }
}

/**
 * Single source of truth hook for reduced motion and reduced visual effects.
 * 
 * Priority:
 * 1. Explicit user override stored in localStorage (`aegis_reduce_visual_effects`)
 * 2. Operating system preference `(prefers-reduced-motion: reduce)`
 * 
 * @returns {boolean} Whether reduced motion/visual effects are active
 */
export function useReducedMotion() {
  const [prefersReduced, setPrefersReduced] = useState(() => {
    const stored = getStoredPreference()
    if (stored !== null) return stored
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-reduced-motion: reduce)').matches
    }
    return false
  })

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return

    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')

    const handleChange = () => {
      const stored = getStoredPreference()
      if (stored !== null) {
        setPrefersReduced(stored)
      } else {
        setPrefersReduced(mediaQuery.matches)
      }
    }

    // Modern and legacy event listener fallback
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handleChange)
    } else if (mediaQuery.addListener) {
      mediaQuery.addListener(handleChange)
    }

    const handleStorage = (e) => {
      if (e.key === STORAGE_KEY) {
        handleChange()
      }
    }
    window.addEventListener('storage', handleStorage)

    return () => {
      if (mediaQuery.removeEventListener) {
        mediaQuery.removeEventListener('change', handleChange)
      } else if (mediaQuery.removeListener) {
        mediaQuery.removeListener(handleChange)
      }
      window.removeEventListener('storage', handleStorage)
    }
  }, [])

  return prefersReduced
}

export function setReducedVisualEffectsPreference(enabled) {
  if (typeof window === 'undefined') return
  try {
    if (enabled === null) {
      localStorage.removeItem(STORAGE_KEY)
    } else {
      localStorage.setItem(STORAGE_KEY, enabled ? 'true' : 'false')
    }
    window.dispatchEvent(new Event('storage'))
  } catch {
    // Gracefully ignore local storage quota / access errors
  }
}

export default useReducedMotion
