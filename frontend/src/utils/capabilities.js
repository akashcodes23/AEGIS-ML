/**
 * AEGIS-ML Hardware & Rendering Capability Detection
 */

/**
 * Validates WebGL rendering context availability safely.
 * @returns {boolean}
 */
export function checkWebGLSupport() {
  if (typeof window === 'undefined') return false
  try {
    const canvas = document.createElement('canvas')
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
    return !!(gl && gl instanceof WebGLRenderingContext)
  } catch {
    return false
  }
}

/**
 * Checks for low-resource or power-constrained devices
 * @param {Navigator} [nav] - Optional navigator object for testing
 * @returns {boolean}
 */
export function isLowResourceDevice(nav = (typeof navigator !== 'undefined' ? navigator : null)) {
  if (!nav) return false

  // Low CPU cores (e.g., <= 2 cores)
  if (typeof nav.hardwareConcurrency === 'number' && nav.hardwareConcurrency <= 2) {
    return true
  }

  // Low device RAM in GB (Chromium deviceMemory API)
  if (typeof nav.deviceMemory === 'number' && nav.deviceMemory < 4) {
    return true
  }

  // User requested data saver
  if (nav.connection && nav.connection.saveData === true) {
    return true
  }

  return false
}

/**
 * Master decision function determining whether 3D Atmosphere should run.
 * 
 * @param {object} params
 * @param {boolean} [params.featureFlag=true] - VITE_ENABLE_3D flag value
 * @param {boolean} [params.reducedMotion=false] - Whether user has reduced motion active
 * @param {boolean} [params.hasWebGL] - Optional override for WebGL test
 * @param {boolean} [params.isLowResource] - Optional override for low-resource test
 * @returns {{ canRun: boolean, reason?: string }}
 */
export function shouldEnable3D({
  featureFlag = true,
  reducedMotion = false,
  hasWebGL = checkWebGLSupport(),
  isLowResource = isLowResourceDevice(),
} = {}) {
  if (!featureFlag) {
    return { canRun: false, reason: 'Feature flag disabled (VITE_ENABLE_3D=false)' }
  }
  if (reducedMotion) {
    return { canRun: false, reason: 'Reduced motion preference active' }
  }
  if (!hasWebGL) {
    return { canRun: false, reason: 'WebGL unavailable or blocked' }
  }
  if (isLowResource) {
    return { canRun: false, reason: 'Low hardware resources or data-saver active' }
  }
  return { canRun: true }
}
