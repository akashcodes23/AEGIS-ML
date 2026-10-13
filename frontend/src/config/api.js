/**
 * AEGIS-ML Frontend API and WebSocket Configuration
 *
 * Provides environment-aware resolution of REST endpoints and WebSocket URLs
 * supporting local proxy development, cross-origin production hosting (Vercel/Render),
 * and automatic protocol promotion (https -> wss).
 */

export const DEFAULT_PRODUCTION_API_URL = 'https://aegis-ml-api.onrender.com'

/**
 * Returns the configured REST API base URL.
 * In local development, if VITE_API_BASE_URL is unset, returns an empty string
 * so requests leverage Vite's local development proxy (e.g., '/api/...').
 * In production or when hosted on external domains (e.g. Vercel), falls back
 * to DEFAULT_PRODUCTION_API_URL if unset.
 */
export const getApiBaseUrl = () => {
  const envUrl = import.meta.env?.VITE_API_BASE_URL
  if (envUrl && typeof envUrl === 'string' && envUrl.trim()) {
    return envUrl.trim().replace(/\/+$/, '')
  }
  // When running in production build or deployed on a public host (e.g. Vercel),
  // fall back to the known production Render backend if no env var was injected.
  if (
    import.meta.env?.PROD ||
    (typeof window !== 'undefined' &&
      window.location.hostname !== 'localhost' &&
      window.location.hostname !== '127.0.0.1')
  ) {
    return DEFAULT_PRODUCTION_API_URL
  }
  return ''
}

/**
 * Resolves a full REST API endpoint URL given a relative path.
 * Handles prefix deduplication (e.g. avoiding duplicate '/api').
 *
 * @param {string} endpoint - Path such as '/api/analysis/files' or 'api/analysis/start'
 * @returns {string} Fully resolved URL or relative path
 */
export const getApiUrl = (endpoint) => {
  const base = getApiBaseUrl()
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`

  if (!base) {
    return cleanEndpoint
  }

  // Prevent double '/api' if base already ends with '/api' and endpoint starts with '/api'
  if (base.endsWith('/api')) {
    if (cleanEndpoint === '/api') {
      return base
    }
    if (cleanEndpoint.startsWith('/api/')) {
      return `${base}${cleanEndpoint.slice(4)}`
    }
  }

  return `${base}${cleanEndpoint}`
}

/**
 * Resolves the WebSocket URL for live threat intelligence streaming.
 * Respects VITE_WS_URL if set, or derives the WebSocket endpoint from VITE_API_BASE_URL,
 * or falls back to window.location with strict HTTPS/WSS protocol handling.
 *
 * @returns {string} Fully qualified ws:// or wss:// URL
 */
export const getWsUrl = () => {
  // 1. Explicit VITE_WS_URL configuration
  const explicitWs = import.meta.env?.VITE_WS_URL
  if (explicitWs && typeof explicitWs === 'string' && explicitWs.trim()) {
    let target = explicitWs.trim()
    // Upgrade ws:// to wss:// if hosted over HTTPS and target is external
    if (typeof window !== 'undefined' && window.location.protocol === 'https:' && target.startsWith('ws://')) {
      if (!target.includes('localhost') && !target.includes('127.0.0.1')) {
        target = target.replace(/^ws:\/\//i, 'wss://')
      }
    }
    return target
  }

  // 2. Derive from VITE_API_BASE_URL if configured or production fallback
  const apiBase = getApiBaseUrl()
  if (apiBase) {
    let wsBase = apiBase
      .replace(/^https:\/\//i, 'wss://')
      .replace(/^http:\/\//i, 'ws://')
      .replace(/\/api\/?$/i, '')
      .replace(/\/+$/, '')
    return `${wsBase}/ws/live`
  }

  // 3. Fallback based on browser window location
  if (typeof window !== 'undefined') {
    const isHttps = window.location.protocol === 'https:'
    const host = window.location.hostname || '127.0.0.1'

    // If on a remote host (e.g. *.vercel.app) without apiBase, point to production backend WS
    if (host !== 'localhost' && host !== '127.0.0.1') {
      return 'wss://aegis-ml-api.onrender.com/ws/live'
    }

    if (isHttps) {
      return `wss://${host}/ws/live`
    }

    // Local development fallback to default backend port :8000
    return `ws://${host}:8000/ws/live`
  }

  return 'ws://127.0.0.1:8000/ws/live'
}
