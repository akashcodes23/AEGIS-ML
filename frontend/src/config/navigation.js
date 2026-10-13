/**
 * AEGIS-ML Navigation Configuration & URL Route Resolution
 */

export const NAV_TABS = ['Dashboard', 'Threat Hunting', 'Entity Graph', 'Reports']

export const TAB_ROUTES = {
  'Dashboard': '/',
  'Threat Hunting': '/threat-hunting',
  'Entity Graph': '/entity-graph',
  'Reports': '/reports',
}

export const ROUTE_TABS = {
  '/': 'Dashboard',
  '/dashboard': 'Dashboard',
  '/threat-hunting': 'Threat Hunting',
  '/hunting': 'Threat Hunting',
  '/entity-graph': 'Entity Graph',
  '/graph': 'Entity Graph',
  '/reports': 'Reports',
  '/report': 'Reports',
}

/**
 * Resolves active navigation tab from window location (pathname and hash fallback).
 *
 * @param {Location} [loc] - Optional custom location object for testing
 * @returns {string} Tab name from NAV_TABS
 */
export function resolveTabFromLocation(loc = (typeof window !== 'undefined' ? window.location : null)) {
  if (!loc) return 'Dashboard'

  // If a hash is explicitly specified (e.g. #/threat-hunting or #reports), check it first
  const hash = (loc.hash || '').toLowerCase().replace(/^#\/?/, '').replace(/\/+$/, '')
  if (hash) {
    if (ROUTE_TABS['/' + hash]) {
      return ROUTE_TABS['/' + hash]
    }
    if (hash === 'threat-hunting' || hash === 'hunting') return 'Threat Hunting'
    if (hash === 'entity-graph' || hash === 'graph') return 'Entity Graph'
    if (hash === 'reports' || hash === 'report') return 'Reports'
  }

  const pathname = (loc.pathname || '').toLowerCase().replace(/\/+$/, '') || '/'
  if (ROUTE_TABS[pathname]) {
    return ROUTE_TABS[pathname]
  }

  return 'Dashboard'
}
