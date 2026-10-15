import { useState, useEffect, useCallback } from 'react'
import { getApiUrl } from '../config/api'

/**
 * Hook to monitor real backend health endpoint.
 * Never fabricates health status.
 * 
 * Returns:
 * - status: 'live' | 'offline' | 'unknown'
 * - details: object | null
 * - checkHealth: manual trigger function
 */
export function useBackendHealth(pollIntervalMs = 30000) {
  const [status, setStatus] = useState('unknown')
  const [details, setDetails] = useState(null)

  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch(getApiUrl('/health'), {
        headers: { Accept: 'application/json' },
      })
      if (res.ok) {
        const data = await res.json().catch(() => ({}))
        setStatus('live')
        setDetails(data)
      } else {
        setStatus('offline')
        setDetails({ httpStatus: res.status })
      }
    } catch {
      setStatus('offline')
      setDetails(null)
    }
  }, [])

  useEffect(() => {
    let mounted = true
    const runCheck = async () => {
      try {
        const res = await fetch(getApiUrl('/health'), {
          headers: { Accept: 'application/json' },
        })
        if (!mounted) return
        if (res.ok) {
          const data = await res.json().catch(() => ({}))
          setStatus('live')
          setDetails(data)
        } else {
          setStatus('offline')
          setDetails({ httpStatus: res.status })
        }
      } catch {
        if (!mounted) return
        setStatus('offline')
        setDetails(null)
      }
    }

    runCheck()
    let timer = null
    if (pollIntervalMs > 0) {
      timer = setInterval(runCheck, pollIntervalMs)
    }

    return () => {
      mounted = false
      if (timer) clearInterval(timer)
    }
  }, [pollIntervalMs])

  return { status, details, checkHealth }
}

export default useBackendHealth
