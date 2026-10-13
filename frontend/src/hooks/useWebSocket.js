import { useEffect, useRef, useState, useCallback } from 'react'
import useAlertStore from '../store/alertStore'
import { getWsUrl } from '../config/api'

const getDefaultWsUrl = () => {
  return getWsUrl()
}

const INITIAL_RECONNECT_DELAY_MS = 2000
const MAX_RECONNECT_DELAY_MS = 6000
const MAX_RECONNECT_ATTEMPTS = 60

const useWebSocket = (url = null) => {
  const [connected, setConnected] = useState(false)
  const [connecting, setConnecting] = useState(true)
  const [error, setError] = useState(null)

  const wsRef = useRef(null)
  const reconnectTimerRef = useRef(null)
  const attemptsRef = useRef(0)
  const mountedRef = useRef(true)

  const { addAlert, addIncident, updateGraph, updateStats, setSimulationRunning } = useAlertStore()

  const handleMessage = useCallback(
    (event) => {
      try {
        const { type, data } = JSON.parse(event.data)
        switch (type) {
          case 'new_alert':
            addAlert(data)
            break
          case 'graph_update':
            updateGraph(data)
            break
          case 'new_incident':
            addIncident(data)
            break
          case 'stats_update':
            updateStats(data)
            // Auto-clear running flag when backend finishes all dataset files
            if (data.analysis_complete) {
              setSimulationRunning(false)
            }
            break
          case 'incident_update':
            if (data?.incident_id) {
              useAlertStore.getState().updateIncident(data)
            }
            if (data?.event_id) {
              useAlertStore.getState().updateAlertStatus(data.event_id, data.status)
            }
            break
          default:
            console.warn('[WS] Unknown message type:', type)
        }
      } catch (err) {
        console.error('[WS] Failed to parse message:', err)
      }
    },
    [addAlert, addIncident, updateGraph, updateStats, setSimulationRunning]
  )

  const connect = useCallback(() => {
    if (!mountedRef.current) return
    if (attemptsRef.current >= MAX_RECONNECT_ATTEMPTS) {
      setConnecting(false)
      setError(`Max reconnect attempts (${MAX_RECONNECT_ATTEMPTS}) reached.`)
      return
    }

    try {
      setConnecting(true)
      let targetUrl = url || getDefaultWsUrl()
      // If previous attempt failed, alternate between localhost and 127.0.0.1 to handle dual-stack IPv4/IPv6
      if (attemptsRef.current > 0 && !url && (targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1'))) {
        if (attemptsRef.current % 2 === 1) {
          targetUrl = targetUrl.replace('localhost', '127.0.0.1')
        } else {
          targetUrl = targetUrl.replace('127.0.0.1', 'localhost')
        }
      }

      const ws = new WebSocket(targetUrl)
      wsRef.current = ws

      ws.onopen = () => {
        if (!mountedRef.current) return
        attemptsRef.current = 0
        setConnected(true)
        setConnecting(false)
        setError(null)
        console.log('[WS] Connected to', targetUrl)
      }

      ws.onmessage = handleMessage

      ws.onerror = (e) => {
        console.error('[WS] Error:', e)
        setError('WebSocket connection error')
      }

      ws.onclose = (e) => {
        if (!mountedRef.current) return
        setConnected(false)
        attemptsRef.current += 1
        const delay = Math.min(
          INITIAL_RECONNECT_DELAY_MS + attemptsRef.current * 500,
          MAX_RECONNECT_DELAY_MS
        )
        if (attemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
          setConnecting(true)
          console.warn(`[WS] Closed (code=${e.code}). Reconnecting in ${delay}ms (attempt ${attemptsRef.current}/${MAX_RECONNECT_ATTEMPTS})...`)
          reconnectTimerRef.current = setTimeout(connect, delay)
        } else {
          setConnecting(false)
          setError(`Disconnected from backend stream after ${MAX_RECONNECT_ATTEMPTS} attempts.`)
        }
      }
    } catch (err) {
      setConnecting(false)
      setError(err.message)
    }
  }, [url, handleMessage])

  const manualReconnect = useCallback(() => {
    attemptsRef.current = 0
    setError(null)
    if (wsRef.current) {
      try { wsRef.current.close() } catch {}
      wsRef.current = null
    }
    clearTimeout(reconnectTimerRef.current)
    connect()
  }, [connect])

  useEffect(() => {
    mountedRef.current = true
    connect()

    return () => {
      mountedRef.current = false
      clearTimeout(reconnectTimerRef.current)
      if (wsRef.current) {
        wsRef.current.onclose = null // prevent reconnect loop on unmount
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [connect])

  return { connected, connecting, error, reconnect: manualReconnect }
}

export default useWebSocket
