import React, { memo, useState, useEffect, useCallback, useRef } from 'react'
import useAlertStore from '../../store/alertStore.js'
import { stateAsOf } from '../../utils/scrubber.js'
import { Play, Pause, SkipBack, SkipForward, RotateCcw, Clock, AlertCircle } from 'lucide-react'
import { useReducedMotion } from '../../hooks/useReducedMotion.js'

/**
 * TemporalScrubber: Interactive Investigation Playhead
 * 
 * Replays security telemetry as of chosen timestamp `t`.
 * Features:
 * - Native accessible <input type="range"> with step buttons and keyboard nav.
 * - Buffers incoming live stream while reviewing past state.
 * - Truthfully reports timestamp basis and session replay scope.
 * - Disables animated autoplay under reduced motion.
 */
export default memo(function TemporalScrubber({ onStateChange }) {
  const alerts = useAlertStore(s => s.alerts)
  const incidents = useAlertStore(s => s.incidents)
  const scrubberTime = useAlertStore(s => s.scrubberTime)
  const liveAlertBuffer = useAlertStore(s => s.liveAlertBuffer)
  const setScrubberTime = useAlertStore(s => s.setScrubberTime)
  const jumpToLatest = useAlertStore(s => s.jumpToLatest)
  const reducedMotion = useReducedMotion()

  const [isPlaying, setIsPlaying] = useState(false)
  const [liveAnnouncement, setLiveAnnouncement] = useState('')
  const playTimerRef = useRef(null)

  // Compute active state and range
  const targetT = scrubberTime !== null ? scrubberTime : Date.now()
  const computed = stateAsOf(alerts, incidents, targetT)
  const { min, max } = computed.timeRange
  const hasRange = max > min
  const isPast = scrubberTime !== null && scrubberTime < max

  // Notify parent component of state change
  useEffect(() => {
    if (onStateChange) {
      onStateChange(computed)
    }
  }, [computed, onStateChange])

  // Format timestamps
  const formatTime = (ts) => {
    if (!ts) return '--:--:--'
    return new Date(ts).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  // Announce time changes to screen readers (throttled)
  const announceTime = useCallback((ts) => {
    const formatted = formatTime(ts)
    setLiveAnnouncement(`Viewing state as of ${formatted}`)
  }, [])

  // Slider change handler
  const handleSliderChange = (e) => {
    const val = Number(e.target.value)
    if (val >= max) {
      jumpToLatest()
    } else {
      setScrubberTime(val)
      announceTime(val)
    }
  }

  // Step controls
  const stepBack = () => {
    if (!hasRange) return
    const step = Math.max(1000, (max - min) / 20)
    const nextVal = Math.max(min, (scrubberTime ?? max) - step)
    setScrubberTime(nextVal)
    announceTime(nextVal)
  }

  const stepForward = () => {
    if (!hasRange) return
    const step = Math.max(1000, (max - min) / 20)
    const current = scrubberTime ?? max
    if (current + step >= max) {
      jumpToLatest()
    } else {
      setScrubberTime(current + step)
      announceTime(current + step)
    }
  }

  // Keyboard navigation on slider
  const handleKeyDown = (e) => {
    if (e.key === 'Home') {
      e.preventDefault()
      setScrubberTime(min)
      announceTime(min)
    } else if (e.key === 'End') {
      e.preventDefault()
      jumpToLatest()
    }
  }

  // Autoplay loop (disabled under reduced motion)
  useEffect(() => {
    if (reducedMotion && isPlaying) {
      setIsPlaying(false)
      return
    }

    if (isPlaying && hasRange) {
      playTimerRef.current = setInterval(() => {
        const current = useAlertStore.getState().scrubberTime ?? max
        const step = Math.max(1000, (max - min) / 30)
        if (current + step >= max) {
          useAlertStore.getState().jumpToLatest()
          setIsPlaying(false)
        } else {
          useAlertStore.getState().setScrubberTime(current + step)
        }
      }, 350)
    }

    return () => {
      if (playTimerRef.current) clearInterval(playTimerRef.current)
    }
  }, [isPlaying, hasRange, min, max, reducedMotion])

  const togglePlay = () => {
    if (reducedMotion) return
    if (!isPlaying && scrubberTime === null) {
      // Start from beginning if at latest
      setScrubberTime(min)
    }
    setIsPlaying(prev => !prev)
  }

  return (
    <div
      role="region"
      aria-label="Temporal Investigation Scrubber"
      className="glass-panel"
      style={{
        padding: '12px 18px',
        margin: '10px 0',
        borderRadius: 14,
        background: 'var(--surface-1)',
        border: '1px solid var(--border-hairline)',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      {/* ── Top Bar: Header, Live/Past Status & Data Scope ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Clock size={15} color={isPast ? 'var(--severity-high-fg)' : 'var(--accent-cyan)'} />
          <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: 'var(--text-primary)' }}>
            Temporal Scrubber
          </span>
          <span style={{ color: 'var(--border-subtle)' }}>|</span>
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              textTransform: 'uppercase',
              padding: '2px 8px',
              borderRadius: 6,
              background: isPast ? 'rgba(251, 146, 60, 0.15)' : 'rgba(0, 240, 255, 0.12)',
              color: isPast ? 'var(--severity-high-fg)' : 'var(--accent-cyan)',
              border: `1px solid ${isPast ? 'rgba(251, 146, 60, 0.35)' : 'rgba(0, 240, 255, 0.25)'}`,
            }}
          >
            {isPast ? 'Viewing Past State' : 'Live Latest'}
          </span>
        </div>

        {/* Scope Honesty Label */}
        <div style={{ fontSize: 10, color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span>
            Session replay of {alerts.length} alerts held in memory ({computed.basis === 'event_time' ? 'Event timestamp' : 'Ingest timestamp'} basis)
          </span>
          {computed.excludedMissingCount > 0 && (
            <span style={{ color: 'var(--text-muted)' }} title="Alerts without valid timestamps excluded from historical replay">
              ({computed.excludedMissingCount} excluded: no timestamp)
            </span>
          )}
        </div>
      </div>

      {/* ── Buffer Notification Bar (When viewing past state) ── */}
      {isPast && (
        <div
          style={{
            padding: '6px 12px',
            borderRadius: 8,
            background: 'rgba(251, 146, 60, 0.08)',
            border: '1px solid rgba(251, 146, 60, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 11,
            color: 'var(--text-secondary)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <AlertCircle size={14} color="var(--severity-high-fg)" />
            <span>
              Viewing state at <strong>{formatTime(computed.timeRange.current)}</strong>.
              {liveAlertBuffer.length > 0 && (
                <span style={{ color: 'var(--text-primary)', marginLeft: 4 }}>
                  ({liveAlertBuffer.length} new live alerts buffered)
                </span>
              )}
            </span>
          </div>

          <button
            type="button"
            onClick={jumpToLatest}
            style={{
              padding: '3px 10px',
              borderRadius: 6,
              background: 'var(--accent-cyan)',
              color: 'var(--surface-0)',
              fontSize: 10,
              fontWeight: 700,
              border: 'none',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            <RotateCcw size={12} />
            Jump to Latest
          </button>
        </div>
      )}

      {/* ── Slider & Transport Controls ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* Play/Pause (disabled under reduced motion) */}
        {!reducedMotion && (
          <button
            type="button"
            onClick={togglePlay}
            disabled={!hasRange}
            aria-label={isPlaying ? 'Pause timeline playback' : 'Play timeline forward'}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--border-hairline)',
              color: 'var(--accent-cyan)',
              borderRadius: 8,
              padding: '6px 10px',
              cursor: hasRange ? 'pointer' : 'not-allowed',
              display: 'inline-flex',
              alignItems: 'center',
              outline: 'none',
            }}
          >
            {isPlaying ? <Pause size={14} /> : <Play size={14} />}
          </button>
        )}

        {/* Step backward */}
        <button
          type="button"
          onClick={stepBack}
          disabled={!hasRange}
          aria-label="Step backward to earlier telemetry"
          style={{
            background: 'var(--surface-2)',
            border: '1px solid var(--border-hairline)',
            color: 'var(--text-secondary)',
            borderRadius: 8,
            padding: '6px 8px',
            cursor: hasRange ? 'pointer' : 'not-allowed',
            outline: 'none',
          }}
        >
          <SkipBack size={13} />
        </button>

        {/* Native HTML Range Slider */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <input
            type="range"
            min={min}
            max={max}
            step={Math.max(1, Math.floor((max - min) / 100))}
            value={computed.timeRange.current}
            onChange={handleSliderChange}
            onKeyDown={handleKeyDown}
            disabled={!hasRange}
            aria-label="Incident progression timeline"
            aria-valuemin={min}
            aria-valuemax={max}
            aria-valuenow={computed.timeRange.current}
            aria-valuetext={`Telemetry at ${formatTime(computed.timeRange.current)}`}
            style={{
              width: '100%',
              accentColor: isPast ? 'var(--severity-high-fg)' : 'var(--accent-cyan)',
              cursor: hasRange ? 'pointer' : 'default',
              height: 6,
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            <span>{formatTime(min)}</span>
            <span style={{ color: isPast ? 'var(--severity-high-fg)' : 'var(--accent-cyan)', fontWeight: 700 }}>
              {formatTime(computed.timeRange.current)}
            </span>
            <span>{formatTime(max)} (Live)</span>
          </div>
        </div>

        {/* Step forward */}
        <button
          type="button"
          onClick={stepForward}
          disabled={!hasRange}
          aria-label="Step forward to later telemetry"
          style={{
            background: 'var(--surface-2)',
            border: '1px solid var(--border-hairline)',
            color: 'var(--text-secondary)',
            borderRadius: 8,
            padding: '6px 8px',
            cursor: hasRange ? 'pointer' : 'not-allowed',
            outline: 'none',
          }}
        >
          <SkipForward size={13} />
        </button>
      </div>

      {/* Screen reader polite live region */}
      <div
        role="status"
        aria-live="polite"
        style={{
          position: 'absolute',
          width: 1,
          height: 1,
          padding: 0,
          margin: -1,
          overflow: 'hidden',
          clip: 'rect(0, 0, 0, 0)',
          whiteSpace: 'nowrap',
          border: 0,
        }}
      >
        {liveAnnouncement}
      </div>
    </div>
  )
})
