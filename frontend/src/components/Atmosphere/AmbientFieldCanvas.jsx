import React, { useEffect, useRef } from 'react'
import {
  Scene,
  PerspectiveCamera,
  WebGLRenderer,
  BufferGeometry,
  Float32BufferAttribute,
  PointsMaterial,
  Points,
  FogExp2,
  Color,
} from 'three'
import { QUALITY_TIERS, evaluateQualityTier } from '../../utils/adaptiveQuality.js'

/**
 * AmbientFieldCanvas
 * 
 * ⚠️ PURELY DECORATIVE ATMOSPHERE ⚠️
 * This component renders ambient background depth and drifting constellation particles.
 * It does NOT represent live telemetry, real network nodes, or detection events.
 * 
 * Technical Specs:
 * - Single draw call using Points with custom vertex attributes.
 * - Gentle mouse-follow parallax with damped lerp.
 * - Adaptive quality tiers (high -> medium -> low -> fallback) with hysteresis.
 * - Suspends render loop on tab hidden (document.hidden) and when offscreen.
 * - Disposes geometries, materials, and WebGL context cleanly on unmount.
 */
export default function AmbientFieldCanvas({ onFallback }) {
  const containerRef = useRef(null)
  const onFallbackRef = useRef(onFallback)

  useEffect(() => {
    onFallbackRef.current = onFallback
  }, [onFallback])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    let animationFrameId = null
    let isVisible = true
    let isIntersecting = true

    // 1. Scene & Atmosphere Setup
    const scene = new Scene()
    // Soft atmospheric fog matching obsidian background
    scene.fog = new FogExp2(0x07090e, 0.007)

    const width = container.clientWidth || window.innerWidth
    const height = container.clientHeight || window.innerHeight

    // 2. Camera Setup
    const camera = new PerspectiveCamera(60, width / height, 1, 1000)
    camera.position.z = 180

    // 3. Renderer Setup with DPR Capping
    const renderer = new WebGLRenderer({
      alpha: true,
      antialias: false,
      powerPreference: 'high-performance',
    })
    const dpr = Math.min(window.devicePixelRatio || 1, 1.75)
    renderer.setPixelRatio(dpr)
    renderer.setSize(width, height)
    renderer.setClearColor(0x07090e, 0) // transparent clear
    container.appendChild(renderer.domElement)

    // 4. Construct Single Draw-Call Particle Constellation
    const particleCount = 360
    const positions = new Float32Array(particleCount * 3)
    const colors = new Float32Array(particleCount * 3)

    // Palettes: Electric Cyan (#00f0ff), Plasma Violet (#a855f7), Slate Neutral (#64748b)
    const colorCyan = new Color(0x00f0ff)
    const colorViolet = new Color(0xa855f7)
    const colorSlate = new Color(0x64748b)

    for (let i = 0; i < particleCount; i++) {
      // Spatial volume: wide x, y, and receding z (-120 to +60)
      positions[i * 3] = (Math.random() - 0.5) * 420
      positions[i * 3 + 1] = (Math.random() - 0.5) * 280
      positions[i * 3 + 2] = (Math.random() - 0.5) * 240

      // Color distribution: mostly subtle slate, sparse cyan & violet accents
      const rand = Math.random()
      let chosenColor = colorSlate
      if (rand < 0.22) {
        chosenColor = colorCyan
      } else if (rand < 0.38) {
        chosenColor = colorViolet
      }

      colors[i * 3] = chosenColor.r
      colors[i * 3 + 1] = chosenColor.g
      colors[i * 3 + 2] = chosenColor.b
    }

    const geometry = new BufferGeometry()
    geometry.setAttribute('position', new Float32BufferAttribute(positions, 3))
    geometry.setAttribute('color', new Float32BufferAttribute(colors, 3))

    const material = new PointsMaterial({
      size: 3.5,
      vertexColors: true,
      transparent: true,
      opacity: 0.72,
      sizeAttenuation: true,
      depthWrite: false,
    })

    const pointSystem = new Points(geometry, material)
    scene.add(pointSystem)

    // 5. Parallax & Motion Tracking
    let targetMouseX = 0
    let targetMouseY = 0
    let currentMouseX = 0
    let currentMouseY = 0

    const handlePointerMove = (e) => {
      targetMouseX = (e.clientX / window.innerWidth - 0.5) * 28
      targetMouseY = (e.clientY / window.innerHeight - 0.5) * 18
    }
    window.addEventListener('pointermove', handlePointerMove, { passive: true })

    // 6. Animation Loop with Tab Visibility, Intersection Awareness & Adaptive Quality
    let lastTime = performance.now()
    let rollingAvgFrameTime = 16.6
    let qualityState = {
      currentTier: 'high',
      consecutiveDegradeFrames: 0,
      consecutiveRecoverFrames: 0,
    }

    const animate = (currentTime) => {
      if (!isVisible || !isIntersecting) {
        return
      }

      const frameDuration = currentTime - lastTime
      const delta = frameDuration * 0.001
      lastTime = currentTime

      // Rolling frame time estimation (exponential moving average)
      rollingAvgFrameTime = rollingAvgFrameTime * 0.95 + frameDuration * 0.05

      // Evaluate adaptive quality tier
      const evalResult = evaluateQualityTier({
        currentTier: qualityState.currentTier,
        rollingAvgFrameTime,
        consecutiveDegradeFrames: qualityState.consecutiveDegradeFrames,
        consecutiveRecoverFrames: qualityState.consecutiveRecoverFrames,
      })
      qualityState = {
        currentTier: evalResult.nextTier,
        consecutiveDegradeFrames: evalResult.consecutiveDegradeFrames,
        consecutiveRecoverFrames: evalResult.consecutiveRecoverFrames,
      }

      if (evalResult.nextTier === 'fallback') {
        stopLoop()
        if (typeof onFallbackRef.current === 'function') {
          onFallbackRef.current()
        }
        return
      }

      const activeConfig = QUALITY_TIERS[evalResult.nextTier]
      if (activeConfig) {
        pointSystem.geometry.setDrawRange(0, activeConfig.particleCount)
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, activeConfig.dprCap))
      }

      // Gentle continuous ambient drift (slow, quiet rotation)
      pointSystem.rotation.y += delta * 0.022
      pointSystem.rotation.x += delta * 0.011

      // Subtle parallax interpolation
      currentMouseX += (targetMouseX - currentMouseX) * 0.04
      currentMouseY += (targetMouseY - currentMouseY) * 0.04
      camera.position.x = currentMouseX
      camera.position.y = -currentMouseY
      camera.lookAt(0, 0, 0)

      renderer.render(scene, camera)
      animationFrameId = requestAnimationFrame(animate)
    }

    const startLoop = () => {
      if (!animationFrameId && isVisible && isIntersecting) {
        lastTime = performance.now()
        animationFrameId = requestAnimationFrame(animate)
      }
    }

    const stopLoop = () => {
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId)
        animationFrameId = null
      }
    }

    startLoop()

    // 7. Page Visibility Listener
    const handleVisibilityChange = () => {
      isVisible = document.visibilityState === 'visible'
      if (isVisible) {
        startLoop()
      } else {
        stopLoop()
      }
    }
    document.addEventListener('visibilitychange', handleVisibilityChange)

    // 8. Intersection Observer on canvas container
    const observer = new IntersectionObserver(([entry]) => {
      isIntersecting = entry.isIntersecting
      if (isIntersecting) {
        startLoop()
      } else {
        stopLoop()
      }
    })
    observer.observe(container)

    // 9. Resize Handling
    const handleResize = () => {
      if (!container) return
      const w = container.clientWidth || window.innerWidth
      const h = container.clientHeight || window.innerHeight
      camera.aspect = w / h
      camera.updateProjectionMatrix()
      renderer.setSize(w, h)
    }
    window.addEventListener('resize', handleResize)

    // 10. Clean Unmount Disposal
    return () => {
      stopLoop()
      window.removeEventListener('pointermove', handlePointerMove)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      window.removeEventListener('resize', handleResize)
      observer.disconnect()

      if (container && renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }

      geometry.dispose()
      material.dispose()
      renderer.dispose()
    }
  }, [])

  return (
    <div
      ref={containerRef}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
        overflow: 'hidden',
      }}
    />
  )
}
