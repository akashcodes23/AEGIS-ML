import React, { lazy, Suspense } from 'react'
import useReducedMotion from '../../hooks/useReducedMotion'
import { shouldEnable3D } from '../../utils/capabilities'
import AtmosphereErrorBoundary from './AtmosphereErrorBoundary'
import AmbientStaticFallback from './AmbientStaticFallback'

// Lazy-load the Three.js 3D canvas chunk after initial paint
const AmbientFieldCanvas = lazy(() => import('./AmbientFieldCanvas'))

/**
 * AmbientField
 * 
 * Master background atmosphere component for AEGIS-ML.
 * 
 * Guarantees:
 * 1. Decorative only: Sit behind all interactive content (`pointer-events: none`).
 * 2. Adaptive fallback: Evaluates reduced motion, hardware constraints, and WebGL support.
 * 3. Error containment: WebGL or context crash falls back cleanly to AmbientStaticFallback.
 * 4. Lazy-loaded: 3D chunk is separated and deferred, keeping initial bundle fast.
 */
export default function AmbientField() {
  const reducedMotion = useReducedMotion()
  const featureFlag = import.meta.env.VITE_ENABLE_3D !== 'false'

  const { canRun } = shouldEnable3D({
    featureFlag,
    reducedMotion,
  })

  if (!canRun) {
    return <AmbientStaticFallback />
  }

  return (
    <AtmosphereErrorBoundary>
      <Suspense fallback={<AmbientStaticFallback />}>
        <AmbientFieldCanvas />
      </Suspense>
    </AtmosphereErrorBoundary>
  )
}
