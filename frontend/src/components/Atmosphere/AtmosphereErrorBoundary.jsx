import React, { Component } from 'react'
import AmbientStaticFallback from './AmbientStaticFallback'

/**
 * Atmosphere Error Boundary
 * 
 * Strict Requirement:
 * Error containment around the 3D canvas so a WebGL or shader failure
 * never disrupts user interaction or crashes the application.
 */
export default class AtmosphereErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.warn('[AEGIS Atmosphere] 3D canvas encountered an error; falling back to static visual system:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return <AmbientStaticFallback />
    }
    return this.props.children
  }
}
