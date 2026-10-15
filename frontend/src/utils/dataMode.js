/**
 * AEGIS-ML Data Mode & Synthetic Disclosure State Resolution
 * 
 * Strict Ground Rule:
 * Wherever synthetic or replayed data is displayed, a visible disclosure
 * must remain on screen. Nothing in the UI may imply synthetic results
 * establish real-world detection accuracy.
 *
 * When real data (e.g. verified PCAP stream or live capture) is active,
 * the disclosure disappears.
 */

/**
 * Determines whether the active telemetry stream is synthetic/demo data.
 *
 * @param {object|null|undefined} stats - Telemetry stats object from alertStore or /api/stats/summary
 * @param {string|null|undefined} currentFile - Currently loaded analysis file name
 * @returns {boolean} True if synthetic or simulated demo data is active; false if real data is active.
 */
export function isSyntheticData(stats = {}, currentFile = '') {
  const safeStats = stats || {}
  const fileStr = typeof currentFile === 'string' ? currentFile.toLowerCase() : ''

  // 1. Explicit backend boolean flag takes precedence
  if (typeof safeStats.is_synthetic === 'boolean') {
    return safeStats.is_synthetic
  }

  // 2. Explicit dataset_type flag
  if (safeStats.dataset_type === 'pcap' || safeStats.dataset_type === 'live') {
    return false
  }
  if (safeStats.dataset_type === 'synthetic' || safeStats.dataset_type === 'demo') {
    return true
  }

  // 3. Inspect active file name
  if (fileStr) {
    if (fileStr.includes('synthetic') || fileStr.includes('.jsonl') || fileStr.includes('behavioral')) {
      return true
    }
    if (fileStr.includes('.pcap') || fileStr.includes('real') || fileStr.includes('live')) {
      return false
    }
  }

  // 4. Default startup state: the preloaded default dataset in AEGIS-ML is behavioral_diversity_labeled.jsonl (synthetic)
  return true
}
