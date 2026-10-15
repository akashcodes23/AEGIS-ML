import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'

const FRONTEND_SRC = path.resolve('frontend/src')

export const CRIMSON_PATTERNS = [
  /#(?:ff3366|ff5277|dc2626|e11d48|f43f5e|ef4444|b91c1c|991b1b|be123c)\b/i,
  /rgba?\(\s*(?:255\s*,\s*(?:51|82)\s*,\s*(?:102|119)|220\s*,\s*38\s*,\s*38|225\s*,\s*29\s*,\s*72)/i,
]

function getSourceFiles(dir) {
  let results = []
  const list = fs.readdirSync(dir)
  for (const file of list) {
    const fullPath = path.join(dir, file)
    const stat = fs.statSync(fullPath)
    if (stat.isDirectory()) {
      results = results.concat(getSourceFiles(fullPath))
    } else if (/\.(jsx|js|css)$/.test(file) && !/\.test\.(js|jsx)$/.test(file)) {
      results.push(fullPath)
    }
  }
  return results
}

export function checkFileForCrimsonViolations(relPath, content) {
  const violations = []
  const lines = content.split('\n')

  lines.forEach((line, lineIdx) => {
    // Check for hard-coded crimson values
    for (const pattern of CRIMSON_PATTERNS) {
      if (pattern.test(line)) {
        // Allowed only in:
        // 1. styles/tokens.css (defining critical tokens)
        // 2. utils/depth.js (defining critical severity tokens)
        // 3. Components that explicitly bind to critical severity, compromised entities,
        //    active malicious edges, or security containment actions.
        const isTokensDef = relPath === 'styles/tokens.css'
        const isDepthDef = relPath === 'utils/depth.js'

        // Check context window (+/- 10 lines)
        const contextStart = Math.max(0, lineIdx - 10)
        const contextEnd = Math.min(lines.length - 1, lineIdx + 10)
        const surroundingContext = lines.slice(contextStart, contextEnd + 1).join(' ')

        const isCriticalRef = /critical|compromised|is_compromised|isCompromised|anomalous|is_anomalous|isAnomalous|isolate|shieldalert|error|danger|false_pos/i.test(surroundingContext)

        if (!isTokensDef && !isDepthDef && !isCriticalRef) {
          violations.push({
            file: relPath,
            line: lineIdx + 1,
            content: line.trim(),
            reason: 'Hard-coded crimson used outside critical severity or compromised context',
          })
        }
      }
    }

    // Check if critical token is used in a non-critical severity mapping
    if (/--severity-critical|--accent-critical/i.test(line)) {
      if (/\b(?:high|medium|low|info|success)\b/i.test(line) && !/critical/i.test(line)) {
        violations.push({
          file: relPath,
          line: lineIdx + 1,
          content: line.trim(),
          reason: 'Critical severity token referenced for a non-critical tier',
        })
      }
    }
  })

  return violations
}

test('Crimson Rarity Guardrail: scans codebase to ensure crimson values and critical tokens are reserved strictly for critical severity', () => {
  const files = getSourceFiles(FRONTEND_SRC)
  assert.ok(files.length > 5, 'Should have scanned source files')

  const violations = []
  for (const filePath of files) {
    const relPath = path.relative(FRONTEND_SRC, filePath)
    const content = fs.readFileSync(filePath, 'utf8')
    violations.push(...checkFileForCrimsonViolations(relPath, content))
  }

  assert.deepEqual(violations, [], `Found crimson guardrail violations:\n${JSON.stringify(violations, null, 2)}`)
})

test('Crimson Guardrail: deliberately introduced stray shade fails the validator', () => {
  const fakeContentWithStrayCrimson = `
    const neutralBadge = {
      color: '#ff5277',
      background: 'transparent'
    }
  `
  const violations = checkFileForCrimsonViolations('components/StrayBadge.jsx', fakeContentWithStrayCrimson)
  assert.ok(violations.length > 0, 'Validator should detect stray crimson shade #ff5277')
  assert.strictEqual(violations[0].reason, 'Hard-coded crimson used outside critical severity or compromised context')
})
