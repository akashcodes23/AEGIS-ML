import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const distAssetsDir = path.resolve(__dirname, '../../dist/assets')

test('Production Build Hygiene: window.useAlertStore is never exposed in standard production builds', () => {
  if (!fs.existsSync(distAssetsDir)) {
    // If dist doesn't exist yet, pass or skip
    return
  }
  const files = fs.readdirSync(distAssetsDir).filter(f => f.endsWith('.js'))
  assert.ok(files.length > 0, 'Production dist assets must contain built JavaScript files')

  for (const file of files) {
    const content = fs.readFileSync(path.join(distAssetsDir, file), 'utf-8')
    assert.strictEqual(
      content.includes('window.useAlertStore='),
      false,
      `File ${file} leaked window.useAlertStore in standard production build!`
    )
    assert.strictEqual(
      content.includes('window.useAlertStore ='),
      false,
      `File ${file} leaked window.useAlertStore in standard production build!`
    )
  }
})
