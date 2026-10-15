# AEGIS-ML Release Verification Checklist (Pre-Merge Validation)

This checklist provides the exact operational sequence that the human repository maintainer should perform before merging the `feat/stage1-cinematic-foundation` through `feat/stage5-release-readiness` branch stack into `main`.

---

## 1. Backend Test Suite Run

Verify that the Python backend inference engine, feature schema, and FastAPI endpoints remain 100% green on your local environment:

```bash
# In repository root:
source venv/bin/activate  # or activate your Python 3.10+ virtualenv
PYTHONPATH=. pytest tests/ -v
```
- [ ] All 336 pytest unit/integration tests pass without warnings or failures.

---

## 2. Frontend Clean Build & Production Guardrail Verification

Verify that the frontend builds cleanly without stale cache and that internal test hooks (`window.useAlertStore`) are stripped:

```bash
cd frontend
rm -rf dist
npm run build
```
- [ ] Build completes cleanly with zero errors.
- [ ] Main entry chunk (`dist/assets/index-*.js`) is under 260 kB raw / 80 kB gzip.
- [ ] Run the production hook check:
  ```bash
  node -e "const fs = require('fs'); const txt = fs.readFileSync(fs.readdirSync('dist/assets').filter(f => f.startsWith('index-') && f.endsWith('.js')).map(f => 'dist/assets/' + f)[0], 'utf8'); if (txt.includes('window.useAlertStore')) { console.error('LEAK DETECTED'); process.exit(1); } else { console.log('Clean: window.useAlertStore stripped from production build'); }"
  ```
- [ ] Run the full frontend unit test suite:
  ```bash
  node --test src/**/*.test.js
  ```
  (All 71 unit tests must pass).

---

## 3. Local Preview & Core Web Vitals (Lighthouse)

Launch the production preview server to validate performance:

```bash
npm run preview -- --port 4173
```
Open Chrome or Chromium to `http://localhost:4173`:
- [ ] **Lighthouse Performance Audit:**
  - Run Lighthouse on Desktop mode for `/`, `/threat-hunting`, `/entity-graph`, and `/reports`.
  - Confirm Performance score $\ge 95$.
  - Confirm LCP $\le 1.2\text{s}$, CLS $\le 0.05$, TBT $\le 50\text{ms}$.
- [ ] **Axe DevTools Browser Extension:**
  - Run axe DevTools extension scan on the live page across all 4 routes.
  - Confirm 0 automated accessibility violations.

---

## 4. Keyboard Navigation & Interaction Pass

Without touching the mouse, navigate the interface using only the keyboard:
- [ ] Press `Tab` on first page load: Verify hidden Skip Link appears and skips to `#main-content` on `Enter`.
- [ ] Press `Alt+1` through `Alt+4` (or `Option+1` to `Option+4` on macOS): Verify clean tab switching.
- [ ] Press `Cmd+K` (macOS) or `Ctrl+K` (Windows): Verify Command Palette opens with focus in search input.
- [ ] Type a search query (e.g., `exfiltration` or `10.0.`): Verify arrow keys navigate items and `Enter` executes.
- [ ] Press `Escape`: Verify palette closes and prior focus is restored.
- [ ] Focus the Temporal Scrubber slider: Use `ArrowLeft` / `ArrowRight` to step through timeline.

---

## 5. Print Preview Verification (Executive Briefing)

Navigate to `http://localhost:4173/reports` and open an incident dossier:
- [ ] Click **"Generate Briefing"** or trigger from palette.
- [ ] Press `Cmd+P` (macOS) or `Ctrl+P` (Windows) to trigger print preview.
- [ ] Confirm:
  - Document background is clean solid white (`#ffffff`) with dark text (`#0f172a`).
  - Navigation dock, backdrop canvas, and interactive buttons are hidden.
  - Running footer displays the mandatory Synthetic Demo Disclosure on every page.
  - Canonical SHA-256 integrity checksum is legible with short verification command.
- [ ] Click **"Download briefing data (JSON)"**: Verify downloaded file hashes to the displayed checksum using:
  ```bash
  shasum -a 256 aegis-briefing-*.json
  ```

---

## 6. Manual Assistive Technology Pass (Screen Readers)

Follow the detailed step-by-step test script in [`docs/accessibility-checklist.md`](docs/accessibility-checklist.md):
- [ ] **macOS / iOS:** Run VoiceOver (`Cmd+F5`). Verify landmark announcements, modal focus traps, and slider values.
- [ ] **Windows:** Run NVDA (`Ctrl+Alt+N`). Verify combobox announcements and evidence gap labels.

---

## 7. Merge Execution Recommendation

Follow the recommended sequential merge strategy:
1. Merge PR 1 (`feat/stage1-cinematic-foundation` → `main`)
2. Merge PR 2 (`feat/stage2-depth-confidence` → `main`)
3. Merge PR 3 (`feat/stage3-evidence-scrubber` → `main`)
4. Merge PR 4 (`feat/stage4-palette-briefing` → `main`)
5. Merge PR 5 (`feat/stage5-release-readiness` → `main`)

*Note: Alternatively, if your organization prefers a single atomic squash merge to preserve linear history on `main`, merge PR 5 directly into `main` after verifying the dry-run merge.*
