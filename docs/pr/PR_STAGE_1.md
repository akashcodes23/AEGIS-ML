# PR: Stage 1 — Cinematic Foundation, Spatial Tokens & Application Shell

- **Branch:** `feat/stage1-cinematic-foundation`
- **Base Target:** `main` (`0dd8d24`)
- **Type:** Foundation Architecture / Design Tokens

---

### 1. Summary of Changes
- Established core "Depth is Data" design token architecture in `frontend/src/styles/tokens.css` (5 elevation surfaces, obsidian base `#07090e`, semantic accents, tabular figures).
- Built high-performance, single-draw-call `AmbientField` Three.js particle canvas with adaptive DPR clamping (strictly decorative, decoupled from data).
- Integrated persistent, non-dismissible Synthetic Demo ribbon across all active views to ensure empirical honesty.
- Implemented responsive Application Shell with accessible navigation dock and keyboard shortcuts (`Alt+1` through `Alt+4`).

### 2. Risk Assessment
- **Risk Level:** Low.
- **Surface Area:** CSS variables, application shell wrapper, decorative background canvas.
- **Mitigation:** Zero changes to backend APIs, schemas, model artifacts, or inference logic. Background field is `aria-hidden="true"` and non-interactive (`pointer-events: none`).

### 3. Test Evidence
- **Automated Tests:** Unit test suite passing (`shouldEnable3D`, `isLowResourceDevice`, `NAV_TABS`).
- **Clean Bundle Impact:** Main chunk raw size: 840.54 kB (+5.26 kB raw, +1.53 kB gzip vs `main`).
- **A11y:** Full `axe-core` evaluation passing with 0 critical/serious violations on the application shell.

### 4. Visual Evidence
- Screenshot: `docs/assets/dashboard.png` (displays application shell, elevation tokens, and synthetic ribbon).

### 5. Known Limitations
- The initial bundle in this stage is not yet route-split (deferred to Stage 5).
