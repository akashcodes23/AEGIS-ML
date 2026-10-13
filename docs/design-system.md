# AEGIS-ML Design System: Depth is Data (Stage 1 Foundation)

The AEGIS-ML interface represents a **spatial intelligence environment** for machine-learning-driven network intrusion detection and automated threat response. Visual properties are not arbitrary decorations; they encode semantic meaning and empirical state.

---

## 1. Core Principles: "Depth is Data"

| Principle | Meaning | System Rule |
|---|---|---|
| **Depth = Kill-Chain Progress** | Earlier stages sit farther back in atmospheric depth; later stages advance closer to the operator. | Mapped via `KILL_CHAIN_DEPTH` constant across the 8 standard stages (`Recon` at $z=-70$ through `Impact` at $z=0$). |
| **Focus = Confidence** | High-confidence classifications render crisp; low-confidence ones render softly defocused. | Governed by `confidenceToFocus(confidence)` producing blur ($0$–$4\text{px}$), opacity ($0.55$–$1.0$), and saturation ($0.70$–$1.0$). |
| **Motion = Real Events** | Only authentic stream events and user intent cause meaningful visual motion. | Decorative background is strictly ambient and decoupled from data-bearing stream visualizations. |
| **Crimson is Rare** | Red/crimson is reserved strictly for Critical Severity alerts and active exploits. | Verified by unit tests and design token guardrails. High severity uses Amber/Orange (`#fb923c`), never Crimson. |
| **One Glow per View** | Restraint in illumination prevents visual noise and preserves operator focus. | Exactly one primary accent glow (`var(--glow-primary)`) may dominate an active viewport. |

---

## 2. Token Architecture (`frontend/src/styles/tokens.css`)

### 2.1 Spatial Elevation & Neutrals
- **Base Canvas (`--surface-0`)**: `#07090e` — Obsidian void.
- **Elevation 1 (`--surface-1`)**: `#0c111c` — Background panels and containers.
- **Elevation 2 (`--surface-2`)**: `#121927` — Interactive cards, input rails.
- **Elevation 3 (`--surface-3`)**: `#182236` — Active pills, elevated controls, modals.
- **Elevation 4 (`--surface-4`)**: `#202d47` — Popovers, active dossiers.

### 2.2 Accents
- **Primary Accent (`--accent-cyan`)**: `#00f0ff` (Electric Cyan) — Used for primary interaction, telemetry focus, and spatial nodes.
- **Secondary Accent (`--accent-violet`)**: `#a855f7` (Plasma Violet) — Used for correlated clusters, pivots, and incident grouping.
- **Critical Accent (`--severity-critical-fg`)**: `#ff3366` (Crimson) — Reserved strictly for Critical severity.
- **No Neon Green**: Green is restrained to Sage/Emerald (`#34d399`) for verified system health.

### 2.3 Text Tiers (WCAG AA Compliant on Canvas)
- **Primary Text (`--text-primary`)**: `#f8fafc` (Contrast $>16:1$).
- **Secondary Text (`--text-secondary`)**: `#94a3b8` (Slate-400, Contrast $>6.5:1$).
- **Tertiary Text (`--text-tertiary`)**: `#64748b` (Slate-500, Contrast $>3.8:1$).
- **Muted Text (`--text-muted`)**: `#475569`.

### 2.4 Severity System
Every severity token provides foreground, soft translucent background, and hairline border variants. In accordance with colorblind-safe accessibility guidelines, severity must **never** be indicated by color alone; all UI elements pair color with text labels and distinctive icons.

| Severity | Foreground (`-fg`) | Background (`-bg`) | Border (`-border`) | Icon | Contrast vs Canvas |
|---|---|---|---|---|---|
| **Critical** | `#ff3366` | `rgba(255, 51, 102, 0.12)` | `rgba(255, 51, 102, 0.35)` | `AlertOctagon` | $>6.5:1$ |
| **High** | `#fb923c` | `rgba(251, 146, 60, 0.12)` | `rgba(251, 146, 60, 0.35)` | `AlertTriangle` | $>7.5:1$ |
| **Medium** | `#facc15` | `rgba(250, 204, 21, 0.12)` | `rgba(250, 204, 21, 0.35)` | `AlertCircle` | $>11:1$ |
| **Low** | `#38bdf8` | `rgba(56, 189, 248, 0.12)` | `rgba(56, 189, 248, 0.35)` | `Info` | $>8.5:1$ |
| **Info** | `#818cf8` | `rgba(129, 140, 248, 0.12)` | `rgba(129, 140, 248, 0.35)` | `HelpCircle` | $>6.8:1$ |
| **Success** | `#34d399` | `rgba(52, 211, 153, 0.12)` | `rgba(52, 211, 153, 0.35)` | `CheckCircle` | $>9.0:1$ |

### 2.5 Typography & Tabular Numerals
- **UI Font**: `Plus Jakarta Sans`, system-ui fallback.
- **Metric / Monospace Font**: `JetBrains Mono`, monospace fallback.
- **Tabular Figures**: All numerical metrics, timestamps, and IP addresses use `.tabular-nums` (`font-variant-numeric: tabular-nums; font-feature-settings: 'tnum' 1;`) to guarantee fixed column alignment and eliminate layout jitter during live telemetry updates.

### 2.6 Surfaces & Glass Panel Primitive
```css
.glass-panel {
  background: var(--glass-bg); /* rgba(12, 17, 28, 0.78) */
  border-radius: 18px;
  border: 1px solid var(--border-hairline); /* rgba(255, 255, 255, 0.07) */
  box-shadow: var(--shadow-elevation-1), var(--glass-highlight);
  backdrop-filter: var(--glass-blur); /* blur(14px) */
  -webkit-backdrop-filter: var(--glass-blur);
}
```
*Fallback*: For browsers lacking `backdrop-filter` support, `@supports not (backdrop-filter: blur(10px))` applies solid midnight navy (`rgba(12, 17, 28, 0.96)`) maintaining full legibility.

### 2.7 Motion Tokens & Reduced Motion
- `--duration-instant`: `0ms`
- `--duration-quick`: `140ms`
- `--duration-smooth`: `280ms`
- `--duration-cinematic`: `550ms`
- Universal `@media (prefers-reduced-motion: reduce)` zeroes all animations and transitions.
- The `useReducedMotion()` hook serves as the single source of truth, synchronizing operating system preferences with the in-app "Reduce Visual Effects" toggle.

---

## 3. Empirical Honesty & Synthetic Demo Disclosure

AEGIS never fabricates health, live status, or detection accuracy:
1. **Real State Only**: WebSocket state displays actual socket status (`Stream Live`, `Connecting...`, `Offline`). The backend health pill displays live `/health` endpoint response (`Live`, `Offline`, `Unknown`).
2. **Persistent Synthetic Ribbon**: When synthetic datasets (`behavioral_diversity_labeled.jsonl`, replayed logs) are active, a non-dismissible ribbon is rendered across the top of all views:
   > *"Synthetic demo data. Results do not reflect real-world detection accuracy."*
3. **Subtle Desaturation Tint**: Synthetic scenes receive `.synthetic-scene-tint` (`saturate(0.94)`), visually differentiating simulated environments from production environments.

---

## 4. Atmospheric 3D Foundation (`AmbientField`)

### 4.1 Component Contract & Decorative Isolation
`AmbientField` (`frontend/src/components/Atmosphere/AmbientField.jsx`) is **purely decorative**.
- It renders subtle spatial depth, soft fog, and slow-drifting constellation particles.
- **Contract**: It must NEVER represent real alert entities, network topology, or detection confidence.
- Rendered with `pointer-events: none`, `aria-hidden="true"`, and sits behind all interactive DOM content (`z-index: 0`).

### 4.2 Performance Specifications
- **Single Draw Call**: Implemented using Three.js `Points` with `BufferGeometry` and `Float32BufferAttribute` for position and color vertex attributes.
- **Adaptive DPR Capping**: Clamped to `Math.min(window.devicePixelRatio, 1.75)` to prevent GPU exhaustion on 4K / Retina displays.
- **Lifecycle Pause**:
  - `document.visibilityState === 'hidden'` immediately pauses the `requestAnimationFrame` loop.
  - `IntersectionObserver` on the canvas container suspends execution when out of the viewport.
- **Resource Disposal**: On component unmount, `geometry.dispose()`, `material.dispose()`, and `renderer.dispose()` are explicitly invoked.
- **Code-Splitting**: Three.js code lives in an isolated chunk (`AmbientFieldCanvas.js`), dynamically imported via `React.lazy` after first paint, keeping the core bundle minimal.

### 4.3 Multi-Tier Fallback Hierarchy
If any of the following conditions occur, `AmbientStaticFallback` is rendered instantly:
1. User activates "Reduce visual effects" via the status bar toggle (`localStorage: aegis_reduce_visual_effects`).
2. Browser signals `prefers-reduced-motion: reduce`.
3. Device has constrained resources (`navigator.hardwareConcurrency <= 2`, memory $<4\text{GB}$, or `saveData: true`).
4. WebGL context creation fails or is unavailable.
5. Feature flag disabled (`VITE_ENABLE_3D=false`).
6. Uncaught rendering error (isolated by `AtmosphereErrorBoundary`).

---

## 5. Architectural Extension Points (Roadmap to Stage 2+)

1. **Kill-Chain Depth on Entity Graph**: Stage 1 introduces `KILL_CHAIN_DEPTH`. In Stage 2, Cytoscape nodes will project along the spatial $z$-axis according to their identified kill-chain progression.
2. **Confidence Defocus on Live Alerts**: Stage 1 delivers `confidenceToFocus()`. Stage 2 will bind this utility to `AlertFeed` items, applying calibrated CSS filter strings based on model probabilities.
3. **Provenance Filament & Camera Glide**: Extending the Three.js canvas to accept an isolated telemetry overlay layer that renders Bezier filaments between correlated incident entities without mixing decorative particles with real data.
4. **Temporal Scrubber**: Integrating time-travel log playback with the kill-chain depth plane.
5. **Command Palette**: Spatial quick-action overlay utilizing Elevation 4 tokens.
