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

## 5. Stage 2: Depth & Confidence on Real Data

### 5.1 Kill-Chain Depth Encoding on Entity Graph (Cytoscape.js)
The Entity Graph uses Cytoscape.js in 2D with spatial depth projection along visual perception dimensions rather than 3D geometry replacement:

- **Source of Truth**: Derived from real event payloads (`current_kill_chain_stage`, alert stage, incident stage) via `normalizeKillChainStage()`.
- **Truthful Stage Fallback**: If an entity stage is unrecognized or absent, it is assigned `UNKNOWN_DEPTH` (`stage: 'Unknown'`, `isKnown: false`). The UI never fabricates or guesses a stage.
- **Multi-Property Visual Attenuation**:
  - **Node Size**: Attenuates from $26\text{px}$ (Reconnaissance) to $48\text{px}$ (Impact). Unknown nodes render at a neutral $32\text{px}$.
  - **Opacity**: Attenuates from $0.65$ (deep atmospheric recession) to $1.0$ (foreground focus). Unknown nodes render at $0.72$.
  - **Border Width**: Attenuates from $1.5\text{px}$ to $3.5\text{px}$.
  - **Z-Index Layering**: Nodes layer cleanly from $z=10$ (Reconnaissance) to $z=17$ (Impact), ensuring foreground nodes cleanly overlap earlier background nodes during pan and zoom.
- **Compromised Entities**: Nodes marked `is_compromised` receive `--severity-critical` (`#ff3366`) borders and elevated glow; all other nodes follow severity or tier tokens.
- **Compact Depth Legend**: A sticky legend (`Recon → Weaponize → Delivery → Exploit → Install → C2 → Exfiltrate → Impact → Unknown`) ensures no visual encoding relies on color alone.
- **Node Dossier / Tooltip**: Every entity card explicitly states its stage in text (`Kill-Chain Progression: Reconnaissance (Depth 1/8)`) or states `Unknown Stage (No alert stage)`.
- **Reduced Motion**: Disables animation durations ($0\text{ms}$ layout transition) and retains static spatial sizing and opacity.

### 5.2 Confidence as Focus on the Alert Feed
Alert cards translate model calibration certainty into visual sharpness:

- **Source of Truth**: Uses `calibrated_confidence` **only when** `is_calibrated === true`.
- **Uncalibrated Scores**: When `is_calibrated === false`, the alert displays `% Uncalibrated Score` and receives the **neutral focus treatment** (`opacity: 0.85, saturate: 0.85, blur: 0px`). It is never sharpened as if it were calibrated.
- **Missing Confidence**: When confidence is missing or null, the card displays `No confidence reported` with neutral treatment.
- **STRICT ACCESSIBILITY RULE: NEVER BLUR TEXT**:
  Text elements remain 100% sharp at all times to satisfy WCAG AA legibility standards. The `confidenceToFocus()` filter string (`filter: blur(...)`) is applied **exclusively to non-text decorative layers**:
  - The card's outer glow halo (`boxShadow`).
  - The severity indicator border softness.
  - The decorative background wash saturation.
- **Informative Legend**: The Alert Feed includes an explicit operator legend: *"Crisper card halo indicates higher calibrated confidence. Uncalibrated alerts receive neutral treatment. Visuals reflect model certainty, not ground-truth detection accuracy."*

### 5.3 Crimson Rarity Guardrail
- Crimson (`#ff3366` / `--severity-critical`) is strictly reserved for Critical Severity alerts, compromised network nodes, and host isolation containment triggers.
- Verified by automated unit test `frontend/src/utils/crimson_guardrail.test.js`, which scans all CSS and JSX files for unauthorized occurrences.

---

## 6. Architectural Extension Points (Roadmap to Stage 3+)

1. **Provenance Filament & Camera Glide**: Isolated overlay layer rendering quadratic Bezier filaments between correlated incident entities, gliding camera to active investigation hubs.
2. **Temporal Scrubber**: Time-slice scrubbing across correlated incidents with spatial replay along the kill-chain depth axis.
3. **Command Palette**: Spatial quick-action bar utilizing Elevation 4 tokens with keyboard navigation.
4. **Threat Hunting Query Scene Changes**: Dynamic background transitions responding to empirical query filters.

