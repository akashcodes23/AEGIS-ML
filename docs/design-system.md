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

### 2.8 Comprehensive Programmatic Contrast Audit (WCAG 2.1 AA/AAA)

All token pairs across the five spatial elevations and foreground tiers were mathematically calculated using the W3C relative luminance formula ($L = 0.2126 R + 0.7152 G + 0.0722 B$). Normal body text requires $\ge 4.5:1$ (WCAG AA) or $\ge 7.0:1$ (WCAG AAA); large text ($\ge 18\text{pt}$ or $\ge 14\text{pt}$ bold) and essential graphical UI components require $\ge 3.0:1$.

| Foreground Token | Hex | Surface | Ratio | WCAG AA Normal (4.5:1) | WCAG AA Large (3.0:1) | WCAG AAA (7.0:1) | Role / Usage |
|---|---|---|---|---|---|---|---|
| `--text-primary` | `#f8fafc` | `--surface-0` (Canvas) | **19.03:1** | Pass | Pass | Pass | Primary text |
| `--text-primary` | `#f8fafc` | `--surface-1` (Panels) | **18.04:1** | Pass | Pass | Pass | Primary text |
| `--text-primary` | `#f8fafc` | `--surface-2` (Cards) | **16.81:1** | Pass | Pass | Pass | Primary text |
| `--text-primary` | `#f8fafc` | `--surface-3` (Active/Pills) | **15.19:1** | Pass | Pass | Pass | Primary text |
| `--text-primary` | `#f8fafc` | `--surface-4` (Popovers) | **13.14:1** | Pass | Pass | Pass | Primary text |
| `--text-secondary` | `#94a3b8` | `--surface-0` (Canvas) | **7.77:1** | Pass | Pass | Pass | Secondary text / labels |
| `--text-secondary` | `#94a3b8` | `--surface-1` (Panels) | **7.36:1** | Pass | Pass | Pass | Secondary text / labels |
| `--text-secondary` | `#94a3b8` | `--surface-2` (Cards) | **6.86:1** | Pass | Pass | Fail | Secondary text / labels |
| `--text-secondary` | `#94a3b8` | `--surface-3` (Active/Pills) | **6.2:1** | Pass | Pass | Fail | Secondary text / labels |
| `--text-secondary` | `#94a3b8` | `--surface-4` (Popovers) | **5.36:1** | Pass | Pass | Fail | Secondary text / labels |
| `--text-tertiary` | `#64748b` | `--surface-0` (Canvas) | **4.18:1** | Fail | Pass | Fail | Tertiary metadata (large/decorative) |
| `--text-tertiary` | `#64748b` | `--surface-1` (Panels) | **3.97:1** | Fail | Pass | Fail | Tertiary metadata (large/decorative) |
| `--text-tertiary` | `#64748b` | `--surface-2` (Cards) | **3.7:1** | Fail | Pass | Fail | Tertiary metadata (large/decorative) |
| `--text-tertiary` | `#64748b` | `--surface-3` (Active/Pills) | **3.34:1** | Fail | Pass | Fail | Tertiary metadata (large/decorative) |
| `--text-tertiary` | `#64748b` | `--surface-4` (Popovers) | **2.89:1** | Fail | Fail | Fail | Tertiary metadata (large/decorative) |
| `--accent-cyan` | `#00f0ff` | `--surface-0` (Canvas) | **14.14:1** | Pass | Pass | Pass | Primary action / telemetry focus |
| `--accent-cyan` | `#00f0ff` | `--surface-1` (Panels) | **13.4:1** | Pass | Pass | Pass | Primary action / telemetry focus |
| `--accent-cyan` | `#00f0ff` | `--surface-2` (Cards) | **12.49:1** | Pass | Pass | Pass | Primary action / telemetry focus |
| `--accent-cyan` | `#00f0ff` | `--surface-3` (Active/Pills) | **11.29:1** | Pass | Pass | Pass | Primary action / telemetry focus |
| `--accent-cyan` | `#00f0ff` | `--surface-4` (Popovers) | **9.76:1** | Pass | Pass | Pass | Primary action / telemetry focus |
| `--accent-violet` | `#a855f7` | `--surface-0` (Canvas) | **5.03:1** | Pass | Pass | Fail | Secondary accent / clusters |
| `--accent-violet` | `#a855f7` | `--surface-1` (Panels) | **4.77:1** | Pass | Pass | Fail | Secondary accent / clusters |
| `--accent-violet` | `#a855f7` | `--surface-2` (Cards) | **4.44:1** | Fail | Pass | Fail | Secondary accent / clusters |
| `--accent-violet` | `#a855f7` | `--surface-3` (Active/Pills) | **4.02:1** | Fail | Pass | Fail | Secondary accent / clusters |
| `--accent-violet` | `#a855f7` | `--surface-4` (Popovers) | **3.47:1** | Fail | Pass | Fail | Secondary accent / clusters |
| `--severity-critical-fg` | `#ff3366` | `--surface-0` (Canvas) | **5.61:1** | Pass | Pass | Fail | Critical severity (strictly rare) |
| `--severity-critical-fg` | `#ff3366` | `--surface-1` (Panels) | **5.32:1** | Pass | Pass | Fail | Critical severity (strictly rare) |
| `--severity-critical-fg` | `#ff3366` | `--surface-2` (Cards) | **4.96:1** | Pass | Pass | Fail | Critical severity (strictly rare) |
| `--severity-critical-fg` | `#ff3366` | `--surface-3` (Active/Pills) | **4.48:1** | Fail | Pass | Fail | Critical severity (strictly rare) |
| `--severity-critical-fg` | `#ff3366` | `--surface-4` (Popovers) | **3.87:1** | Fail | Pass | Fail | Critical severity (strictly rare) |
| `--severity-high-fg` | `#fb923c` | `--surface-0` (Canvas) | **8.8:1** | Pass | Pass | Pass | High severity |
| `--severity-high-fg` | `#fb923c` | `--surface-1` (Panels) | **8.34:1** | Pass | Pass | Pass | High severity |
| `--severity-high-fg` | `#fb923c` | `--surface-2` (Cards) | **7.77:1** | Pass | Pass | Pass | High severity |
| `--severity-high-fg` | `#fb923c` | `--surface-3` (Active/Pills) | **7.02:1** | Pass | Pass | Pass | High severity |
| `--severity-high-fg` | `#fb923c` | `--surface-4` (Popovers) | **6.07:1** | Pass | Pass | Fail | High severity |
| `--severity-medium-fg` | `#facc15` | `--surface-0` (Canvas) | **13.0:1** | Pass | Pass | Pass | Medium severity |
| `--severity-medium-fg` | `#facc15` | `--surface-1` (Panels) | **12.33:1** | Pass | Pass | Pass | Medium severity |
| `--severity-medium-fg` | `#facc15` | `--surface-2` (Cards) | **11.48:1** | Pass | Pass | Pass | Medium severity |
| `--severity-medium-fg` | `#facc15` | `--surface-3` (Active/Pills) | **10.38:1** | Pass | Pass | Pass | Medium severity |
| `--severity-medium-fg` | `#facc15` | `--surface-4` (Popovers) | **8.98:1** | Pass | Pass | Pass | Medium severity |
| `--severity-low-fg` | `#38bdf8` | `--surface-0` (Canvas) | **9.3:1** | Pass | Pass | Pass | Low severity |
| `--severity-low-fg` | `#38bdf8` | `--surface-1` (Panels) | **8.81:1** | Pass | Pass | Pass | Low severity |
| `--severity-low-fg` | `#38bdf8` | `--surface-2` (Cards) | **8.21:1** | Pass | Pass | Pass | Low severity |
| `--severity-low-fg` | `#38bdf8` | `--surface-3` (Active/Pills) | **7.42:1** | Pass | Pass | Pass | Low severity |
| `--severity-low-fg` | `#38bdf8` | `--surface-4` (Popovers) | **6.42:1** | Pass | Pass | Fail | Low severity |
| `--severity-info-fg` | `#818cf8` | `--surface-0` (Canvas) | **6.68:1** | Pass | Pass | Fail | Informational |
| `--severity-info-fg` | `#818cf8` | `--surface-1` (Panels) | **6.33:1** | Pass | Pass | Fail | Informational |
| `--severity-info-fg` | `#818cf8` | `--surface-2` (Cards) | **5.9:1** | Pass | Pass | Fail | Informational |
| `--severity-info-fg` | `#818cf8` | `--surface-3` (Active/Pills) | **5.33:1** | Pass | Pass | Fail | Informational |
| `--severity-info-fg` | `#818cf8` | `--surface-4` (Popovers) | **4.61:1** | Pass | Pass | Fail | Informational |
| `--severity-success-fg` | `#34d399` | `--surface-0` (Canvas) | **10.36:1** | Pass | Pass | Pass | System health / verified |
| `--severity-success-fg` | `#34d399` | `--surface-1` (Panels) | **9.82:1** | Pass | Pass | Pass | System health / verified |
| `--severity-success-fg` | `#34d399` | `--surface-2` (Cards) | **9.15:1** | Pass | Pass | Pass | System health / verified |
| `--severity-success-fg` | `#34d399` | `--surface-3` (Active/Pills) | **8.27:1** | Pass | Pass | Pass | System health / verified |
| `--severity-success-fg` | `#34d399` | `--surface-4` (Popovers) | **7.15:1** | Pass | Pass | Pass | System health / verified |

#### Soft Badge Surface Contrast Table (Foreground on Soft Translucent Background over Surface-1)

| Badge Type | Foreground | Effective Blended Background | Ratio | AA Normal | AA Large | Component Guideline |
|---|---|---|---|---|---|---|
| **Critical badge** | `#ff3366` | `#291525` | **4.82:1** (Solid backing: **5.61:1**) | Pass | Pass | Paired with `AlertOctagon` icon + text label |
| **High badge** | `#fb923c` | `#292020` | **7.02:1** (Solid backing: **8.80:1**) | Pass | Pass | Paired with `AlertTriangle` icon + text label |
| **Medium badge** | `#facc15` | `#29271b` | **9.79:1** (Solid backing: **13.00:1**) | Pass | Pass | Paired with `AlertCircle` icon + text label |
| **Low badge** | `#38bdf8` | `#112636` | **7.24:1** (Solid backing: **9.30:1**) | Pass | Pass | Paired with `Info` icon + text label |
| **Info badge** | `#818cf8` | `#1a2036` | **5.40:1** (Solid backing: **6.68:1**) | Pass | Pass | Paired with `HelpCircle` icon + text label |
| **Success badge** | `#34d399` | `#11282b` | **8.02:1** (Solid backing: **10.36:1**) | Pass | Pass | Paired with `CheckCircle` icon + text label |

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

### 5.3 Crimson Allowlist & Rarity Guardrail
- Crimson (`#ff3366` / `--severity-critical`) is strictly reserved for:
  1. **Critical Severity alerts**: High-risk, high-confidence detections requiring immediate triage.
  2. **Compromised network nodes**: Identified hosts with confirmed active exploitation in the topology.
  3. **Containment triggers**: High-impact isolation / firewall block actions.
- **Strict Prohibition**: High severity alerts MUST use Amber/Orange (`#fb923c`), medium severity uses Golden Yellow (`#facc15`), and low severity uses Cyan (`#38bdf8`). Crimson is NEVER permitted for high, medium, low, info, or neutral UI decoration.
- Verified by automated unit test `frontend/src/utils/crimson_guardrail.test.js`, which scans all CSS and JSX files for unauthorized occurrences.

---

## 6. Stage 3: Evidence Trail & Temporal Scrubber

### 6.1 Evidence Trail Architecture (`buildEvidenceChain`)
The Evidence Trail provides a visual and accessible provenance thread reconstructing the exact detection sequence:
`Supporting Event → Feature Deviation → Model Score → Detection Alert → Correlated Incident`.

- **Pure Functional Pipeline**: Constructed via pure function `buildEvidenceChain(alert, incident, context)`. Every link is evaluated against real fields in active payloads.
- **Truthful Link Status**:
  - `present`: Field exists with authentic value. Renders with solid SVG filament and cyan/amber/crimson glowing node.
  - `absent`: Field is missing or null. Renders as a **dashed line with a labeled gap ("not recorded")**. Missing data is NEVER fabricated or inferred.
  - `partial`: Field exists but has qualified provenance (e.g. uncalibrated model score or model-level global importance).
- **Global vs. Local Feature Importance Labeling**:
  - **Local Feature Importance**: Per-alert behavioral deviation against entity historical baseline. Labeled *"Primary deviating features (local alert deviation)"* with specific feature deltas.
  - **Global Model-Level Importance**: Random Forest Gini impurity calculated during offline model training. If an alert lacks local deviations and only reports global importance, the status is marked `partial` and explicitly labeled:
    > *"Model-level feature importance (not specific to this alert)"*
  - **Rule**: Never present global feature importance as an alert-specific explanation.
- **Confidence Node Rules**:
  - Calibrated only when `is_calibrated === true` and `calibrated_confidence` is present.
  - Uncalibrated scores are marked `partial` and labeled *"Uncalibrated raw score (no isotonic calibration applied)"*.
  - Missing confidence is marked `absent` and labeled *"No confidence reported"*.
- **Screen Reader Accessibility Equivalent**:
  - The SVG filament is strictly visual and marked `aria-hidden="true"`.
  - An ordered list (`<ol className="sr-only">` or interactive DOM list) provides the semantic primary content for assistive technologies, announcing each link's stage, label, value, and recorded status.
  - Operators can toggle *"Inspect Provenance (N links)"* to examine raw field paths (`activeAlert.raw_event`, `alert.feature_importance`, `alert.calibrated_confidence`, etc.).

### 6.2 Entity Graph Camera Glide & Relationship Honesty
- **Incident Camera Glide**: When an incident is selected, the Entity Graph executes `cy.animate({ fit: { eles: targetNodes, padding: 60 } })` over `600ms`.
- **Reduced Motion Compliance**: When `useReducedMotion()` is active or the OS requests reduced motion, `cy.fit(targetNodes, 60)` executes immediately with duration `0ms` (no animation).
- **Spatial Dimming**: Uninvolved entities and edges are dimmed to `opacity: 0.18`, visually isolating the investigation cluster while maintaining structural context.
- **Relationship Honesty**: Edges between nodes are drawn **only** when supported by verified `relationship_evidence` or observed communication events. The UI never creates synthetic links.
- **Reset View Control**: When an incident is focused, a visible floating *"Reset Focus (Clear Dimming)"* control allows operators to return instantly to the full topology.

### 6.3 Temporal Scrubber Architecture (`stateAsOf`)
The Temporal Scrubber enables temporal replay of how an incident unfolded over time:

- **Pure Functional Filtering**: `stateAsOf(alerts, incidents, t)` returns the exact historical slice of visible alerts, incidents, graph nodes, and edges as of timestamp `t`.
- **Timestamp Basis & Honesty**:
  - The UI explicitly states the timestamp basis in text: *"Basis: Event Time (from packet captures and log telemetry)"* or *"Basis: Ingest Time (wall-clock stream arrival)"*.
  - Session Scope Disclosure: *"Session replay of N alerts held in this browser session. Synthetic Demo timestamps reflect dataset replay times."*
  - Missing Timestamps: Items lacking timestamps are excluded from the timeline and counted in `excludedMissingCount` with a visible warning; timestamps are NEVER guessed or fabricated.
- **Live-Stream Buffering (`liveAlertBuffer`)**:
  - When the playhead is moved into the past (`scrubberTime < maxTime`), live WebSocket streaming is NOT dropped.
  - Incoming alerts are buffered in `liveAlertBuffer`.
  - The UI presents an unobtrusive status pill: *"Viewing past state (N alerts buffered in live memory)"*.
  - Clicking *"Jump to Latest"* sets `scrubberTime` to `null`, flushes the buffer into the primary alert stream, and returns the view to real-time telemetry.
- **Cytoscape 500-Node Pan & Zoom Performance**:
  - Enabled `hideEdgesOnViewport: true` and `textureOnViewport: true`.
  - Removed global CSS transitions on node elements (`transition: all 0.2s`) to prevent layout thrashing.
  - Measured panning performance on 500 nodes improved from **34.4 FPS to 60.4 FPS** with long tasks $<50\text{ms}$.

---

## 7. Stage 4: Command Palette, Hunting Focus, and Executive Briefing Reports

### 7.1 Command Palette Architecture (`CommandPalette` & `searchPalette`)
The Command Palette (`Cmd+K` / `Ctrl+K`) serves as a keyboard-first navigation and rapid triage launcher across real application state:

- **Pure Functional Search & Ranking**: Powered by `searchPalette(query, sources)` with zero runtime fuzzy-search dependencies. The search algorithm computes deterministic prefix, word-boundary, and substring match scores, ranking exact matches first, followed by title matches, entity identifiers, and metadata.
- **Included Scope (Real State Only)**:
  - **Navigation**: Instant routing to Dashboard, Threat Hunting, Entity Graph, and Reports.
  - **Incidents & Alerts**: Searchable by ID, title, severity, threat type, entity, and kill-chain stage across active store state. Truthfully displays result counts (e.g. `"Showing 20 of 42"`).
  - **Entity Jump**: Jump directly to an entity in the graph, initiating camera focus and node selection.
  - **Temporal Scrubber Controls**: "Jump to Latest" (flushing the live buffer) and step forward/backward controls.
  - **Display Settings**: Quick toggle for "Reduce Visual Effects".
- **Excluded Actions by Design**:
  - Destructive and privileged operations (host containment, IP blocking, model reloading, admin settings) are **strictly excluded** from the command palette.
  - *Rationale*: Safety and accountability. High-impact remediation actions must remain protected behind their existing contextual UI, multi-factor verification, and explicit confirmation modals.
- **Elevation 4 Token Styling**:
  - Built using `--surface-4` (`#202d47`), subtle backdrop blur, hairline border (`rgba(255, 255, 255, 0.12)`), and high-contrast focus rings (`var(--accent-cyan)`).
- **Accessibility & Keyboard Standard (WAI-ARIA 1.2 Combobox/Listbox)**:
  - Implements `role="dialog"`, `aria-modal="true"`, and `role="combobox"` linked to `role="listbox"` via `aria-controls` and `aria-activedescendant`.
  - Full keyboard trapping with active focus management; focus restores cleanly to the initiating DOM trigger upon closing.
  - Navigation keys (`ArrowDown`, `ArrowUp`, `Home`, `End`, `Enter`, `Escape`) fully supported.
  - Polite live region (`aria-live="polite"`) announces result counts dynamically for screen reader operators.
  - Dual access: Global keyboard shortcut (`⌘K` / `Ctrl+K`) plus a visible header shell trigger button for discoverability and pointer-only users. Input typing is never hijacked unless accompanied by meta keys.

---

### 7.2 Strict Decorative Isolation: "The Ambient Canvas Never Reacts to Data"
- **Architectural Guardrail**: The 3D Three.js particle field (`AmbientField`) is strictly an atmospheric depth layer and **must NEVER react to data, alerts, queries, or user filters**.
- **Rationale**: Visual properties in AEGIS encode empirical ground truth ("Depth is Data"). If ambient background particles pulsed, shifted color, or accelerated in response to threat queries, operators could misinterpret decorative motion as empirical telemetry.
- **Data-Bearing Component Isolation**: All visual responses to threat hunting filters, incident selection, and evidence exploration are strictly contained within real-data components (Entity Graph, Evidence Trail, and Alert Feed).

---

### 7.3 Hunting-Driven Graph Focus
Connecting Threat Hunting query state directly to the Entity Graph allows operators to visually isolate matching entities while preserving spatial context:

- **State Integration**: Ingests active filters (`searchQuery`, `selectedSev`, `selectedLayer`, `selectedStatus`, `selectedThreatType`) from `useAlertStore`.
- **Spatial Attenuation**:
  - Matched entities retain full opacity (`1.0`) and receive prominent accent rings.
  - Non-matching entities and irrelevant nodes are dimmed to atmospheric recession (`opacity: 0.18`).
  - Edges between non-matching nodes are dimmed; only evidence-backed edges connected to matched entities remain illuminated.
- **Camera Glide & Reduced Motion**:
  - Under standard motion: smoothly fits the camera to matched nodes (`cy.animate({ fit: { eles, padding: 60 } })` over `600ms`).
  - Under reduced motion: instant viewport fit (`0ms` duration).
- **Honest Scope Summary Banner**:
  - When matches exist: displays a prominent top-pinned badge:
    > *"Focused on N of M entities matching: [Filter Criteria]"* accompanied by an explicit `✕ Clear focus` control.
  - When zero entities match: displays a truthful notice:
    > *"No entities match active hunting filters ([Filter Criteria]). Graph remains unfocused."*
    The system NEVER dims or zooms into an empty void.

---

### 7.4 Executive Briefing Report Export (`BriefingModal` & `buildBriefingData`)
The Executive Briefing provides an auditable, high-level briefing document for leadership and external stakeholders without modifying existing JSON or CSV export pipelines:

- **Print-Optimized HTML (`@media print`)**:
  - Renders a clean, print-ready document utilizing native browser print (`window.print()`).
  - Requires **zero external PDF libraries**, keeping runtime dependencies lean.
  - Full `@media print` stylesheet isolates the briefing document, hiding application shells, navigation docks, and canvas backgrounds, applying solid `#ffffff` background with `#0f172a` primary text for crisp readability and zero ink waste.
- **Empirical Content Structure**:
  - Executive header with incident ID, title, severity, kill-chain progression, and MITRE ATT&CK techniques.
  - Timeline sequence differentiating verified **Observations** from analytical **Hypotheses**.
  - Complete Stage 3 Evidence Provenance Chain, faithfully preserving dashed gaps (`absent` links) and qualified explanations.
  - Stage 2 Calibrated vs. Uncalibrated confidence status.
  - Embedded topology snapshot using Cytoscape.js built-in PNG rasterizer (`cy.png()`).
- **Mandatory Synthetic Demo Disclosures**:
  - When operating on synthetic or replayed data, the cover carries a prominent banner:
    > *"Synthetic demo data. Results do not reflect real-world detection accuracy."*
  - In printed format, this exact disclosure is permanently repeated across the running footer of every printed page.
- **Audit Metadata & Integrity Checksum**:
  - Displays generation timestamp, data source mode, timestamp basis (Event Time vs. Ingest Time), application version/commit, and session alert scope.
  - Computes a SHA-256 digest of the canonical briefing JSON payload using Web Crypto `SubtleCrypto`.
  - **Strict Naming Standard**: The checksum is labeled exactly as:
    > *"Integrity checksum (detects accidental changes; not a digital signature)"*
  - Prohibition: The system NEVER refers to this checksum as "cryptographic validation," "tamper-proof," or "digitally signed."
  - Graceful Fallback: In environments lacking `SubtleCrypto`, the checksum is omitted with an explicit disclosure (*"SubtleCrypto unavailable in this environment; checksum omitted"*).
- **Preservation of Existing Pipelines**: All pre-existing incident JSON and CSV exports remain completely untouched and operational.

---

## 8. Architectural Extension Points (Roadmap to Stage 5)

1. **Skippable First-Run Cinematic Intro**:
   - High-impact atmospheric entry sequence for executive SOC demonstrations.
   - Strict honesty constraint: Zero fake terminal "booting" text or fabricated system checks; purely decorative spatial emergence.
   - Fully skippable via `Escape` key, click, or immediate bypass when `prefers-reduced-motion` is detected.
2. **Mid-Range & Constrained Device Optimization Pass**:
   - Dynamic canvas resolution scaling and particle count reduction for Intel UHD and mobile GPUs.
   - Frame budget throttling to ensure stable $60\text{FPS}$ across lower-tier hardware.
3. **Comprehensive Accessibility Audit**:
   - Repo-wide screen reader verification across VoiceOver and NVDA.
   - Comprehensive high-contrast theme validation.
4. **Interactive Walkthrough & Screenshot Assets**:
   - Automated visual regression and demonstration captures for README documentation.
5. **Stacked Branch Merge Strategy**:
   - Structured rebase and merge order:
     `feat/stage1-cinematic-foundation` → `feat/stage2-depth-confidence` → `feat/stage3-evidence-scrubber` → `feat/stage4-palette-briefing` → `main`.

