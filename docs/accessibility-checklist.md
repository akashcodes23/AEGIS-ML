# AEGIS-ML Manual Screen-Reader Verification Checklist

> **Disclaimer**: This checklist was compiled by the development agent based on the implemented WAI-ARIA 1.2 semantics and automated `axe-core` passes. **The AI agent cannot execute VoiceOver or NVDA.** Human evaluation using real assistive technologies is required before final sign-off.

---

## 1. Test Environment Setup

| Platform | Screen Reader | Browser | Shortcut to Toggle |
|---|---|---|---|
| **macOS** | VoiceOver | Safari / Chromium | `Cmd + F5` |
| **Windows** | NVDA | Edge / Chrome / Firefox | `Ctrl + Alt + N` |
| **iOS / iPadOS** | VoiceOver | Mobile Safari | Triple-click Side / Home button |

---

## 2. Feature-by-Feature Verification Script

### 2.1 Application Shell & Landmark Navigation
1. **Initial Page Load (`/`)**:
   - **Action**: Load the application with VoiceOver/NVDA running.
   - **Expected Announcement**: Page title announces `AEGIS-ML | Spatial Intrusion Detection`.
   - **Keyboard Tab #1**: Focus lands on the hidden Skip Link: `"Skip to main content, link"`. Pressing `Enter` jumps focus directly to the main landmark container (`#main-content`), bypassing navigation.
2. **Navigation Dock**:
   - **Role**: `tablist` containing four tabs: `Dashboard`, `Threat Hunting`, `Entity Graph`, `Reports`.
   - **Expected Announcement**: Each tab announces its label, selection state (e.g., `"Dashboard, selected tab, 1 of 4"`), and associated shortcut hint (`⌥1` or `Alt+1`).
   - **Arrow Navigation**: Left/Right arrow keys navigate between tabs; `Enter` or `Space` activates the route.

### 2.2 First-Run Intro Sequence
1. **First-Visit Behavior**:
   - **Action**: Clear `localStorage` or open a private window to `/`.
   - **Expected Announcement**: Focus immediately lands on `"Skip intro, button"`.
   - **Accessibility**: The background SVG assembly animation is marked `aria-hidden="true"` and conveys zero auditory chatter or fake boot text.
   - **Action**: Press `Escape` or `Enter`.
   - **Expected Announcement**: Intro overlay unmounts immediately. Focus is cleanly restored to the main content container.
2. **Reduced Motion**:
   - **Action**: Enable `prefers-reduced-motion` in OS settings and refresh.
   - **Expected Announcement**: Intro does not render; operator lands directly on the main application interface.

### 2.3 Command Palette (`Cmd+K` / `Ctrl+K`)
1. **Triggering Palette**:
   - **Action**: Press `Cmd+K` (macOS) or `Ctrl+K` (Windows/Linux).
   - **Expected Announcement**: Dialog opens. Screen reader announces: `"Command and entity palette, dialog"`. Focus moves directly into the search input: `"Search entities, alerts, routes, or actions, combobox, expanded"`.
2. **Combobox Navigation**:
   - **Action**: Type `critical` or an IP address (`198.51.100.22`).
   - **Action**: Press `ArrowDown` / `ArrowUp`.
   - **Expected Announcement**: Active descendant announces item label, category group (e.g., `"Exfiltration to 198.51.100.22, Critical Alert, 1 of 6"`).
3. **Dismissal**:
   - **Action**: Press `Escape`.
   - **Expected Announcement**: Dialog closes; focus is restored back to the element that was focused prior to opening the palette.

### 2.4 Evidence Trail Modal (Provenance Chain)
1. **Opening Evidence Trail**:
   - **Action**: Navigate to any alert in the Alert Feed and press `Enter` on `"View evidence trail"`.
   - **Expected Announcement**: Dialog opens: `"Evidence Provenance Chain for Alert <ID>, dialog"`.
2. **Provenance Link Sequence**:
   - **Expected Announcement**: Reads the 5-link progression (`Ingest Packet` → `ML Classification` → `Correlation Graph` → `Incident Cluster` → `Response Action`).
   - **Evidence Gaps**: If an evidence link is absent (e.g., uncalibrated confidence or unverified feature weights), verify that VoiceOver announces: `"Absent evidence link: <Reason>"`. It must not announce fabricated status.
3. **Dismissal**:
   - **Action**: Press `Escape` or activate `"Close evidence modal, button"`.

### 2.5 Temporal Investigation Scrubber
1. **Slider Control**:
   - **Role**: `slider` with accessible label `"Incident progression timeline"`.
   - **Expected Announcement**: Announces `aria-valuenow`, `aria-valuemin`, `aria-valuemax`, and dynamic `aria-valuetext` (e.g., `"Telemetry at 10:45:00 AM"`).
2. **Transport Buttons**:
   - **Action**: Tab to `"Play timeline forward, button"` and `"Step backward to earlier telemetry, button"`.
   - **Expected Announcement**: Clear button labels. During playback, play button announces `"Pause timeline playback"`.
3. **Past State Buffer Announcement**:
   - **Action**: Scrub backward into past telemetry.
   - **Expected Announcement**: Status banner announces: `"Viewing state at <time>. Incoming live alerts buffered: <count>"`.

### 2.6 Threat Hunting Focus Mode
1. **Focus Bar**:
   - **Role**: Region labeled `"Active Hunting Filter Focus"`.
   - **Expected Announcement**: Reads the active filter criteria (e.g., `"Stage: Command and Control | Severity: Critical"`), matching entity count, and graph highlight status.
2. **Clear Action**:
   - **Action**: Tab to `"Clear focus, button"` and press `Enter`.
   - **Expected Announcement**: Focus is cleared; full topology restored.

### 2.7 Executive Briefing Report & Integrity Checksum
1. **Modal Presentation**:
   - **Expected Announcement**: `"Executive Incident Briefing Report, dialog"`.
2. **Verification Checksum**:
   - **Expected Announcement**: Identifies the integrity hash with exact label: `"Integrity checksum (detects accidental changes; not a digital signature)"`.
3. **Download Action**:
   - **Action**: Tab to `"Download briefing data (JSON), button"`.
   - **Expected Announcement**: Verifies file download initiates with exact SHA-256 payload.
4. **Verification Instructions**:
   - **Expected Announcement**: Reads the shell verification instruction (`shasum -a 256 <filename>`).

---

## 3. High-Contrast & Zoom Checklist

- [ ] **Windows High Contrast Mode (`forced-colors: active`)**:
  - Text colors automatically map to `CanvasText` and backgrounds map to `Canvas`.
  - Hairline borders and focus rings remain visible using system `Highlight` / `ButtonBorder`.
- [ ] **200% Browser Zoom**:
  - No horizontal scrolling occurs on standard desktop viewports (1440px).
  - Navigation tabs, metrics cards, and modals wrap cleanly into accessible vertical stacks.
- [ ] **WCAG 1.4.12 Text Spacing Override**:
  - Setting line height to $1.5$, letter spacing to $0.12\text{em}$, and word spacing to $0.16\text{em}$ causes no truncated text or broken buttons.
