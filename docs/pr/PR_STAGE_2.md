# PR: Stage 2 — Kill-Chain Depth & Calibrated Confidence

- **Branch:** `feat/stage2-depth-confidence`
- **Base Target:** `feat/stage1-cinematic-foundation` (`41aeab4`)
- **Type:** Feature / Semantic Visualization

---

### 1. Summary of Changes
- Integrated 3D spatial depth mapping into Cytoscape.js Entity Graph via `KILL_CHAIN_DEPTH` constant mapping the 8 MITRE ATT&CK stages from $z=-70$ to $z=0$.
- Implemented `confidenceToFocus()` pure mapping function translating isotonic calibrated posterior probabilities $\hat{P}(Y=c|X)$ into visual focus (blur, opacity, saturation).
- Enforced strict "Crimson is Rare" guardrail: `#ff3366` reserved strictly for Critical Severity alerts.
- Added live depth slice slider and uncalibrated confidence indicators.

### 2. Risk Assessment
- **Risk Level:** Low to Medium.
- **Surface Area:** Cytoscape style declarations and Alert Feed rendering cards.
- **Mitigation:** Unassigned or missing kill-chain stages default safely to truthful neutral depth without guessing. Models and backend endpoints remain untouched.

### 3. Test Evidence
- **Automated Tests:** Unit tests passing for `KILL_CHAIN_DEPTH`, `confidenceToFocus`, `crimson_guardrail.test.js`.
- **Clean Bundle Impact:** Main chunk raw size: 845.12 kB (+4.58 kB raw, +2 bytes gzip vs Stage 1).
- **Scale Validation:** Verified 500-node graph scaling with smooth frame rates.

### 4. Visual Evidence
- Screenshot: `docs/assets/entity_graph_depth.png` (Kill-chain depth legend, spatial layer hierarchy).
- Screenshot: `docs/assets/alert_feed_confidence.png` (Calibrated vs uncalibrated confidence states).

### 5. Known Limitations
- High-contrast issues on small badges were identified during Stage 3 and resolved in Stage 4/5 with obsidian backing.
