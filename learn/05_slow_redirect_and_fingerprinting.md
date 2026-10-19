# 05 — Slow Redirect & Browser Fingerprinting

## Why Standard 302 Redirects Fall Short

A conventional HTTP 301/302 redirect happens entirely at the network layer:
```http
HTTP/1.1 302 Found
Location: https://decoy-destination.com
```

While simple, it only captures:
- Remote IP (which may be masked behind a commercial VPN, Tor, or web proxy)
- Standard HTTP headers (`User-Agent`, `Accept-Language`)

Sophisticated attackers frequently route their web scrapers and browsers through proxies. A standard 302 redirect reveals nothing about the attacker's true underlying machine or physical hardware.

---

## The Interstitial Canary Technique

The **Slow Redirect** canary (`/r/:tokenID`) serves an HTML/CSS interstitial page that resembles a standard corporate security verification screen (e.g. "Verifying connection...").

During the 800ms to 1200ms interstitial window, client-side JavaScript executes non-invasive hardware and browser profiling:

```
Victim / Attacker Browser               Canary Server
         |                                     |
         | -------- 1. GET /r/:id -----------> |
         |                                     |
         | <--- 2. Interstitial HTML + JS ---- |
         |                                     |
    [Executes Profiler]:                       |
    - 2D Canvas rendering                      |
    - WebGL GPU extraction                     |
    - CPU cores / Device RAM                   |
    - Screen metrics & timezone                |
         |                                     |
         | -------- 3. POST /f/:id ----------> |
         |            (JSON Fingerprint)       | (Records event + GPU forensic data)
         |                                     |
         | <------- 4. 204 No Content -------- |
         |                                     |
    [window.location.replace(targetURL)] ----> [Decoy Destination]
```

---

## Key Forensic Signals Collected

### 1. Canvas 2D Hash
Different operating systems, graphic cards, and font rasterization engines draw identical 2D canvas instructions with minute sub-pixel variations.
```javascript
const canvas = document.createElement('canvas');
const ctx = canvas.getContext('2d');
ctx.textBaseline = "top";
ctx.font = "14px 'Arial'";
ctx.fillStyle = "#f60";
ctx.fillRect(125, 1, 62, 20);
ctx.fillStyle = "#069";
ctx.fillText("CanaryFP", 2, 15);
// Hash computed from canvas.toDataURL()
```

### 2. WebGL GPU Unmasking
Browsers mask raw GPU hardware unless queried through the WebGL debug extension:
```javascript
const gl = canvas.getContext('webgl');
const dbg = gl.getExtension('WEBGL_debug_renderer_info');
const vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
const renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
```
**Example Extracted Forensic Artifact:**
- `vendor`: `Google Inc. (NVIDIA)`
- `renderer`: `ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)`

This hardware footprint stays consistent even if the attacker switches IP addresses, rotates user-agents, or uses incognito mode!

### 3. Hardware Metrics
- `navigator.hardwareConcurrency`: Physical CPU core count.
- `navigator.deviceMemory`: Device RAM category in gigabytes.
- `window.screen`: Full display resolution, available desktop bounds, color depth.
- `Intl.DateTimeFormat().resolvedOptions().timeZone`: System timezone (e.g., `Europe/Moscow`, `America/Chicago`), which often betrays VPN users.

---

## Guaranteed Forwarding with Timeout Fail-Safe

To ensure that network latency or aggressive ad-blockers do not trap the user on a blank screen, a two-phase redirect is enforced:
1. When the `fetch('/f/:tokenID')` promise resolves, a 200ms timer triggers `window.location.replace(targetURL)`.
2. A strict fallback `setTimeout(redirect, 1500)` fires unconditionally after 1.5 seconds regardless of network status.
