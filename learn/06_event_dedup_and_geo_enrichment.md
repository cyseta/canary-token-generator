> **Update:** de-duplication is atomic (`SET NX`) and keyed by token + IP + *class* (`hit` vs `fp`), so the browser-fingerprint alert is no longer suppressed by the initial hit. The window is fixed (5 min), not sliding. Pagination is `LIMIT/OFFSET`, not cursor-based.

# 06 — Event Pipeline, GeoIP & Deduplication

## The Threat of Notification Storms

When a canary token is triggered by an attacker or an automated security scanner (such as VirusTotal, Microsoft Defender SmartScreen, or Google Safe Browsing), it is rarely accessed just once. 

A single file inspection can trigger dozens of automated HTTP requests within seconds. Without intelligent rate-limiting and deduplication:
- Incident response teams suffer **alert fatigue**.
- Webhook endpoints and Telegram bot rate limits are exceeded.
- Legitimate alerts become lost in noise.

---

## 4-Stage Event Processing Pipeline

When any canary endpoint (HTTP pixel, K8s probe, or MySQL honeypot) receives a hit, it passes through our decoupled event service:

```
[Inbound Trigger]
       │
       ▼
1. GEO ENRICHMENT  ──────► MaxMind GeoLite2 MMDB (Country, City, Coordinates)
       │                   (Gracefully falls back to NopProvider if no DB file)
       ▼
2. EVENT STORAGE   ──────► SQL Repository (Persists raw event, increments hit_count)
       │
       ▼
3. DEDUPLICATION   ──────► Redis / In-Memory Cache (5-minute silence window)
       │
   [Duplicate?]
    ├── Yes ─────────────► Silence notification (Logged in DB, but suppresses alert)
    └── No  ─────────────► Forward to Notification Dispatcher
       │
       ▼
4. ASYNC DISPATCH  ──────► Buffered Worker Pool (Queue: 500, Workers: 4)
                           ├── Webhook: HMAC-SHA256 Signed + Exponential Backoff
                           └── Telegram: Markdown formatted Bot API alert
```

---

## Sliding-Window Deduplication Mechanics

Deduplication uses atomic cache operations (Redis or our memory cache janitor):

1. Key format: `dedup:<tokenID>:<sourceIP>`
2. When an event arrives:
   ```go
   dedupKey := fmt.Sprintf("dedup:%s:%s", tok.ID, triggerCtx.SourceIP)
   isDuplicate, _ := cache.Exists(ctx, dedupKey)

   if isDuplicate {
       // Suppress alert, but event is still saved in DB for audit trail
       return ev, nil
   }

   // Lock the window for 5 minutes
   cache.Set(ctx, dedupKey, "1", 5 * time.Minute)
   ```
3. Subsequent requests from the same IP within 5 minutes still increment the token's total hit counter and appear in the UI event log, but do **not** trigger new webhooks or Telegram messages.

---

## Webhook Security: HMAC-SHA256 Signatures

To ensure that downstream SIEMs and alerting platforms can verify that a webhook genuinely originated from your Canary daemon (and not an attacker forging payloads), every outgoing webhook is cryptographically signed:

### Outgoing Headers
```http
POST /api/canary-alerts HTTP/1.1
Host: siem.corp.internal
Content-Type: application/json
User-Agent: Canary-Notifier/1.0
X-Canary-Timestamp: 1728950400
X-Canary-Signature: sha256=a8f4c28190d7e63b...
```

### Signature Computation
```text
Signature = HMAC_SHA256(SecretKey, Timestamp + "." + RequestBody)
```

### Receiver Verification Example (Node.js / Python / Go)
```python
import hmac, hashlib

def verify_canary_webhook(secret, body, timestamp, signature):
    payload = f"{timestamp}.".encode() + body
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```
This construction prevents replay attacks by binding the HMAC signature to the `X-Canary-Timestamp` header.
