# 00 — Architecture & Honeytoken Mechanics

Welcome to the **Canary Token Generator** architecture documentation (`learn/`).

## What is a Canary Token?

A **Canary Token** (also known as a *honeytoken* or *digital tripwire*) is a deceptive, high-fidelity security mechanism. Unlike traditional defensive detection (like IDS or SIEM signatures) that produce frequent false positives, canary tokens possess a unique property:

> **Canary tokens have zero legitimate business use.**
> If a canary token is ever accessed, triggered, or queried, it is almost certainly evidence of an active intrusion, unauthorized reconnaissance, data exfiltration, or credential harvesting.

```
+-----------------------------------------------------------------------------------+
|                              Canary Deception Lifecycle                           |
|                                                                                   |
|   1. GENERATE               2. PLANT                        3. TRIGGER            |
|   [Token Generator] ------> [Bait Placement] -------------> [Attacker Action]     |
|   • Web Bug                 • Desktop folder                • Opens PDF in Adobe  |
|   • Byte-exact PDF          • Git repository / CI           • Curls .env endpoint |
|   • OpenXML DOCX            • ~/.kube/config                • Queries K8s cluster |
|   • Fake .env secrets       • Bash history                  • Attempts MySQL auth |
|   • MySQL honeypot          • Public paste / forum          • Clicks canary link  |
|   • Slow redirect                                                                 |
|                                                                    |              |
|                                                                    v              |
|   6. ALERT & CONTAIN        5. RECORD & ENRICH              4. INTERCEPT          |
|   [Incident Response] <---- [Event Pipeline] <------------- [Canary Sensor]       |
|   • HMAC Webhook to SIEM    • MaxMind GeoIP Country/City    • HTTP router /t/:id  |
|   • Telegram Alert          • Redis Sliding Dedup Window    • TCP :3306 MySQL     |
|   • Live Ops Dashboard      • Client hints & Canvas hash    • Wildcard /k/:id/*   |
+-----------------------------------------------------------------------------------+
```

---

## System Component Layout

```
canary-token-generator/
├── backend/
│   ├── cmd/canary/                main.go — wiring, signal handling, MySQL listener spawn, retention loop
│   └── internal/
│       ├── token/                 Service, repository, handler, generator interface
│       │   └── generators/
│       │       ├── webbug/        Embedded JPEG pixel
│       │       ├── pixel/         Shared 1x1 GIF helper used by every "visited" response
│       │       ├── pdf/           Byte-exact PDF placeholder substitution (76-byte URL window)
│       │       ├── docx/          ZIP-aware footer rewrite
│       │       ├── envfile/       Recipe shuffler + canary line injection
│       │       │   └── recipes/   aws.go, db.go, github.go, stripe.go
│       │       ├── kubeconfig/    text/template renderer + wildcard /k/ handler
│       │       ├── mysql/         protocol.go (handshake + auth + err packets), server.go (TCP), handler.go
│       │       └── slowredirect/  HTML interstitial + fingerprint POST handler
│       ├── event/                 Event entity, service (geo enrich → insert → dedup → notify), repository
│       ├── notify/                Worker pool, queue, status writer
│       │   ├── webhook/           HMAC-signed POSTs with exponential backoff
│       │   └── telegram/          Bot API client
│       ├── middleware/            request_id, logging, recovery, realip, fingerprint, ratelimit, turnstile, operator_bearer, headers
│       ├── geoip/                 MaxMind MMDB lookup wrapper (nop when no DB present)
│       ├── turnstile/             Cloudflare Turnstile siteverify
│       ├── admin/                 Stats, listing, force-disable
│       ├── core/                  DB pool, Redis client, migrations, telemetry, errors, validation, response envelopes
│       ├── health/                /healthz handler with readiness/shutdown flags
│       └── server/                chi router shell with graceful shutdown + drain delay
├── frontend/
│   └── src/
│       ├── pages/landing/         Token creation form (type-aware metadata, Turnstile widget, artifact reveal)
│       └── pages/manage/          Token detail + event table (cursor paginated, GeoIP cells, dedup silence)
├── infra/
│   ├── nginx/                     prod.nginx, dev.nginx (Vite proxy)
│   └── docker/                    Dockerfiles for prod binary, Air hot-reload, Vite HMR
├── compose.yml                    Production stack
├── dev.compose.yml                Dev stack with Jaeger
├── cloudflared.compose.yml        Tunnel overlay
├── justfile                       Recipes grouped by frontend / backend / lint / compose / tunnel / dev / util
└── learn/                         You are here
```

---

## Chapters in this Guide

1. [01 — Byte-Exact PDF Substitution](./01_byte_exact_pdf_substitution.md): Learn how PDF xref tables work and why string substitution must preserve the exact byte length.
2. [02 — OpenXML (.docx) Footer Rewrite](./02_docx_zip_relationship_injection.md): Learn how Word OpenXML packaging can be leveraged for external image tracking without macros.
3. [03 — MySQL Wire Protocol Honeypot](./03_mysql_wire_protocol_honeypot.md): Learn how the binary MySQL 8.0/5.7 protocol functions and how to trap attackers on TCP port 3306.
4. [04 — Kubeconfig & K8s Discovery Canaries](./04_kubeconfig_and_k8s_canaries.md): Learn how `kubectl` discovers cluster APIs and how our wildcard handler collects intruder fingerprints.
5. [05 — Slow Redirect & Browser Fingerprinting](./05_slow_redirect_and_fingerprinting.md): Learn how client-side Canvas and WebGL techniques unmask visitors behind proxies.
6. [06 — Event Pipeline, GeoIP & Deduplication](./06_event_dedup_and_geo_enrichment.md): Learn how events are enriched, deduplicated to prevent notification storms, and dispatched securely via HMAC webhooks.
