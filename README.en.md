*[Leer en español](README.md)*

# Canary Token Generator — Cyber Deception System

A full-stack, modular deception platform designed to fabricate, deploy, and monitor deceptive canary tokens (honeytokens). When touched or probed by unauthorized intruders, the system records forensic telemetry (source IP, GeoIP location, client hints, browser hardware fingerprint) and dispatches real-time alerts.

```
canary-token-generator/
├── backend/                       Go 1.26+ daemon, Chi router, pure Go MySQL listener, async notification pool
│   ├── cmd/canary/                main.go — wiring, signal handling, MySQL listener spawn, retention loop
│   └── internal/
│       ├── token/                 Service, repository, handler, generator interface
│       │   └── generators/
│       │       ├── webbug/        Embedded JPEG tracking pixel
│       │       ├── pixel/         Shared 43-byte transparent 1x1 GIF helper
│       │       ├── pdf/           Byte-exact PDF placeholder substitution (76-byte URL window)
│       │       ├── docx/          OpenXML ZIP-aware footer relationship rewrite
│       │       ├── envfile/       Recipe shuffler + canary line injection (AWS, DB, GitHub, Stripe)
│       │       ├── kubeconfig/    text/template renderer + wildcard /k/ probe handler
│       │       ├── mysql/         protocol.go (wire handshake/auth/err), server.go (TCP), handler.go
│       │       └── slowredirect/  HTML interstitial + fingerprint POST beacon handler
│       ├── event/                 Event entity, service (geo enrich → insert → dedup → notify), repository
│       ├── notify/                Worker pool, queue, HMAC signed webhooks, Telegram bot client
│       ├── middleware/            request_id, logging, recovery, realip, fingerprint, ratelimit, turnstile, operator_bearer, headers
│       ├── geoip/                 MaxMind MMDB lookup wrapper (with NopProvider fallback)
│       ├── turnstile/             Cloudflare Turnstile siteverify
│       ├── admin/                 Stats, token listing, force-disable
│       ├── core/                  DB pool (SQLite / Postgres), Redis client / memory cache, migrations, telemetry
│       ├── health/                /healthz handler with readiness and draining shutdown flags
│       └── server/                Chi router shell with graceful shutdown and drain delay
├── frontend/                      Modern React + Vite + Tailwind CSS SPA (Built with pnpm)
│   └── src/
│       ├── pages/landing/         Token creation form (type-aware metadata, Turnstile, artifact reveal)
│       └── pages/manage/          Token detail + paginated event table (GeoIP badges, forensics modal)
├── infra/
│   ├── nginx/                     prod.nginx, dev.nginx (Vite HMR proxy)
│   └── docker/                    Dockerfiles for prod binary, Air hot-reload, Vite HMR
├── compose.yml                    Production stack (Postgres + Redis + Backend + Nginx)
├── dev.compose.yml                Dev stack with Jaeger OpenTelemetry tracing
├── cloudflared.compose.yml        Cloudflare Tunnel overlay for public ingress
├── justfile                       Grouped recipe runner (frontend, backend, lint, compose, tunnel, dev, util)
└── learn/                         Technical deep-dive learning guides & specifications
```

---

## Supported Canary Generators

| Type | Name | Mechanism | Intruder Artifact | Detection reliability |
|---|---|---|---|---|
| `webbug` | **Web Bug / Pixel** | Hidden 1x1 image | HTML snippet, Markdown badge, `.html` page | Medium: needs a client that loads remote images (mail clients often block them; image proxies hide the real IP) |
| `pdf` | **Acrobat PDF** | `/OpenAction` URI, structure computed at build time | Confidential-looking PDF | **Low**: Acrobat usually asks for confirmation; browser viewers ignore it. Test with your own readers |
| `docx` | **Word Document** | OpenXML external image in the footer | Valid `.docx` | Medium: Protected View blocks it until "Enable editing" |
| `envfile` | **Decoy .env File** | Realistic-format decoy credentials + endpoint variables | `.env` (AWS, DB, GitHub, Stripe recipes) | Medium/Low: the keys are NOT real, so trying them against AWS/GitHub/Stripe never reaches you. It fires when tooling follows `AWS_ENDPOINT_URL`/`GITHUB_API_URL`/`STRIPE_API_BASE`, or someone connects to the DB host (MySQL honeypot) |
| `kubeconfig` | **Kubeconfig Token** | Kubernetes API trap (`/k/:id/*`) | `~/.kube/config` with a realistic service-account JWT | High for anyone who runs `kubectl` with it |
| `mysql` | **MySQL Honeypot** | Binary TCP server on port 3306 | `my.cnf` + `mysql` command | High, **when the port is reachable by the attacker**. Records whether the *exact planted password* was used and the client program/version |
| `slowredirect` | **Slow Redirect** | Interstitial page with canvas / WebGL fingerprint | Link that collects signals and redirects | High for humans; link scanners/preview bots also open it (tagged `link-preview-or-scanner`). Fingerprints are client-reported: treat as indicators |

> Honesty note: canary tokens detect *contact*, not intent. Visits from scanners and previewers are tagged, not
> silently discarded. For real cloud-credential detection use provider-native canaries (e.g. an IAM user with no
> permissions plus CloudTrail alerts).

---

## Quickstart

### Option 1: Run Locally (Standalone Mode)

The backend natively supports embedded SQLite and in-memory caching out-of-the-box with zero external services required!

```bash
# 1. Run Backend Daemon
cd backend
go run ./cmd/canary

# 2. In another terminal, run Frontend Dev Server (using pnpm)
cd frontend
pnpm install
pnpm dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

### Option 2: Run with Docker Compose (Production Stack)

```bash
cp .env.example .env          # fill in BASE_URL, ADMIN_TOKEN, POSTGRES_PASSWORD, REDIS_PASSWORD (openssl rand -hex 32)
docker compose up -d --build  # Postgres, Redis, Go backend (non-root, read-only FS), Nginx
docker compose logs -f
```
The stack **refuses to start without secrets** (there are no default credentials) and serves **HTTP only**: put it behind a
TLS-terminating load balancer or use the Cloudflare Tunnel overlay (`just tunnel-up`). The MySQL honeypot listens on `3306`
and must be reachable by the attacker (an HTTP tunnel does not forward it; set `PUBLIC_MYSQL_HOST`).
`/admin` is only reachable from the Docker host itself (edit `infra/nginx/prod.nginx` to add your management network).
For GeoIP place `GeoLite2-City.mmdb` in `data/geoip/`.

---

### Option 3: Run with `just` Runner

If you use `just`:
```bash
just frontend-install  # Installs frontend dependencies with pnpm
just frontend-build    # Builds production Vite bundle
just backend-test      # Runs all Go unit and integration tests
just dev               # Launches dev stack with Air hot reload and Jaeger
```

---

## Security model (what changed vs. earlier versions)

See [`AUDIT.md`](AUDIT.md) for the full list of findings and fixes. Highlights:

- **Client IP is never taken from a header unless the TCP peer is a trusted proxy** (`TRUSTED_PROXIES`, `CLIENT_IP_HEADER`).
- **Management key** travels in the `X-Manage-Key` header (not in the URL), links use the URL fragment (`/#/manage/<key>`),
  and only its SHA-256 is stored. Existing plaintext keys are migrated automatically on first start.
- **Webhooks are SSRF-safe**: https only, internal/metadata addresses refused at connect time, no redirects, bounded per host.
- Tokens can be deleted by their owner (`DELETE /api/manage`), including all recorded events.
- Sensitive request headers (`Authorization`, `Cookie`, ...) are redacted before storage.

## Technical Deep-Dives in `learn/`

> Some guides describe the original design. Where the implementation changed (PDF generation, MySQL attribution, deduplication)
> the guide carries an *Update* note at the top.


The `learn/` directory contains complete architectural guides and protocol specifications:

1. [00 — Architecture & Honeytoken Mechanics](learn/00_architecture_overview.md)
2. [01 — Byte-Exact PDF Substitution](learn/01_byte_exact_pdf_substitution.md)
3. [02 — OpenXML (.docx) Footer Rewrite](learn/02_docx_zip_relationship_injection.md)
4. [03 — MySQL Wire Protocol Honeypot](learn/03_mysql_wire_protocol_honeypot.md)
5. [04 — Kubeconfig & K8s Canaries](learn/04_kubeconfig_and_k8s_canaries.md)
6. [05 — Slow Redirect & Browser Fingerprinting](learn/05_slow_redirect_and_fingerprinting.md)
7. [06 — Event Pipeline, GeoIP & Deduplication](learn/06_event_dedup_and_geo_enrichment.md)

---

## License

MIT License. Open-source deception engineering for blue teams and security researchers.
