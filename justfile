# Justfile for Canary Token Generator

default:
    @just --list

# ==============================================================================
# FRONTEND (Managed exclusively with pnpm)
# ==============================================================================

# Install frontend dependencies with pnpm
frontend-install:
    cd frontend && pnpm install

# Start frontend dev server
frontend-dev:
    cd frontend && pnpm dev

# Build frontend production bundle
frontend-build:
    cd frontend && pnpm build

# Preview built frontend
frontend-preview:
    cd frontend && pnpm preview

# ==============================================================================
# BACKEND (Go 1.26+, ver backend/go.mod)
# ==============================================================================

# Run backend daemon locally with SQLite
backend-run:
    cd backend && go run ./cmd/canary

# Build standalone backend binary
backend-build:
    cd backend && go build -ldflags="-w -s" -o ../bin/canary-daemon ./cmd/canary

# Run all backend unit & integration tests
backend-test:
    cd backend && go test -v -race ./...

# Escaneo de vulnerabilidades conocidas en dependencias (Go y npm)
audit:
    cd backend && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
    cd frontend && pnpm audit --prod

# Tidy Go modules
backend-tidy:
    cd backend && go mod tidy

# ==============================================================================
# LINT & CODE QUALITY
# ==============================================================================

# Run Go and TypeScript typechecks
lint: lint-backend lint-frontend

lint-backend:
    cd backend && go vet ./...

lint-frontend:
    cd frontend && pnpm tsc --noEmit

# ==============================================================================
# DOCKER COMPOSE (Production Stack)
# ==============================================================================

# Spin up production stack (Postgres + Redis + Backend + Nginx)
compose-up:
    docker compose -f compose.yml up -d --build

# Stop production stack
compose-down:
    docker compose -f compose.yml down

# View logs for production services
compose-logs:
    docker compose -f compose.yml logs -f

# Check health of production services
compose-ps:
    docker compose -f compose.yml ps

# ==============================================================================
# CLOUDFLARE TUNNEL OVERLAY
# ==============================================================================

# Run production stack with Cloudflare Tunnel overlay
tunnel-up:
    docker compose -f compose.yml -f cloudflared.compose.yml up -d

# Stop tunnel stack
tunnel-down:
    docker compose -f compose.yml -f cloudflared.compose.yml down

# ==============================================================================
# DEVELOPMENT STACK
# ==============================================================================

# Start complete dev stack with hot reloading (Air + Vite HMR + Jaeger)
dev:
    docker compose -f dev.compose.yml up --build

# Stop dev stack
dev-down:
    docker compose -f dev.compose.yml down -v

# ==============================================================================
# UTILITIES & VERIFICATION
# ==============================================================================

# Probe health endpoint
test-health:
    curl -i http://localhost:8080/healthz

# Test MySQL honeypot connection with fake credentials
test-mysql:
    mysql -h 127.0.0.1 -P 3306 -u intruder_probe -p'stolen_password' prod_db || true  # trafico de fondo: NO genera alerta (solo cuenta en /admin/stats)
