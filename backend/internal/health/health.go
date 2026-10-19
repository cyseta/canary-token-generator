package health

import (
	"context"
	"database/sql"
	"net/http"
	"sync/atomic"
	"time"

	"canary-token-generator/backend/internal/core"
)

type Checker struct {
	db             *sql.DB
	isReady        atomic.Bool
	isShuttingDown atomic.Bool
}

func NewChecker(db *sql.DB) *Checker {
	c := &Checker{db: db}
	c.isReady.Store(true)
	c.isShuttingDown.Store(false)
	return c
}

func (c *Checker) SetReady(ready bool) {
	c.isReady.Store(ready)
}

func (c *Checker) SetShuttingDown() {
	c.isShuttingDown.Store(true)
	c.isReady.Store(false)
}

func (c *Checker) Healthz(w http.ResponseWriter, r *http.Request) {
	if c.isShuttingDown.Load() {
		core.JSONError(w, http.StatusServiceUnavailable, "Server is draining / shutting down")
		return
	}

	if !c.isReady.Load() {
		core.JSONError(w, http.StatusServiceUnavailable, "Server is not yet ready")
		return
	}

	if c.db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()
		if err := c.db.PingContext(ctx); err != nil {
			core.JSONError(w, http.StatusServiceUnavailable, "Database unreachable")
			return
		}
	}

	core.JSONSuccess(w, map[string]any{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}
