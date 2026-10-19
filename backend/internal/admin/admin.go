package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/event"
	"canary-token-generator/backend/internal/middleware"
	"canary-token-generator/backend/internal/token"

	"github.com/go-chi/chi/v5"
)

var serverStartTime = time.Now()

type Handler struct {
	tokenService token.Service
	eventService event.Service
}

func NewHandler(tokenService token.Service, eventService event.Service) *Handler {
	return &Handler{
		tokenService: tokenService,
		eventService: eventService,
	}
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	totalCount, err := h.tokenService.CountTokens(r.Context())
	if err != nil {
		core.JSONError(w, http.StatusInternalServerError, "Failed to count tokens")
		return
	}

	totalEvents, err := h.eventService.CountEvents(r.Context())
	if err != nil {
		core.JSONError(w, http.StatusInternalServerError, "Failed to count events")
		return
	}

	core.JSONSuccess(w, map[string]any{
		"total_tokens":   totalCount,
		"total_events":   totalEvents,
		"metrics":        core.SnapshotMetrics(), // copia atomica: antes se serializaba la estructura mientras otras goroutines la modificaban (data race)
		"uptime_seconds": int64(time.Since(serverStartTime).Seconds()),
	})
}

func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 && val <= 200 {
			limit = val
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 && val <= 1_000_000 {
			offset = val
		}
	}

	tokens, total, err := h.tokenService.ListTokens(r.Context(), limit, offset)
	if err != nil {
		core.JSONError(w, http.StatusInternalServerError, "Failed to list tokens")
		return
	}

	core.JSONSuccess(w, map[string]any{
		"tokens": tokens,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *Handler) ForceDisable(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		IsActive *bool `json:"is_active"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IsActive == nil {
		core.JSONError(w, http.StatusBadRequest, "Body must be {\"is_active\": true|false}")
		return
	}

	if _, err := h.tokenService.GetByID(r.Context(), id); err != nil {
		core.JSONError(w, http.StatusNotFound, "Token not found")
		return
	}

	updated, err := h.tokenService.SetActiveByID(r.Context(), id, *body.IsActive)
	if err != nil {
		core.JSONError(w, http.StatusInternalServerError, "Failed to toggle token state")
		return
	}

	slog.Warn("admin changed token state", "token_id", id, "is_active", *body.IsActive, "ip", middleware.ClientIP(r)) // pista de auditoria
	core.JSONSuccess(w, updated)
}

func (h *Handler) GetRecentEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	events, err := h.eventService.GetRecentEvents(r.Context(), limit)
	if err != nil {
		core.JSONError(w, http.StatusInternalServerError, "Failed to fetch events")
		return
	}

	core.JSONSuccess(w, events)
}
