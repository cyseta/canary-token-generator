package middleware

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"canary-token-generator/backend/internal/core"
)

// RateLimit aplica una ventana fija por (nombre de limite, IP). El incremento y el TTL se fijan en una
// unica operacion atomica; antes eran dos pasos con una condicion de carrera que podia reiniciar el
// contador. Si la cache falla se deja pasar (fail-open) para no tumbar la deteccion.
func RateLimit(cache core.CacheClient, name string, maxReqs int64, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := "rl:" + name + ":" + ClientIP(r)
			count, err := cache.IncrWithTTL(r.Context(), key, window)
			if err != nil {
				slog.Warn("rate limiter cache error, failing open", "limit", name, "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if count > maxReqs {
				w.Header().Set("Retry-After", strconv.Itoa(int(window.Seconds())))
				core.JSONError(w, http.StatusTooManyRequests, "Too many requests, please slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
