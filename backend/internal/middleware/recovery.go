package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"canary-token-generator/backend/internal/core"
)

func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec) // senal legitima de net/http: no se debe tragar
				}
				core.IncErrors()
				slog.Error("panic recovered in http handler", "error", rec, "stack", string(debug.Stack()))
				core.JSONError(w, http.StatusInternalServerError, "Internal Server Error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
