package middleware

import (
	"net/http"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/turnstile"
)

func TurnstileCheck(verifier turnstile.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("CF-Turnstile-Token")
			if token == "" {
				token = r.Header.Get("X-Turnstile-Token")
			}

			ip := GetRealIP(r.Context())
			valid, err := verifier.Verify(r.Context(), token, ip)
			if !valid || err != nil {
				core.JSONError(w, http.StatusForbidden, "Turnstile verification failed")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
