package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"canary-token-generator/backend/internal/core"
)

// OperatorBearer protege /admin. Se comparan los SHA-256 de ambos valores (longitud fija) para no
// filtrar la longitud del token por tiempo, y se responde siempre 401 con el mismo mensaje.
func OperatorBearer(expectedToken string) func(http.Handler) http.Handler {
	expected := sha256.Sum256([]byte(expectedToken))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deny := func() {
				w.Header().Set("WWW-Authenticate", `Bearer realm="canary-admin"`)
				core.JSONError(w, http.StatusUnauthorized, "Unauthorized")
			}
			parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || expectedToken == "" {
				deny()
				return
			}
			provided := sha256.Sum256([]byte(strings.TrimSpace(parts[1])))
			if subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
				deny()
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
