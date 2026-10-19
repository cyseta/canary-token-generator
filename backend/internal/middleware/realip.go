package middleware

import (
	"context"
	"net/http"

	"canary-token-generator/backend/internal/clientip"
)

const RealIPKey contextKey = "RealIP"

// RealIP resuelve la IP del cliente UNA sola vez por peticion. Las cabeceras de reenvio solo se
// aceptan si la conexion directa viene de un proxy de confianza (ver package clientip); antes se
// creia cualquier X-Forwarded-For/CF-Connecting-IP, lo que permitia falsificar la IP registrada
// (el dato forense central de esta herramienta) y esquivar el rate limit rotando la cabecera.
func RealIP(res *clientip.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), RealIPKey, res.FromRequest(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetRealIP(ctx context.Context) string {
	if ip, ok := ctx.Value(RealIPKey).(string); ok {
		return ip
	}
	return ""
}

// ClientIP devuelve la IP ya resuelta o, si el middleware no estuvo en la cadena, la de la conexion.
func ClientIP(r *http.Request) string {
	if ip := GetRealIP(r.Context()); ip != "" {
		return ip
	}
	if a, ok := clientip.Parse(hostOnly(r.RemoteAddr)); ok {
		return a.String()
	}
	return "unknown"
}
