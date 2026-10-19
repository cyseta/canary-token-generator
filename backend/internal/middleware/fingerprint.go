package middleware

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

const FingerprintKey contextKey = "ClientFingerprint"

type ClientHints struct {
	SecChUa         string `json:"sec_ch_ua"`
	SecChUaMobile   string `json:"sec_ch_ua_mobile"`
	SecChUaPlatform string `json:"sec_ch_ua_platform"`
	AcceptLanguage  string `json:"accept_language"`
	SecFetchDest    string `json:"sec_fetch_dest"`
	SecFetchMode    string `json:"sec_fetch_mode"`
	SecFetchSite    string `json:"sec_fetch_site"`
	DNT             string `json:"dnt"`
}

func Fingerprint(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := ClientHints{
			SecChUa:         r.Header.Get("Sec-CH-UA"),
			SecChUaMobile:   r.Header.Get("Sec-CH-UA-Mobile"),
			SecChUaPlatform: r.Header.Get("Sec-CH-UA-Platform"),
			AcceptLanguage:  r.Header.Get("Accept-Language"),
			SecFetchDest:    r.Header.Get("Sec-Fetch-Dest"),
			SecFetchMode:    r.Header.Get("Sec-Fetch-Mode"),
			SecFetchSite:    r.Header.Get("Sec-Fetch-Site"),
			DNT:             r.Header.Get("DNT"),
		}

		ctx := context.WithValue(r.Context(), FingerprintKey, hints)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetFingerprintHints(ctx context.Context) (ClientHints, bool) {
	hints, ok := ctx.Value(FingerprintKey).(ClientHints)
	return hints, ok
}

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true, "x-amz-security-token": true,
}

const (
	maxCapturedHeaders = 64
	maxHeaderValueLen  = 512
)

// priorityHeaders se conservan SIEMPRE, aunque un atacante envie cientos de cabeceras de relleno para
// desplazarlas del limite.
var priorityHeaders = map[string]bool{
	"user-agent": true, "referer": true, "host": true, "origin": true, "accept": true, "accept-language": true,
	"accept-encoding": true, "x-forwarded-for": true, "x-forwarded-proto": true, "x-real-ip": true, "via": true,
	"sec-ch-ua": true, "sec-ch-ua-platform": true, "sec-fetch-site": true, "sec-fetch-mode": true, "sec-fetch-dest": true,
	"content-type": true, "content-length": true, "purpose": true, "sec-purpose": true,
}

func cleanValue(v []string) string {
	val := strings.Join(v, ", ")
	if len(val) > maxHeaderValueLen {
		val = strings.ToValidUTF8(val[:maxHeaderValueLen], "") + "…"
	}
	return val
}

// ExtractCleanHeaders devuelve las cabeceras listas para guardar: en minusculas, con todos los valores,
// acotadas en numero y tamano (antes eran ilimitadas: relleno de la BD) y con las credenciales
// redactadas (un intruso puede enviar cookies/tokens de OTROS sistemas; no se almacenan).
// El resultado es DETERMINISTA: se recorre en orden y las cabeceras prioritarias nunca se descartan.
func ExtractCleanHeaders(r *http.Request) map[string]string {
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)

	headers := make(map[string]string, len(keys))
	// 1) credenciales: siempre se marcan como redactadas (no ocupan cupo)
	// 2) cabeceras prioritarias
	// 3) el resto en orden alfabetico hasta el limite
	for _, lk := range keys {
		if sensitiveHeaders[lk] {
			headers[lk] = "[redacted]"
		}
	}
	for _, lk := range keys {
		if priorityHeaders[lk] {
			headers[lk] = cleanValue(r.Header.Values(http.CanonicalHeaderKey(lk)))
		}
	}
	truncated := false
	for _, lk := range keys {
		if _, done := headers[lk]; done {
			continue
		}
		if len(headers) >= maxCapturedHeaders {
			truncated = true
			break
		}
		headers[lk] = cleanValue(r.Header.Values(http.CanonicalHeaderKey(lk)))
	}
	if truncated {
		headers["_truncated"] = "true"
	}
	return headers
}
