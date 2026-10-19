package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"canary-token-generator/backend/internal/clientip"
	"canary-token-generator/backend/internal/core"
)

func TestRealIPIgnoresSpoofedHeadersFromUntrustedPeer(t *testing.T) {
	res, _ := clientip.New(nil, "")
	var got string
	h := RealIP(res)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = GetRealIP(r.Context()) }))
	r := httptest.NewRequest("GET", "/t/x", nil)
	r.RemoteAddr = "203.0.113.50:4444"
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	r.Header.Set("CF-Connecting-IP", strings.Repeat("A", 100))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "203.0.113.50" {
		t.Fatalf("IP registrada %q: la cabecera falsificada no debe prevalecer", got)
	}
}

// Regresion: en modo memoria el rate limit nunca se activaba (Incr siempre devolvia 1).
func TestRateLimitActuallyLimits(t *testing.T) {
	cache := core.NewMemoryCache()
	defer cache.Close()
	res, _ := clientip.New(nil, "")
	h := RealIP(res)(RateLimit(cache, "create", 3, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	codes := []int{}
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("POST", "/api/tokens", nil)
		r.RemoteAddr = "203.0.113.50:1"
		r.Header.Set("X-Forwarded-For", "1.2."+string(rune('0'+i))+".4") // rotar la cabecera ya no evade el limite
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		codes = append(codes, w.Code)
	}
	if codes[2] != 204 || codes[3] != 429 || codes[4] != 429 {
		t.Fatalf("codigos %v: se esperaba 429 a partir de la 4a peticion", codes)
	}
	// otra IP no se ve afectada
	r := httptest.NewRequest("POST", "/api/tokens", nil)
	r.RemoteAddr = "203.0.113.99:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("el limite debe ser por IP")
	}
	_ = context.Background
}

func TestOperatorBearer(t *testing.T) {
	ok := OperatorBearer(strings.Repeat("s3", 20))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	try := func(auth string) int {
		r := httptest.NewRequest("GET", "/admin/stats", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		ok.ServeHTTP(w, r)
		return w.Code
	}
	if try("Bearer "+strings.Repeat("s3", 20)) != 200 {
		t.Fatal("token valido")
	}
	for _, bad := range []string{"", "Bearer x", "Basic abc", "Bearer " + strings.Repeat("s3", 21), "Bearer"} {
		if try(bad) != 401 {
			t.Fatalf("%q debe dar 401 uniforme", bad)
		}
	}
	// token esperado vacio nunca autentica
	empty := OperatorBearer("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()
	empty.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("un token vacio no debe autenticar")
	}
}

func TestRequestIDValidation(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, in := range []string{"evil\r\nX-Injected: 1", strings.Repeat("a", 500), "<script>"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header["X-Request-Id"] = []string{in}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("X-Request-ID"); got == in || len(got) > 64 {
			t.Fatalf("valor del cliente reflejado: %q", got)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-ID", "abc-123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("X-Request-ID") != "abc-123" {
		t.Fatal("un ID valido se conserva")
	}
}

func TestExtractCleanHeadersRedactsAndCaps(t *testing.T) {
	// Se repite muchas veces: la version anterior iteraba un map (orden aleatorio) y fallaba de forma intermitente.
	for run := 0; run < 200; run++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer real-secret")
		r.Header.Set("Cookie", "session=abc")
		r.Header.Set("User-Agent", "curl/8")
		r.Header.Add("Accept", "a")
		r.Header.Add("Accept", "b")
		r.Header.Set("X-Big", strings.Repeat("z", 5000))
		for i := 0; i < 100; i++ { // relleno para intentar desplazar las cabeceras importantes
			r.Header.Set(fmt.Sprintf("A-Filler-%03d", i), "v")
		}
		h := ExtractCleanHeaders(r)
		if h["authorization"] != "[redacted]" || h["cookie"] != "[redacted]" {
			t.Fatalf("run %d: credenciales sin redactar: %v", run, h["authorization"])
		}
		if h["user-agent"] != "curl/8" || h["accept"] != "a, b" {
			t.Fatalf("run %d: las cabeceras prioritarias deben conservarse siempre (ua=%q accept=%q)", run, h["user-agent"], h["accept"])
		}
		if len(h) > maxCapturedHeaders+1 || h["_truncated"] != "true" {
			t.Fatalf("run %d: acotado incorrecto n=%d", run, len(h))
		}
		if len(h["x-big"]) > maxHeaderValueLen+5 {
			t.Fatal("valor sin acotar")
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	for k, want := range map[string]string{"X-XSS-Protection": "0", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if w.Header().Get(k) != want {
			t.Fatalf("%s=%q", k, w.Header().Get(k))
		}
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") || w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("falta CSP/HSTS")
	}
}
