package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"canary-token-generator/backend/internal/admin"
	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/event"
	"canary-token-generator/backend/internal/geoip"
	"canary-token-generator/backend/internal/health"
	"canary-token-generator/backend/internal/server"
	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/docx"
	"canary-token-generator/backend/internal/token/generators/envfile"
	"canary-token-generator/backend/internal/token/generators/kubeconfig"
	mysqlGen "canary-token-generator/backend/internal/token/generators/mysql"
	"canary-token-generator/backend/internal/token/generators/pdf"
	"canary-token-generator/backend/internal/token/generators/slowredirect"
	"canary-token-generator/backend/internal/token/generators/webbug"
	"canary-token-generator/backend/internal/turnstile"
)

const adminTok = "0123456789abcdef0123456789abcdef0123"

type app struct {
	h    http.Handler
	evs  event.Repository
	db   *core.DB
	repo token.Repository
}

func newApp(t *testing.T) *app {
	t.Helper()
	db, err := core.InitDB(&core.Config{DBDriver: "sqlite", DBDSN: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cache := core.NewMemoryCache()
	t.Cleanup(cache.Close)
	cfg := &core.Config{BaseURL: "https://ops.example.com", AdminToken: adminTok, ClientIPHeader: "x-forwarded-for", AllowedOrigins: []string{"https://ops.example.com"}}
	repo := token.NewRepository(db)
	evRepo := event.NewRepository(db)
	evSvc := event.NewService(evRepo, repo.IncrementHitCount, &geoip.NopProvider{}, cache, nil)
	svc := token.NewService(repo)
	for _, g := range []token.Generator{webbug.New(), pdf.New(), docx.New(), envfile.New(), kubeconfig.New(), mysqlGen.New(), slowredirect.New()} {
		svc.RegisterGenerator(g)
	}
	srv, err := server.New(cfg, token.NewHandler(svc, evSvc, turnstile.NewVerifier(""), cfg), admin.NewHandler(svc, evSvc), health.NewChecker(db.DB), cache)
	if err != nil {
		t.Fatal(err)
	}
	return &app{h: srv.Handler(), evs: evRepo, db: db, repo: repo}
}

type resp struct {
	*httptest.ResponseRecorder
}

func (a *app) do(method, path string, body any, hdr map[string]string, remote string) resp {
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r := httptest.NewRequest(method, path, rd)
	if remote == "" {
		remote = "203.0.113.50:5555"
	}
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, r)
	return resp{w}
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &m); err != nil {
		t.Fatalf("respuesta no JSON (%d): %s", r.Code, r.Body.String())
	}
	return m
}

type created struct{ id, key, trigger string }

func (a *app) create(t *testing.T, body map[string]any) created {
	t.Helper()
	r := a.do("POST", "/api/tokens", body, nil, "")
	if r.Code != 201 {
		t.Fatalf("create: %d %s", r.Code, r.Body.String())
	}
	d := r.json(t)["data"].(map[string]any)
	return created{id: d["token"].(map[string]any)["id"].(string), key: d["manage_key"].(string), trigger: d["trigger_url"].(string)}
}

func (a *app) events(t *testing.T, id string) []*event.Event {
	t.Helper()
	evs, _, err := a.evs.ListByToken(nil2ctx(), id, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestCreateAndManageFlow(t *testing.T) {
	a := newApp(t)
	r := a.do("POST", "/api/tokens", map[string]any{"type": "webbug", "label": "HR share"}, nil, "")
	if r.Code != 201 || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create %d %v", r.Code, r.Header())
	}
	d := r.json(t)["data"].(map[string]any)
	key := d["manage_key"].(string)
	tokJSON, _ := json.Marshal(d["token"])
	if strings.Contains(string(tokJSON), "manage_key") || strings.Contains(string(tokJSON), key) {
		t.Fatalf("el token serializado filtra la clave: %s", tokJSON)
	}
	if !strings.Contains(d["manage_url"].(string), "/#/manage/"+key) {
		t.Fatal("manage_url debe usar fragmento")
	}
	// autenticacion por cabecera
	ok := a.do("GET", "/api/manage", nil, map[string]string{"X-Manage-Key": key}, "")
	if ok.Code != 200 {
		t.Fatalf("manage con clave: %d %s", ok.Code, ok.Body.String())
	}
	for name, hdr := range map[string]map[string]string{"sin cabecera": nil, "clave erronea": {"X-Manage-Key": "k" + strings.Repeat("0", 32)}, "hash": {"X-Manage-Key": token.HashManageKey(key)}} {
		if got := a.do("GET", "/api/manage", nil, hdr, ""); got.Code != 404 {
			t.Fatalf("%s: %d (esperado 404 uniforme)", name, got.Code)
		}
	}
	// la ruta antigua con la clave en la URL ya no existe
	if got := a.do("GET", "/api/manage/"+key, nil, nil, ""); got.Code != 404 {
		t.Fatalf("la ruta con clave en la URL debe haber desaparecido: %d", got.Code)
	}
	// toggle
	tg := a.do("POST", "/api/manage/toggle", map[string]any{"is_active": false}, map[string]string{"X-Manage-Key": key}, "")
	if tg.Code != 200 || tg.json(t)["data"].(map[string]any)["is_active"] != false {
		t.Fatalf("toggle: %s", tg.Body.String())
	}
	if bad := a.do("POST", "/api/manage/toggle", map[string]any{}, map[string]string{"X-Manage-Key": key}, ""); bad.Code != 400 {
		t.Fatal("toggle sin is_active debe ser 400 (antes se desactivaba por omision)")
	}
}

func TestCreateValidationAndErrorHandling(t *testing.T) {
	a := newApp(t)
	cases := map[string]any{
		"javascript target": map[string]any{"type": "slowredirect", "target_url": "javascript:alert(1)"},
		"ssrf webhook":      map[string]any{"type": "pdf", "notify_channel": "webhook", "webhook_url": "http://169.254.169.254/"},
		"tipo":              map[string]any{"type": "../etc"},
		"json roto":         "{not json",
		"body enorme":       `{"type":"pdf","label":"` + strings.Repeat("a", 100_000) + `"}`,
		"dos documentos":    `{"type":"pdf"}{"type":"pdf"}`,
	}
	for name, body := range cases {
		r := a.do("POST", "/api/tokens", body, nil, "")
		if r.Code != 400 {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
		for _, leak := range []string{"sql", "constraint", "goroutine", "/home/", ".go:"} {
			if strings.Contains(strings.ToLower(r.Body.String()), leak) {
				t.Errorf("%s: la respuesta filtra detalles internos (%q)", name, leak)
			}
		}
	}
}

func TestTriggersRecordAllMethodsAndAreIndistinguishable(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "webbug"})
	for _, m := range []string{"GET", "HEAD", "POST", "PUT"} { // antes HEAD/PUT daban 405 y no se detectaban
		if r := a.do(m, "/t/"+c.id, nil, map[string]string{"User-Agent": "curl/8"}, ""); r.Code != 200 {
			t.Fatalf("%s: %d", m, r.Code)
		}
	}
	if n := len(a.events(t, c.id)); n != 4 {
		t.Fatalf("eventos=%d, esperado 4", n)
	}
	known, unknown := a.do("GET", "/t/"+c.id, nil, nil, ""), a.do("GET", "/t/cdoesnotexist000000000000", nil, nil, "")
	if known.Code != unknown.Code || !bytes.Equal(known.Body.Bytes(), unknown.Body.Bytes()) {
		t.Fatal("la respuesta debe ser identica para tokens validos e invalidos")
	}
	if r := a.do("GET", "/t/"+c.id+"/extra/path.png", nil, nil, ""); r.Code != 200 {
		t.Fatalf("subrutas: %d", r.Code)
	}
}

func TestSourceIPCannotBeSpoofed(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "webbug"})
	// atacante directo con cabeceras falsas
	a.do("GET", "/t/"+c.id, nil, map[string]string{"X-Forwarded-For": "8.8.8.8", "CF-Connecting-IP": strings.Repeat("A", 100)}, "203.0.113.50:1")
	// detras del proxy de confianza (peer privado)
	a.do("GET", "/t/"+c.id, nil, map[string]string{"X-Forwarded-For": "1.1.1.1, 198.51.100.7"}, "172.18.0.5:1")
	ips := map[string]bool{}
	for _, e := range a.events(t, c.id) {
		ips[e.SourceIP] = true
	}
	if !ips["203.0.113.50"] || !ips["198.51.100.7"] || ips["8.8.8.8"] || ips["1.1.1.1"] || len(ips) != 2 {
		t.Fatalf("IPs registradas: %v", ips)
	}
}

func TestSensitiveHeadersAreNotStored(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "webbug"})
	a.do("GET", "/t/"+c.id, nil, map[string]string{"Authorization": "Bearer SUPERSECRET", "Cookie": "sid=SUPERSECRET", "X-Test": "visible"}, "")
	e := a.events(t, c.id)[0]
	if strings.Contains(e.Headers, "SUPERSECRET") || !strings.Contains(e.Headers, "[redacted]") || !strings.Contains(e.Headers, "visible") {
		t.Fatalf("cabeceras: %s", e.Headers)
	}
}

func TestScannerTagging(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "webbug"})
	a.do("GET", "/t/"+c.id, nil, map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Slackbot-LinkExpanding 1.0)"}, "")
	if e := a.events(t, c.id)[0]; !strings.Contains(e.Fingerprint, "link-preview-or-scanner") {
		t.Fatalf("falta la etiqueta de escaner: %s", e.Fingerprint)
	}
}

func TestKubeEndpointIsNotAnOracle(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "kubeconfig"})
	valid := a.do("GET", "/k/"+c.id+"/api/v1/namespaces", nil, map[string]string{"Authorization": "Bearer x"}, "")
	invalid := a.do("GET", "/k/cffffffffffffffffffffffff/api/v1/namespaces", nil, map[string]string{"Authorization": "Bearer x"}, "")
	if valid.Code != 401 || valid.Code != invalid.Code || valid.Body.String() != invalid.Body.String() {
		t.Fatalf("el endpoint distingue tokens validos de invalidos:\n%s\n%s", valid.Body, invalid.Body)
	}
	evs := a.events(t, c.id)
	if len(evs) != 1 || evs[0].Protocol != "KUBE_API" {
		t.Fatalf("eventos: %+v", evs)
	}
}

func TestSlowRedirectPageIsXSSFreeWithNonceCSP(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "slowredirect", "target_url": "https://example.org/landing"})
	r := a.do("GET", "/r/"+c.id, nil, nil, "")
	csp := r.Header().Get("Content-Security-Policy")
	nonce := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(csp)
	if r.Code != 200 || nonce == nil || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP: %q (code %d)", csp, r.Code)
	}
	if strings.Count(r.Body.String(), `nonce="`+nonce[1]+`"`) != 2 || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("el nonce de la CSP debe coincidir con el de los bloques inline y no debe cachearse")
	}
	// Inyectar un destino malicioso directamente en la BD (fila heredada) tampoco llega a la pagina.
	a.db.Exec(`UPDATE tokens SET target_url='javascript:alert(document.domain)' WHERE id=?`, c.id)
	if body := a.do("GET", "/r/"+c.id, nil, nil, "").Body.String(); strings.Contains(body, "javascript:") {
		t.Fatal("una fila heredada con javascript: llego a la pagina")
	}
	if len(a.events(t, c.id)) != 2 {
		t.Fatal("cada visita a /r/ debe registrar un evento")
	}
}

func TestFingerprintBeaconIsAllowlisted(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "slowredirect"})
	junk := `{"canvasHash":"abc","timezone":"UTC","screen":{"width":1920,"height":1080,"evil":"x"},"languages":["es","en","a","b","c","d","e","f","g","h"],
	 "evil":"<script>","__proto__":{"x":1},"nested":{"a":{"b":{"c":1}}},"platform":12345}`
	r := a.do("POST", "/f/"+c.id, junk, map[string]string{"Content-Type": "text/plain"}, "")
	if r.Code != 204 {
		t.Fatalf("code %d", r.Code)
	}
	evs := a.events(t, c.id)
	if len(evs) != 1 || evs[0].Protocol != "BROWSER_FP" {
		t.Fatalf("eventos: %+v", evs)
	}
	var fp map[string]any
	json.Unmarshal([]byte(evs[0].Fingerprint), &fp)
	for _, bad := range []string{"evil", "__proto__", "nested", "platform"} {
		if _, ok := fp[bad]; ok {
			t.Errorf("clave no permitida almacenada: %s", bad)
		}
	}
	if fp["canvasHash"] != "abc" || len(fp["languages"].([]any)) != 8 || fp["screen"].(map[string]any)["evil"] != nil {
		t.Fatalf("fingerprint: %v", fp)
	}
	if huge := a.do("POST", "/f/"+c.id, strings.Repeat("x", 500_000), nil, ""); huge.Code != 204 {
		t.Fatal("cuerpos enormes se toleran sin error ni almacenamiento")
	}
}

// REGRESION: en modo memoria el rate limit nunca se activaba; y rotar X-Forwarded-For lo evadia.
func TestCreateRateLimitWorksAndCannotBeBypassedWithHeaders(t *testing.T) {
	a := newApp(t)
	got429 := 0
	for i := 0; i < 40; i++ {
		r := a.do("POST", "/api/tokens", map[string]any{"type": "webbug"}, map[string]string{"X-Forwarded-For": fmt.Sprintf("9.9.9.%d", i)}, "203.0.113.77:1")
		if r.Code == 429 {
			got429++
			if r.Header().Get("Retry-After") == "" {
				t.Fatal("falta Retry-After")
			}
		}
	}
	if got429 != 10 {
		t.Fatalf("429s=%d, esperado 10 (limite 30/min)", got429)
	}
	if r := a.do("POST", "/api/tokens", map[string]any{"type": "webbug"}, nil, "203.0.113.78:1"); r.Code != 201 {
		t.Fatal("otra IP no debe verse afectada")
	}
}

func TestDownloadRequiresManageKey(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "envfile", "options": map[string]any{"recipe": "github"}})
	if r := a.do("GET", "/api/manage/download", nil, nil, ""); r.Code != 404 {
		t.Fatal("la descarga publica por ID ya no debe existir")
	}
	if r := a.do("GET", "/api/tokens/"+c.id+"/download", nil, nil, ""); r.Code != 404 {
		t.Fatal("la ruta antigua publica debe haber desaparecido")
	}
	r := a.do("GET", "/api/manage/download", nil, map[string]string{"X-Manage-Key": c.key}, "")
	if r.Code != 200 || !strings.HasPrefix(r.Header().Get("Content-Disposition"), "attachment;") || !strings.Contains(r.Body.String(), "ghp_") || strings.Contains(r.Body.String(), "AKIA") {
		t.Fatalf("descarga: %d %q\n%s", r.Code, r.Header().Get("Content-Disposition"), r.Body.String())
	}
	if r2 := a.do("GET", "/api/manage/download", nil, map[string]string{"X-Manage-Key": c.key}, ""); r2.Body.String() != r.Body.String() {
		t.Fatal("la descarga debe ser estable")
	}
}

func TestOwnerDeleteRemovesEverything(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "webbug"})
	a.do("GET", "/t/"+c.id, nil, nil, "")
	if r := a.do("DELETE", "/api/manage", nil, map[string]string{"X-Manage-Key": c.key}, ""); r.Code != 200 {
		t.Fatalf("delete %d", r.Code)
	}
	if len(a.events(t, c.id)) != 0 || a.do("GET", "/api/manage", nil, map[string]string{"X-Manage-Key": c.key}, "").Code != 404 {
		t.Fatal("token y eventos deben desaparecer")
	}
	if a.do("DELETE", "/api/manage", nil, nil, "").Code != 404 {
		t.Fatal("sin clave no se borra nada")
	}
}

func TestAdminAuthRateLimitAndRedaction(t *testing.T) {
	a := newApp(t)
	c := a.create(t, map[string]any{"type": "webbug", "notify_channel": "webhook", "webhook_url": "https://hooks.example.com/SECRETPATH", "webhook_secret": "hmac-secret"})

	noAuth, wrong := a.do("GET", "/admin/stats", nil, nil, ""), a.do("GET", "/admin/stats", nil, map[string]string{"Authorization": "Bearer nope"}, "")
	if noAuth.Code != 401 || wrong.Code != 401 || noAuth.Body.String() != wrong.Body.String() {
		t.Fatal("401 uniforme esperado")
	}
	auth := map[string]string{"Authorization": "Bearer " + adminTok}
	list := a.do("GET", "/admin/tokens", nil, auth, "")
	if list.Code != 200 {
		t.Fatalf("list %d %s", list.Code, list.Body)
	}
	for _, leak := range []string{c.key, "SECRETPATH", "hmac-secret", "manage_key", "notify_config"} {
		if strings.Contains(list.Body.String(), leak) {
			t.Fatalf("el listado de administracion filtra %q (antes devolvia TODAS las claves de gestion)", leak)
		}
	}
	if st := a.do("GET", "/admin/stats", nil, auth, ""); st.Code != 200 || st.json(t)["data"].(map[string]any)["total_tokens"].(float64) != 1 {
		t.Fatalf("stats: %s", st.Body)
	}
	// deshabilitar: los toques posteriores dejan de registrarse
	if r := a.do("POST", "/admin/tokens/"+c.id+"/disable", map[string]any{"is_active": false}, auth, ""); r.Code != 200 {
		t.Fatalf("disable %d %s", r.Code, r.Body)
	}
	a.do("GET", "/t/"+c.id, nil, nil, "")
	if len(a.events(t, c.id)) != 0 {
		t.Fatal("token deshabilitado registro un evento")
	}
	// fuerza bruta del token de operador
	limited := false
	for i := 0; i < 40; i++ {
		if a.do("GET", "/admin/stats", nil, map[string]string{"Authorization": fmt.Sprintf("Bearer guess%d", i)}, "203.0.113.99:1").Code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("el endpoint /admin debe limitar los intentos de fuerza bruta")
	}
}

func TestSecurityHeadersAndPublicConfig(t *testing.T) {
	a := newApp(t)
	r := a.do("GET", "/api/config", nil, nil, "")
	if r.Code != 200 || r.json(t)["data"].(map[string]any)["turnstile_site_key"] != "" {
		t.Fatalf("config: %s", r.Body)
	}
	for k, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "X-Xss-Protection": "0", "Referrer-Policy": "no-referrer"} {
		if r.Header().Get(k) != want {
			t.Errorf("%s=%q", k, r.Header().Get(k))
		}
	}
	if !strings.Contains(r.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("falta CSP")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(r.Header().Get("X-Request-Id")) {
		t.Error("X-Request-ID invalido")
	}
}

func nil2ctx() context.Context { return context.Background() }
