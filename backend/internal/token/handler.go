package token

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/event"
	"canary-token-generator/backend/internal/middleware"
	"canary-token-generator/backend/internal/token/generators/pixel"
	"canary-token-generator/backend/internal/turnstile"
)

type Handler struct {
	tokenService Service
	eventService event.Service
	turnstile    turnstile.Verifier
	cfg          *core.Config
}

func NewHandler(tokenService Service, eventService event.Service, turnstile turnstile.Verifier, cfg *core.Config) *Handler {
	return &Handler{tokenService: tokenService, eventService: eventService, turnstile: turnstile, cfg: cfg}
}

const (
	maxJSONBody   = 32 << 10 // peticiones JSON de la API
	maxFPBody     = 16 << 10 // beacon de huella
	maxPageLimit  = 100
	maxPageOffset = 1_000_000
	manageKeyHdr  = "X-Manage-Key"
)

// decodeJSON limita el tamano del body (antes era ilimitado) y exige un unico documento JSON.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data")
	}
	return nil
}

// writeServiceError traduce errores del servicio. Los mensajes de error INTERNOS (SQL, rutas, etc.)
// nunca se envian al cliente: antes se devolvia err.Error() en las respuestas 500.
func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrInvalidInput):
		core.JSONError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), core.ErrInvalidInput.Error()+": "))
	case errors.Is(err, core.ErrNotFound):
		core.JSONError(w, http.StatusNotFound, "Not found")
	default:
		slog.Error("request failed", "error", err)
		core.JSONError(w, http.StatusInternalServerError, "Internal error")
	}
}

func pagination(r *http.Request) (limit, offset int) {
	limit, offset = 20, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, maxPageLimit)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v > 0 {
		offset = min(v, maxPageOffset)
	}
	return
}

// authedToken autentica con la clave de gestion enviada en la CABECERA X-Manage-Key. Ya no viaja en la
// ruta de la URL, por lo que no acaba en logs de acceso, historial del navegador ni cabeceras Referer.
func (h *Handler) authedToken(w http.ResponseWriter, r *http.Request) (*Token, bool) {
	tok, err := h.tokenService.GetByManageKey(r.Context(), strings.TrimSpace(r.Header.Get(manageKeyHdr)))
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			core.JSONError(w, http.StatusNotFound, "Not found") // misma respuesta para "no existe" y "clave invalida"
		} else {
			writeServiceError(w, err)
		}
		return nil, false
	}
	return tok, true
}

// GET /api/config
func (h *Handler) PublicConfig(w http.ResponseWriter, r *http.Request) {
	siteKey := ""
	if h.cfg.TurnstileSecret != "" {
		siteKey = h.cfg.TurnstileSiteKey
	}
	core.JSONSuccess(w, map[string]any{"turnstile_site_key": siteKey})
}

// POST /api/tokens
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var req CreateTokenRequest
	if err := decodeJSON(w, r, &req); err != nil {
		core.JSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if h.cfg.TurnstileSecret != "" {
		if ok, err := h.turnstile.Verify(r.Context(), req.TurnstileToken, middleware.ClientIP(r)); err != nil || !ok {
			core.JSONError(w, http.StatusForbidden, "Turnstile verification failed")
			return
		}
	}
	resp, err := h.tokenService.CreateToken(r.Context(), req, h.cfg.BaseURL)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store") // la respuesta contiene el secreto de gestion
	core.JSON(w, http.StatusCreated, resp)
}

// GET /api/manage
func (h *Handler) GetManageToken(w http.ResponseWriter, r *http.Request) {
	tok, ok := h.authedToken(w, r)
	if !ok {
		return
	}
	limit, offset := pagination(r)
	events, total, err := h.eventService.ListEvents(r.Context(), tok.ID, limit, offset)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if events == nil {
		events = []*event.Event{}
	}
	w.Header().Set("Cache-Control", "no-store")
	core.JSONSuccess(w, map[string]any{"token": tok, "events": events, "total": total, "limit": limit, "offset": offset})
}

// POST /api/manage/toggle
func (h *Handler) ToggleToken(w http.ResponseWriter, r *http.Request) {
	tok, ok := h.authedToken(w, r)
	if !ok {
		return
	}
	var body struct {
		IsActive *bool `json:"is_active"`
	}
	if err := decodeJSON(w, r, &body); err != nil || body.IsActive == nil {
		core.JSONError(w, http.StatusBadRequest, "Body must be {\"is_active\": true|false}")
		return
	}
	updated, err := h.tokenService.SetActiveByID(r.Context(), tok.ID, *body.IsActive)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	core.JSONSuccess(w, updated)
}

// DELETE /api/manage : el propietario puede borrar su token y todos sus eventos.
func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	if err := h.tokenService.DeleteByManageKey(r.Context(), strings.TrimSpace(r.Header.Get(manageKeyHdr))); err != nil {
		writeServiceError(w, err)
		return
	}
	core.JSONSuccess(w, map[string]bool{"deleted": true})
}

// GET /api/manage/download : antes era publica y se identificaba solo por el ID del token (que va
// incrustado en el propio senuelo); ahora exige la clave de gestion.
func (h *Handler) DownloadArtifact(w http.ResponseWriter, r *http.Request) {
	tok, ok := h.authedToken(w, r)
	if !ok {
		return
	}
	res, err := h.tokenService.GenerateArtifact(r.Context(), tok, h.cfg.BaseURL)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if len(res.Artifact) == 0 {
		core.JSONError(w, http.StatusNotFound, "No downloadable artifact for this token type")
		return
	}
	w.Header().Set("Content-Type", res.ContentType)
	// FormatMediaType escapa el nombre correctamente (evita inyeccion de comillas en filename).
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": res.ArtifactName}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(res.Artifact)))
	_, _ = w.Write(res.Artifact)
}

// ---------------------------------------------------------------------------------------------
// Disparadores publicos
// ---------------------------------------------------------------------------------------------

var scannerUA = []string{
	"slackbot", "microsoft office", "ms-office", "outlook", "safelinks", "googlebot", "bingbot", "facebookexternalhit",
	"twitterbot", "whatsapp", "discordbot", "telegrambot", "linkedinbot", "googleimageproxy", "skypeuripreview",
	"proofpoint", "mimecast", "barracuda", "urlscan", "headlesschrome", "preview", "bot/", "crawler", "spider",
}

// tagsForRequest marca las visitas que probablemente son escaneres de enlaces / previsualizadores
// (principal fuente de falsos positivos en canary tokens).
func tagsForRequest(r *http.Request) []string {
	var tags []string
	ua := strings.ToLower(r.UserAgent())
	for _, s := range scannerUA {
		if strings.Contains(ua, s) {
			tags = append(tags, "link-preview-or-scanner")
			break
		}
	}
	if strings.EqualFold(r.Header.Get("Purpose"), "prefetch") || strings.EqualFold(r.Header.Get("Sec-Purpose"), "prefetch") {
		tags = append(tags, "prefetch")
	}
	if r.Method == http.MethodHead {
		tags = append(tags, "head-request")
	}
	return tags
}

var awsCredRe = regexp.MustCompile(`Credential=([A-Z0-9]{16,32})/`)

func buildTriggerContext(r *http.Request, protocol string, fingerprint map[string]any) event.TriggerContext {
	fp := map[string]any{}
	for k, v := range fingerprint {
		fp[k] = v
	}
	// Una peticion firmada con SigV4 revela QUE clave AWS senuelo se uso (la clave en si no se almacena).
	if m := awsCredRe.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		fp["aws_access_key_id"] = m[1]
	}
	return event.TriggerContext{
		SourceIP: middleware.ClientIP(r), UserAgent: r.UserAgent(), Referer: r.Referer(), Protocol: protocol,
		Headers: middleware.ExtractCleanHeaders(r), Fingerprint: fp, Tags: tagsForRequest(r),
	}
}

func (h *Handler) record(r *http.Request, tok *Token, tc event.TriggerContext) {
	// RecordTrigger ya desacopla el contexto de la peticion. Los errores se registran (antes se descartaban).
	if _, err := h.eventService.RecordTrigger(r.Context(), tok.ToTarget(), tc); err != nil && !errors.Is(err, core.ErrTokenDisabled) {
		slog.Error("FAILED TO RECORD TRIGGER", "token_id", tok.ID, "protocol", tc.Protocol, "error", err)
	}
}

// GET|HEAD|POST /t/{tokenID}[/*]
func (h *Handler) TriggerHTTP(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tokenID")
	if tok, err := h.tokenService.GetByID(r.Context(), id); err == nil && tok.IsActive {
		h.record(r, tok, buildTriggerContext(r, "HTTP", nil))
	}
	pixel.Serve1x1GIF(w) // respuesta identica exista el token o no
}

// GET /r/{tokenID}
func (h *Handler) SlowRedirectInterstitial(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tokenID")
	tok, err := h.tokenService.GetByID(r.Context(), id)
	if err != nil || !tok.IsActive || tok.Type != "slowredirect" {
		http.Redirect(w, r, "https://www.google.com", http.StatusFound)
		return
	}
	h.record(r, tok, buildTriggerContext(r, "HTTP_REDIRECT_INIT", nil))

	nonce := GenerateSecureID("", 16)
	page, err := h.tokenService.RenderRedirect(r.Context(), tok, h.cfg.BaseURL, nonce)
	if err != nil {
		slog.Error("failed to render redirect page", "token_id", id, "error", err)
		http.Redirect(w, r, "https://www.google.com", http.StatusFound)
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+
		"'; connect-src "+originOf(h.cfg.BaseURL)+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	_, _ = io.WriteString(w, page)
}

func originOf(base string) string {
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "'self'"
}

// fingerprintSchema es una lista BLANCA de claves y tipos aceptados del beacon. El resto se descarta:
// el cuerpo lo controla el atacante y antes se almacenaba tal cual (JSON arbitrario, hasta 64 KB).
var fingerprintSchema = map[string]string{
	"screen": "obj", "timezone": "str", "timezoneOffset": "num", "platform": "str", "languages": "strs",
	"hardwareConcurrency": "num", "deviceMemory": "num", "touchPoints": "num", "doNotTrack": "str",
	"canvasHash": "str", "webglVendor": "str", "webglRenderer": "str",
}

func clampStr(s string) string {
	if len(s) > 256 {
		s = s[:256]
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

func sanitizeFingerprint(raw map[string]any) map[string]any {
	out := map[string]any{}
	for key, kind := range fingerprintSchema {
		v, ok := raw[key]
		if !ok {
			continue
		}
		switch kind {
		case "str":
			if s, ok := v.(string); ok {
				out[key] = clampStr(s)
			}
		case "num":
			if n, ok := v.(float64); ok {
				out[key] = n
			}
		case "strs":
			if arr, ok := v.([]any); ok {
				var ss []string
				for _, e := range arr {
					if s, ok := e.(string); ok && len(ss) < 8 {
						ss = append(ss, clampStr(s))
					}
				}
				out[key] = ss
			}
		case "obj":
			if m, ok := v.(map[string]any); ok {
				o := map[string]float64{}
				for _, f := range []string{"width", "height", "colorDepth", "availWidth", "availHeight"} {
					if n, ok := m[f].(float64); ok {
						o[f] = n
					}
				}
				out[key] = o
			}
		}
	}
	return out
}

// POST /f/{tokenID}
func (h *Handler) FingerprintPOST(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tokenID")
	defer func() { w.WriteHeader(http.StatusNoContent) }()

	tok, err := h.tokenService.GetByID(r.Context(), id)
	if err != nil || !tok.IsActive {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFPBody))
	if err != nil {
		return
	}
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		raw = map[string]any{}
	}
	h.record(r, tok, buildTriggerContext(r, "BROWSER_FP", sanitizeFingerprint(raw)))
}

// ANY /k/{tokenID}/*  -> emula un API server de Kubernetes que rechaza el token.
func (h *Handler) KubeWildcard(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tokenID")
	if tok, err := h.tokenService.GetByID(r.Context(), id); err == nil && tok.IsActive {
		h.record(r, tok, buildTriggerContext(r, "KUBE_API", map[string]any{"probed_path": clampStr(r.URL.Path), "probed_method": r.Method}))
	}
	// Respuesta IDENTICA para tokens validos e invalidos. Antes el mensaje difería ("Invalid bearer token"
	// vs "Unauthorized"), lo que permitia a un atacante enumerar cuales eran senuelos.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`+"\n")
}

var _ = time.Second
var _ = context.Background
