package event

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/geoip"
	"canary-token-generator/backend/internal/netguard"
	"canary-token-generator/backend/internal/notify"
	"canary-token-generator/backend/internal/notify/telegram"
	"canary-token-generator/backend/internal/notify/webhook"
)

type harness struct {
	svc      Service
	repo     Repository
	db       *core.DB
	mu       sync.Mutex
	received []webhook.Payload
	tok      TargetToken
	srv      *httptest.Server
	disp     *notify.Dispatcher
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := core.InitDB(&core.Config{DBDriver: "sqlite", DBDSN: filepath.Join(t.TempDir(), "e.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &harness{db: db}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p webhook.Payload
		_ = json.NewDecoder(r.Body).Decode(&p)
		h.mu.Lock()
		h.received = append(h.received, p)
		h.mu.Unlock()
	}))
	t.Cleanup(h.srv.Close)
	wc := webhook.NewClientWith(netguard.NewClient(netguard.Policy{AllowPrivate: true, AllowHTTP: true}))
	h.disp = notify.NewDispatcherWith(2, 100, wc, telegram.NewClient(""))
	cache := core.NewMemoryCache()
	t.Cleanup(cache.Close)
	h.repo = NewRepository(db)
	h.svc = NewService(h.repo, func(ctx context.Context, id string) error {
		_, err := db.ExecContext(ctx, db.Rebind(`UPDATE tokens SET hit_count = hit_count + 1 WHERE id = $1`), id)
		return err
	}, &geoip.NopProvider{}, cache, h.disp)

	cfg, _ := json.Marshal(map[string]string{"webhook_url": h.srv.URL})
	h.tok = TargetToken{ID: "c1", Type: "webbug", Label: "t", IsActive: true, NotifyChannel: "webhook", NotifyConfig: string(cfg)}
	if _, err := db.Exec(db.Rebind(`INSERT INTO tokens (id,type,label,manage_key) VALUES ($1,$2,$3,$4)`), "c1", "webbug", "t", "k"); err != nil {
		t.Fatal(err)
	}
	return h
}

// drena la cola y devuelve lo recibido
func (h *harness) flush() []webhook.Payload {
	h.disp.Shutdown()
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]webhook.Payload(nil), h.received...)
}

func TestEventPersistsEvenIfRequestContextCancelled(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // el cliente ya cerro la conexion
	if _, err := h.svc.RecordTrigger(ctx, h.tok, TriggerContext{SourceIP: "198.51.100.1", Protocol: "HTTP"}); err != nil {
		t.Fatalf("el evento debe registrarse aunque la peticion este cancelada: %v", err)
	}
	if n, _ := h.svc.CountEvents(context.Background()); n != 1 {
		t.Fatalf("eventos=%d", n)
	}
	h.flush()
}

// Regresion: la huella del navegador (la que desenmascara al visitante) quedaba silenciada por la alerta inicial.
func TestFingerprintAlertNotSuppressedByInitialHit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.svc.RecordTrigger(ctx, h.tok, TriggerContext{SourceIP: "198.51.100.1", Protocol: "HTTP_REDIRECT_INIT"})
	h.svc.RecordTrigger(ctx, h.tok, TriggerContext{SourceIP: "198.51.100.1", Protocol: "HTTP_REDIRECT_INIT"}) // duplicado: se silencia
	h.svc.RecordTrigger(ctx, h.tok, TriggerContext{SourceIP: "198.51.100.1", Protocol: "BROWSER_FP", Fingerprint: map[string]any{"canvasHash": "abc"}})
	got := h.flush()
	if len(got) != 2 {
		t.Fatalf("alertas=%d, esperado 2 (init + fingerprint)", len(got))
	}
	var sawFP bool
	for _, p := range got {
		if p.Protocol == "BROWSER_FP" && p.Fingerprint["canvasHash"] == "abc" {
			sawFP = true
		}
	}
	if !sawFP {
		t.Fatal("la alerta con la huella no se envio")
	}
	if n, _ := h.svc.CountEvents(ctx); n != 3 {
		t.Fatalf("los 3 eventos deben guardarse aunque se silencie la alerta: %d", n)
	}
}

// Regresion: Exists+Set no era atomico => rafagas concurrentes generaban alertas duplicadas.
func TestDedupIsAtomicUnderConcurrency(t *testing.T) {
	h := newHarness(t)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.svc.RecordTrigger(context.Background(), h.tok, TriggerContext{SourceIP: "198.51.100.9", Protocol: "HTTP"})
		}()
	}
	wg.Wait()
	if got := h.flush(); len(got) != 1 {
		t.Fatalf("alertas=%d, esperado exactamente 1", len(got))
	}
}

// Regresion: un valor de IP anomalo (cabecera falsificada) hacia fallar el INSERT en Postgres (VARCHAR(64)) y se perdia el evento.
func TestGarbageSourceIPStillRecorded(t *testing.T) {
	h := newHarness(t)
	ev, err := h.svc.RecordTrigger(context.Background(), h.tok, TriggerContext{SourceIP: strings.Repeat("A", 500), Protocol: "HTTP"})
	if err != nil || ev.SourceIP != "unknown" {
		t.Fatalf("ev=%+v err=%v", ev, err)
	}
	h.flush()
}

func TestTagsAndFieldCaps(t *testing.T) {
	h := newHarness(t)
	huge := map[string]string{}
	for i := 0; i < 2000; i++ {
		huge[strings.Repeat("h", 20)+string(rune('a'+i%26))+strings.Repeat("x", i%50)+time.Duration(i).String()] = strings.Repeat("v", 100)
	}
	ev, err := h.svc.RecordTrigger(context.Background(), h.tok, TriggerContext{
		SourceIP: "198.51.100.3", Protocol: "HTTP", UserAgent: strings.Repeat("ñ", 2000), Referer: strings.Repeat("r", 5000),
		Headers: huge, Tags: []string{"link-preview-or-scanner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.UserAgent) > 512 || !isValidUTF8(ev.UserAgent) || len(ev.Referer) > 1024 || len(ev.Headers) > maxJSONColumn {
		t.Fatalf("campos sin acotar: ua=%d ref=%d hdr=%d", len(ev.UserAgent), len(ev.Referer), len(ev.Headers))
	}
	if !strings.Contains(ev.Fingerprint, "link-preview-or-scanner") {
		t.Fatal("las etiquetas deben persistirse en el fingerprint")
	}
	got := h.flush()
	if len(got) != 1 || len(got[0].Tags) != 1 {
		t.Fatalf("la alerta debe incluir las etiquetas: %+v", got)
	}
}

func isValidUTF8(s string) bool { return strings.ToValidUTF8(s, "") == s }

func TestRepositoryPaginationRetentionAndOrder(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < 5; i++ {
		e := &Event{ID: "e" + string(rune('0'+i)), TokenID: "c1", SourceIP: "1.1.1.1", Protocol: "HTTP", Headers: "{}", Fingerprint: "{}", CreatedAt: base.Add(time.Duration(i) * time.Hour)}
		if err := h.repo.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	page, total, err := h.repo.ListByToken(ctx, "c1", 2, 0)
	if err != nil || total != 5 || len(page) != 2 || page[0].ID != "e4" {
		t.Fatalf("page=%v total=%d err=%v", page, total, err)
	}
	page2, _, _ := h.repo.ListByToken(ctx, "c1", 2, 2)
	if page2[0].ID != "e2" {
		t.Fatalf("segunda pagina incorrecta: %s", page2[0].ID)
	}
	n, err := h.repo.DeleteOlderThan(ctx, base.Add(150*time.Minute)) // borra e0,e1,e2
	if err != nil || n != 3 {
		t.Fatalf("borrados=%d err=%v", n, err)
	}
	h.flush()
}
