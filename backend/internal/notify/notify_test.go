package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"canary-token-generator/backend/internal/netguard"
	"canary-token-generator/backend/internal/notify/telegram"
	"canary-token-generator/backend/internal/notify/webhook"
)

func privClient() *webhook.Client {
	return webhook.NewClientWith(netguard.NewClient(netguard.Policy{AllowPrivate: true, AllowHTTP: true, Timeout: 3 * time.Second}))
}

// Regresion SSRF: la URL de webhook la aporta un usuario anonimo; no debe poder alcanzar la red interna.
func TestWebhookSSRFBlockedByDefault(t *testing.T) {
	var hits int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer internal.Close()
	d := NewDispatcherWith(1, 4, webhook.NewClient(false), telegram.NewClient(""))
	d.Enqueue(NotificationJob{NotifyChannel: "webhook", WebhookURL: internal.URL, TokenID: "t"})
	d.Shutdown()
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("el webhook alcanzo un servicio interno (SSRF)")
	}
}

func TestShutdownDrainsQueueAndEnqueueAfterIsSafe(t *testing.T) {
	var got int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&got, 1)
	}))
	defer srv.Close()
	d := NewDispatcherWith(2, 100, privClient(), telegram.NewClient(""))
	for i := 0; i < 20; i++ {
		d.Enqueue(NotificationJob{NotifyChannel: "webhook", WebhookURL: srv.URL + "/" + string(rune('a'+i)), TokenID: "t"})
	}
	d.Shutdown() // antes: cancel() inmediato descartaba las alertas pendientes
	if n := atomic.LoadInt32(&got); n != 20 {
		t.Fatalf("entregadas %d de 20: se perdieron alertas al apagar", n)
	}
	if d.Enqueue(NotificationJob{TokenID: "late"}) { // antes: panic "send on closed channel"
		t.Fatal("Enqueue tras Shutdown debe devolver false")
	}
	d.Shutdown() // idempotente
}

func TestWebhookRetryPolicyAndSignature(t *testing.T) {
	var calls int32
	var sig, ts string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		sig, ts = r.Header.Get("X-Canary-Signature"), r.Header.Get("X-Canary-Timestamp")
		b, _ := io.ReadAll(r.Body)
		var p webhook.Payload
		_ = json.Unmarshal(b, &p)
		switch r.URL.Path {
		case "/bad":
			w.WriteHeader(400)
		case "/flaky":
			if atomic.LoadInt32(&calls) < 3 {
				w.WriteHeader(503)
			}
		}
	}))
	defer srv.Close()
	c := privClient()
	c.SetBackoff(time.Millisecond)

	atomic.StoreInt32(&calls, 0)
	if err := c.Send(context.Background(), srv.URL+"/bad", "", webhook.Payload{}); err == nil || atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("4xx no debe reintentarse: calls=%d err=%v", calls, err)
	}
	atomic.StoreInt32(&calls, 0)
	if err := c.Send(context.Background(), srv.URL+"/flaky", "s3cret", webhook.Payload{EventID: "e1"}); err != nil || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("5xx debe reintentarse hasta exito: calls=%d err=%v", calls, err)
	}
	if !strings.HasPrefix(sig, "sha256=") || ts == "" {
		t.Fatal("falta firma HMAC")
	}
}

func TestWebhookErrorDoesNotLeakURLSecrets(t *testing.T) {
	c := privClient()
	c.SetBackoff(time.Millisecond)
	err := c.Send(context.Background(), "http://127.0.0.1:1/services/T000/B000/SECRETSECRET", "", webhook.Payload{})
	if err == nil || strings.Contains(err.Error(), "SECRETSECRET") {
		t.Fatalf("el error no debe contener la URL secreta: %v", err)
	}
}

// Regresion: un atacante no puede acaparar todos los workers con un destino tarpit.
func TestPerHostConcurrencyCap(t *testing.T) {
	release := make(chan struct{})
	var inflight, maxSeen int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&inflight, 1)
		for {
			m := atomic.LoadInt32(&maxSeen)
			if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
				break
			}
		}
		<-release
		atomic.AddInt32(&inflight, -1)
	}))
	defer slow.Close()
	var fastHits int32
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&fastHits, 1) }))
	defer fast.Close()

	d := NewDispatcherWith(4, 50, privClient(), telegram.NewClient(""))
	for i := 0; i < 10; i++ {
		d.Enqueue(NotificationJob{NotifyChannel: "webhook", WebhookURL: slow.URL, TokenID: "attacker"})
	}
	time.Sleep(150 * time.Millisecond)
	d.Enqueue(NotificationJob{NotifyChannel: "webhook", WebhookURL: fast.URL, TokenID: "legit"})
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&fastHits) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&fastHits) == 0 {
		t.Fatal("la alerta legitima quedo bloqueada por el destino lento (starvation)")
	}
	if m := atomic.LoadInt32(&maxSeen); m > maxConcurrentPerWebhookHost {
		t.Fatalf("concurrencia por host %d > %d", m, maxConcurrentPerWebhookHost)
	}
	close(release)
	d.Shutdown()
}

var _ sync.Mutex

func TestTelegramFormatEscapesAttackerControlledValues(t *testing.T) {
	txt := telegram.FormatAlert(telegram.Alert{
		Label: "<b>x</b>", Type: "pdf", Protocol: "HTTP", IP: "1.2.3.4", City: "A_B", Country: "C*D",
		UserAgent: "evil`_*[x](http://a)</code><a href=1>", Time: "t", Tags: []string{"a<b"},
	})
	for _, bad := range []string{"<a href", "</code><a", "<b>x</b>"} {
		if strings.Contains(txt, bad) {
			t.Fatalf("HTML sin escapar: %q en %s", bad, txt)
		}
	}
	long := telegram.FormatAlert(telegram.Alert{UserAgent: strings.Repeat("A", 100000)})
	if len(long) > 4096 {
		t.Fatalf("mensaje demasiado largo: %d", len(long))
	}
}

// Regresion: el token del bot (va en la URL) se filtraba a los logs via *url.Error.
func TestTelegramErrorDoesNotLeakBotToken(t *testing.T) {
	c := telegram.NewClientWith("123456:SUPERSECRETBOTTOKEN", "http://127.0.0.1:1", &http.Client{Timeout: time.Second})
	err := c.SendAlert(context.Background(), "42", "hi")
	if err == nil || strings.Contains(err.Error(), "SUPERSECRETBOTTOKEN") {
		t.Fatalf("el error filtra el token: %v", err)
	}
}

func TestTelegramSendsHTMLParseMode(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !strings.Contains(r.URL.Path, "/bot123:tok/sendMessage") {
			t.Errorf("ruta inesperada %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	c := telegram.NewClientWith("123:tok", srv.URL, srv.Client())
	if err := c.SendAlert(context.Background(), "42", "hello"); err != nil {
		t.Fatal(err)
	}
	if body["parse_mode"] != "HTML" || body["chat_id"] != "42" {
		t.Fatalf("payload: %v", body)
	}
}
