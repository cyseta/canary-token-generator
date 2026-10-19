package notify

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/notify/telegram"
	"canary-token-generator/backend/internal/notify/webhook"
)

type NotificationJob struct {
	EventID        string
	TokenID        string
	TokenLabel     string
	TokenType      string
	NotifyChannel  string
	WebhookURL     string
	WebhookSecret  string
	TelegramChatID string
	SourceIP       string
	UserAgent      string
	Country        string
	City           string
	Protocol       string
	Tags           []string
	Headers        map[string]any
	Fingerprint    map[string]any
	TriggeredAt    time.Time
}

const maxConcurrentPerWebhookHost = 2

type Dispatcher struct {
	webhookClient  *webhook.Client
	telegramClient *telegram.Client
	queue          chan NotificationJob

	mu     sync.RWMutex // protege closed y el envio al canal (evita "send on closed channel")
	closed bool

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	gateMu sync.Mutex
	inUse  map[string]int
}

func NewDispatcher(workers int, queueSize int, botToken string, allowPrivateWebhooks bool) *Dispatcher {
	return NewDispatcherWith(workers, queueSize, webhook.NewClient(allowPrivateWebhooks), telegram.NewClient(botToken))
}

func NewDispatcherWith(workers, queueSize int, wc *webhook.Client, tc *telegram.Client) *Dispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{
		webhookClient: wc, telegramClient: tc,
		queue: make(chan NotificationJob, queueSize),
		ctx:   ctx, cancel: cancel, inUse: map[string]int{},
	}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go d.worker(i + 1)
	}
	return d
}

// Enqueue es seguro frente a llamadas concurrentes con Shutdown. Una alerta descartada se contabiliza.
func (d *Dispatcher) Enqueue(job NotificationJob) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		core.IncAlertsDropped()
		slog.Error("dispatcher closed, alert dropped", "token_id", job.TokenID)
		return false
	}
	select {
	case d.queue <- job:
		return true
	default:
		core.IncAlertsDropped()
		slog.Error("notification queue full, ALERT DROPPED", "token_id", job.TokenID)
		return false
	}
}

func (d *Dispatcher) worker(id int) {
	defer d.wg.Done()
	for job := range d.queue { // se vacia la cola completa antes de terminar
		d.processJob(job)
	}
}

// acquireHost limita la concurrencia por host de webhook: un destino lento (tarpit) controlado por
// un atacante no puede acaparar todos los workers y dejar sin alertas al resto de usuarios.
func (d *Dispatcher) acquireHost(h string) bool {
	d.gateMu.Lock()
	defer d.gateMu.Unlock()
	if d.inUse[h] >= maxConcurrentPerWebhookHost {
		return false
	}
	d.inUse[h]++
	return true
}

func (d *Dispatcher) releaseHost(h string) {
	d.gateMu.Lock()
	defer d.gateMu.Unlock()
	if d.inUse[h]--; d.inUse[h] <= 0 {
		delete(d.inUse, h)
	}
}

func (d *Dispatcher) processJob(job NotificationJob) {
	ctx, cancel := context.WithTimeout(d.ctx, 15*time.Second)
	defer cancel()

	switch job.NotifyChannel {
	case "webhook":
		if job.WebhookURL == "" {
			slog.Warn("webhook url is empty, skipping notification", "token_id", job.TokenID)
			return
		}
		host := webhook.Destination(job.WebhookURL)
		if !d.acquireHost(host) {
			core.IncAlertsDropped()
			slog.Error("webhook host saturated, ALERT DROPPED", "token_id", job.TokenID, "dest", host)
			return
		}
		defer d.releaseHost(host)
		payload := webhook.Payload{
			EventID: job.EventID, TokenID: job.TokenID, TokenLabel: job.TokenLabel, TokenType: job.TokenType,
			TriggeredAt: job.TriggeredAt, SourceIP: job.SourceIP, UserAgent: job.UserAgent,
			Country: job.Country, City: job.City, Protocol: job.Protocol, Tags: job.Tags,
			Headers: job.Headers, Fingerprint: job.Fingerprint,
		}
		if err := d.webhookClient.Send(ctx, job.WebhookURL, job.WebhookSecret, payload); err != nil {
			core.IncAlertFailures()
			slog.Error("failed to dispatch webhook alert", "token_id", job.TokenID, "dest", host, "error", err)
		}

	case "telegram":
		if job.TelegramChatID == "" {
			slog.Warn("telegram chat id is empty, skipping alert", "token_id", job.TokenID)
			return
		}
		text := telegram.FormatAlert(telegram.Alert{
			Label: job.TokenLabel, Type: job.TokenType, Protocol: job.Protocol, IP: job.SourceIP,
			City: job.City, Country: job.Country, UserAgent: job.UserAgent, Tags: job.Tags,
			Time: job.TriggeredAt.Format(time.RFC3339),
		})
		if err := d.telegramClient.SendAlert(ctx, job.TelegramChatID, text); err != nil {
			core.IncAlertFailures()
			slog.Error("failed to dispatch telegram alert", "token_id", job.TokenID, "error", err)
		}
	}
}

// Shutdown vacia la cola pendiente (hasta 10s) antes de parar; despues cancela lo que siga en curso.
func (d *Dispatcher) Shutdown() { d.ShutdownTimeout(10 * time.Second) }

func (d *Dispatcher) ShutdownTimeout(timeout time.Duration) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	close(d.queue)
	d.mu.Unlock()

	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("notification dispatcher drained and stopped cleanly")
	case <-time.After(timeout):
		slog.Warn("notification dispatcher drain timed out, cancelling in-flight jobs")
		d.cancel()
		<-done
	}
	d.cancel()
}
