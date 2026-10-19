package event

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"canary-token-generator/backend/internal/clientip"
	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/geoip"
	"canary-token-generator/backend/internal/notify"

	"github.com/google/uuid"
)

type HitCounter func(ctx context.Context, tokenID string) error

type Service interface {
	RecordTrigger(ctx context.Context, tok TargetToken, triggerCtx TriggerContext) (*Event, error)
	ListEvents(ctx context.Context, tokenID string, limit int, offset int) ([]*Event, int64, error)
	GetRecentEvents(ctx context.Context, limit int) ([]*Event, error)
	CountEvents(ctx context.Context) (int64, error)
}

type eventService struct {
	eventRepo  Repository
	hitCounter HitCounter
	geoIP      geoip.Provider
	cache      core.CacheClient
	dispatcher *notify.Dispatcher
	dedupTTL   time.Duration
}

func NewService(
	eventRepo Repository,
	hitCounter HitCounter,
	geoIP geoip.Provider,
	cache core.CacheClient,
	dispatcher *notify.Dispatcher,
) Service {
	return &eventService{
		eventRepo: eventRepo, hitCounter: hitCounter, geoIP: geoIP, cache: cache, dispatcher: dispatcher,
		dedupTTL: 5 * time.Minute,
	}
}

type notifyConfig struct {
	WebhookURL     string `json:"webhook_url,omitempty"`
	WebhookSecret  string `json:"webhook_secret,omitempty"`
	TelegramChatID string `json:"telegram_chat_id,omitempty"`
}

const (
	maxUserAgent  = 512
	maxReferer    = 1024
	maxJSONColumn = 16 * 1024
	protocolBrwFP = "BROWSER_FP"
	dedupClassHit = "hit"
	dedupClassFP  = "fp"
)

func clamp(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) && len(s) > 0 { // no cortar una runa por la mitad
		s = s[:len(s)-1]
	}
	return s
}

// capJSON serializa v y, si excede el limite, guarda un marcador en vez de dejar crecer la BD sin control.
func capJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil || len(b) > maxJSONColumn {
		return `{"_truncated":true}`
	}
	return string(b)
}

func (s *eventService) RecordTrigger(parent context.Context, tok TargetToken, tc TriggerContext) (*Event, error) {
	if !tok.IsActive {
		return nil, core.ErrTokenDisabled
	}
	// La deteccion NO puede depender de que el cliente mantenga la conexion abierta: si cancela la
	// peticion (o la cierra tras recibir el pixel) el evento debe registrarse igualmente.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()

	// La IP debe ser valida (los handlers ya la resuelven de forma segura; esto es defensa en profundidad
	// y evita que un valor anomalo haga fallar el INSERT en columnas VARCHAR(64) y se pierda el evento).
	ip := "unknown"
	if a, ok := clientip.Parse(tc.SourceIP); ok {
		ip = a.String()
	}
	loc := s.geoIP.Lookup(ip)

	fp := make(map[string]any, len(tc.Fingerprint)+1)
	for k, v := range tc.Fingerprint {
		fp[k] = v
	}
	if len(tc.Tags) > 0 {
		fp["_tags"] = tc.Tags
	}

	ev := &Event{
		ID: uuid.New().String(), TokenID: tok.ID, SourceIP: ip,
		UserAgent: clamp(tc.UserAgent, maxUserAgent), Referer: clamp(tc.Referer, maxReferer),
		Protocol: clamp(tc.Protocol, 32), Country: clamp(loc.Country, 64), City: clamp(loc.City, 128),
		Headers: capJSON(tc.Headers), Fingerprint: capJSON(fp), CreatedAt: time.Now().UTC(),
	}

	if err := s.eventRepo.Insert(ctx, ev); err != nil {
		core.IncErrors()
		slog.Error("failed to record canary event in database", "token_id", tok.ID, "error", err)
		return nil, err
	}
	if s.hitCounter != nil {
		if err := s.hitCounter(ctx, tok.ID); err != nil {
			slog.Warn("failed to increment hit counter", "token_id", tok.ID, "error", err)
		}
	}
	core.IncEventsLogged()

	// Deduplicado ATOMICO (SetNX) por token+IP+clase. La clase separa el "primer toque" de la huella
	// del navegador: antes el beacon con el fingerprint (lo que desenmascara al visitante) quedaba
	// silenciado por la alerta inicial de la misma IP.
	class := dedupClassHit
	if ev.Protocol == protocolBrwFP {
		class = dedupClassFP
	}
	acquired, err := s.cache.SetNX(ctx, fmt.Sprintf("dedup:%s:%s:%s", tok.ID, ip, class), "1", s.dedupTTL)
	if err != nil {
		slog.Warn("cache error on dedup check, notifying anyway", "error", err)
		acquired = true // ante la duda, alertar
	}
	if !acquired {
		slog.Info("suppressing duplicate alert (silence window active)", "token_id", tok.ID, "ip", ip, "class", class)
		return ev, nil
	}

	if tok.NotifyChannel != "" && tok.NotifyChannel != "none" && s.dispatcher != nil {
		var cfg notifyConfig
		if tok.NotifyConfig != "" {
			_ = json.Unmarshal([]byte(tok.NotifyConfig), &cfg)
		}
		headersMap := make(map[string]any, len(tc.Headers))
		for k, v := range tc.Headers {
			headersMap[k] = v
		}
		s.dispatcher.Enqueue(notify.NotificationJob{
			EventID: ev.ID, TokenID: tok.ID, TokenLabel: tok.Label, TokenType: tok.Type,
			NotifyChannel: tok.NotifyChannel, WebhookURL: cfg.WebhookURL, WebhookSecret: cfg.WebhookSecret,
			TelegramChatID: cfg.TelegramChatID, SourceIP: ev.SourceIP, UserAgent: ev.UserAgent,
			Country: ev.Country, City: ev.City, Protocol: ev.Protocol, Tags: tc.Tags,
			Headers: headersMap, Fingerprint: fp, TriggeredAt: ev.CreatedAt,
		})
	}
	return ev, nil
}

func (s *eventService) ListEvents(ctx context.Context, tokenID string, limit int, offset int) ([]*Event, int64, error) {
	return s.eventRepo.ListByToken(ctx, tokenID, limit, offset)
}

func (s *eventService) GetRecentEvents(ctx context.Context, limit int) ([]*Event, error) {
	return s.eventRepo.GetRecentEvents(ctx, limit)
}

func (s *eventService) CountEvents(ctx context.Context) (int64, error) {
	return s.eventRepo.CountAll(ctx)
}

var _ = strings.TrimSpace
