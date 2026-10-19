package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"canary-token-generator/backend/internal/event"
)

type Token struct {
	ID    string
	Type  string
	Label string
	// ManageKey contiene el HASH SHA-256 del secreto de gestion (el secreto en claro solo existe un
	// instante en memoria al crear el token y se devuelve una unica vez). Nunca se serializa.
	ManageKey     string
	TargetURL     string
	NotifyChannel string // webhook, telegram, none
	NotifyConfig  string // JSON con secretos: nunca se serializa tal cual
	Metadata      string // JSON: semilla de artefactos y opciones. Nunca se serializa.
	HitCount      int64
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type NotifyConfigData struct {
	WebhookURL     string `json:"webhook_url,omitempty"`
	WebhookSecret  string `json:"webhook_secret,omitempty"`
	TelegramChatID string `json:"telegram_chat_id,omitempty"`
}

// NotifySummary es la vista segura de la configuracion de notificacion: ni la URL completa del webhook
// (suele contener el secreto), ni el secreto HMAC.
type NotifySummary struct {
	WebhookHost      string `json:"webhook_host,omitempty"`
	HasWebhookSecret bool   `json:"has_webhook_secret,omitempty"`
	TelegramChatID   string `json:"telegram_chat_id,omitempty"` // enmascarado
}

func (t *Token) GetNotifyConfig() NotifyConfigData {
	var cfg NotifyConfigData
	if t.NotifyConfig != "" {
		_ = json.Unmarshal([]byte(t.NotifyConfig), &cfg)
	}
	return cfg
}

func (t *Token) NotifySummary() NotifySummary {
	cfg := t.GetNotifyConfig()
	var s NotifySummary
	if cfg.WebhookURL != "" {
		if u, err := url.Parse(cfg.WebhookURL); err == nil {
			s.WebhookHost = u.Host
		}
		s.HasWebhookSecret = cfg.WebhookSecret != ""
	}
	if id := cfg.TelegramChatID; id != "" {
		if strings.HasPrefix(id, "@") || len(id) <= 4 {
			s.TelegramChatID = id
		} else {
			s.TelegramChatID = "••••" + id[len(id)-4:]
		}
	}
	return s
}

type tokenJSON struct {
	ID            string        `json:"id"`
	Type          string        `json:"type"`
	Label         string        `json:"label"`
	TargetURL     string        `json:"target_url,omitempty"`
	NotifyChannel string        `json:"notify_channel"`
	Notify        NotifySummary `json:"notify"`
	HitCount      int64         `json:"hit_count"`
	IsActive      bool          `json:"is_active"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// MarshalJSON es una lista BLANCA explicita: anadir un campo sensible a Token no lo expone por accidente.
func (t Token) MarshalJSON() ([]byte, error) {
	return json.Marshal(tokenJSON{
		ID: t.ID, Type: t.Type, Label: t.Label, TargetURL: t.TargetURL, NotifyChannel: t.NotifyChannel,
		Notify: t.NotifySummary(), HitCount: t.HitCount, IsActive: t.IsActive, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	})
}

func (t *Token) ToTarget() event.TargetToken {
	return event.TargetToken{
		ID: t.ID, Type: t.Type, Label: t.Label, IsActive: t.IsActive,
		NotifyChannel: t.NotifyChannel, NotifyConfig: t.NotifyConfig,
	}
}

func GenerateSecureID(prefix string, length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// HashManageKey devuelve el SHA-256 (hex) del secreto. Al ser una clave aleatoria de 128 bits no
// necesita un KDF lento; basta para que una fuga de la BD no permita tomar el control de los tokens.
func HashManageKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
