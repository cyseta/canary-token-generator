package event

import (
	"encoding/json"
	"time"
)

type TargetToken struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Label         string `json:"label"`
	IsActive      bool   `json:"is_active"`
	NotifyChannel string `json:"notify_channel"`
	NotifyConfig  string `json:"notify_config"`
}

type Event struct {
	ID          string    `json:"id"`
	TokenID     string    `json:"token_id"`
	SourceIP    string    `json:"source_ip"`
	UserAgent   string    `json:"user_agent"`
	Referer     string    `json:"referer,omitempty"`
	Protocol    string    `json:"protocol"` // HTTP, MYSQL, KUBE, BROWSER_FP
	Country     string    `json:"country,omitempty"`
	City        string    `json:"city,omitempty"`
	Headers     string    `json:"headers,omitempty"`     // JSON string
	Fingerprint string    `json:"fingerprint,omitempty"` // JSON string
	CreatedAt   time.Time `json:"created_at"`
}

type TriggerContext struct {
	TokenID     string            `json:"token_id"`
	SourceIP    string            `json:"source_ip"`
	UserAgent   string            `json:"user_agent"`
	Referer     string            `json:"referer"`
	Protocol    string            `json:"protocol"`
	Headers     map[string]string `json:"headers"`
	Fingerprint map[string]any    `json:"fingerprint"`
	Tags        []string          `json:"tags,omitempty"` // p.ej. "link-preview-or-scanner"
}

func (e *Event) ParsedHeaders() map[string]string {
	res := make(map[string]string)
	if e.Headers != "" {
		_ = json.Unmarshal([]byte(e.Headers), &res)
	}
	return res
}

func (e *Event) ParsedFingerprint() map[string]any {
	res := make(map[string]any)
	if e.Fingerprint != "" {
		_ = json.Unmarshal([]byte(e.Fingerprint), &res)
	}
	return res
}
