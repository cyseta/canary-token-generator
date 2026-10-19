package token

import (
	"context"
	"net/url"
	"strings"
)

type GenerateRequest struct {
	TokenID    string
	Label      string
	TriggerURL string
	TargetURL  string
	BaseURL    string         // URL publica del servicio, sin barra final
	Seed       string         // semilla persistida: hace los artefactos deterministas
	Nonce      string         // nonce CSP para paginas HTML servidas en vivo
	Options    map[string]any // YA validadas por el servicio
}

// Base devuelve la URL base del servicio con fallback a la derivada de TriggerURL.
func (r GenerateRequest) Base() string {
	if r.BaseURL != "" {
		return strings.TrimRight(r.BaseURL, "/")
	}
	if s, ok := r.Options["base_url"].(string); ok && s != "" {
		return strings.TrimRight(s, "/")
	}
	if u, err := url.Parse(r.TriggerURL); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return ""
}

type GenerateResult struct {
	Artifact     []byte         `json:"-"`
	ArtifactName string         `json:"artifact_name,omitempty"`
	ContentType  string         `json:"content_type,omitempty"`
	Snippet      string         `json:"snippet,omitempty"`
	Instructions string         `json:"instructions,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type Generator interface {
	Type() string
	Generate(ctx context.Context, req GenerateRequest) (*GenerateResult, error)
}
