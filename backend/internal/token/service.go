package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/netguard"
	"canary-token-generator/backend/internal/token/generators/seed"
)

type CreateTokenRequest struct {
	Type           string         `json:"type"`
	Label          string         `json:"label"`
	TargetURL      string         `json:"target_url,omitempty"`
	NotifyChannel  string         `json:"notify_channel,omitempty"`
	WebhookURL     string         `json:"webhook_url,omitempty"`
	WebhookSecret  string         `json:"webhook_secret,omitempty"`
	TelegramChatID string         `json:"telegram_chat_id,omitempty"`
	Options        map[string]any `json:"options,omitempty"`
	TurnstileToken string         `json:"turnstile_token,omitempty"`
}

type CreateTokenResponse struct {
	Token        *Token         `json:"token"`
	ManageKey    string         `json:"manage_key"` // se devuelve UNA sola vez; en la BD solo queda su hash
	ManageURL    string         `json:"manage_url"`
	TriggerURL   string         `json:"trigger_url"`
	DownloadURL  string         `json:"download_url,omitempty"` // requiere la cabecera X-Manage-Key
	ArtifactName string         `json:"artifact_name,omitempty"`
	ContentType  string         `json:"content_type,omitempty"`
	Snippet      string         `json:"snippet,omitempty"`
	Instruction  string         `json:"instructions,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type Service interface {
	RegisterGenerator(g Generator)
	CreateToken(ctx context.Context, req CreateTokenRequest, baseURL string) (*CreateTokenResponse, error)
	GetByManageKey(ctx context.Context, manageKey string) (*Token, error)
	GetByID(ctx context.Context, id string) (*Token, error)
	ToggleToken(ctx context.Context, manageKey string, isActive bool) (*Token, error)
	SetActiveByID(ctx context.Context, id string, isActive bool) (*Token, error)
	DeleteByManageKey(ctx context.Context, manageKey string) error
	GenerateArtifact(ctx context.Context, tok *Token, baseURL string) (*GenerateResult, error)
	RenderRedirect(ctx context.Context, tok *Token, baseURL, nonce string) (string, error)
	ListTokens(ctx context.Context, limit int, offset int) ([]*Token, int64, error)
	CountTokens(ctx context.Context) (int64, error)
	IncrementHitCount(ctx context.Context, id string) error
}

type Option func(*tokenService)

// WithWebhookPolicy fija la politica anti-SSRF usada para validar las URL de webhook.
func WithWebhookPolicy(p netguard.Policy) Option {
	return func(s *tokenService) { s.webhookPolicy = p }
}

type tokenService struct {
	repo          Repository
	generators    map[string]Generator
	webhookPolicy netguard.Policy
}

func NewService(repo Repository, opts ...Option) Service {
	s := &tokenService{repo: repo, generators: make(map[string]Generator)}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *tokenService) RegisterGenerator(g Generator) { s.generators[g.Type()] = g }

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", core.ErrInvalidInput, fmt.Sprintf(format, a...))
}

func (s *tokenService) CreateToken(ctx context.Context, req CreateTokenRequest, baseURL string) (*CreateTokenResponse, error) {
	baseURL = strings.TrimRight(baseURL, "/")

	// ---- 1. Validacion (antes se aceptaba cualquier cosa: javascript: en target_url, URLs de webhook internas...) ----
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	gen, ok := s.generators[req.Type]
	if !ok {
		return nil, invalid("unknown token type")
	}
	label, err := core.NormalizeLabel(req.Label)
	if err != nil {
		return nil, err
	}
	if label == "" {
		label = "Canary " + strings.ToUpper(req.Type) + " token"
	}
	channel, err := core.ValidateNotifyChannel(req.NotifyChannel)
	if err != nil {
		return nil, err
	}
	cfg := NotifyConfigData{}
	switch channel {
	case "webhook":
		u, err := netguard.ValidateURL(req.WebhookURL, s.webhookPolicy)
		if err != nil {
			return nil, invalid("webhook_url: %v", err)
		}
		secret, err := core.ValidateWebhookSecret(req.WebhookSecret)
		if err != nil {
			return nil, err
		}
		cfg.WebhookURL, cfg.WebhookSecret = u.String(), secret
	case "telegram":
		id, err := core.ValidateTelegramChatID(req.TelegramChatID)
		if err != nil {
			return nil, err
		}
		cfg.TelegramChatID = id
	}
	targetURL := ""
	if req.Type == "slowredirect" {
		if targetURL, err = core.ValidateTargetURL(req.TargetURL); err != nil {
			return nil, err
		}
	}
	options, err := core.SanitizeOptions(req.Type, req.Options)
	if err != nil {
		return nil, err
	}

	// ---- 2. Identificadores y secretos ----
	tokenID := GenerateSecureID("c", 12)   // 96 bits
	manageKey := GenerateSecureID("k", 16) // 128 bits, devuelto una sola vez
	seedHex := seed.NewSeed()
	triggerURL := fmt.Sprintf("%s/t/%s", baseURL, tokenID)

	// ---- 3. Generar el artefacto ANTES de persistir: si falla no queda un token huerfano y activo ----
	genResult, err := gen.Generate(ctx, GenerateRequest{
		TokenID: tokenID, Label: label, TriggerURL: triggerURL, TargetURL: targetURL,
		BaseURL: baseURL, Seed: seedHex, Options: options,
	})
	if err != nil {
		core.IncErrors()
		slog.Error("failed to generate canary artifact", "type", req.Type, "error", err)
		return nil, fmt.Errorf("failed to generate canary payload: %w", err)
	}

	notifyJSON := "{}"
	if channel != "none" {
		notifyJSON = mustJSON(cfg)
	}
	now := time.Now().UTC()
	tok := &Token{
		ID: tokenID, Type: req.Type, Label: label, ManageKey: HashManageKey(manageKey),
		TargetURL: targetURL, NotifyChannel: channel, NotifyConfig: notifyJSON,
		Metadata: seed.EncodeMeta(seedHex, options),
		IsActive: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.repo.Create(ctx, tok); err != nil {
		core.IncErrors()
		return nil, fmt.Errorf("failed to save token: %w", err)
	}
	core.IncTokensCreated()

	resp := &CreateTokenResponse{
		Token: tok, ManageKey: manageKey,
		ManageURL:  fmt.Sprintf("%s/#/manage/%s", baseURL, manageKey), // fragmento: nunca llega a logs de servidor ni a Referer
		TriggerURL: triggerURL, Snippet: genResult.Snippet, Instruction: genResult.Instructions, Metadata: genResult.Metadata,
	}
	if len(genResult.Artifact) > 0 {
		resp.DownloadURL = "/api/manage/download"
		resp.ArtifactName, resp.ContentType = genResult.ArtifactName, genResult.ContentType
	}
	return resp, nil
}

func (s *tokenService) GetByManageKey(ctx context.Context, key string) (*Token, error) {
	return s.repo.GetByManageKey(ctx, key)
}
func (s *tokenService) GetByID(ctx context.Context, id string) (*Token, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *tokenService) ToggleToken(ctx context.Context, key string, active bool) (*Token, error) {
	tok, err := s.repo.GetByManageKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return s.SetActiveByID(ctx, tok.ID, active)
}

func (s *tokenService) SetActiveByID(ctx context.Context, id string, active bool) (*Token, error) {
	if err := s.repo.SetActive(ctx, id, active); err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, id)
}

// DeleteByManageKey permite al propietario borrar su token y sus eventos (derecho de supresion).
func (s *tokenService) DeleteByManageKey(ctx context.Context, key string) error {
	tok, err := s.repo.GetByManageKey(ctx, key)
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, tok.ID)
}

func (s *tokenService) generatorFor(tok *Token) (Generator, error) {
	gen, ok := s.generators[tok.Type]
	if !ok {
		return nil, fmt.Errorf("no generator registered for type %q", tok.Type)
	}
	return gen, nil
}

// GenerateArtifact regenera el artefacto con la semilla y las opciones guardadas: produce SIEMPRE los
// mismos bytes que se mostraron al crear el token (antes cambiaba en cada descarga y perdia la receta).
func (s *tokenService) GenerateArtifact(ctx context.Context, tok *Token, baseURL string) (*GenerateResult, error) {
	gen, err := s.generatorFor(tok)
	if err != nil {
		return nil, err
	}
	baseURL = strings.TrimRight(baseURL, "/")
	seedHex, options := seed.DecodeMeta(tok.Metadata)
	return gen.Generate(ctx, GenerateRequest{
		TokenID: tok.ID, Label: tok.Label, TriggerURL: fmt.Sprintf("%s/t/%s", baseURL, tok.ID),
		TargetURL: tok.TargetURL, BaseURL: baseURL, Seed: seedHex, Options: options,
	})
}

func (s *tokenService) RenderRedirect(ctx context.Context, tok *Token, baseURL, nonce string) (string, error) {
	gen, ok := s.generators["slowredirect"]
	if !ok {
		return "", errors.New("slowredirect generator not registered")
	}
	baseURL = strings.TrimRight(baseURL, "/")
	res, err := gen.Generate(ctx, GenerateRequest{
		TokenID: tok.ID, Label: tok.Label, TriggerURL: fmt.Sprintf("%s/t/%s", baseURL, tok.ID),
		TargetURL: tok.TargetURL, BaseURL: baseURL, Nonce: nonce,
	})
	if err != nil {
		return "", err
	}
	return string(res.Artifact), nil
}

func (s *tokenService) ListTokens(ctx context.Context, limit int, offset int) ([]*Token, int64, error) {
	return s.repo.List(ctx, limit, offset)
}
func (s *tokenService) CountTokens(ctx context.Context) (int64, error) { return s.repo.Count(ctx) }
func (s *tokenService) IncrementHitCount(ctx context.Context, id string) error {
	return s.repo.IncrementHitCount(ctx, id)
}

func mustJSON(v any) string {
	b, err := jsonMarshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
