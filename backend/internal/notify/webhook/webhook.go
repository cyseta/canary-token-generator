package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/netguard"
)

type Payload struct {
	EventID     string         `json:"event_id"`
	TokenID     string         `json:"token_id"`
	TokenLabel  string         `json:"token_label"`
	TokenType   string         `json:"token_type"`
	TriggeredAt time.Time      `json:"triggered_at"`
	SourceIP    string         `json:"source_ip"`
	UserAgent   string         `json:"user_agent"`
	Country     string         `json:"country,omitempty"`
	City        string         `json:"city,omitempty"`
	Protocol    string         `json:"protocol"`
	Tags        []string       `json:"tags,omitempty"`
	Headers     map[string]any `json:"headers,omitempty"`
	Fingerprint map[string]any `json:"fingerprint,omitempty"`
}

type Client struct {
	httpClient *http.Client
	backoff    time.Duration
}

// NewClient crea un cliente que NO puede alcanzar redes internas (anti-SSRF) salvo que el
// operador lo permita explicitamente (allowPrivate, solo autoalojado de confianza).
func NewClient(allowPrivate bool) *Client {
	return NewClientWith(netguard.NewClient(netguard.Policy{AllowPrivate: allowPrivate, AllowHTTP: allowPrivate, Timeout: 10 * time.Second}))
}

// SetBackoff ajusta la espera inicial entre reintentos (usado en tests).
func (c *Client) SetBackoff(d time.Duration) { c.backoff = d }

func NewClientWith(hc *http.Client) *Client {
	return &Client{httpClient: hc, backoff: 500 * time.Millisecond}
}

// Destination devuelve solo esquema+host: las URL de webhook (Slack, Discord...) contienen secretos
// y nunca deben escribirse completas en los logs.
func Destination(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "invalid-url"
	}
	return u.Scheme + "://" + u.Host
}

// sanitizeErr elimina la URL (con sus secretos) que *url.Error incluye en su mensaje.
func sanitizeErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

func retryable(status int) bool { return status == http.StatusTooManyRequests || status >= 500 }

func (c *Client) Send(ctx context.Context, targetURL, secret string, payload Payload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}
	dest := Destination(targetURL)
	const maxAttempts = 3
	backoff := c.backoff

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			return sanitizeErr(err)
		}
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Canary-Notifier/1.0")
		req.Header.Set("X-Canary-Timestamp", timestamp)
		req.Header.Set("X-Canary-Event-Id", payload.EventID)
		if secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(timestamp + "."))
			mac.Write(body)
			req.Header.Set("X-Canary-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = sanitizeErr(err)
			if errors.Is(err, netguard.ErrBlockedAddress) {
				return fmt.Errorf("webhook destination blocked by SSRF policy: %w", netguard.ErrBlockedAddress)
			}
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				core.IncWebhooksSent()
				slog.Info("webhook delivered", "dest", dest, "status", resp.StatusCode)
				return nil
			}
			lastErr = fmt.Errorf("non-2xx response: %d", resp.StatusCode)
			if !retryable(resp.StatusCode) {
				return lastErr // 4xx: reintentar no sirve
			}
		}

		if attempt == maxAttempts {
			break
		}
		slog.Warn("webhook attempt failed, retrying", "attempt", attempt, "dest", dest, "error", lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return fmt.Errorf("webhook delivery failed after %d attempts: %w", maxAttempts, lastErr)
}
