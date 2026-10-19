package turnstile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Verifier interface {
	Verify(ctx context.Context, token string, remoteIP string) (bool, error)
}

type SiteVerifyResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
	Action      string    `json:"action"`
	Cdata       string    `json:"cdata"`
}

type CloudflareVerifier struct {
	secretKey  string
	httpClient *http.Client
}

func NewVerifier(secretKey string) Verifier {
	return &CloudflareVerifier{
		secretKey: secretKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (v *CloudflareVerifier) Verify(ctx context.Context, token string, remoteIP string) (bool, error) {
	// If secret key is empty, turnstile is disabled (dev mode)
	if strings.TrimSpace(v.secretKey) == "" {
		return true, nil
	}

	if strings.TrimSpace(token) == "" {
		return false, fmt.Errorf("missing turnstile token")
	}

	data := url.Values{}
	data.Set("secret", v.secretKey)
	data.Set("response", token)
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("turnstile request failed: %w", err)
	}
	defer resp.Body.Close()

	var siteResp SiteVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&siteResp); err != nil {
		return false, fmt.Errorf("failed to decode turnstile response: %w", err)
	}

	if !siteResp.Success {
		return false, fmt.Errorf("turnstile verification failed: %s", strings.Join(siteResp.ErrorCodes, ", "))
	}

	return true, nil
}
