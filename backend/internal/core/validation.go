package core

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxLabelRunes = 120
	MaxURLLen     = 2048
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, a...))
}

// NormalizeLabel limpia y valida la etiqueta. Elimina caracteres de control y los de
// reordenamiento bidireccional (usados para falsear texto en alertas).
func NormalizeLabel(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", invalid("label is not valid UTF-8")
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F:
			// descartar
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if utf8.RuneCountInString(out) > MaxLabelRunes {
		return "", invalid("label must be at most %d characters", MaxLabelRunes)
	}
	return out, nil
}

// ValidateTargetURL admite solo http(s) sin credenciales: evita javascript:, data:, etc.
func ValidateTargetURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > MaxURLLen {
		return "", invalid("target_url is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", invalid("target_url must be an absolute http(s) URL without credentials")
	}
	return u.String(), nil
}

func IsValidURL(str string) bool {
	_, err := ValidateTargetURL(str)
	return err == nil && strings.TrimSpace(str) != ""
}

func ValidateNotifyChannel(ch string) (string, error) {
	switch ch = strings.ToLower(strings.TrimSpace(ch)); ch {
	case "", "none":
		return "none", nil
	case "webhook", "telegram":
		return ch, nil
	}
	return "", invalid("notify_channel must be one of: none, webhook, telegram")
}

var telegramChatRe = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)

func ValidateTelegramChatID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !telegramChatRe.MatchString(id) {
		return "", invalid("telegram_chat_id must be a numeric chat id or an @channel name")
	}
	return id, nil
}

func ValidateWebhookSecret(s string) (string, error) {
	if len(s) > 256 {
		return "", invalid("webhook_secret is too long (max 256)")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", invalid("webhook_secret contains control characters")
		}
	}
	return s, nil
}

var envRecipes = map[string]bool{"aws": true, "db": true, "database": true, "github": true, "stripe": true, "combo": true, "all": true}

// SanitizeOptions deja pasar solo las opciones conocidas de cada tipo. Cualquier otra clave se descarta.
func SanitizeOptions(tokenType string, in map[string]any) (map[string]any, error) {
	out := map[string]any{}
	if tokenType == "envfile" {
		if v, ok := in["recipe"]; ok {
			s, isStr := v.(string)
			s = strings.ToLower(strings.TrimSpace(s))
			if !isStr || !envRecipes[s] {
				return nil, invalid("options.recipe must be one of: aws, db, github, stripe, combo")
			}
			out["recipe"] = s
		}
	}
	return out, nil
}
