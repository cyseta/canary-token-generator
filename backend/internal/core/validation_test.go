package core

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeLabel(t *testing.T) {
	got, err := NormalizeLabel("  Salary\n\tReport\x00 2026 \u202Egpj.exe ")
	if err != nil || got != "Salary Report 2026 gpj.exe" {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := NormalizeLabel(strings.Repeat("a", 121)); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("debe rechazar etiquetas largas")
	}
	if _, err := NormalizeLabel("bad\xff"); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("debe rechazar UTF-8 invalido")
	}
	if s, _ := NormalizeLabel(strings.Repeat("ñ", 120)); len([]rune(s)) != 120 {
		t.Fatal("el limite se cuenta en runas, no en bytes")
	}
}

func TestValidateTargetURL(t *testing.T) {
	for _, bad := range []string{"javascript:alert(1)", "data:text/html,x", "//evil.com", "ftp://x.com", "https://u:p@x.com", "https:///x", "vbscript:x", strings.Repeat("a", 3000)} {
		if _, err := ValidateTargetURL(bad); err == nil {
			t.Errorf("%q deberia rechazarse", bad)
		}
	}
	if u, err := ValidateTargetURL(" https://example.com/a?b=1 "); err != nil || u != "https://example.com/a?b=1" {
		t.Fatalf("got %q %v", u, err)
	}
	if u, err := ValidateTargetURL(""); err != nil || u != "" {
		t.Fatal("vacio es valido (campo opcional)")
	}
	if IsValidURL("javascript:alert(1)") || !IsValidURL("http://a.com") || IsValidURL("") {
		t.Fatal("IsValidURL incoherente")
	}
}

func TestOtherValidators(t *testing.T) {
	if c, err := ValidateNotifyChannel(""); err != nil || c != "none" {
		t.Fatal("canal vacio => none")
	}
	if _, err := ValidateNotifyChannel("sms"); err == nil {
		t.Fatal("canal desconocido debe fallar")
	}
	for _, ok := range []string{"123456789", "-1001234567890", "@mychannel"} {
		if _, err := ValidateTelegramChatID(ok); err != nil {
			t.Errorf("%q valido", ok)
		}
	}
	for _, bad := range []string{"", "abc", "@a", "1 2", "12345678901234567890123", "@my channel", "1;DROP"} {
		if _, err := ValidateTelegramChatID(bad); err == nil {
			t.Errorf("%q debe fallar", bad)
		}
	}
	if _, err := ValidateWebhookSecret(strings.Repeat("a", 257)); err == nil {
		t.Fatal("secreto largo")
	}
	if _, err := ValidateWebhookSecret("a\nb"); err == nil {
		t.Fatal("secreto con control")
	}
}

func TestSanitizeOptions(t *testing.T) {
	out, err := SanitizeOptions("envfile", map[string]any{"recipe": " AWS ", "base_url": "http://evil", "x": 1})
	if err != nil || len(out) != 1 || out["recipe"] != "aws" {
		t.Fatalf("got %v %v", out, err)
	}
	if _, err := SanitizeOptions("envfile", map[string]any{"recipe": "../../etc"}); err == nil {
		t.Fatal("receta invalida")
	}
	if out, _ := SanitizeOptions("pdf", map[string]any{"recipe": "aws"}); len(out) != 0 {
		t.Fatal("otros tipos no admiten opciones")
	}
}

func TestConfigValidate(t *testing.T) {
	prod := func(tok string) *Config {
		return &Config{AppEnv: "production", BaseURL: "https://c.example.com", AdminToken: tok, RetentionDays: 90}
	}
	for _, bad := range []string{"", "short", "canary-super-secret-admin-token", "canary-operator-super-secret-token"} {
		if err := prod(bad).Validate(); err == nil {
			t.Errorf("token %q no debe aceptarse en produccion", bad)
		}
	}
	if err := prod(strings.Repeat("a1", 16)).Validate(); err != nil {
		t.Fatalf("token fuerte debe aceptarse: %v", err)
	}
	c := prod(strings.Repeat("a1", 16))
	c.AllowPrivateWebhooks = true
	if c.Validate() == nil {
		t.Fatal("ALLOW_PRIVATE_WEBHOOKS prohibido en produccion")
	}
	if (&Config{AppEnv: "development", BaseURL: "javascript:x", RetentionDays: 1}).Validate() == nil {
		t.Fatal("BASE_URL invalida")
	}
}

func TestLoadConfigNoDefaultAdminToken(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("ADMIN_TOKEN", "")
	a, b := LoadConfig(), LoadConfig()
	if !a.AdminTokenGenerated || len(a.AdminToken) < 32 || a.AdminToken == b.AdminToken {
		t.Fatal("en desarrollo debe generarse un token aleatorio distinto por arranque")
	}
	t.Setenv("APP_ENV", "production")
	if LoadConfig().AdminToken != "" {
		t.Fatal("en produccion no se autogenera: debe fallar Validate")
	}
}
