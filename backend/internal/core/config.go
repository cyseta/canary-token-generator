package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"canary-token-generator/backend/internal/clientip"
)

type Config struct {
	AppEnv            string
	HTTPPort          int
	MySQLPort         int
	BaseURL           string
	DBDriver          string // "sqlite" or "postgres"
	DBDSN             string
	RedisAddr         string
	RedisPassword     string
	AdminToken        string
	RetentionDays     int
	RetentionInterval time.Duration
	GeoIPPath         string
	TurnstileSecret   string
	TurnstileSiteKey  string
	TelegramBotToken  string
	DrainDelay        time.Duration

	// Seguridad de red
	TrustedProxies       []string // CIDR/IP de proxies cuyas cabeceras X-Forwarded-For se aceptan
	ClientIPHeader       string   // x-forwarded-for (defecto) | x-real-ip | cf-connecting-ip
	AllowedOrigins       []string // CORS
	AllowPrivateWebhooks bool     // SOLO autoalojado de confianza: permite webhooks a redes internas y http://

	// Honeypot MySQL
	PublicMySQLHost    string // host que se incrusta en las credenciales senuelo
	PublicMySQLPort    int
	MySQLMaxConns      int
	MySQLMaxConnsPerIP int

	AdminTokenGenerated bool // true si se genero uno aleatorio (solo desarrollo)
}

// knownDefaultTokens son valores que existieron en versiones previas del proyecto.
var knownDefaultTokens = map[string]bool{
	"canary-super-secret-admin-token":    true,
	"canary-operator-super-secret-token": true,
	"canary-dev-operator-token":          true,
	"changeme":                           true,
}

func LoadConfig() *Config {
	base := strings.TrimRight(getEnv("BASE_URL", "http://localhost:8080"), "/")
	cfg := &Config{
		AppEnv:            getEnv("APP_ENV", "development"),
		HTTPPort:          getEnvInt("HTTP_PORT", 8080),
		MySQLPort:         getEnvInt("MYSQL_PORT", 3306),
		BaseURL:           base,
		DBDriver:          getEnv("DB_DRIVER", "sqlite"),
		DBDSN:             getEnv("DB_DSN", "canary.db"),
		RedisAddr:         getEnv("REDIS_ADDR", ""),
		RedisPassword:     getEnv("REDIS_PASSWORD", ""),
		AdminToken:        getEnv("ADMIN_TOKEN", ""),
		RetentionDays:     getEnvInt("RETENTION_DAYS", 90),
		RetentionInterval: getEnvDuration("RETENTION_INTERVAL", 24*time.Hour),
		GeoIPPath:         getEnv("GEOIP_PATH", "GeoLite2-City.mmdb"),
		TurnstileSecret:   getEnv("TURNSTILE_SECRET_KEY", ""),
		TurnstileSiteKey:  getEnv("TURNSTILE_SITE_KEY", ""),
		TelegramBotToken:  getEnv("TELEGRAM_BOT_TOKEN", ""),
		DrainDelay:        getEnvDuration("DRAIN_DELAY", 3*time.Second),

		TrustedProxies:       splitCSV(getEnv("TRUSTED_PROXIES", "")),
		ClientIPHeader:       getEnv("CLIENT_IP_HEADER", "x-forwarded-for"),
		AllowedOrigins:       splitCSV(getEnv("CORS_ALLOWED_ORIGINS", base)),
		AllowPrivateWebhooks: getEnvBool("ALLOW_PRIVATE_WEBHOOKS", false),

		PublicMySQLHost:    getEnv("PUBLIC_MYSQL_HOST", ""),
		MySQLMaxConns:      getEnvInt("MYSQL_MAX_CONNS", 256),
		MySQLMaxConnsPerIP: getEnvInt("MYSQL_MAX_CONNS_PER_IP", 8),
	}
	cfg.PublicMySQLPort = getEnvInt("PUBLIC_MYSQL_PORT", cfg.MySQLPort)
	if cfg.PublicMySQLHost == "" {
		if u, err := url.Parse(base); err == nil {
			cfg.PublicMySQLHost = u.Hostname()
		}
	}
	if cfg.AdminToken == "" && !cfg.IsProduction() {
		// Nunca hay un token por defecto conocido: en desarrollo se genera uno aleatorio por arranque.
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		cfg.AdminToken = hex.EncodeToString(b)
		cfg.AdminTokenGenerated = true
	}
	return cfg
}

func (c *Config) IsProduction() bool { return strings.EqualFold(c.AppEnv, "production") }

// Validate rechaza configuraciones inseguras. Debe llamarse al arrancar.
func (c *Config) Validate() error {
	var errs []error
	if u, err := url.Parse(c.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		errs = append(errs, fmt.Errorf("BASE_URL must be an absolute http(s) URL, got %q", c.BaseURL))
	}
	if c.IsProduction() {
		switch {
		case c.AdminToken == "":
			errs = append(errs, errors.New("ADMIN_TOKEN is required in production"))
		case len(c.AdminToken) < 24:
			errs = append(errs, errors.New("ADMIN_TOKEN must be at least 24 characters"))
		case knownDefaultTokens[c.AdminToken]:
			errs = append(errs, errors.New("ADMIN_TOKEN is a known default value; generate a random one (openssl rand -hex 32)"))
		}
		if c.AllowPrivateWebhooks {
			errs = append(errs, errors.New("ALLOW_PRIVATE_WEBHOOKS must not be enabled on a public production instance (SSRF)"))
		}
	}
	if _, err := clientip.New(c.TrustedProxies, c.ClientIPHeader); err != nil {
		errs = append(errs, err)
	}
	if c.RetentionDays < 1 {
		errs = append(errs, errors.New("RETENTION_DAYS must be >= 1"))
	}
	return errors.Join(errs...)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}
