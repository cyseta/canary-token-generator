package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const defaultBase = "https://api.telegram.org"

type Client struct {
	botToken   string
	baseURL    string
	httpClient *http.Client
}

type sendMessageReq struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func NewClient(botToken string) *Client {
	return NewClientWith(botToken, defaultBase, &http.Client{Timeout: 10 * time.Second})
}

func NewClientWith(botToken, baseURL string, hc *http.Client) *Client {
	return &Client{botToken: botToken, baseURL: strings.TrimRight(baseURL, "/"), httpClient: hc}
}

// Alert agrupa los datos de la alerta. TODOS los valores son potencialmente controlados por el atacante
// (User-Agent, cabeceras, etiqueta) y se escapan antes de componer el mensaje.
type Alert struct {
	Label, Type, Protocol, IP, City, Country, UserAgent, Time string
	Tags                                                      []string
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max]) + "…"
}

func esc(s string, max int) string { return html.EscapeString(truncate(s, max)) }

// FormatAlert genera un mensaje HTML de Telegram. Antes se usaba Markdown con valores sin escapar:
// un simple "`" o "_" en el User-Agent hacia que la API devolviera 400 y la alerta se perdia.
func FormatAlert(a Alert) string {
	var b strings.Builder
	b.WriteString("🚨 <b>CANARY TOKEN TRIGGERED</b>\n\n")
	fmt.Fprintf(&b, "🏷 <b>Label:</b> <code>%s</code>\n", esc(a.Label, 120))
	fmt.Fprintf(&b, "⚙️ <b>Type:</b> <code>%s</code>\n", esc(a.Type, 32))
	fmt.Fprintf(&b, "🌐 <b>Protocol:</b> <code>%s</code>\n", esc(a.Protocol, 32))
	fmt.Fprintf(&b, "📡 <b>IP:</b> <code>%s</code>\n", esc(a.IP, 64))
	fmt.Fprintf(&b, "📍 <b>Location:</b> %s, %s\n", esc(a.City, 64), esc(a.Country, 64))
	fmt.Fprintf(&b, "💻 <b>User-Agent:</b> <code>%s</code>\n", esc(a.UserAgent, 300))
	if len(a.Tags) > 0 {
		fmt.Fprintf(&b, "🔖 <b>Tags:</b> %s\n", esc(strings.Join(a.Tags, ", "), 120))
	}
	fmt.Fprintf(&b, "⏰ <b>Time:</b> <code>%s</code>", esc(a.Time, 40))
	return b.String()
}

// SendAlert envia el mensaje. Los errores NUNCA contienen el token del bot (va en la URL y
// *url.Error lo incluiria en su mensaje, filtrandolo a los logs).
func (c *Client) SendAlert(ctx context.Context, chatID string, text string) error {
	if c.botToken == "" {
		return errors.New("telegram bot token not configured")
	}
	data, err := json.Marshal(sendMessageReq{ChatID: chatID, Text: truncate(text, 4000), ParseMode: "HTML", DisableWebPagePreview: true})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/bot%s/sendMessage", c.baseURL, c.botToken), bytes.NewReader(data))
	if err != nil {
		return errors.New("telegram: could not build request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var tg struct {
			Description string `json:"description"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 2048)).Decode(&tg)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, truncate(tg.Description, 200))
	}
	slog.Info("telegram alert dispatched", "chat_id", chatID)
	return nil
}
