package core

import (
	"log/slog"
	"os"
	"sync/atomic"
)

// Metrics usa contadores atomicos tipados: lectura y escritura concurrentes sin data races.
type Metrics struct {
	tokensCreated     atomic.Uint64
	eventsLogged      atomic.Uint64
	webhooksSent      atomic.Uint64
	errorsTotal       atomic.Uint64
	alertsDropped     atomic.Uint64
	alertFailures     atomic.Uint64
	mysqlUnattributed atomic.Uint64
}

type MetricsSnapshot struct {
	TokensCreated     uint64 `json:"tokens_created"`
	EventsLogged      uint64 `json:"events_logged"`
	WebhooksSent      uint64 `json:"webhooks_sent"`
	ErrorsTotal       uint64 `json:"errors_total"`
	AlertsDropped     uint64 `json:"alerts_dropped"`
	AlertFailures     uint64 `json:"alert_failures"`
	MySQLUnattributed uint64 `json:"mysql_unattributed"`
}

var GlobalMetrics = &Metrics{}

func IncTokensCreated()     { GlobalMetrics.tokensCreated.Add(1) }
func IncEventsLogged()      { GlobalMetrics.eventsLogged.Add(1) }
func IncWebhooksSent()      { GlobalMetrics.webhooksSent.Add(1) }
func IncErrors()            { GlobalMetrics.errorsTotal.Add(1) }
func IncAlertsDropped()     { GlobalMetrics.alertsDropped.Add(1) }
func IncAlertFailures()     { GlobalMetrics.alertFailures.Add(1) }
func IncMySQLUnattributed() { GlobalMetrics.mysqlUnattributed.Add(1) }

func SnapshotMetrics() MetricsSnapshot {
	m := GlobalMetrics
	return MetricsSnapshot{
		TokensCreated: m.tokensCreated.Load(), EventsLogged: m.eventsLogged.Load(),
		WebhooksSent: m.webhooksSent.Load(), ErrorsTotal: m.errorsTotal.Load(),
		AlertsDropped: m.alertsDropped.Load(), AlertFailures: m.alertFailures.Load(),
		MySQLUnattributed: m.mysqlUnattributed.Load(),
	}
}

func InitTelemetry(env string) {
	var handler slog.Handler
	if env == "production" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	}
	slog.SetDefault(slog.New(handler))
}
