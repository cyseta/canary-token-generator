package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"canary-token-generator/backend/internal/admin"
	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/event"
	"canary-token-generator/backend/internal/geoip"
	"canary-token-generator/backend/internal/health"
	"canary-token-generator/backend/internal/netguard"
	"canary-token-generator/backend/internal/notify"
	"canary-token-generator/backend/internal/server"
	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/docx"
	"canary-token-generator/backend/internal/token/generators/envfile"
	"canary-token-generator/backend/internal/token/generators/kubeconfig"
	mysqlGen "canary-token-generator/backend/internal/token/generators/mysql"
	"canary-token-generator/backend/internal/token/generators/pdf"
	"canary-token-generator/backend/internal/token/generators/slowredirect"
	"canary-token-generator/backend/internal/token/generators/webbug"
	"canary-token-generator/backend/internal/turnstile"
)

func main() { os.Exit(run()) }

func run() int {
	cfg := core.LoadConfig()
	core.InitTelemetry(cfg.AppEnv)

	// Una configuracion insegura (sin ADMIN_TOKEN fuerte en produccion, etc.) impide arrancar.
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		return 1
	}
	if cfg.AdminTokenGenerated {
		// Solo desarrollo: se muestra una vez porque no hay valor por defecto conocido.
		slog.Warn("no ADMIN_TOKEN set: generated a random one for this process (development only)", "admin_token", cfg.AdminToken)
	}
	if cfg.IsProduction() && len(cfg.BaseURL) >= 7 && cfg.BaseURL[:7] == "http://" {
		slog.Warn("BASE_URL uses plain http in production: manage links and canary URLs will not be protected by TLS")
	}
	slog.Info("initializing canary token generator daemon...", "env", cfg.AppEnv, "http_port", cfg.HTTPPort, "mysql_port", cfg.MySQLPort)

	db, err := core.InitDB(cfg)
	if err != nil {
		slog.Error("failed to initialize database", "error", err)
		return 1
	}
	defer db.Close()

	cache := core.InitRedisOrMemory(cfg)
	if mc, ok := cache.(*core.MemoryCache); ok {
		defer mc.Close()
	}

	geoIP := geoip.NewProvider(cfg.GeoIPPath)
	defer geoIP.Close()

	turnstileVerifier := turnstile.NewVerifier(cfg.TurnstileSecret)

	dispatcher := notify.NewDispatcher(8, 500, cfg.TelegramBotToken, cfg.AllowPrivateWebhooks)

	tokenRepo := token.NewRepository(db)
	eventRepo := event.NewRepository(db)

	// Migracion unica: las claves de gestion en claro de versiones anteriores pasan a almacenarse como hash.
	if n, err := tokenRepo.HashLegacyManageKeys(context.Background()); err != nil {
		slog.Error("failed to hash legacy manage keys", "error", err)
		return 1
	} else if n > 0 {
		slog.Info("migrated legacy manage keys to SHA-256 hashes", "count", n)
	}

	eventService := event.NewService(eventRepo, tokenRepo.IncrementHitCount, geoIP, cache, dispatcher)
	tokenService := token.NewService(tokenRepo, token.WithWebhookPolicy(netguard.Policy{
		AllowPrivate: cfg.AllowPrivateWebhooks, AllowHTTP: cfg.AllowPrivateWebhooks,
	}))

	tokenService.RegisterGenerator(webbug.New())
	tokenService.RegisterGenerator(pdf.New())
	tokenService.RegisterGenerator(docx.New())
	tokenService.RegisterGenerator(envfile.NewWithMySQL(cfg.PublicMySQLHost, cfg.PublicMySQLPort))
	tokenService.RegisterGenerator(kubeconfig.New())
	tokenService.RegisterGenerator(mysqlGen.NewWithPublic(cfg.PublicMySQLHost, cfg.PublicMySQLPort))
	tokenService.RegisterGenerator(slowredirect.New())

	mysqlConnHandler := mysqlGen.NewConnectionHandler(tokenRepo, eventService)
	mysqlServer := mysqlGen.NewServer(cfg.MySQLPort, mysqlConnHandler)
	mysqlServer.SetLimits(cfg.MySQLMaxConns, cfg.MySQLMaxConnsPerIP)
	mysqlRunning := false
	if err := mysqlServer.Start(); err != nil {
		// El puerto 3306 NO es privilegiado (>1024): el fallo suele ser que ya esta en uso.
		slog.Warn("could not bind mysql honeypot port; mysql/envfile-db tokens will not detect anything", "port", cfg.MySQLPort, "error", err)
	} else {
		mysqlRunning = true
	}

	retentionCtx, cancelRetention := context.WithCancel(context.Background())
	defer cancelRetention()
	go startRetentionLoop(retentionCtx, eventRepo, cfg.RetentionDays, cfg.RetentionInterval)

	healthChecker := health.NewChecker(db.DB)
	tokenHandler := token.NewHandler(tokenService, eventService, turnstileVerifier, cfg)
	adminHandler := admin.NewHandler(tokenService, eventService)

	srv, err := server.New(cfg, tokenHandler, adminHandler, healthChecker, cache)
	if err != nil {
		slog.Error("failed to build HTTP server", "error", err)
		return 1
	}

	serverErrChan := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil {
			serverErrChan <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	exitCode := 0
	select {
	case err := <-serverErrChan:
		slog.Error("server fatal runtime error", "error", err)
		exitCode = 1
	case sig := <-sigChan:
		slog.Info("received termination signal, starting graceful shutdown", "signal", sig.String())
	}

	// Apagado ordenado: primero dejan de entrar eventos (HTTP, MySQL) y por ultimo se vacia la cola de alertas.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown returned error", "error", err)
	}
	if mysqlRunning {
		_ = mysqlServer.Shutdown(shutdownCtx)
	}
	cancelRetention()
	dispatcher.Shutdown() // drena las alertas pendientes
	slog.Info("shutdown complete")
	return exitCode
}

func startRetentionLoop(ctx context.Context, eventRepo event.Repository, retentionDays int, interval time.Duration) {
	prune := func() {
		cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays) // UTC: igual que los timestamps almacenados
		deleted, err := eventRepo.DeleteOlderThan(ctx, cutoff)
		if err != nil {
			slog.Error("failed to prune expired events", "error", err)
			return
		}
		if deleted > 0 {
			slog.Info("pruned expired events according to retention policy", "count", deleted, "cutoff", cutoff.Format(time.RFC3339))
		}
	}
	prune() // al arrancar (antes la primera limpieza tardaba 24h)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}
