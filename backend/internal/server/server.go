package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"canary-token-generator/backend/internal/admin"
	"canary-token-generator/backend/internal/clientip"
	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/health"
	"canary-token-generator/backend/internal/middleware"
	"canary-token-generator/backend/internal/token"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type Server struct {
	httpServer    *http.Server
	healthChecker *health.Checker
	drainDelay    time.Duration
	router        chi.Router
}

// Handler expone el router (usado por los tests de integracion).
func (s *Server) Handler() http.Handler { return s.router }

func New(
	cfg *core.Config,
	tokenHandler *token.Handler,
	adminHandler *admin.Handler,
	healthChecker *health.Checker,
	cache core.CacheClient,
) (*Server, error) {
	resolver, err := clientip.New(cfg.TrustedProxies, cfg.ClientIPHeader)
	if err != nil {
		return nil, err
	}
	r := chi.NewRouter()

	r.Use(chiMiddleware.CleanPath)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP(resolver))
	r.Use(middleware.Logger)
	r.Use(middleware.Recovery)
	r.Use(middleware.SecurityHeaders(strings.HasPrefix(cfg.BaseURL, "https://")))
	r.Use(middleware.Fingerprint)

	// CORS: la SPA se sirve desde el mismo origen. Antes era "*", que permitia a cualquier web llamar a la API.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-Manage-Key", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID", "Content-Disposition"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/healthz", healthChecker.Healthz)

	// Disparadores publicos. Aceptan CUALQUIER metodo (GET, HEAD, POST...): antes HEAD (previsualizadores,
	// escaneres de correo) devolvia 405 y no se detectaba. Limite generoso por IP para proteger la BD de inundaciones.
	trig := middleware.RateLimit(cache, "trigger", 120, time.Minute)
	r.With(trig).HandleFunc("/t/{tokenID}", tokenHandler.TriggerHTTP)
	r.With(trig).HandleFunc("/t/{tokenID}/*", tokenHandler.TriggerHTTP)
	r.With(trig).Get("/r/{tokenID}", tokenHandler.SlowRedirectInterstitial)
	r.With(trig).Post("/f/{tokenID}", tokenHandler.FingerprintPOST)
	r.With(trig).HandleFunc("/k/{tokenID}/*", tokenHandler.KubeWildcard)
	r.With(trig).HandleFunc("/k/{tokenID}", tokenHandler.KubeWildcard)

	manage := middleware.RateLimit(cache, "manage", 60, time.Minute)
	r.Route("/api", func(api chi.Router) {
		api.Get("/config", tokenHandler.PublicConfig)
		api.With(middleware.RateLimit(cache, "create", 30, time.Minute)).Post("/tokens", tokenHandler.CreateToken)

		// La clave de gestion viaja en la cabecera X-Manage-Key (no en la URL).
		api.With(manage).Get("/manage", tokenHandler.GetManageToken)
		api.With(manage).Delete("/manage", tokenHandler.DeleteToken)
		api.With(manage).Post("/manage/toggle", tokenHandler.ToggleToken)
		api.With(manage).Get("/manage/download", tokenHandler.DownloadArtifact)
	})

	r.Route("/admin", func(adm chi.Router) {
		adm.Use(middleware.RateLimit(cache, "admin", 30, time.Minute)) // frena la fuerza bruta del token de operador
		adm.Use(middleware.OperatorBearer(cfg.AdminToken))
		adm.Get("/stats", adminHandler.GetStats)
		adm.Get("/tokens", adminHandler.ListTokens)
		adm.Post("/tokens/{id}/disable", adminHandler.ForceDisable)
		adm.Get("/events/recent", adminHandler.GetRecentEvents)
	})

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second, // mitigacion de Slowloris
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10, // 16 KiB (por defecto 1 MiB)
	}
	return &Server{httpServer: httpServer, healthChecker: healthChecker, drainDelay: cfg.DrainDelay, router: r}, nil
}

func (s *Server) Start() error {
	slog.Info("starting HTTP canary server", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("marking server unhealthy and beginning drain delay...", "drain_delay", s.drainDelay)
	s.healthChecker.SetShuttingDown()
	select { // antes un time.Sleep ciego ignoraba el contexto de apagado
	case <-time.After(s.drainDelay):
	case <-ctx.Done():
	}
	slog.Info("shutting down HTTP server connections")
	return s.httpServer.Shutdown(ctx)
}
