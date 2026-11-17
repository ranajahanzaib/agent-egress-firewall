package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/audit"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/observability"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/policy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/proxy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/routing"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/vault"
)

type Server struct {
	httpServer   *http.Server
	cfg          *config.Config
	infClient    *inspection.Client
	proxyHandler *proxy.ProxyHandler
}

func New(
	cfg *config.Config,
	router *routing.Router,
	policyEngine *policy.Engine,
	infClient *inspection.Client,
	vaultStore *vault.Vault,
	auditStore *audit.Store,
	metrics *observability.Metrics,
) *Server {
	proxyHandler := proxy.NewProxyHandler(
		cfg,
		router,
		policyEngine,
		infClient,
		vaultStore,
		auditStore,
		metrics,
	)

	mux := http.NewServeMux()

	// Operational endpoints
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "healthy",
			"version": "0.1.0",
		})
	})

	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check inference health
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		var infStatus string = "disconnected"
		if infClient != nil {
			resp, err := infClient.CheckHealth(ctx)
			if err == nil && resp != nil {
				infStatus = "ready"
			}
		}

		if infStatus != "ready" && cfg.Inference.EnableML {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ready":     false,
				"inference": infStatus,
				"message":   "inference engine unavailable",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ready":     true,
			"routes":    len(cfg.Routes),
			"inference": infStatus,
		})
	})

	mux.Handle("GET /metrics", promhttp.Handler())

	// Fallback to proxy handler for all outbound traffic
	mux.Handle("/", proxyHandler)

	httpSrv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	return &Server{
		httpServer:   httpSrv,
		cfg:          cfg,
		infClient:    infClient,
		proxyHandler: proxyHandler,
	}
}

func (s *Server) Start() error {
	slog.Info("Starting AEGF Proxy Server", "listen", s.cfg.Server.Listen)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server failed: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("Shutting down AEGF Proxy Server gracefully")
	if s.infClient != nil {
		_ = s.infClient.Close()
	}
	return s.httpServer.Shutdown(ctx)
}
