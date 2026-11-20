package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/observability"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/policy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/routing"
)

func TestOperationalEndpoints(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:           "127.0.0.1:0",
			MaxBodySizeBytes: 1048576,
		},
		Inference: config.InferenceConfig{
			EnableML: false, // In degraded / pattern-only mode, ready endpoint can return 200 without inference client
		},
		Routes: []config.RouteConfig{
			{
				ID: "mock",
				Match: config.RouteMatch{
					PathPrefix: "/mock",
				},
				Upstream: "http://127.0.0.1:9999",
				Policy:   "default",
			},
		},
		Policies: []config.PolicyConfig{
			{
				Name:          "default",
				DefaultAction: "allow",
			},
		},
	}

	router, err := routing.NewRouter(cfg.Routes)
	if err != nil {
		t.Fatal(err)
	}
	policyEngine := policy.NewEngine(cfg.Policies)
	metrics := observability.NewMetrics(prometheus.NewRegistry())

	srv := New(cfg, router, policyEngine, nil, nil, nil, metrics)

	// 1. Test /health
	reqHealth := httptest.NewRequest("GET", "/health", nil)
	recHealth := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(recHealth, reqHealth)

	if recHealth.Code != http.StatusOK {
		t.Errorf("expected 200 from /health, got %d", recHealth.Code)
	}

	var healthResp map[string]any
	if err := json.Unmarshal(recHealth.Body.Bytes(), &healthResp); err != nil {
		t.Fatalf("failed parsing /health JSON: %v", err)
	}
	if healthResp["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", healthResp["status"])
	}

	// 2. Test /ready (with EnableML=false, ready should be true)
	reqReady := httptest.NewRequest("GET", "/ready", nil)
	recReady := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(recReady, reqReady)

	if recReady.Code != http.StatusOK {
		t.Errorf("expected 200 from /ready, got %d", recReady.Code)
	}

	// 3. Test /metrics
	reqMetrics := httptest.NewRequest("GET", "/metrics", nil)
	recMetrics := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(recMetrics, reqMetrics)

	if recMetrics.Code != http.StatusOK {
		t.Errorf("expected 200 from /metrics, got %d", recMetrics.Code)
	}
	if recMetrics.Body.Len() == 0 {
		t.Error("expected non-empty metrics output")
	}
}
