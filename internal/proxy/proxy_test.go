package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/audit"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/observability"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/policy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/routing"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/vault"
)

func TestProxyOpenProxyBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	auditDB := filepath.Join(tmpDir, "audit.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	cfg := &config.Config{
		Server: config.ServerConfig{
			MaxBodySizeBytes: 1048576,
		},
		Routes: []config.RouteConfig{
			{
				ID: "openai",
				Match: config.RouteMatch{
					PathPrefix: "/openai",
				},
				Upstream: "http://127.0.0.1:9999",
				Policy:   "strict",
			},
		},
		Policies: []config.PolicyConfig{
			{
				Name:          "strict",
				DefaultAction: "allow",
			},
		},
	}

	router, err := routing.NewRouter(cfg.Routes)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}
	policyEngine := policy.NewEngine(cfg.Policies)

	key, _ := vault.GenerateMasterKey()
	vaultStore, _ := vault.Open(vaultDB, key, "")
	defer vaultStore.Close()

	auditStore, _ := audit.Open(auditDB)
	defer auditStore.Close()

	metrics := observability.NewMetrics(prometheus.NewRegistry())

	handler := NewProxyHandler(cfg, router, policyEngine, nil, vaultStore, auditStore, metrics)

	// Send request to an unconfigured route
	req := httptest.NewRequest("GET", "/unauthorized/path", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON error: %v", err)
	}
	if resp["error"] != "route_not_found" {
		t.Errorf("expected error=route_not_found, got %v", resp["error"])
	}
}

func TestProxyConcurrencyLimit(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			MaxConcurrency:   1,
			MaxBodySizeBytes: 1048576,
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
	}

	router, _ := routing.NewRouter(cfg.Routes)
	policyEngine := policy.NewEngine(cfg.Policies)
	metrics := observability.NewMetrics(prometheus.NewRegistry())

	handler := NewProxyHandler(cfg, router, policyEngine, nil, nil, nil, metrics)
	handler.activeConns = 2 // Simulate exceeding concurrency

	req := httptest.NewRequest("POST", "/mock/test", strings.NewReader("hello"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable, got %d", rec.Code)
	}
}

func TestProxyForwardAllowedRequest(t *testing.T) {
	upstreamHit := false
	var receivedBody string

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		b := new(bytes.Buffer)
		b.ReadFrom(r.Body)
		receivedBody = b.String()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			MaxBodySizeBytes: 1048576,
		},
		Routes: []config.RouteConfig{
			{
				ID: "mock-route",
				Match: config.RouteMatch{
					PathPrefix: "/ai",
				},
				Upstream:    mockUpstream.URL,
				StripPrefix: true,
				Policy:      "allow-all",
			},
		},
		Policies: []config.PolicyConfig{
			{
				Name:          "allow-all",
				DefaultAction: "allow",
				FailureBehavior: config.FailureBehavior{
					InferenceUnavailable: "allow",
				},
			},
		},
	}

	router, _ := routing.NewRouter(cfg.Routes)
	policyEngine := policy.NewEngine(cfg.Policies)
	metrics := observability.NewMetrics(prometheus.NewRegistry())

	handler := NewProxyHandler(cfg, router, policyEngine, nil, nil, nil, metrics)

	input := `{"query": "benign search query"}`
	req := httptest.NewRequest("POST", "/ai/v1/search", strings.NewReader(input))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	if !upstreamHit {
		t.Error("expected upstream to be contacted")
	}
	if receivedBody != input {
		t.Errorf("expected '%s', got '%s'", input, receivedBody)
	}
}

func TestProxyFailClosedWhenInferenceNil(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			MaxBodySizeBytes: 1048576,
		},
		Routes: []config.RouteConfig{
			{
				ID: "mock-route",
				Match: config.RouteMatch{
					PathPrefix: "/ai",
				},
				Upstream: "http://127.0.0.1:9999",
				Policy:   "strict-fail-closed",
			},
		},
		Policies: []config.PolicyConfig{
			{
				Name:          "strict-fail-closed",
				DefaultAction: "allow",
				FailureBehavior: config.FailureBehavior{
					InferenceUnavailable: "block",
				},
			},
		},
	}

	router, _ := routing.NewRouter(cfg.Routes)
	policyEngine := policy.NewEngine(cfg.Policies)
	metrics := observability.NewMetrics(prometheus.NewRegistry())

	handler := NewProxyHandler(cfg, router, policyEngine, nil, nil, nil, metrics)

	input := `{"query": "benign search query"}`
	req := httptest.NewRequest("POST", "/ai/v1/search", strings.NewReader(input))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway for fail-closed, got %d", rec.Code)
	}

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "security_inference_unavailable" {
		t.Errorf("expected security_inference_unavailable, got %v", resp["error"])
	}
}

func TestProxyAuditRecording(t *testing.T) {
	tmpDir := t.TempDir()
	auditDB := filepath.Join(tmpDir, "audit.db")
	auditStore, err := audit.Open(auditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			MaxBodySizeBytes: 1048576,
		},
		Routes: []config.RouteConfig{
			{
				ID: "test-route",
				Match: config.RouteMatch{
					PathPrefix: "/test",
				},
				Upstream: "http://127.0.0.1:9999",
				Policy:   "test-policy",
			},
		},
		Policies: []config.PolicyConfig{
			{
				Name:          "test-policy",
				DefaultAction: "allow",
			},
		},
	}

	router, _ := routing.NewRouter(cfg.Routes)
	policyEngine := policy.NewEngine(cfg.Policies)
	metrics := observability.NewMetrics(prometheus.NewRegistry())

	handler := NewProxyHandler(cfg, router, policyEngine, nil, nil, auditStore, metrics)

	// Blocked on unknown route
	req := httptest.NewRequest("GET", "/not-found", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	events, err := auditStore.Query(context.Background(), audit.Filter{Limit: 10})
	if err != nil {
		t.Fatalf("failed to query audit store: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Decision != "block" {
		t.Errorf("expected decision=block, got %s", events[0].Decision)
	}
}
