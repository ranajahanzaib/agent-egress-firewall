package routing

import (
	"net/http/httptest"
	"testing"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
)

func TestRouterMatchingAndRewrite(t *testing.T) {
	configs := []config.RouteConfig{
		{
			ID: "openai",
			Match: config.RouteMatch{
				PathPrefix: "/openai",
			},
			Upstream:    "https://api.openai.com",
			StripPrefix: true,
			Policy:      "strict",
		},
		{
			ID: "internal",
			Match: config.RouteMatch{
				PathPrefix: "/internal/v1",
			},
			Upstream:    "https://internal.corp.net/base",
			StripPrefix: true,
			Policy:      "internal",
		},
	}

	router, err := NewRouter(configs)
	if err != nil {
		t.Fatalf("NewRouter failed: %v", err)
	}

	// 1. Match /openai/v1/chat/completions
	req := httptest.NewRequest("POST", "http://localhost:8080/openai/v1/chat/completions?model=gpt-4", nil)
	route, err := router.Match(req)
	if err != nil {
		t.Fatalf("expected route match, got error: %v", err)
	}
	if route.ID != "openai" {
		t.Errorf("expected route ID openai, got %s", route.ID)
	}

	route.RewriteRequest(req)
	if req.URL.Scheme != "https" || req.URL.Host != "api.openai.com" {
		t.Errorf("expected target https://api.openai.com, got %s://%s", req.URL.Scheme, req.URL.Host)
	}
	if req.URL.Path != "/v1/chat/completions" {
		t.Errorf("expected path /v1/chat/completions, got %s", req.URL.Path)
	}
	if req.URL.RawQuery != "model=gpt-4" {
		t.Errorf("expected query preserved, got %s", req.URL.RawQuery)
	}

	// 2. Unmatched path must fail (anti-open-proxy)
	unmatchedReq := httptest.NewRequest("GET", "http://localhost:8080/unregistered/path", nil)
	if _, err := router.Match(unmatchedReq); err == nil {
		t.Fatalf("expected error for unregistered route, got nil")
	}

	// 3. Test joining with upstream base path
	internalReq := httptest.NewRequest("GET", "http://localhost:8080/internal/v1/users/123", nil)
	iRoute, err := router.Match(internalReq)
	if err != nil {
		t.Fatal(err)
	}
	iRoute.RewriteRequest(internalReq)
	if internalReq.URL.Path != "/base/users/123" {
		t.Errorf("expected /base/users/123, got %s", internalReq.URL.Path)
	}
}
