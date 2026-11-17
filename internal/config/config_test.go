package config

import (
	"os"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	cfg := DefaultConfig()
	// Should fail because no routes
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for empty routes, got nil")
	}

	cfg.Policies = append(cfg.Policies, PolicyConfig{
		Name:          "strict-ai",
		DefaultAction: "allow",
		OnDetection: map[string]string{
			"API_KEY": "block",
			"EMAIL":   "redact",
		},
	})

	cfg.Routes = append(cfg.Routes, RouteConfig{
		ID: "openai",
		Match: RouteMatch{
			PathPrefix: "/openai",
		},
		Upstream: "https://api.openai.com",
		Policy:   "strict-ai",
	})

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestLoadFile(t *testing.T) {
	yamlData := `
server:
  listen: "127.0.0.1:9090"
routes:
  - id: test-route
    match:
      path_prefix: /test
    upstream: https://httpbin.org
    strip_prefix: true
    policy: default-policy
policies:
  - name: default-policy
    default_action: allow
    on_detection:
      EMAIL: redact
`
	tmp, err := os.CreateTemp("", "aegf-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write([]byte(yamlData)); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	cfg, err := LoadFile(tmp.Name())
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	if cfg.Server.Listen != "127.0.0.1:9090" {
		t.Errorf("expected listen 127.0.0.1:9090, got %s", cfg.Server.Listen)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].ID != "test-route" {
		t.Errorf("unexpected routes: %+v", cfg.Routes)
	}
}
