package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/audit"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/observability"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/policy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/proxy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/routing"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/vault"
)

func TestMain(m *testing.M) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:50051", 200*time.Millisecond)
	var infCmd *exec.Cmd
	if err != nil {
		binPath := "../../bin/aegf-inference"
		modelDir := "../../models/gliner-small"
		if _, statErr := os.Stat(binPath); statErr == nil {
			infCmd = exec.Command(binPath, "--listen", "127.0.0.1:50051", "--model-dir", modelDir)
			if err := infCmd.Start(); err == nil {
				for i := 0; i < 50; i++ {
					c, e := net.DialTimeout("tcp", "127.0.0.1:50051", 100*time.Millisecond)
					if e == nil {
						c.Close()
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	} else {
		conn.Close()
	}

	code := m.Run()

	if infCmd != nil && infCmd.Process != nil {
		_ = infCmd.Process.Kill()
		_ = infCmd.Wait()
	}

	os.Exit(code)
}

type MockUpstream struct {
	server       *httptest.Server
	mu           sync.Mutex
	lastRequest  *http.Request
	receivedBody []byte
	requestCount int
}

func newMockUpstream() *MockUpstream {
	m := &MockUpstream{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.requestCount++
		m.receivedBody = body
		m.lastRequest = r.Clone(r.Context())
		m.mu.Unlock()

		if r.URL.Path == "/v1/sse" {
			// Streaming SSE response
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}
			for i := 1; i <= 3; i++ {
				fmt.Fprintf(w, "data: {\"event\": %d, \"text\": \"chunk-%d\"}\n\n", i, i)
				flusher.Flush()
				time.Sleep(20 * time.Millisecond)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"echo":   string(body),
		})
	})
	m.server = httptest.NewServer(handler)
	return m
}

func (m *MockUpstream) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

func (m *MockUpstream) getReceived() (int, []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requestCount, m.receivedBody
}

func setupE2EEnvironment(t *testing.T, upstreamURL string, infAddress string) (*proxy.ProxyHandler, *vault.Vault, *audit.Store) {
	tmpDir := t.TempDir()
	vaultDB := filepath.Join(tmpDir, "vault.db")
	auditDB := filepath.Join(tmpDir, "audit.db")

	vaultKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	vaultStore, err := vault.Open(vaultDB, vaultKey, "")
	if err != nil {
		t.Fatal(err)
	}

	auditStore, err := audit.Open(auditDB)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:           "127.0.0.1:0",
			MaxBodySizeBytes: 5 * 1024 * 1024,
			MaxConcurrency:   100,
			InferenceTimeout: 5 * time.Second,
		},
		Inference: config.InferenceConfig{
			Address:        infAddress,
			Timeout:        5 * time.Second,
			EnableML:       true,
			EnablePatterns: true,
			MinConfidence:  0.60,
		},
		Vault: config.VaultConfig{
			Enabled: true,
			DBPath:  vaultDB,
		},
		Audit: config.AuditConfig{
			Enabled: true,
			DBPath:  auditDB,
		},
		Routes: []config.RouteConfig{
			{
				ID:          "mock-ai",
				Match:       config.RouteMatch{PathPrefix: "/ai"},
				Upstream:    upstreamURL,
				StripPrefix: true,
				Policy:      "strict-ai",
			},
		},
		Policies: []config.PolicyConfig{
			{
				Name:              "strict-ai",
				DefaultAction:     "allow",
				MinimumConfidence: 0.65,
				OnDetection: map[string]string{
					"PERSON":            "redact",
					"EMAIL":             "redact",
					"ACCOUNT_NUMBER":    "redact",
					"INTERNAL_PROJECT":  "redact",
					"API_KEY":           "block",
					"PRIVATE_KEY":       "block",
					"INTERNAL_BUILD_ID": "block",
				},
				FailureBehavior: config.FailureBehavior{
					InferenceUnavailable: "block",
					InferenceTimeout:     "block",
					MalformedPayload:     "block",
				},
			},
		},
		Patterns: []config.PatternConfig{
			{
				Name:       "BUILD_ID_PATTERN",
				Category:   "INTERNAL_BUILD_ID",
				Regex:      `\bBUILD-[0-9]{8}-[a-f0-9]{8}\b`,
				Confidence: 1.0,
				Enabled:    true,
			},
		},
	}

	router, err := routing.NewRouter(cfg.Routes)
	if err != nil {
		t.Fatal(err)
	}

	policyEngine := policy.NewEngine(cfg.Policies)

	infClient, err := inspection.NewClient(infAddress)
	if err != nil {
		t.Fatal(err)
	}

	metrics := observability.NewMetrics(nil)
	proxyHandler := proxy.NewProxyHandler(
		cfg,
		router,
		policyEngine,
		infClient,
		vaultStore,
		auditStore,
		metrics,
	)

	return proxyHandler, vaultStore, auditStore
}

func TestE2E_ScenarioA_AllowedRequest(t *testing.T) {
	mockUpstream := newMockUpstream()
	defer mockUpstream.Close()

	proxyHandler, vaultStore, auditStore := setupE2EEnvironment(t, mockUpstream.server.URL, "127.0.0.1:50051")
	defer vaultStore.Close()
	defer auditStore.Close()

	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	payload := `{"question": "What is the capital of France?"}`
	resp, err := http.Post(proxyServer.URL+"/ai/v1/chat", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	count, received := mockUpstream.getReceived()
	if count != 1 {
		t.Fatalf("expected 1 request upstream, got %d", count)
	}

	if !strings.Contains(string(received), "capital of France") {
		t.Errorf("expected original payload received upstream, got: %s", string(received))
	}
}

func TestE2E_ScenarioB_RedactedPersonalInfo(t *testing.T) {
	mockUpstream := newMockUpstream()
	defer mockUpstream.Close()

	proxyHandler, vaultStore, auditStore := setupE2EEnvironment(t, mockUpstream.server.URL, "127.0.0.1:50051")
	defer vaultStore.Close()
	defer auditStore.Close()

	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	payload := `{
		"customer": "John Smith",
		"email": "john.smith@example.com",
		"message": "Please look up my account."
	}`

	resp, err := http.Post(proxyServer.URL+"/ai/v1/account", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	count, received := mockUpstream.getReceived()
	if count != 1 {
		t.Fatalf("expected upstream to receive request, count=%d", count)
	}

	receivedStr := string(received)
	// CRITICAL SECURITY ASSERTION: Plaintext email and sensitive name must NEVER reach upstream!
	if strings.Contains(receivedStr, "john.smith@example.com") {
		t.Fatalf("SECURITY VIOLATION: raw email leaked to upstream: %s", receivedStr)
	}
	if !strings.Contains(receivedStr, "[AEGF:") {
		t.Fatalf("expected redacted vault tokens in upstream body, got: %s", receivedStr)
	}

	// Verify reversible vault restoration
	restored, err := vaultStore.RestoreText(context.Background(), receivedStr)
	if err != nil {
		t.Fatalf("vault restoration failed: %v", err)
	}
	if !strings.Contains(restored, "john.smith@example.com") {
		t.Errorf("restored content does not contain original email: %s", restored)
	}
}

func TestE2E_ScenarioC_BlockedCredential(t *testing.T) {
	mockUpstream := newMockUpstream()
	defer mockUpstream.Close()

	proxyHandler, vaultStore, auditStore := setupE2EEnvironment(t, mockUpstream.server.URL, "127.0.0.1:50051")
	defer vaultStore.Close()
	defer auditStore.Close()

	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	payload := `{
		"api_key": "sk-proj-1234567890abcdef1234567890",
		"message": "Use this credential to authenticate."
	}`

	resp, err := http.Post(proxyServer.URL+"/ai/v1/query", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Must be rejected with 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}

	// CRITICAL ASSERTION: Mock upstream must receive ZERO requests!
	count, _ := mockUpstream.getReceived()
	if count != 0 {
		t.Fatalf("SECURITY VIOLATION: upstream received %d requests for blocked credential!", count)
	}

	var errResp map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] != "egress_blocked_by_policy" {
		t.Errorf("unexpected error payload: %+v", errResp)
	}
}

func TestE2E_ScenarioD_FailClosedOnInferenceUnavailable(t *testing.T) {
	mockUpstream := newMockUpstream()
	defer mockUpstream.Close()

	// Point inference to dead port (unavailable)
	proxyHandler, vaultStore, auditStore := setupE2EEnvironment(t, mockUpstream.server.URL, "127.0.0.1:59999")
	defer vaultStore.Close()
	defer auditStore.Close()

	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	payload := `{"data": "some customer info"}`
	resp, err := http.Post(proxyServer.URL+"/ai/v1/test", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Under strict policy, must reject with 502 Bad Gateway
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected fail-closed 502, got %d", resp.StatusCode)
	}

	// Mock upstream must receive ZERO requests
	count, _ := mockUpstream.getReceived()
	if count != 0 {
		t.Fatalf("SECURITY VIOLATION: uninspected request reached upstream during inference failure!")
	}
}

func TestE2E_ScenarioE_StreamingResponseSSE(t *testing.T) {
	mockUpstream := newMockUpstream()
	defer mockUpstream.Close()

	proxyHandler, vaultStore, auditStore := setupE2EEnvironment(t, mockUpstream.server.URL, "127.0.0.1:50051")
	defer vaultStore.Close()
	defer auditStore.Close()

	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	req, _ := http.NewRequest("POST", proxyServer.URL+"/ai/v1/sse", strings.NewReader(`{"stream": true}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", resp.Header.Get("Content-Type"))
	}

	// Read chunks as they arrive
	buf := make([]byte, 1024)
	chunksReceived := 0
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunksReceived++
			chunkStr := string(buf[:n])
			if !strings.Contains(chunkStr, "data:") {
				t.Errorf("unexpected SSE chunk: %s", chunkStr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("error reading streaming response: %v", err)
		}
	}

	if chunksReceived < 2 {
		t.Errorf("expected multiple streamed chunks, got %d", chunksReceived)
	}
}

func TestE2E_ScenarioF_DynamicCategory(t *testing.T) {
	mockUpstream := newMockUpstream()
	defer mockUpstream.Close()

	proxyHandler, vaultStore, auditStore := setupE2EEnvironment(t, mockUpstream.server.URL, "127.0.0.1:50051")
	defer vaultStore.Close()
	defer auditStore.Close()

	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	// Contains custom dynamic category pattern: BUILD-20261117-a1b2c3d4
	payload := `{
		"build_id": "BUILD-20261117-a1b2c3d4",
		"project": "testing-dynamic-categories"
	}`

	resp, err := http.Post(proxyServer.URL+"/ai/v1/build", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should be blocked by custom pattern
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for dynamic build ID, got %d", resp.StatusCode)
	}

	count, _ := mockUpstream.getReceived()
	if count != 0 {
		t.Fatalf("SECURITY VIOLATION: dynamic category payload leaked upstream!")
	}
}
