package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Inference InferenceConfig `yaml:"inference"`
	Vault     VaultConfig     `yaml:"vault"`
	Audit     AuditConfig     `yaml:"audit"`
	Routes    []RouteConfig   `yaml:"routes"`
	Policies  []PolicyConfig  `yaml:"policies"`
	Entities  []EntityConfig  `yaml:"entities"`
	Patterns  []PatternConfig `yaml:"patterns"`
}

type ServerConfig struct {
	Listen           string        `yaml:"listen"`
	ReadTimeout      time.Duration `yaml:"read_timeout"`
	WriteTimeout     time.Duration `yaml:"write_timeout"`
	IdleTimeout      time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout  time.Duration `yaml:"shutdown_timeout"`
	MaxBodySizeBytes int64         `yaml:"max_body_size_bytes"`
	MaxConcurrency   int           `yaml:"max_concurrency"`
	InferenceTimeout time.Duration `yaml:"inference_timeout"`
}

type InferenceConfig struct {
	Address          string        `yaml:"address"`
	Timeout          time.Duration `yaml:"timeout"`
	EnableML         bool          `yaml:"enable_ml"`
	EnablePatterns   bool          `yaml:"enable_patterns"`
	MinConfidence    float64       `yaml:"min_confidence"`
	MaxSpansPerField int           `yaml:"max_spans_per_field"`
}

type VaultConfig struct {
	Enabled   bool   `yaml:"enabled"`
	DBPath    string `yaml:"db_path"`
	MasterKey string `yaml:"master_key"` // Hex-encoded 32-byte key or from AEGF_VAULT_KEY env
	KeyFile   string `yaml:"key_file"`
	Retention string `yaml:"retention"`
}

type AuditConfig struct {
	Enabled   bool   `yaml:"enabled"`
	DBPath    string `yaml:"db_path"`
	Retention string `yaml:"retention"`
}

type RouteMatch struct {
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
}

type RouteConfig struct {
	ID          string     `yaml:"id"`
	Match       RouteMatch `yaml:"match"`
	Upstream    string     `yaml:"upstream"`
	StripPrefix bool       `yaml:"strip_prefix"`
	Policy      string     `yaml:"policy"`
	Headers     []string   `yaml:"inspect_headers"`
	QueryParams []string   `yaml:"inspect_query_params"`
}

type FailureBehavior struct {
	InferenceUnavailable string `yaml:"inference_unavailable"` // "block" or "allow"
	InferenceTimeout     string `yaml:"inference_timeout"`
	MalformedPayload     string `yaml:"malformed_payload"`
	UnsupportedContent   string `yaml:"unsupported_content"`
	OversizedPayload     string `yaml:"oversized_payload"`
}

type DestinationException struct {
	Destination string   `yaml:"destination"` // wildcard or exact hostname
	Allow       []string `yaml:"allow"`       // categories allowed for this destination
}

type PolicyConfig struct {
	Name              string                 `yaml:"name"`
	DefaultAction     string                 `yaml:"default_action"` // "allow", "redact", "block"
	OnDetection       map[string]string      `yaml:"on_detection"`   // CATEGORY -> "allow" | "redact" | "block"
	Destinations      []string               `yaml:"destinations"`
	Exceptions        []DestinationException `yaml:"exceptions"`
	MinimumConfidence float64                `yaml:"minimum_confidence"`
	FailureBehavior   FailureBehavior        `yaml:"failure_behavior"`
}

type EntityConfig struct {
	Name                string  `yaml:"name"`
	Description         string  `yaml:"description"`
	Enabled             bool    `yaml:"enabled"`
	ConfidenceThreshold float64 `yaml:"confidence_threshold"`
}

type PatternConfig struct {
	Name       string  `yaml:"name"`
	Category   string  `yaml:"category"`
	Regex      string  `yaml:"regex"`
	Confidence float64 `yaml:"confidence"`
	Enabled    bool    `yaml:"enabled"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:           "127.0.0.1:8080",
			ReadTimeout:      30 * time.Second,
			WriteTimeout:     60 * time.Second,
			IdleTimeout:      90 * time.Second,
			ShutdownTimeout:  15 * time.Second,
			MaxBodySizeBytes: 10 * 1024 * 1024, // 10MB
			MaxConcurrency:   500,
			InferenceTimeout: 5 * time.Second,
		},
		Inference: InferenceConfig{
			Address:          "127.0.0.1:50051",
			Timeout:          5 * time.Second,
			EnableML:         true,
			EnablePatterns:   true,
			MinConfidence:    0.50,
			MaxSpansPerField: 100,
		},
		Vault: VaultConfig{
			Enabled:   true,
			DBPath:    "vault.db",
			Retention: "30d",
		},
		Audit: AuditConfig{
			Enabled:   true,
			DBPath:    "audit.db",
			Retention: "90d",
		},
		Routes:   []RouteConfig{},
		Policies: []PolicyConfig{},
		Entities: []EntityConfig{},
		Patterns: []PatternConfig{},
	}
}

func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML config: %w", err)
	}

	// Environment variable overrides
	if envListen := os.Getenv("AEGF_SERVER_LISTEN"); envListen != "" {
		cfg.Server.Listen = envListen
	}
	if envInf := os.Getenv("AEGF_INFERENCE_ADDRESS"); envInf != "" {
		cfg.Inference.Address = envInf
	}
	if envVaultKey := os.Getenv("AEGF_VAULT_KEY"); envVaultKey != "" {
		cfg.Vault.MasterKey = envVaultKey
	}
	if envVaultDB := os.Getenv("AEGF_VAULT_DB"); envVaultDB != "" {
		cfg.Vault.DBPath = envVaultDB
	}
	if envAuditDB := os.Getenv("AEGF_AUDIT_DB"); envAuditDB != "" {
		cfg.Audit.DBPath = envAuditDB
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen cannot be empty")
	}

	if c.Inference.Address == "" {
		return fmt.Errorf("inference.address cannot be empty")
	}

	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route must be configured to prevent open-proxy")
	}

	routeIDs := make(map[string]bool)
	for i, r := range c.Routes {
		if r.ID == "" {
			return fmt.Errorf("route[%d]: id is required", i)
		}
		if routeIDs[r.ID] {
			return fmt.Errorf("route[%d]: duplicate route id '%s'", i, r.ID)
		}
		routeIDs[r.ID] = true

		if r.Match.PathPrefix == "" {
			return fmt.Errorf("route '%s': match.path_prefix is required", r.ID)
		}
		if !strings.HasPrefix(r.Match.PathPrefix, "/") {
			return fmt.Errorf("route '%s': match.path_prefix must begin with '/'", r.ID)
		}

		if r.Upstream == "" {
			return fmt.Errorf("route '%s': upstream is required", r.ID)
		}
		u, err := url.Parse(r.Upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("route '%s': upstream must be a valid http or https URL (got '%s')", r.ID, r.Upstream)
		}

		if r.Policy == "" {
			return fmt.Errorf("route '%s': policy is required", r.ID)
		}
	}

	policyMap := make(map[string]bool)
	for i, p := range c.Policies {
		if p.Name == "" {
			return fmt.Errorf("policy[%d]: name is required", i)
		}
		if policyMap[p.Name] {
			return fmt.Errorf("policy[%d]: duplicate policy name '%s'", i, p.Name)
		}
		policyMap[p.Name] = true

		defAction := strings.ToLower(p.DefaultAction)
		if defAction != "allow" && defAction != "redact" && defAction != "block" {
			return fmt.Errorf("policy '%s': default_action must be 'allow', 'redact', or 'block'", p.Name)
		}

		for cat, act := range p.OnDetection {
			a := strings.ToLower(act)
			if a != "allow" && a != "redact" && a != "block" {
				return fmt.Errorf("policy '%s': on_detection['%s'] action '%s' invalid", p.Name, cat, act)
			}
		}
	}

	// Verify all routes refer to existing policies
	for _, r := range c.Routes {
		if !policyMap[r.Policy] {
			return fmt.Errorf("route '%s' references unknown policy '%s'", r.ID, r.Policy)
		}
	}

	// Validate custom patterns
	for i, pat := range c.Patterns {
		if pat.Name == "" {
			return fmt.Errorf("pattern[%d]: name is required", i)
		}
		if pat.Category == "" {
			return fmt.Errorf("pattern '%s': category is required", pat.Name)
		}
		if pat.Regex == "" {
			return fmt.Errorf("pattern '%s': regex cannot be empty", pat.Name)
		}
		if _, err := regexp.Compile(pat.Regex); err != nil {
			return fmt.Errorf("pattern '%s': invalid regex '%s': %w", pat.Name, pat.Regex, err)
		}
	}

	return nil
}
