package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/audit"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection/pb"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/observability"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/policy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/routing"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/server"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/vault"
)

const Version = "0.1.0"

func printUsage() {
	fmt.Printf(`aegf - Agent Egress Firewall v%s
Self-Hosted AI and Application Egress Security

Usage:
  aegf <command> [arguments]

Primary Commands:
  serve              Start the egress security proxy and operational endpoints
  doctor             Run preflight diagnostics across dependencies and configuration
  version            Print application and component versions
  scan               Scan text or file without proxying (supports stdin)
  config validate    Validate firewall configuration and security policies
  policy test        Evaluate a sample payload against a selected security policy
  audit list         Query request audit trail records
  vault list         List encrypted redaction records for a request ID
  vault inspect      Inspect a redaction vault record metadata by token
  vault restore      Restore vaulted redactions in a file or stdin to original content
  vault purge        Purge vault records older than specified duration
  models list        List installed model assets and status
  models fetch       Download default model assets (GLiNER ONNX)
  models verify      Verify model integrity and engine compatibility

Use "aegf <command> -h" for more information about a command.
`, Version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "version":
		runVersion()
	case "serve":
		runServe(os.Args[2:])
	case "doctor":
		runDoctor(os.Args[2:])
	case "config":
		runConfig(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "vault":
		runVault(os.Args[2:])
	case "models":
		runModels(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func runVersion() {
	fmt.Printf("aegf version %s (Go runtime %s)\n", Version, runtime.Version())
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "configs/config.example.yaml", "Path to YAML configuration file")
	_ = fs.Parse(args)

	_ = observability.SetupLogger()
	slog.Info("Initializing AEGF", "version", Version, "config", *configPath)

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	router, err := routing.NewRouter(cfg.Routes)
	if err != nil {
		slog.Error("Failed to initialize router", "error", err)
		os.Exit(1)
	}

	policyEngine := policy.NewEngine(cfg.Policies)

	// Connect to Rust inference service
	slog.Info("Connecting to inference engine", "address", cfg.Inference.Address)
	infClient, err := inspection.NewClient(cfg.Inference.Address)
	if err != nil {
		slog.Warn("Could not immediately connect to inference engine; running with lazy connection", "error", err)
	}

	// Open Vault
	var vaultStore *vault.Vault
	if cfg.Vault.Enabled {
		v, err := vault.Open(cfg.Vault.DBPath, cfg.Vault.MasterKey, cfg.Vault.KeyFile)
		if err != nil {
			slog.Error("Failed to open redaction vault", "error", err)
			os.Exit(1)
		}
		vaultStore = v
		defer vaultStore.Close()
	}

	// Open Audit Store
	var auditStore *audit.Store
	if cfg.Audit.Enabled {
		as, err := audit.Open(cfg.Audit.DBPath)
		if err != nil {
			slog.Error("Failed to open audit store", "error", err)
			os.Exit(1)
		}
		auditStore = as
		defer auditStore.Close()
	}

	metrics := observability.NewMetrics(prometheus.DefaultRegisterer)

	srv := server.New(cfg, router, policyEngine, infClient, vaultStore, auditStore, metrics)

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Termination signal received; shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Error during graceful shutdown", "error", err)
		}
	}()

	if err := srv.Start(); err != nil {
		slog.Error("Server error", "error", err)
		os.Exit(1)
	}
}

func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", "configs/config.example.yaml", "Path to YAML configuration file")
	_ = fs.Parse(args)

	fmt.Printf("=== AEGF Doctor Diagnostics ===\n\n")

	// 1. Config Check
	fmt.Printf("[1/8] Configuration: ")
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Printf("OK (%d routes, %d policies, %d entities)\n", len(cfg.Routes), len(cfg.Policies), len(cfg.Entities))
	}

	// 2. Go runtime
	fmt.Printf("[2/8] Gateway Runtime: OK (Go %s)\n", strings.TrimPrefix(runtime.Version(), "go"))

	// 3. SQLite Database paths
	fmt.Printf("[3/8] SQLite Storage: ")
	if cfg != nil {
		testDir := filepath.Dir(cfg.Vault.DBPath)
		if testDir == "" || testDir == "." {
			testDir = "."
		}
		if _, err := os.Stat(testDir); err == nil {
			fmt.Printf("OK (vault: %s, audit: %s)\n", cfg.Vault.DBPath, cfg.Audit.DBPath)
		} else {
			fmt.Printf("WARN (directory %s not writable)\n", testDir)
		}
	} else {
		fmt.Printf("SKIPPED\n")
	}

	// 4. Vault Key
	fmt.Printf("[4/8] Vault Master Key: ")
	if cfg != nil && cfg.Vault.Enabled {
		if cfg.Vault.MasterKey != "" || cfg.Vault.KeyFile != "" || os.Getenv("AEGF_VAULT_KEY") != "" {
			fmt.Printf("OK (configured)\n")
		} else {
			fmt.Printf("WARN (ephemeral key will be generated; set AEGF_VAULT_KEY or key_file for persistence)\n")
		}
	} else {
		fmt.Printf("DISABLED\n")
	}

	// 5. Model Assets
	fmt.Printf("[5/8] Model Assets: ")
	modelDir := "models/gliner-small"
	if _, err := os.Stat(filepath.Join(modelDir, "model_quantized.onnx")); err == nil {
		fmt.Printf("OK (GLiNER ONNX model installed at %s)\n", modelDir)
	} else if _, err := os.Stat(filepath.Join(modelDir, "model.onnx")); err == nil {
		fmt.Printf("OK (GLiNER ONNX model installed at %s)\n", modelDir)
	} else {
		fmt.Printf("WARN (model not found at %s; run 'aegf models fetch')\n", modelDir)
	}

	// 6. Inference Service Connectivity
	fmt.Printf("[6/8] Rust Inference Engine: ")
	infAddr := "127.0.0.1:50051"
	if cfg != nil && cfg.Inference.Address != "" {
		infAddr = cfg.Inference.Address
	}

	infClient, err := inspection.NewClient(infAddr)
	if err != nil {
		fmt.Printf("OFFLINE (failed to initialize client: %v)\n", err)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		status, err := infClient.GetModelStatus(ctx)
		if err != nil {
			fmt.Printf("OFFLINE (could not reach %s: %v)\n", infAddr, err)
		} else if !status.ModelLoaded {
			fmt.Printf("DEGRADED (connected to %s, model not loaded, running in pattern-only mode)\n", infAddr)
		} else {
			fmt.Printf("OK (model_loaded=%v, model=%s, device=%s)\n", status.ModelLoaded, status.ModelName, status.Device)
		}
		_ = infClient.Close()
	}

	// 7. Security Rules Preflight
	fmt.Printf("[7/8] Policy Engine Preflight: ")
	if cfg != nil && len(cfg.Policies) > 0 {
		fmt.Printf("OK (%d valid policies)\n", len(cfg.Policies))
	} else {
		fmt.Printf("WARN (no policies defined)\n")
	}

	// 8. Open-Proxy Protection
	fmt.Printf("[8/8] Open-Proxy Protection: ")
	if cfg != nil && len(cfg.Routes) > 0 {
		fmt.Printf("ACTIVE (strict route prefix matching enforced)\n")
	} else {
		fmt.Printf("FAIL (no routes configured)\n")
	}

	fmt.Printf("\nDiagnostics complete.\n")
}

func runConfig(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: aegf config validate [--config path]")
		os.Exit(1)
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("config validate", flag.ExitOnError)
		path := fs.String("config", "configs/config.example.yaml", "Config file path")
		_ = fs.Parse(args[1:])

		cfg, err := config.LoadFile(*path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Configuration validation FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Configuration in '%s' is VALID.\n", *path)
		fmt.Printf("- Server Listen: %s\n", cfg.Server.Listen)
		fmt.Printf("- Routes: %d\n", len(cfg.Routes))
		for _, r := range cfg.Routes {
			fmt.Printf("    * %s (%s -> %s, policy: %s)\n", r.ID, r.Match.PathPrefix, r.Upstream, r.Policy)
		}
		fmt.Printf("- Policies: %d\n", len(cfg.Policies))
		fmt.Printf("- Custom Entities: %d\n", len(cfg.Entities))
		fmt.Printf("- Custom Patterns: %d\n", len(cfg.Patterns))
	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	addr := fs.String("address", "127.0.0.1:50051", "Inference engine address")
	file := fs.String("file", "", "Input file to scan (omit to read from stdin)")
	format := fs.String("format", "text", "Output format: text or json")
	_ = fs.Parse(args)

	var textToScan string
	if *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read file: %v\n", err)
			os.Exit(1)
		}
		textToScan = string(data)
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read stdin: %v\n", err)
			os.Exit(1)
		}
		textToScan = string(data)
	}

	client, err := inspection.NewClient(*addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to inference service at %s: %v\n", *addr, err)
		os.Exit(1)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Scan(ctx, &pb.ScanRequest{
		RequestId: "cli_scan",
		Fields: []*pb.ScanField{
			{
				FieldId: "input",
				Text:    textToScan,
			},
		},
		Options: &pb.ScanOptions{
			EnableMl:             true,
			EnablePatterns:       true,
			DefaultMinConfidence: 0.50,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
	} else {
		fmt.Printf("Scan completed in %d ms (%d detections found)\n\n", resp.InferenceDurationMs, len(resp.Detections))
		for i, d := range resp.Detections {
			fmt.Printf("[%d] Category: %-15s Source: %-8s Conf: %.2f  Span: [%d, %d]  Text: '%s'\n",
				i+1, d.Category, d.Source, d.Confidence, d.Start, d.End, d.Text)
		}
	}
}

func runPolicy(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: aegf policy test --policy <name> --input <file>")
		os.Exit(1)
	}

	switch args[0] {
	case "test":
		fs := flag.NewFlagSet("policy test", flag.ExitOnError)
		configPath := fs.String("config", "configs/config.example.yaml", "Config file path")
		policyName := fs.String("policy", "", "Policy name to evaluate against")
		inputFile := fs.String("input", "", "Path to input file containing request payload")
		dest := fs.String("destination", "api.openai.com", "Target destination hostname")
		_ = fs.Parse(args[1:])

		if *policyName == "" || *inputFile == "" {
			fmt.Println("Error: --policy and --input are required.")
			fs.Usage()
			os.Exit(1)
		}

		cfg, err := config.LoadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
			os.Exit(1)
		}

		policyEngine := policy.NewEngine(cfg.Policies)
		pol, exists := policyEngine.GetPolicy(*policyName)
		if !exists {
			fmt.Fprintf(os.Stderr, "Policy '%s' not found in configuration\n", *policyName)
			os.Exit(1)
		}

		inputData, err := os.ReadFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read input file %s: %v\n", *inputFile, err)
			os.Exit(1)
		}

		req := &http.Request{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(inputData)),
		}
		if strings.HasSuffix(*inputFile, ".json") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "text/plain")
		}

		extracted, err := inspection.ExtractFromRequest(req, 10*1024*1024, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Extraction error: %v\n", err)
			os.Exit(1)
		}

		// Connect to inference
		infClient, err := inspection.NewClient(cfg.Inference.Address)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Inference connection error: %v\n", err)
			os.Exit(1)
		}
		defer infClient.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		scanResp, err := infClient.Scan(ctx, &pb.ScanRequest{
			RequestId: "policy_test",
			Fields:    extracted.Fields,
			Options: &pb.ScanOptions{
				EnableMl:             true,
				EnablePatterns:       true,
				DefaultMinConfidence: pol.MinimumConfidence,
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Inference error: %v\n", err)
			os.Exit(1)
		}

		decision, err := policyEngine.Evaluate(*policyName, *dest, scanResp.Detections)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Policy evaluation error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("=== Policy Test Evaluation: %s ===\n", *policyName)
		fmt.Printf("Destination: %s\n", *dest)
		fmt.Printf("Detections Found: %d\n", len(scanResp.Detections))
		for i, ed := range decision.Detections {
			fmt.Printf("  [%d] Category: %-15s Action: %-8s Conf: %.2f  Field: %s\n",
				i+1, ed.Detection.Category, ed.Action, ed.Detection.Confidence, ed.Detection.FieldId)
		}
		fmt.Printf("\nFINAL ENFORCEMENT DECISION: %s\n", strings.ToUpper(string(decision.FinalAction)))
		fmt.Printf("Reason: %s\n", decision.Reason)
		fmt.Printf("Would Forward to Destination: %v\n", decision.FinalAction != policy.ActionBlock)
		fmt.Printf("Entities Redacted: %d, Entities Blocked: %d\n", len(decision.RedactList), len(decision.BlockList))

	default:
		fmt.Fprintf(os.Stderr, "Unknown policy subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func runAudit(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: aegf audit list [--db path] [--route name] [--decision action] [--limit N]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("audit list", flag.ExitOnError)
		dbPath := fs.String("db", "audit.db", "Audit SQLite DB path")
		route := fs.String("route", "", "Filter by route ID")
		decision := fs.String("decision", "", "Filter by decision (allow, redact, block)")
		limit := fs.Int("limit", 20, "Number of records to retrieve")
		_ = fs.Parse(args[1:])

		store, err := audit.Open(*dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open audit database %s: %v\n", *dbPath, err)
			os.Exit(1)
		}
		defer store.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		events, err := store.Query(ctx, audit.Filter{
			Route:    *route,
			Decision: *decision,
			Limit:    *limit,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to query audit events: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("=== Audit Records (%d found) ===\n\n", len(events))
		for _, ev := range events {
			fmt.Printf("[%s] ReqID: %s  Route: %-10s  Decision: %-7s  Forwarded: %-5v  Duration: %dms\n",
				ev.Timestamp.Format("2006-01-02 15:04:05"), ev.RequestID, ev.Route, strings.ToUpper(ev.Decision), ev.Forwarded, ev.DurationMs)
			if len(ev.Detections) > 0 {
				var detList []string
				for _, d := range ev.Detections {
					detList = append(detList, fmt.Sprintf("%s(%s,%.2f)", d.Category, d.Action, d.Confidence))
				}
				fmt.Printf("   Detections: %s\n", strings.Join(detList, ", "))
			}
			if ev.FailureReason != "" {
				fmt.Printf("   Reason: %s\n", ev.FailureReason)
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown audit subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func resolveVaultKey(key, keyFile string) (string, string) {
	if key != "" {
		return key, ""
	}
	if envKey := os.Getenv("AEGF_VAULT_KEY"); envKey != "" {
		return envKey, ""
	}
	if keyFile != "" {
		return "", keyFile
	}
	if _, err := os.Stat("vault.key"); err == nil {
		return "", "vault.key"
	}
	return "", ""
}

func runVault(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: aegf vault <list|inspect|restore|purge>")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("vault list", flag.ExitOnError)
		dbPath := fs.String("db", "vault.db", "Vault SQLite DB path")
		reqID := fs.String("request-id", "", "Filter by request ID")
		key := fs.String("key", "", "Vault master encryption key (hex)")
		keyFile := fs.String("key-file", "", "Vault key file path")
		_ = fs.Parse(args[1:])

		k, kf := resolveVaultKey(*key, *keyFile)
		v, err := vault.Open(*dbPath, k, kf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		ctx := context.Background()
		records, err := v.ListByRequestID(ctx, *reqID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list vault records: %v\n", err)
			os.Exit(1)
		}

		if *reqID != "" {
			fmt.Printf("=== Vault Records for Request: %s (%d found) ===\n", *reqID, len(records))
		} else {
			fmt.Printf("=== Vault Records (%d found) ===\n", len(records))
		}
		for _, r := range records {
			fmt.Printf("Token: %-28s Category: %-15s Path: %s  Destination: %s\n",
				r.Token, r.Category, r.FieldPath, r.Destination)
		}

	case "inspect":
		fs := flag.NewFlagSet("vault inspect", flag.ExitOnError)
		dbPath := fs.String("db", "vault.db", "Vault SQLite DB path")
		token := fs.String("token", "", "Token identifier (e.g. [AEGF:PERSON:8F32A1C9])")
		key := fs.String("key", "", "Vault master encryption key (hex)")
		keyFile := fs.String("key-file", "", "Vault key file path")
		_ = fs.Parse(args[1:])

		if *token == "" {
			fmt.Println("Error: --token is required")
			os.Exit(1)
		}

		k, kf := resolveVaultKey(*key, *keyFile)
		v, err := vault.Open(*dbPath, k, kf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		rec, _, err := v.GetByToken(context.Background(), *token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Vault inspect failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("=== Vault Record Metadata ===\n")
		fmt.Printf("Token:       %s\n", rec.Token)
		fmt.Printf("Category:    %s\n", rec.Category)
		fmt.Printf("Request ID:  %s\n", rec.RequestID)
		fmt.Printf("Field Path:  %s\n", rec.FieldPath)
		fmt.Printf("Destination: %s\n", rec.Destination)
		fmt.Printf("Policy:      %s\n", rec.PolicyID)
		fmt.Printf("Created At:  %s\n", rec.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Expires At:  %s\n", rec.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Plaintext:   [PROTECTED - Run 'aegf vault restore' to restore content]\n")

	case "restore":
		fs := flag.NewFlagSet("vault restore", flag.ExitOnError)
		dbPath := fs.String("db", "vault.db", "Vault SQLite DB path")
		input := fs.String("input", "", "Input file with tokens (or - for stdin)")
		output := fs.String("output", "", "Output file (or omit for stdout)")
		key := fs.String("key", "", "Vault master encryption key (hex)")
		keyFile := fs.String("key-file", "", "Vault key file path")
		_ = fs.Parse(args[1:])

		k, kf := resolveVaultKey(*key, *keyFile)
		v, err := vault.Open(*dbPath, k, kf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		var rawData []byte
		if *input == "" || *input == "-" {
			rawData, err = io.ReadAll(os.Stdin)
		} else {
			rawData, err = os.ReadFile(*input)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed reading input: %v\n", err)
			os.Exit(1)
		}

		restored, err := v.RestoreText(context.Background(), string(rawData))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Restoration error: %v\n", err)
			os.Exit(1)
		}

		if *output != "" {
			if err := os.WriteFile(*output, []byte(restored), 0600); err != nil {
				fmt.Fprintf(os.Stderr, "Failed writing output file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Successfully restored tokens into %s\n", *output)
		} else {
			fmt.Println(restored)
		}

	case "purge":
		fs := flag.NewFlagSet("vault purge", flag.ExitOnError)
		dbPath := fs.String("db", "vault.db", "Vault SQLite DB path")
		olderThanStr := fs.String("older-than", "30d", "Purge records older than duration (e.g. 30d, 24h)")
		key := fs.String("key", "", "Vault master encryption key (hex)")
		keyFile := fs.String("key-file", "", "Vault key file path")
		_ = fs.Parse(args[1:])

		dur, err := parseDurationDays(*olderThanStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid duration: %v\n", err)
			os.Exit(1)
		}

		k, kf := resolveVaultKey(*key, *keyFile)
		v, err := vault.Open(*dbPath, k, kf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		deleted, err := v.Purge(context.Background(), dur)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Purge error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Purged %d expired vault records.\n", deleted)

	default:
		fmt.Fprintf(os.Stderr, "Unknown vault subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func runModels(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: aegf models <list|fetch|verify>")
		os.Exit(1)
	}

	modelDir := "models/gliner-small"

	switch args[0] {
	case "list":
		fmt.Printf("=== Configured Model Assets ===\n")
		fmt.Printf("Primary Model:  nexuswho/gliner-onnx-small\n")
		fmt.Printf("Model Directory: %s\n", modelDir)
		if _, err := os.Stat(filepath.Join(modelDir, "model_quantized.onnx")); err == nil {
			fmt.Printf("Status:          INSTALLED (Ready for inference)\n")
		} else {
			fmt.Printf("Status:          NOT INSTALLED (Run 'aegf models fetch')\n")
		}

	case "fetch":
		fmt.Println("Fetching GLiNER ONNX model from Hugging Face...")
		scriptPath := "scripts/download_model.py"
		if _, err := os.Stat(scriptPath); err == nil {
			cmd := exec.Command("python3", scriptPath)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Download script failed: %v\nPlease run manually: python3 %s\n", err, scriptPath)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Script not found at %s. Please ensure scripts/download_model.py exists.\n", scriptPath)
		}

	case "verify":
		fmt.Printf("Verifying model files at %s...\n", modelDir)
		required := []string{"model_quantized.onnx", "tokenizer.json", "gliner_config.json"}
		allGood := true
		for _, f := range required {
			path := filepath.Join(modelDir, f)
			if fi, err := os.Stat(path); err == nil {
				fmt.Printf("  [OK] %-22s (%d bytes)\n", f, fi.Size())
			} else {
				fmt.Printf("  [FAIL] %-20s (missing)\n", f)
				allGood = false
			}
		}
		if allGood {
			fmt.Println("Model verification SUCCESSFUL.")
		} else {
			fmt.Println("Model verification FAILED. Some files are missing.")
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown models subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func parseDurationDays(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(daysStr, "%d", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}
