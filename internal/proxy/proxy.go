package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync/atomic"
	"time"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/audit"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection/pb"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/observability"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/policy"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/routing"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/vault"
)

type ProxyHandler struct {
	cfg          *config.Config
	router       *routing.Router
	policyEngine *policy.Engine
	infClient    *inspection.Client
	vaultStore   *vault.Vault
	auditStore   *audit.Store
	metrics      *observability.Metrics
	reverseProxy *httputil.ReverseProxy
	activeConns  int64
}

func NewProxyHandler(
	cfg *config.Config,
	router *routing.Router,
	policyEngine *policy.Engine,
	infClient *inspection.Client,
	vaultStore *vault.Vault,
	auditStore *audit.Store,
	metrics *observability.Metrics,
) *ProxyHandler {
	// Standard connection-pooled transport
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	rp := &httputil.ReverseProxy{
		Director:      func(req *http.Request) {}, // Director logic handled dynamically per request
		Transport:     transport,
		FlushInterval: -1, // Flush immediately to support SSE & chunked streaming responses
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			slog.Error("Upstream proxy error", "error", err, "path", req.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "upstream_gateway_error",
				"message": err.Error(),
			})
		},
	}

	return &ProxyHandler{
		cfg:          cfg,
		router:       router,
		policyEngine: policyEngine,
		infClient:    infClient,
		vaultStore:   vaultStore,
		auditStore:   auditStore,
		metrics:      metrics,
		reverseProxy: rp,
	}
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t0 := time.Now()
	reqID := req.Header.Get("X-Request-ID")
	if reqID == "" {
		reqID = generateRequestID()
	}

	// Concurrency bounding
	current := atomic.AddInt64(&p.activeConns, 1)
	defer atomic.AddInt64(&p.activeConns, -1)
	if p.metrics != nil {
		p.metrics.ActiveRequests.Set(float64(current))
	}

	if p.cfg.Server.MaxConcurrency > 0 && int(current) > p.cfg.Server.MaxConcurrency {
		p.respondError(w, http.StatusServiceUnavailable, "service_concurrency_exceeded", "Maximum active proxy connections exceeded")
		return
	}

	// 1. Match route
	route, err := p.router.Match(req)
	if err != nil {
		slog.Warn("Route match failed (open-proxy blocked)", "path", req.URL.Path, "error", err)
		p.recordAudit(reqID, "unknown", req.URL.Path, "none", "block", nil, false, time.Since(t0), 0, err.Error())
		p.respondError(w, http.StatusNotFound, "route_not_found", err.Error())
		return
	}

	// 2. Extract inspectable content
	maxBody := p.cfg.Server.MaxBodySizeBytes
	if maxBody <= 0 {
		maxBody = 10 * 1024 * 1024
	}

	extracted, err := inspection.ExtractFromRequest(req, maxBody, route.Headers, route.QueryParams)
	if err != nil {
		failAct := p.policyEngine.EvaluateFailure(route.Policy, policy.FailureMalformedPayload)
		slog.Warn("Request extraction error", "route", route.ID, "error", err, "failure_action", failAct)
		if failAct == policy.ActionBlock {
			p.recordAudit(reqID, route.ID, route.Upstream.String(), route.Policy, "block", nil, false, time.Since(t0), 0, err.Error())
			p.respondError(w, http.StatusBadRequest, "malformed_request_payload", err.Error())
			return
		}
	}

	// 3. Scan with Rust inference engine over gRPC
	var detections []*pb.Detection
	var inferenceDuration time.Duration

	if len(extracted.Fields) > 0 {
		scanCtx, cancel := context.WithTimeout(req.Context(), p.cfg.Inference.Timeout)
		defer cancel()

		var pbEntities []*pb.EntityDefinition
		for _, e := range p.cfg.Entities {
			pbEntities = append(pbEntities, &pb.EntityDefinition{
				Name:                e.Name,
				Description:         e.Description,
				ConfidenceThreshold: e.ConfidenceThreshold,
				Enabled:             e.Enabled,
			})
		}

		var pbPatterns []*pb.PatternDefinition
		for _, pat := range p.cfg.Patterns {
			pbPatterns = append(pbPatterns, &pb.PatternDefinition{
				Name:       pat.Name,
				Category:   pat.Category,
				Regex:      pat.Regex,
				Confidence: pat.Confidence,
				Enabled:    pat.Enabled,
			})
		}

		scanReq := &pb.ScanRequest{
			RequestId: reqID,
			Fields:    extracted.Fields,
			Entities:  pbEntities,
			Patterns:  pbPatterns,
			Options: &pb.ScanOptions{
				EnableMl:             p.cfg.Inference.EnableML,
				EnablePatterns:       p.cfg.Inference.EnablePatterns,
				DefaultMinConfidence: p.cfg.Inference.MinConfidence,
				MaxSpansPerField:     uint32(p.cfg.Inference.MaxSpansPerField),
			},
		}

		tInf0 := time.Now()
		scanResp, err := p.infClient.Scan(scanCtx, scanReq)
		inferenceDuration = time.Since(tInf0)
		if p.metrics != nil {
			p.metrics.InferenceDurationSeconds.Observe(inferenceDuration.Seconds())
		}

		if err != nil {
			var failType policy.FailureType = policy.FailureInferenceUnavailable
			if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
				failType = policy.FailureInferenceTimeout
			}
			failAct := p.policyEngine.EvaluateFailure(route.Policy, failType)
			slog.Error("Inference service call failed", "route", route.ID, "error", err, "failure_action", failAct)

			if failAct == policy.ActionBlock {
				p.recordAudit(reqID, route.ID, route.Upstream.String(), route.Policy, "block", nil, false, time.Since(t0), inferenceDuration, err.Error())
				p.respondError(w, http.StatusBadGateway, "security_inference_unavailable", "Outbound request blocked due to inference engine unavailability")
				return
			}
		} else if scanResp != nil {
			detections = scanResp.Detections
		}
	}

	// Record detections metrics
	if p.metrics != nil {
		for _, d := range detections {
			p.metrics.DetectionsTotal.WithLabelValues(d.Category, d.Source).Inc()
		}
	}

	// 4. Evaluate Security Policy
	upstreamHost := route.Upstream.Host
	decision, err := p.policyEngine.Evaluate(route.Policy, upstreamHost, detections)
	if err != nil {
		slog.Error("Policy evaluation failed", "route", route.ID, "error", err)
		p.respondError(w, http.StatusInternalServerError, "policy_evaluation_error", err.Error())
		return
	}

	// 5. Enforce Decision
	switch decision.FinalAction {
	case policy.ActionBlock:
		slog.Warn("Request blocked by security policy",
			"request_id", reqID,
			"route", route.ID,
			"policy", route.Policy,
			"blocked_count", len(decision.BlockList),
			"reason", decision.Reason,
		)
		p.recordAudit(reqID, route.ID, route.Upstream.String(), route.Policy, "block", decision.Detections, false, time.Since(t0), inferenceDuration, decision.Reason)
		if p.metrics != nil {
			p.metrics.RequestsTotal.WithLabelValues(route.ID, "block").Inc()
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":      "egress_blocked_by_policy",
			"request_id": reqID,
			"policy":     route.Policy,
			"reason":     decision.Reason,
		})
		return

	case policy.ActionRedact:
		// Generate tokens and persist sensitive items to encrypted vault
		var vaultItems []vault.StoreItem
		var redactions []inspection.FieldRedaction

		for _, det := range decision.RedactList {
			token, err := vault.GenerateToken(det.Category)
			if err != nil {
				slog.Error("Failed to generate redaction token", "error", err)
				p.respondError(w, http.StatusInternalServerError, "redaction_error", "Failed generating security token")
				return
			}

			vaultItems = append(vaultItems, vault.StoreItem{
				ID:          generateRequestID(),
				RequestID:   reqID,
				Token:       token,
				Category:    det.Category,
				Plaintext:   det.Text,
				FieldPath:   det.FieldId,
				Destination: route.Upstream.String(),
				PolicyID:    route.Policy,
			})

			redactions = append(redactions, inspection.FieldRedaction{
				FieldID:     det.FieldId,
				Start:       int(det.Start),
				End:         int(det.End),
				Replacement: token,
			})
		}

		// Store in encrypted vault
		if p.vaultStore != nil && len(vaultItems) > 0 {
			if err := p.vaultStore.Store(req.Context(), vaultItems); err != nil {
				slog.Error("Failed to store redactions in vault; failing closed", "error", err)
				p.recordAudit(reqID, route.ID, route.Upstream.String(), route.Policy, "block", decision.Detections, false, time.Since(t0), inferenceDuration, "vault write failure")
				p.respondError(w, http.StatusInternalServerError, "vault_storage_failed", "Failed to securely persist redaction entries")
				return
			}
		}

		// Mutate payload
		mutatedBody, err := inspection.MutatePayload(extracted, redactions)
		if err != nil {
			slog.Error("Failed to mutate payload; failing closed", "error", err)
			p.recordAudit(reqID, route.ID, route.Upstream.String(), route.Policy, "block", decision.Detections, false, time.Since(t0), inferenceDuration, "payload mutation failure")
			p.respondError(w, http.StatusInternalServerError, "payload_redaction_failed", "Failed to apply entity redactions")
			return
		}

		// Update request body with mutated content
		req.Body = io.NopCloser(bytes.NewReader(mutatedBody))
		req.ContentLength = int64(len(mutatedBody))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(mutatedBody)))

		p.recordAudit(reqID, route.ID, route.Upstream.String(), route.Policy, "redact", decision.Detections, true, time.Since(t0), inferenceDuration, "")
		if p.metrics != nil {
			p.metrics.RequestsTotal.WithLabelValues(route.ID, "redact").Inc()
		}

	case policy.ActionAllow:
		// Reset body reader for forwarding original content
		if extracted.OriginalBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(extracted.OriginalBytes))
			req.ContentLength = int64(len(extracted.OriginalBytes))
		}
		p.recordAudit(reqID, route.ID, route.Upstream.String(), route.Policy, "allow", decision.Detections, true, time.Since(t0), inferenceDuration, "")
		if p.metrics != nil {
			p.metrics.RequestsTotal.WithLabelValues(route.ID, "allow").Inc()
		}
	}

	// 6. Forward Request to Upstream
	route.RewriteRequest(req)
	req.Header.Set("X-Forwarded-By", "agent-egress-firewall")
	req.Header.Set("X-Request-ID", reqID)

	p.reverseProxy.ServeHTTP(w, req)
	if p.metrics != nil {
		p.metrics.ProxyDurationSeconds.Observe(time.Since(t0).Seconds())
	}
}

func (p *ProxyHandler) recordAudit(
	reqID, route, destination, policyName, decision string,
	detections []*policy.EvaluatedDetection,
	forwarded bool,
	duration time.Duration,
	inferenceDuration time.Duration,
	failureReason string,
) {
	if p.auditStore == nil {
		return
	}

	var auditDets []audit.Detection
	for _, ed := range detections {
		auditDets = append(auditDets, audit.Detection{
			Category:   ed.Detection.Category,
			Source:     ed.Detection.Source,
			Confidence: ed.Detection.Confidence,
			Field:      ed.Detection.FieldId,
			Action:     string(ed.Action),
			DetectorID: ed.Detection.DetectorId,
		})
	}

	ev := &audit.AuditEvent{
		ID:                  generateRequestID(),
		RequestID:           reqID,
		Timestamp:           time.Now(),
		Route:               route,
		Destination:         destination,
		Policy:              policyName,
		Decision:            decision,
		Detections:          auditDets,
		Forwarded:           forwarded,
		DurationMs:          duration.Milliseconds(),
		InferenceDurationMs: inferenceDuration.Milliseconds(),
		FailureReason:       failureReason,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.auditStore.Record(ctx, ev); err != nil {
		slog.Error("Failed to write audit record", "error", err)
	}
}

func (p *ProxyHandler) respondError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   code,
		"message": message,
	})
}

func generateRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}
