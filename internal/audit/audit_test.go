package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditStore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	event1 := &AuditEvent{
		ID:          "evt-1",
		RequestID:   "req-001",
		Timestamp:   time.Now(),
		Route:       "openai",
		Destination: "https://api.openai.com",
		Policy:      "strict-ai",
		Decision:    "redact",
		Detections: []Detection{
			{
				Category:   "EMAIL",
				Source:     "gliner",
				Confidence: 0.97,
				Field:      "/customer/email",
				Action:     "redact",
				DetectorID: "gliner-small",
			},
		},
		Forwarded:           true,
		DurationMs:          45,
		InferenceDurationMs: 30,
	}

	event2 := &AuditEvent{
		ID:          "evt-2",
		RequestID:   "req-002",
		Timestamp:   time.Now(),
		Route:       "anthropic",
		Destination: "https://api.anthropic.com",
		Policy:      "strict-ai",
		Decision:    "block",
		Detections: []Detection{
			{
				Category:   "API_KEY",
				Source:     "pattern",
				Confidence: 1.0,
				Field:      "/api_key",
				Action:     "block",
				DetectorID: "openai_key",
			},
		},
		Forwarded:           false,
		DurationMs:          10,
		InferenceDurationMs: 5,
		FailureReason:       "blocked by policy due to API_KEY",
	}

	if err := store.Record(ctx, event1); err != nil {
		t.Fatalf("Record event1 failed: %v", err)
	}
	if err := store.Record(ctx, event2); err != nil {
		t.Fatalf("Record event2 failed: %v", err)
	}

	// Query by request ID
	retrieved, err := store.GetByRequestID(ctx, "req-001")
	if err != nil {
		t.Fatalf("GetByRequestID failed: %v", err)
	}
	if retrieved.Decision != "redact" || !retrieved.Forwarded {
		t.Errorf("unexpected retrieved event: %+v", retrieved)
	}
	if len(retrieved.Detections) != 1 || retrieved.Detections[0].Category != "EMAIL" {
		t.Errorf("unexpected detections: %+v", retrieved.Detections)
	}

	// Filter query by decision
	blockedEvents, err := store.Query(ctx, Filter{Decision: "block"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(blockedEvents) != 1 || blockedEvents[0].RequestID != "req-002" {
		t.Errorf("expected 1 blocked event, got %d", len(blockedEvents))
	}

	// Filter query by category
	emailEvents, err := store.Query(ctx, Filter{Category: "EMAIL"})
	if err != nil {
		t.Fatal(err)
	}
	if len(emailEvents) != 1 || emailEvents[0].RequestID != "req-001" {
		t.Errorf("expected 1 email event, got %d", len(emailEvents))
	}
}
