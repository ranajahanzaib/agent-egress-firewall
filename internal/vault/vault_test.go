package vault

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestVaultEncryptionAndRestoration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "vault.db")

	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	v, err := Open(dbPath, key, "")
	if err != nil {
		t.Fatalf("Open vault failed: %v", err)
	}
	defer v.Close()

	ctx := context.Background()

	token1, _ := GenerateToken("PERSON")
	token2, _ := GenerateToken("EMAIL")

	items := []StoreItem{
		{
			ID:          "rec-1",
			RequestID:   "req-100",
			Token:       token1,
			Category:    "PERSON",
			Plaintext:   "John Smith",
			FieldPath:   "/customer/name",
			Destination: "https://api.openai.com",
			PolicyID:    "strict-ai",
			TTL:         time.Hour,
		},
		{
			ID:          "rec-2",
			RequestID:   "req-100",
			Token:       token2,
			Category:    "EMAIL",
			Plaintext:   "john.smith@example.org",
			FieldPath:   "/customer/email",
			Destination: "https://api.openai.com",
			PolicyID:    "strict-ai",
			TTL:         time.Hour,
		},
	}

	if err := v.Store(ctx, items); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Verify GetByToken
	rec1, plain1, err := v.GetByToken(ctx, token1)
	if err != nil {
		t.Fatalf("GetByToken failed: %v", err)
	}
	if plain1 != "John Smith" {
		t.Errorf("expected John Smith, got %s", plain1)
	}
	if rec1.Category != "PERSON" {
		t.Errorf("expected PERSON, got %s", rec1.Category)
	}

	// Verify ListByRequestID
	records, err := v.ListByRequestID(ctx, "req-100")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	// Verify RestoreText
	redactedJSON := `{"name": "` + token1 + `", "contact": "` + token2 + `"}`
	restored, err := v.RestoreText(ctx, redactedJSON)
	if err != nil {
		t.Fatalf("RestoreText failed: %v", err)
	}

	expectedJSON := `{"name": "John Smith", "contact": "john.smith@example.org"}`
	if restored != expectedJSON {
		t.Errorf("expected restored '%s', got '%s'", expectedJSON, restored)
	}
}

func TestVaultTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "vault_tamper.db")

	key1, _ := GenerateMasterKey()
	key2, _ := GenerateMasterKey() // Different key

	v1, err := Open(dbPath, key1, "")
	if err != nil {
		t.Fatal(err)
	}

	token, _ := GenerateToken("SECRET")
	err = v1.Store(context.Background(), []StoreItem{
		{
			ID:        "rec-secret",
			RequestID: "req-1",
			Token:     token,
			Category:  "SECRET",
			Plaintext: "SuperSecretPassword123!",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	v1.Close()

	// Open with wrong key -> Decryption must fail!
	v2, err := Open(dbPath, key2, "")
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()

	_, _, err = v2.GetByToken(context.Background(), token)
	if err == nil {
		t.Fatalf("expected decryption error with wrong key, got nil")
	}
}
