package inspection

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractAndMutateJSON(t *testing.T) {
	inputJSON := `{
		"customer": "John Smith",
		"email": "john@example.com",
		"account_balance": 123456789.987654321,
		"tags": ["vip", "secret_project_omega"],
		"nested": {
			"notes": "Contact user at john@example.com immediately."
		}
	}`

	req := httptest.NewRequest("POST", "/test", strings.NewReader(inputJSON))
	req.Header.Set("Content-Type", "application/json")

	payload, err := ExtractFromRequest(req, 1024*1024, nil, nil)
	if err != nil {
		t.Fatalf("ExtractFromRequest failed: %v", err)
	}

	if payload.Type != ContentTypeJSON {
		t.Fatalf("expected ContentTypeJSON, got %v", payload.Type)
	}

	// Verify fields
	fieldMap := make(map[string]string)
	for _, f := range payload.Fields {
		fieldMap[f.FieldId] = f.Text
	}

	if fieldMap["/customer"] != "John Smith" {
		t.Errorf("expected John Smith, got %s", fieldMap["/customer"])
	}
	if fieldMap["/email"] != "john@example.com" {
		t.Errorf("expected john@example.com, got %s", fieldMap["/email"])
	}
	if fieldMap["/tags/1"] != "secret_project_omega" {
		t.Errorf("expected secret_project_omega, got %s", fieldMap["/tags/1"])
	}

	// Apply redaction
	redactions := []FieldRedaction{
		{
			FieldID:     "/customer",
			Start:       0,
			End:         10,
			Replacement: "[AEGF:PERSON:1111]",
		},
		{
			FieldID:     "/email",
			Start:       0,
			End:         16,
			Replacement: "[AEGF:EMAIL:2222]",
		},
		{
			FieldID:     "/nested/notes",
			Start:       16,
			End:         32, // "john@example.com"
			Replacement: "[AEGF:EMAIL:3333]",
		},
	}

	mutatedBytes, err := MutatePayload(payload, redactions)
	if err != nil {
		t.Fatalf("MutatePayload failed: %v", err)
	}

	var parsed map[string]any
	dec := json.NewDecoder(bytes.NewReader(mutatedBytes))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		t.Fatalf("failed to decode mutated JSON: %v", err)
	}

	if parsed["customer"] != "[AEGF:PERSON:1111]" {
		t.Errorf("customer not redacted: %v", parsed["customer"])
	}
	if parsed["email"] != "[AEGF:EMAIL:2222]" {
		t.Errorf("email not redacted: %v", parsed["email"])
	}

	// Verify number format was not corrupted or precision lost
	numStr := parsed["account_balance"].(json.Number).String()
	if numStr != "123456789.987654321" {
		t.Errorf("number precision corrupted: got %s", numStr)
	}

	nested := parsed["nested"].(map[string]any)
	expectedNotes := "Contact user at [AEGF:EMAIL:3333] immediately."
	if nested["notes"] != expectedNotes {
		t.Errorf("expected notes '%s', got '%s'", expectedNotes, nested["notes"])
	}
}

func TestUnicodeTextRedaction(t *testing.T) {
	// Text with emoji and Arabic
	rawText := "Hello 👋 John Smith! 🌍 مرحبا John Smith"
	req := httptest.NewRequest("POST", "/text", strings.NewReader(rawText))
	req.Header.Set("Content-Type", "text/plain")

	payload, err := ExtractFromRequest(req, 1024*1024, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Redact second John Smith:
	// "Hello 👋 " is 8 chars: H(0) e(1) l(2) l(3) o(4)  (5) 👋(6)  (7)
	// John Smith is 8..18
	// "! 🌍 مرحبا " is 10 chars -> 18..28
	// second John Smith is 28..38
	runes := []rune(rawText)
	secondStart := strings.LastIndex(rawText, "John Smith")
	charStart := len([]rune(rawText[:secondStart]))
	charEnd := charStart + len([]rune("John Smith"))

	redactions := []FieldRedaction{
		{
			FieldID:     "body",
			Start:       charStart,
			End:         charEnd,
			Replacement: "[REDACTED]",
		},
	}

	mutated, err := MutatePayload(payload, redactions)
	if err != nil {
		t.Fatal(err)
	}

	expected := "Hello 👋 John Smith! 🌍 مرحبا [REDACTED]"
	if string(mutated) != expected {
		t.Errorf("expected '%s', got '%s'", expected, string(mutated))
	}
	_ = runes
}

func TestGzipCompression(t *testing.T) {
	orig := `{"secret": "sensitive-data"}`
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(orig))
	zw.Close()

	req := httptest.NewRequest("POST", "/data", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	payload, err := ExtractFromRequest(req, 1024*1024, nil, nil)
	if err != nil {
		t.Fatalf("extract gzip failed: %v", err)
	}
	if !payload.IsGzipped {
		t.Fatalf("expected payload to be marked as gzipped")
	}

	redactions := []FieldRedaction{
		{
			FieldID:     "/secret",
			Start:       0,
			End:         14,
			Replacement: "[TOKEN]",
		},
	}

	mutatedGzip, err := MutatePayload(payload, redactions)
	if err != nil {
		t.Fatalf("mutate gzip failed: %v", err)
	}

	zr, err := gzip.NewReader(bytes.NewReader(mutatedGzip))
	if err != nil {
		t.Fatalf("reading mutated gzip: %v", err)
	}
	decomp, _ := io.ReadAll(zr)
	zr.Close()

	if !strings.Contains(string(decomp), `"[TOKEN]"`) {
		t.Errorf("expected [TOKEN] in decompressed output, got %s", string(decomp))
	}
}

func TestGzipTextRedaction(t *testing.T) {
	orig := "Contact user at john@example.com for assistance."
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(orig))
	zw.Close()

	req := httptest.NewRequest("POST", "/data", &buf)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")

	payload, err := ExtractFromRequest(req, 1024*1024, nil, nil)
	if err != nil {
		t.Fatalf("extract gzip failed: %v", err)
	}
	if !payload.IsGzipped {
		t.Fatalf("expected payload to be marked as gzipped")
	}

	redactions := []FieldRedaction{
		{
			FieldID:     "body",
			Start:       16,
			End:         32, // john@example.com
			Replacement: "[REDACTED_EMAIL]",
		},
	}

	mutatedGzip, err := MutatePayload(payload, redactions)
	if err != nil {
		t.Fatalf("mutate gzip failed: %v", err)
	}

	zr, err := gzip.NewReader(bytes.NewReader(mutatedGzip))
	if err != nil {
		t.Fatalf("reading mutated gzip: %v", err)
	}
	decomp, _ := io.ReadAll(zr)
	zr.Close()

	expected := "Contact user at [REDACTED_EMAIL] for assistance."
	if string(decomp) != expected {
		t.Errorf("expected '%s', got '%s'", expected, string(decomp))
	}
}
