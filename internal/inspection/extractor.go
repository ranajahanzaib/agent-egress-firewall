package inspection

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection/pb"
)

type ContentType int

const (
	ContentTypeUnknown ContentType = iota
	ContentTypeJSON
	ContentTypeText
	ContentTypeForm
)

type ExtractedPayload struct {
	Type          ContentType
	Fields        []*pb.ScanField
	OriginalBytes []byte
	IsGzipped     bool
	ParsedJSON    any
	ParsedForm    url.Values
}

type FieldRedaction struct {
	FieldID     string
	Start       int // Unicode character offset
	End         int // Unicode character offset
	Replacement string
}

func DetectContentType(contentTypeHeader string) ContentType {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentTypeHeader, ";")[0]))
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return ContentTypeJSON
	case mediaType == "text/plain" || strings.HasPrefix(mediaType, "text/"):
		return ContentTypeText
	case mediaType == "application/x-www-form-urlencoded":
		return ContentTypeForm
	default:
		return ContentTypeUnknown
	}
}

// ExtractFromRequest inspects headers, query parameters, and request body.
func ExtractFromRequest(req *http.Request, maxBodySize int64, inspectHeaders []string, inspectQueryParams []string) (*ExtractedPayload, error) {
	payload := &ExtractedPayload{
		Type:   ContentTypeUnknown,
		Fields: []*pb.ScanField{},
	}

	// 1. Inspect configured headers
	for _, h := range inspectHeaders {
		val := req.Header.Get(h)
		if val != "" {
			payload.Fields = append(payload.Fields, &pb.ScanField{
				FieldId: "header:" + h,
				Text:    val,
				Context: "header",
			})
		}
	}

	// 2. Inspect configured query params
	if len(inspectQueryParams) > 0 && req.URL != nil {
		q := req.URL.Query()
		for _, param := range inspectQueryParams {
			val := q.Get(param)
			if val != "" {
				payload.Fields = append(payload.Fields, &pb.ScanField{
					FieldId: "query:" + param,
					Text:    val,
					Context: "query",
				})
			}
		}
	}

	// 3. Inspect body if present
	if req.Body == nil {
		return payload, nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	if int64(len(bodyBytes)) > maxBodySize {
		return nil, fmt.Errorf("request body exceeds maximum allowed size (%d bytes)", maxBodySize)
	}
	payload.OriginalBytes = bodyBytes

	// Check for gzip compression
	rawBytes := bodyBytes
	if req.Header.Get("Content-Encoding") == "gzip" {
		payload.IsGzipped = true
		gzReader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("invalid gzip compressed body: %w", err)
		}
		defer gzReader.Close()
		decompressed, err := io.ReadAll(io.LimitReader(gzReader, maxBodySize+1))
		if err != nil {
			return nil, fmt.Errorf("decompressing gzip body: %w", err)
		}
		if int64(len(decompressed)) > maxBodySize {
			return nil, fmt.Errorf("decompressed body exceeds limit (%d bytes)", maxBodySize)
		}
		rawBytes = decompressed
	}

	if len(rawBytes) == 0 {
		return payload, nil
	}

	cType := DetectContentType(req.Header.Get("Content-Type"))
	payload.Type = cType

	switch cType {
	case ContentTypeJSON:
		dec := json.NewDecoder(bytes.NewReader(rawBytes))
		dec.UseNumber()
		var parsed any
		if err := dec.Decode(&parsed); err != nil {
			return nil, fmt.Errorf("malformed JSON body: %w", err)
		}
		payload.ParsedJSON = parsed
		extractJSONFields("", parsed, &payload.Fields)

	case ContentTypeForm:
		form, err := url.ParseQuery(string(rawBytes))
		if err != nil {
			return nil, fmt.Errorf("malformed form payload: %w", err)
		}
		payload.ParsedForm = form
		for k, vals := range form {
			for i, v := range vals {
				fieldID := fmt.Sprintf("form:%s[%d]", k, i)
				payload.Fields = append(payload.Fields, &pb.ScanField{
					FieldId: fieldID,
					Text:    v,
					Context: "form",
				})
			}
		}

	case ContentTypeText:
		payload.Fields = append(payload.Fields, &pb.ScanField{
			FieldId: "body",
			Text:    string(rawBytes),
			Context: "text",
		})

	default:
		// Unknown or binary payload
	}

	return payload, nil
}

func extractJSONFields(currPath string, val any, fields *[]*pb.ScanField) {
	switch v := val.(type) {
	case map[string]any:
		for k, child := range v {
			escapedKey := strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
			path := currPath + "/" + escapedKey
			extractJSONFields(path, child, fields)
		}
	case []any:
		for i, child := range v {
			path := currPath + "/" + strconv.Itoa(i)
			extractJSONFields(path, child, fields)
		}
	case string:
		*fields = append(*fields, &pb.ScanField{
			FieldId: currPath,
			Text:    v,
			Context: "json",
		})
	}
}

// MutatePayload applies redactions to the payload and returns the mutated body bytes.
func MutatePayload(payload *ExtractedPayload, redactions []FieldRedaction) ([]byte, error) {
	if len(redactions) == 0 {
		return payload.OriginalBytes, nil
	}

	// Group redactions by field_id
	byField := make(map[string][]FieldRedaction)
	for _, r := range redactions {
		byField[r.FieldID] = append(byField[r.FieldID], r)
	}

	switch payload.Type {
	case ContentTypeJSON:
		for fieldID, fieldReds := range byField {
			if !strings.HasPrefix(fieldID, "/") {
				continue
			}
			applyJSONRedaction(payload.ParsedJSON, fieldID, fieldReds)
		}
		mutated, err := json.Marshal(payload.ParsedJSON)
		if err != nil {
			return nil, fmt.Errorf("reserializing redacted JSON: %w", err)
		}
		if payload.IsGzipped {
			return compressGzip(mutated)
		}
		return mutated, nil

	case ContentTypeText:
		if reds, ok := byField["body"]; ok {
			mutated := applyTextRedactions(string(payload.OriginalBytes), reds)
			if payload.IsGzipped {
				return compressGzip([]byte(mutated))
			}
			return []byte(mutated), nil
		}
		return payload.OriginalBytes, nil

	case ContentTypeForm:
		for k, vals := range payload.ParsedForm {
			for i := range vals {
				fieldID := fmt.Sprintf("form:%s[%d]", k, i)
				if reds, ok := byField[fieldID]; ok {
					payload.ParsedForm[k][i] = applyTextRedactions(vals[i], reds)
				}
			}
		}
		encoded := payload.ParsedForm.Encode()
		if payload.IsGzipped {
			return compressGzip([]byte(encoded))
		}
		return []byte(encoded), nil

	default:
		return payload.OriginalBytes, nil
	}
}

func applyTextRedactions(text string, redactions []FieldRedaction) string {
	// Sort redactions in descending order of start offset so earlier offsets remain valid
	sort.Slice(redactions, func(i, j int) bool {
		return redactions[i].Start > redactions[j].Start
	})

	runes := []rune(text)
	for _, r := range redactions {
		if r.Start >= len(runes) || r.End > len(runes) || r.Start > r.End {
			continue
		}
		replRunes := []rune(r.Replacement)
		prefix := runes[:r.Start]
		suffix := runes[r.End:]
		runes = append(prefix, append(replRunes, suffix...)...)
	}
	return string(runes)
}

func applyJSONRedaction(root any, path string, redactions []FieldRedaction) {
	tokens := parseJSONPointer(path)
	if len(tokens) == 0 {
		return
	}

	var curr any = root
	for i := 0; i < len(tokens)-1; i++ {
		t := tokens[i]
		switch v := curr.(type) {
		case map[string]any:
			curr = v[t]
		case []any:
			idx, err := strconv.Atoi(t)
			if err != nil || idx < 0 || idx >= len(v) {
				return
			}
			curr = v[idx]
		default:
			return
		}
	}

	lastToken := tokens[len(tokens)-1]
	switch v := curr.(type) {
	case map[string]any:
		if strVal, ok := v[lastToken].(string); ok {
			v[lastToken] = applyTextRedactions(strVal, redactions)
		}
	case []any:
		idx, err := strconv.Atoi(lastToken)
		if err == nil && idx >= 0 && idx < len(v) {
			if strVal, ok := v[idx].(string); ok {
				v[idx] = applyTextRedactions(strVal, redactions)
			}
		}
	}
}

func parseJSONPointer(ptr string) []string {
	if ptr == "" || !strings.HasPrefix(ptr, "/") {
		return nil
	}
	parts := strings.Split(ptr[1:], "/")
	var tokens []string
	for _, p := range parts {
		token := strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")
		tokens = append(tokens, token)
	}
	return tokens
}

func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
