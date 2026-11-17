package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrTokenNotFound = errors.New("vault token not found")
	ErrInvalidKey    = errors.New("invalid master encryption key (must be 32 bytes)")
	TokenRegex       = regexp.MustCompile(`\[AEGF:[A-Za-z0-9_]+:([A-Fa-f0-9]{12,16})\]`)
)

type Record struct {
	ID          string
	RequestID   string
	Token       string
	Category    string
	FieldPath   string
	Destination string
	PolicyID    string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

type Vault struct {
	db   *sql.DB
	aead cipher.AEAD
}

// GenerateMasterKey creates a new cryptographically secure 32-byte key formatted as hex.
func GenerateMasterKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generating random key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// GenerateToken creates an unpredictable token for an entity category: [AEGF:CATEGORY:HEX].
func GenerateToken(category string) (string, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("[AEGF:%s:%s]", strings.ToUpper(category), strings.ToUpper(hex.EncodeToString(b))), nil
}

func Open(dbPath string, masterKeyHex string, keyFile string) (*Vault, error) {
	// 1. Resolve master key
	var keyBytes []byte
	if masterKeyHex != "" {
		b, err := hex.DecodeString(strings.TrimSpace(masterKeyHex))
		if err != nil {
			return nil, fmt.Errorf("decoding hex master key: %w", err)
		}
		keyBytes = b
	} else if keyFile != "" {
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			// Generate new key and save with 0600 permissions
			newKey, err := GenerateMasterKey()
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(keyFile, []byte(newKey), 0600); err != nil {
				return nil, fmt.Errorf("saving new vault key to %s: %w", keyFile, err)
			}
			b, _ := hex.DecodeString(newKey)
			keyBytes = b
		} else {
			content, err := os.ReadFile(keyFile)
			if err != nil {
				return nil, fmt.Errorf("reading vault key file %s: %w", keyFile, err)
			}
			b, err := hex.DecodeString(strings.TrimSpace(string(content)))
			if err != nil {
				return nil, fmt.Errorf("invalid hex in vault key file %s: %w", keyFile, err)
			}
			keyBytes = b
		}
	} else {
		// In-memory / ephemeral default if not specified
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, err
		}
		keyBytes = b
	}

	if len(keyBytes) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("initializing AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-GCM: %w", err)
	}

	// 2. Open SQLite database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening vault sqlite database %s: %w", dbPath, err)
	}

	// Ensure tables exist
	schema := `
	CREATE TABLE IF NOT EXISTS redaction_records (
		id TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		token TEXT NOT NULL UNIQUE,
		category TEXT NOT NULL,
		ciphertext BLOB NOT NULL,
		nonce BLOB NOT NULL,
		field_path TEXT NOT NULL,
		destination TEXT NOT NULL,
		policy_id TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_records_request_id ON redaction_records(request_id);
	CREATE INDEX IF NOT EXISTS idx_records_token ON redaction_records(token);
	CREATE INDEX IF NOT EXISTS idx_records_expires_at ON redaction_records(expires_at);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing vault schema: %w", err)
	}

	return &Vault{
		db:   db,
		aead: aead,
	}, nil
}

func (v *Vault) Close() error {
	if v.db != nil {
		return v.db.Close()
	}
	return nil
}

type StoreItem struct {
	ID          string
	RequestID   string
	Token       string
	Category    string
	Plaintext   string
	FieldPath   string
	Destination string
	PolicyID    string
	TTL         time.Duration
}

// Store encrypts sensitive values and persists them to SQLite in a single transaction.
func (v *Vault) Store(ctx context.Context, items []StoreItem) error {
	if len(items) == 0 {
		return nil
	}

	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting vault transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO redaction_records (
			id, request_id, token, category, ciphertext, nonce, field_path, destination, policy_id, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}
	defer stmt.Close()

	now := time.Now()

	for _, item := range items {
		nonce := make([]byte, v.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("generating nonce: %w", err)
		}

		ciphertext := v.aead.Seal(nil, nonce, []byte(item.Plaintext), []byte(item.Token))

		expiresAt := now.Add(item.TTL)
		if item.TTL <= 0 {
			expiresAt = now.Add(30 * 24 * time.Hour) // default 30 days
		}

		_, err := stmt.ExecContext(ctx,
			item.ID,
			item.RequestID,
			item.Token,
			item.Category,
			ciphertext,
			nonce,
			item.FieldPath,
			item.Destination,
			item.PolicyID,
			now.Unix(),
			expiresAt.Unix(),
		)
		if err != nil {
			return fmt.Errorf("inserting vault record: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing vault transaction: %w", err)
	}

	return nil
}

// GetByToken retrieves and decrypts the sensitive value for a given token.
func (v *Vault) GetByToken(ctx context.Context, token string) (*Record, string, error) {
	row := v.db.QueryRowContext(ctx, `
		SELECT id, request_id, token, category, ciphertext, nonce, field_path, destination, policy_id, created_at, expires_at
		FROM redaction_records
		WHERE token = ?
	`, token)

	var rec Record
	var ciphertext, nonce []byte
	var createdAtSec, expiresAtSec int64

	err := row.Scan(
		&rec.ID,
		&rec.RequestID,
		&rec.Token,
		&rec.Category,
		&ciphertext,
		&nonce,
		&rec.FieldPath,
		&rec.Destination,
		&rec.PolicyID,
		&createdAtSec,
		&expiresAtSec,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrTokenNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("querying vault token: %w", err)
	}

	rec.CreatedAt = time.Unix(createdAtSec, 0)
	rec.ExpiresAt = time.Unix(expiresAtSec, 0)

	plaintextBytes, err := v.aead.Open(nil, nonce, ciphertext, []byte(token))
	if err != nil {
		return nil, "", fmt.Errorf("decrypting vault record: %w", err)
	}

	return &rec, string(plaintextBytes), nil
}

// ListByRequestID lists all redaction records created for a specific request, or all recent records if reqID is empty.
func (v *Vault) ListByRequestID(ctx context.Context, reqID string) ([]*Record, error) {
	query := `
		SELECT id, request_id, token, category, field_path, destination, policy_id, created_at, expires_at
		FROM redaction_records
		ORDER BY created_at DESC
		LIMIT 100
	`
	var args []any
	if reqID != "" {
		query = `
			SELECT id, request_id, token, category, field_path, destination, policy_id, created_at, expires_at
			FROM redaction_records
			WHERE request_id = ?
			ORDER BY created_at ASC
		`
		args = append(args, reqID)
	}

	rows, err := v.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying request records: %w", err)
	}
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		var rec Record
		var createdSec, expiresSec int64
		if err := rows.Scan(
			&rec.ID,
			&rec.RequestID,
			&rec.Token,
			&rec.Category,
			&rec.FieldPath,
			&rec.Destination,
			&rec.PolicyID,
			&createdSec,
			&expiresSec,
		); err != nil {
			return nil, err
		}
		rec.CreatedAt = time.Unix(createdSec, 0)
		rec.ExpiresAt = time.Unix(expiresSec, 0)
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// RestoreText parses any AEGF tokens inside text and restores their original plaintext.
func (v *Vault) RestoreText(ctx context.Context, text string) (string, error) {
	matches := TokenRegex.FindAllString(text, -1)
	if len(matches) == 0 {
		return text, nil
	}

	// Deduplicate tokens
	uniqueTokens := make(map[string]bool)
	for _, m := range matches {
		uniqueTokens[m] = true
	}

	restored := text
	for token := range uniqueTokens {
		_, plain, err := v.GetByToken(ctx, token)
		if err != nil {
			if errors.Is(err, ErrTokenNotFound) {
				// Keep token as-is if not found in vault
				continue
			}
			return "", err
		}
		restored = strings.ReplaceAll(restored, token, plain)
	}

	return restored, nil
}

// Purge removes vault records older than the specified duration.
func (v *Vault) Purge(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	res, err := v.db.ExecContext(ctx, "DELETE FROM redaction_records WHERE created_at < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging vault records: %w", err)
	}
	return res.RowsAffected()
}
