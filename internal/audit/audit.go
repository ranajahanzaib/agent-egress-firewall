package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type AuditEvent struct {
	ID                  string      `json:"id"`
	RequestID           string      `json:"request_id"`
	Timestamp           time.Time   `json:"timestamp"`
	Route               string      `json:"route"`
	Destination         string      `json:"destination"`
	Policy              string      `json:"policy"`
	Decision            string      `json:"decision"`
	Detections          []Detection `json:"detections"`
	Forwarded           bool        `json:"forwarded"`
	DurationMs          int64       `json:"duration_ms"`
	InferenceDurationMs int64       `json:"inference_duration_ms"`
	FailureReason       string      `json:"failure_reason,omitempty"`
}

type Detection struct {
	Category   string  `json:"category"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Field      string  `json:"field"`
	Action     string  `json:"action"`
	DetectorID string  `json:"detector_id"`
}

type Filter struct {
	Route     string
	Decision  string
	Category  string
	StartTime *time.Time
	EndTime   *time.Time
	Limit     int
	Offset    int
}

type Store struct {
	db *sql.DB
}

func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening audit sqlite database %s: %w", dbPath, err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		timestamp INTEGER NOT NULL,
		route TEXT NOT NULL,
		destination TEXT NOT NULL,
		policy TEXT NOT NULL,
		decision TEXT NOT NULL,
		detections_json TEXT NOT NULL,
		forwarded INTEGER NOT NULL,
		duration_ms INTEGER NOT NULL,
		inference_duration_ms INTEGER NOT NULL,
		failure_reason TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_events(request_id);
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);
	CREATE INDEX IF NOT EXISTS idx_audit_route ON audit_events(route);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing audit schema: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) Record(ctx context.Context, event *AuditEvent) error {
	detsJSON, err := json.Marshal(event.Detections)
	if err != nil {
		detsJSON = []byte("[]")
	}

	forwardedInt := 0
	if event.Forwarded {
		forwardedInt = 1
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			id, request_id, timestamp, route, destination, policy, decision,
			detections_json, forwarded, duration_ms, inference_duration_ms, failure_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		event.ID,
		event.RequestID,
		event.Timestamp.Unix(),
		event.Route,
		event.Destination,
		event.Policy,
		event.Decision,
		string(detsJSON),
		forwardedInt,
		event.DurationMs,
		event.InferenceDurationMs,
		event.FailureReason,
	)
	if err != nil {
		return fmt.Errorf("inserting audit event: %w", err)
	}
	return nil
}

func (s *Store) GetByRequestID(ctx context.Context, reqID string) (*AuditEvent, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, request_id, timestamp, route, destination, policy, decision,
		       detections_json, forwarded, duration_ms, inference_duration_ms, failure_reason
		FROM audit_events
		WHERE request_id = ?
		LIMIT 1
	`, reqID)

	var ev AuditEvent
	var tsSec int64
	var detsStr string
	var forwardedInt int

	err := row.Scan(
		&ev.ID,
		&ev.RequestID,
		&tsSec,
		&ev.Route,
		&ev.Destination,
		&ev.Policy,
		&ev.Decision,
		&detsStr,
		&forwardedInt,
		&ev.DurationMs,
		&ev.InferenceDurationMs,
		&ev.FailureReason,
	)
	if err != nil {
		return nil, err
	}

	ev.Timestamp = time.Unix(tsSec, 0)
	ev.Forwarded = (forwardedInt == 1)
	_ = json.Unmarshal([]byte(detsStr), &ev.Detections)

	return &ev, nil
}

func (s *Store) Query(ctx context.Context, filter Filter) ([]*AuditEvent, error) {
	var whereClauses []string
	var args []any

	if filter.Route != "" {
		whereClauses = append(whereClauses, "route = ?")
		args = append(args, filter.Route)
	}
	if filter.Decision != "" {
		whereClauses = append(whereClauses, "decision = ?")
		args = append(args, filter.Decision)
	}
	if filter.Category != "" {
		whereClauses = append(whereClauses, "detections_json LIKE ?")
		args = append(args, "%"+filter.Category+"%")
	}
	if filter.StartTime != nil {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, filter.StartTime.Unix())
	}
	if filter.EndTime != nil {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, filter.EndTime.Unix())
	}

	query := `
		SELECT id, request_id, timestamp, route, destination, policy, decision,
		       detections_json, forwarded, duration_ms, inference_duration_ms, failure_reason
		FROM audit_events
	`
	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit events: %w", err)
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var tsSec int64
		var detsStr string
		var forwardedInt int

		if err := rows.Scan(
			&ev.ID,
			&ev.RequestID,
			&tsSec,
			&ev.Route,
			&ev.Destination,
			&ev.Policy,
			&ev.Decision,
			&detsStr,
			&forwardedInt,
			&ev.DurationMs,
			&ev.InferenceDurationMs,
			&ev.FailureReason,
		); err != nil {
			return nil, err
		}
		ev.Timestamp = time.Unix(tsSec, 0)
		ev.Forwarded = (forwardedInt == 1)
		_ = json.Unmarshal([]byte(detsStr), &ev.Detections)
		events = append(events, &ev)
	}

	return events, rows.Err()
}

func (s *Store) Purge(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	res, err := s.db.ExecContext(ctx, "DELETE FROM audit_events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging audit events: %w", err)
	}
	return res.RowsAffected()
}
