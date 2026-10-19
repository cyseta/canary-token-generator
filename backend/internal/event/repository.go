package event

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"canary-token-generator/backend/internal/core"
)

type Repository interface {
	Insert(ctx context.Context, e *Event) error
	ListByToken(ctx context.Context, tokenID string, limit int, offset int) ([]*Event, int64, error)
	CountAll(ctx context.Context) (int64, error)
	GetRecentEvents(ctx context.Context, limit int) ([]*Event, error)
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

type sqlRepository struct{ db *core.DB }

func NewRepository(db *core.DB) Repository { return &sqlRepository{db: db} }

const eventColumns = `id, token_id, source_ip, user_agent, referer, protocol, country, city, headers, fingerprint, created_at`

func (r *sqlRepository) Insert(ctx context.Context, e *Event) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO events (`+eventColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`),
		e.ID, e.TokenID, e.SourceIP, e.UserAgent, e.Referer, e.Protocol, e.Country, e.City, e.Headers, e.Fingerprint, e.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}
	return nil
}

func scanEvents(rows *sql.Rows) ([]*Event, error) {
	defer rows.Close()
	var events []*Event
	for rows.Next() {
		ev := &Event{}
		if err := rows.Scan(&ev.ID, &ev.TokenID, &ev.SourceIP, &ev.UserAgent, &ev.Referer, &ev.Protocol,
			&ev.Country, &ev.City, &ev.Headers, &ev.Fingerprint, &ev.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err() // antes no se comprobaba: un error de iteracion truncaba resultados en silencio
}

func (r *sqlRepository) ListByToken(ctx context.Context, tokenID string, limit int, offset int) ([]*Event, int64, error) {
	var total int64
	if err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*) FROM events WHERE token_id = $1`), tokenID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`
		SELECT `+eventColumns+` FROM events WHERE token_id = $1
		ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`), tokenID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	events, err := scanEvents(rows)
	return events, total, err
}

func (r *sqlRepository) CountAll(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&count)
	return count, err
}

func (r *sqlRepository) GetRecentEvents(ctx context.Context, limit int) ([]*Event, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`
		SELECT `+eventColumns+` FROM events ORDER BY created_at DESC, id DESC LIMIT $1`), limit)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

func (r *sqlRepository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM events WHERE created_at < $1`), cutoff.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
