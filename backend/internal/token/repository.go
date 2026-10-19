package token

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"canary-token-generator/backend/internal/core"
)

type Repository interface {
	Create(ctx context.Context, t *Token) error
	GetByID(ctx context.Context, id string) (*Token, error)
	GetByManageKey(ctx context.Context, key string) (*Token, error)
	IncrementHitCount(ctx context.Context, id string) error
	SetActive(ctx context.Context, id string, active bool) error
	List(ctx context.Context, limit int, offset int) ([]*Token, int64, error)
	Count(ctx context.Context) (int64, error)
	Delete(ctx context.Context, id string) error
	// HashLegacyManageKeys convierte las claves en claro de versiones antiguas en su hash SHA-256.
	HashLegacyManageKeys(ctx context.Context) (int, error)
}

type sqlRepository struct{ db *core.DB }

func NewRepository(db *core.DB) Repository { return &sqlRepository{db: db} }

const tokenColumns = `id, type, label, manage_key, target_url, notify_channel, notify_config, metadata, hit_count, is_active, created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanToken(s rowScanner) (*Token, error) {
	t := &Token{}
	err := s.Scan(&t.ID, &t.Type, &t.Label, &t.ManageKey, &t.TargetURL, &t.NotifyChannel, &t.NotifyConfig,
		&t.Metadata, &t.HitCount, &t.IsActive, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Create guarda el token. t.ManageKey debe contener ya el HASH.
func (r *sqlRepository) Create(ctx context.Context, t *Token) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO tokens (`+tokenColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`),
		t.ID, t.Type, t.Label, t.ManageKey, t.TargetURL, t.NotifyChannel, t.NotifyConfig, t.Metadata,
		t.HitCount, t.IsActive, t.CreatedAt.UTC(), t.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("failed to insert token: %w", err)
	}
	return nil
}

func (r *sqlRepository) GetByID(ctx context.Context, id string) (*Token, error) {
	t, err := scanToken(r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+tokenColumns+` FROM tokens WHERE id = $1`), id))
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	return t, err
}

// GetByManageKey recibe el secreto EN CLARO y busca por su hash.
func (r *sqlRepository) GetByManageKey(ctx context.Context, key string) (*Token, error) {
	if key == "" || len(key) > 128 {
		return nil, core.ErrNotFound
	}
	t, err := scanToken(r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+tokenColumns+` FROM tokens WHERE manage_key = $1`), HashManageKey(key)))
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		return nil, fmt.Errorf("failed to get token by manage key: %w", err)
	}
	return t, err
}

func (r *sqlRepository) IncrementHitCount(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE tokens SET hit_count = hit_count + 1, updated_at = $1 WHERE id = $2`), time.Now().UTC(), id)
	return err
}

func (r *sqlRepository) SetActive(ctx context.Context, id string, active bool) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE tokens SET is_active = $1, updated_at = $2 WHERE id = $3`), active, time.Now().UTC(), id)
	return err
}

func (r *sqlRepository) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens`).Scan(&n)
	return n, err
}

func (r *sqlRepository) List(ctx context.Context, limit int, offset int) ([]*Token, int64, error) {
	total, err := r.Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+tokenColumns+` FROM tokens ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var tokens []*Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, 0, err
		}
		tokens = append(tokens, t)
	}
	return tokens, total, rows.Err()
}

func (r *sqlRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM tokens WHERE id = $1`), id)
	return err
}

func (r *sqlRepository) HashLegacyManageKeys(ctx context.Context) (int, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, manage_key FROM tokens WHERE LENGTH(manage_key) <> 64`)
	if err != nil {
		return 0, err
	}
	type pair struct{ id, key string }
	var legacy []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.id, &p.key); err != nil {
			rows.Close()
			return 0, err
		}
		legacy = append(legacy, p)
	}
	rows.Close() // imprescindible antes de escribir: SQLite usa una unica conexion
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, p := range legacy {
		if _, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE tokens SET manage_key = $1 WHERE id = $2`), HashManageKey(p.key), p.id); err != nil {
			return 0, err
		}
	}
	return len(legacy), nil
}
