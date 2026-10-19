package core

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
	Driver string
}

var placeholderRe = regexp.MustCompile(`\$\d+`)

// Rebind permite escribir cada consulta UNA sola vez con marcadores estilo Postgres ($1, $2...).
// Para SQLite los convierte en "?". Requisito: los marcadores deben aparecer una vez cada uno y en
// orden ascendente (todas las consultas del proyecto lo cumplen; hay un test que lo garantiza).
func (db *DB) Rebind(q string) string {
	if db.Driver == "sqlite" {
		return placeholderRe.ReplaceAllString(q, "?")
	}
	return q
}

// sqliteDSN anade las pragmas imprescindibles que SQLite NO activa por defecto:
//   - foreign_keys: sin ella ON DELETE CASCADE no se aplica y quedan eventos huerfanos.
//   - busy_timeout: sin ella las escrituras concurrentes fallan al instante con "database is locked".
//   - journal_mode=WAL: lecturas concurrentes con una escritura.
func sqliteDSN(dsn string) string {
	if strings.Contains(dsn, "_pragma=") {
		return dsn
	}
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
}

func InitDB(cfg *Config) (*DB, error) {
	driverName := strings.ToLower(cfg.DBDriver)
	dsn := cfg.DBDSN

	if driverName == "postgres" || driverName == "postgresql" || driverName == "pgx" {
		driverName = "pgx"
	} else {
		driverName = "sqlite"
		if dsn == "" {
			dsn = "canary.db"
		}
		dsn = sqliteDSN(dsn)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if driverName == "sqlite" {
		db.SetMaxOpenConns(1) // SQLite admite un unico escritor; evita contencion y "database is locked"
	} else {
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(10)
	}
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database (%s): %w", driverName, err)
	}
	slog.Info("connected to database", "driver", driverName)

	database := &DB{DB: db, Driver: driverName}
	if err := database.migrate(ctx); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}
	return database, nil
}

func (db *DB) migrate(ctx context.Context) error {
	var schema string
	if db.Driver == "sqlite" {
		schema = `
		CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			label TEXT NOT NULL,
			manage_key TEXT NOT NULL UNIQUE,
			target_url TEXT DEFAULT '',
			notify_channel TEXT DEFAULT 'none',
			notify_config TEXT DEFAULT '{}',
			metadata TEXT DEFAULT '{}',
			hit_count INTEGER DEFAULT 0,
			is_active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_tokens_type ON tokens(type);
		DROP INDEX IF EXISTS idx_tokens_manage_key;

		CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
			source_ip TEXT NOT NULL,
			user_agent TEXT DEFAULT '',
			referer TEXT DEFAULT '',
			protocol TEXT DEFAULT 'HTTP',
			country TEXT DEFAULT '',
			city TEXT DEFAULT '',
			headers TEXT DEFAULT '{}',
			fingerprint TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_events_token_created ON events(token_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
		DROP INDEX IF EXISTS idx_events_token_id;
		`
	} else {
		schema = `
		CREATE TABLE IF NOT EXISTS tokens (
			id VARCHAR(64) PRIMARY KEY,
			type VARCHAR(32) NOT NULL,
			label VARCHAR(255) NOT NULL,
			manage_key VARCHAR(64) NOT NULL UNIQUE,
			target_url TEXT DEFAULT '',
			notify_channel VARCHAR(32) DEFAULT 'none',
			notify_config TEXT DEFAULT '{}',
			metadata TEXT DEFAULT '{}',
			hit_count BIGINT DEFAULT 0,
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_tokens_type ON tokens(type);
		DROP INDEX IF EXISTS idx_tokens_manage_key;

		CREATE TABLE IF NOT EXISTS events (
			id VARCHAR(64) PRIMARY KEY,
			token_id VARCHAR(64) NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
			source_ip VARCHAR(64) NOT NULL,
			user_agent TEXT DEFAULT '',
			referer TEXT DEFAULT '',
			protocol VARCHAR(32) DEFAULT 'HTTP',
			country VARCHAR(64) DEFAULT '',
			city VARCHAR(128) DEFAULT '',
			headers TEXT DEFAULT '{}',
			fingerprint TEXT DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_events_token_created ON events(token_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
		DROP INDEX IF EXISTS idx_events_token_id;
		`
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return err
	}
	slog.Info("database schema migrations applied successfully")
	return nil
}
