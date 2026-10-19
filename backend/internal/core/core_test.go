package core

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRebindAndDSN(t *testing.T) {
	s := &DB{Driver: "sqlite"}
	p := &DB{Driver: "pgx"}
	q := "UPDATE t SET a=$1, b=$2 WHERE id=$3"
	if s.Rebind(q) != "UPDATE t SET a=?, b=? WHERE id=?" || p.Rebind(q) != q {
		t.Fatal("rebind incorrecto")
	}
	if !strings.Contains(sqliteDSN("x.db"), "file:x.db?_pragma=foreign_keys(1)") || sqliteDSN("file:a?_pragma=foo(1)") != "file:a?_pragma=foo(1)" {
		t.Fatal("dsn incorrecto: " + sqliteDSN("x.db"))
	}
	if !strings.Contains(sqliteDSN("file:x.db?mode=rwc"), "mode=rwc&_pragma=") {
		t.Fatal("debe respetar query previa")
	}
}

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := InitDB(&Config{DBDriver: "sqlite", DBDSN: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// Regresion: sin PRAGMA foreign_keys el CASCADE no se aplicaba en SQLite y se aceptaban eventos huerfanos.
func TestSQLiteForeignKeysEnforced(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO events (id, token_id, source_ip) VALUES ($1,$2,$3)`), "e1", "no-existe", "1.1.1.1"); err == nil {
		t.Fatal("deberia fallar por clave foranea")
	}
	db.ExecContext(ctx, db.Rebind(`INSERT INTO tokens (id,type,label,manage_key) VALUES ($1,$2,$3,$4)`), "t1", "pdf", "l", "k1")
	db.ExecContext(ctx, db.Rebind(`INSERT INTO events (id, token_id, source_ip) VALUES ($1,$2,$3)`), "e1", "t1", "1.1.1.1")
	db.ExecContext(ctx, `DELETE FROM tokens WHERE id='t1'`)
	var n int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 0 {
		t.Fatalf("ON DELETE CASCADE no aplicado: quedan %d eventos", n)
	}
}

// Regresion: sin busy_timeout/WAL las escrituras concurrentes fallaban con "database is locked" (eventos perdidos).
func TestSQLiteConcurrentWrites(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.ExecContext(ctx, db.Rebind(`INSERT INTO tokens (id,type,label,manage_key) VALUES ($1,$2,$3,$4)`), "t1", "pdf", "l", "k1")
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				_, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO events (id, token_id, source_ip) VALUES ($1,$2,$3)`), fmt.Sprintf("e-%d-%d", i, j), "t1", "1.1.1.1")
				if err != nil {
					errs <- err
				}
				if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE tokens SET hit_count = hit_count + 1 WHERE id = $1`), "t1"); err != nil {
					errs <- err
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("escritura concurrente fallo: %v", err)
	}
	var hits int
	db.QueryRowContext(ctx, `SELECT hit_count FROM tokens WHERE id='t1'`).Scan(&hits)
	if hits != 200 {
		t.Fatalf("hit_count=%d, esperado 200", hits)
	}
}

// Regresion: MemoryCache.Incr tenia el cuerpo vacio y SIEMPRE devolvia 1 (rate limit inoperante en modo standalone).
func TestMemoryCacheIncrActuallyCounts(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()
	for want := int64(1); want <= 5; want++ {
		if got, _ := c.Incr(ctx, "k"); got != want {
			t.Fatalf("Incr #%d devolvio %d", want, got)
		}
	}
	// TTL fijado solo en la creacion y expiracion correcta
	if n, _ := c.IncrWithTTL(ctx, "w", 50*time.Millisecond); n != 1 {
		t.Fatal("primera llamada debe ser 1")
	}
	if n, _ := c.IncrWithTTL(ctx, "w", 50*time.Millisecond); n != 2 {
		t.Fatal("segunda debe ser 2")
	}
	time.Sleep(70 * time.Millisecond)
	if n, _ := c.IncrWithTTL(ctx, "w", 50*time.Millisecond); n != 1 {
		t.Fatal("tras expirar vuelve a 1")
	}
}

func TestMemoryCacheSetNXAtomic(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := c.SetNX(ctx, "dedup:x", "1", time.Minute); ok {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("SetNX concurrente: %d ganadores (debe ser exactamente 1)", winners)
	}
}

func TestMemoryCacheBounded(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	c.maxSize = 10
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if _, err := c.IncrWithTTL(ctx, fmt.Sprint("k", i), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.IncrWithTTL(ctx, "overflow", time.Minute); err != ErrCacheFull {
		t.Fatalf("debe rechazar claves nuevas al llenarse, got %v", err)
	}
	if n, err := c.IncrWithTTL(ctx, "k3", time.Minute); err != nil || n != 2 {
		t.Fatal("las claves existentes siguen funcionando")
	}
}

func TestMetricsSnapshotRaceFree(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); IncEventsLogged() }()
		go func() { defer wg.Done(); _ = SnapshotMetrics() }()
	}
	wg.Wait()
}

var _ = regexp.MustCompile
