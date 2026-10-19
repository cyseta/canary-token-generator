package mysql

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/event"
	"canary-token-generator/backend/internal/geoip"
	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/seed"
)

// ---------- helpers de cliente (implementacion independiente del protocolo) ----------

func nativeScramble(pw string, salt []byte) []byte {
	s1 := sha1.Sum([]byte(pw))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(s2[:])
	mix := h.Sum(nil)
	out := make([]byte, 20)
	for i := range out {
		out[i] = s1[i] ^ mix[i]
	}
	return out
}

func lenencStr(s string) []byte { return append([]byte{byte(len(s))}, s...) }

func clientResponse(user string, auth []byte, db string, attrs map[string]string) []byte {
	var b bytes.Buffer
	caps := uint32(0x1 | 0x4 | 0x8 | 0x200 | 0x8000 | 0x80000 | 0x100000)
	_ = binary.Write(&b, binary.LittleEndian, caps)
	_ = binary.Write(&b, binary.LittleEndian, uint32(1<<24))
	b.WriteByte(0xff)
	b.Write(make([]byte, 23))
	b.WriteString(user)
	b.WriteByte(0)
	b.WriteByte(byte(len(auth)))
	b.Write(auth)
	b.WriteString(db)
	b.WriteByte(0)
	b.WriteString("mysql_native_password")
	b.WriteByte(0)
	var ab bytes.Buffer
	for k, v := range attrs {
		ab.Write(lenencStr(k))
		ab.Write(lenencStr(v))
	}
	b.WriteByte(byte(ab.Len()))
	b.Write(ab.Bytes())
	return b.Bytes()
}

func saltFromGreeting(p []byte) []byte {
	idx := 1 + bytes.IndexByte(p[1:], 0) + 1
	part1 := p[idx+4 : idx+12]
	part2 := p[idx+31 : idx+43]
	return append(append([]byte{}, part1...), part2...)
}

// ---------- tests de protocolo ----------

func TestReadPacketRejectsOversizedBeforeAllocating(t *testing.T) {
	hdr := []byte{0xff, 0xff, 0xff, 0x01} // declara 16 MiB, sin cuerpo
	var ms1, ms2 runtime.MemStats
	runtime.ReadMemStats(&ms1)
	for i := 0; i < 200; i++ {
		_, _, err := ReadPacket(bytes.NewReader(hdr))
		if err != ErrPacketTooLarge {
			t.Fatalf("err=%v, esperado ErrPacketTooLarge", err)
		}
	}
	runtime.ReadMemStats(&ms2)
	// antes: 200 x 16 MiB = 3,2 GiB reservados por un cliente SIN autenticar
	if alloc := ms2.TotalAlloc - ms1.TotalAlloc; alloc > 4<<20 {
		t.Fatalf("se reservaron %d bytes ante cabeceras maliciosas", alloc)
	}
}

func TestHandshakeIsRealistic(t *testing.T) {
	for i := 0; i < 3000; i++ { // antes ~7,5% de los saludos llevaban un 0x00 en el salt
		p, salt := BuildHandshake(uint32(i), DefaultServerVersion)
		if len(salt) != 20 || bytes.IndexByte(salt, 0) >= 0 {
			t.Fatalf("salt invalido: %x", salt)
		}
		if !bytes.Equal(saltFromGreeting(p), salt) {
			t.Fatal("el salt del paquete no coincide")
		}
	}
	p, _ := BuildHandshake(1, DefaultServerVersion)
	if strings.Contains(strings.ToLower(string(p)), "canary") || !bytes.Contains(p, []byte("mysql_native_password")) {
		t.Fatal("el banner no debe delatar el honeypot")
	}
	idx := 1 + bytes.IndexByte(p[1:], 0) + 1
	lower := binary.LittleEndian.Uint16(p[idx+13 : idx+15])
	upper := binary.LittleEndian.Uint16(p[idx+18 : idx+20])
	caps := uint32(lower) | uint32(upper)<<16
	if caps&capPluginAuth == 0 || caps&capConnectAttrs == 0 || caps&capSSL != 0 {
		t.Fatalf("capacidades incorrectas: %#x", caps)
	}
}

func TestParseHandshakeResponseWithAttributes(t *testing.T) {
	a, err := ParseHandshakeResponse41(clientResponse("svc_x", bytes.Repeat([]byte{1}, 20), "production",
		map[string]string{"_client_name": "libmysql", "_client_version": "8.0.36", "program_name": "mysql"}))
	if err != nil || a.Username != "svc_x" || a.Database != "production" || a.AuthPlugin != "mysql_native_password" ||
		a.Attributes["_client_name"] != "libmysql" || a.Attributes["program_name"] != "mysql" || len(a.AuthResponse) != 20 {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestParseHandshakeResponseIsRobustToTruncationAndGarbage(t *testing.T) {
	good := clientResponse("svc_x", bytes.Repeat([]byte{1}, 20), "db", map[string]string{"k": "v"})
	for n := 0; n < len(good); n++ { // ningun truncamiento debe provocar panic
		_, _ = ParseHandshakeResponse41(good[:n])
	}
	garbage := make([]byte, 400)
	for i := range garbage {
		garbage[i] = byte(i * 7)
	}
	binary.LittleEndian.PutUint32(garbage, 0x00180a0f|capProtocol41)
	_, _ = ParseHandshakeResponse41(garbage)
}

func TestVerifyNativePassword(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, 20)
	if !VerifyNativePassword(salt, nativeScramble("pw", salt), "pw") || VerifyNativePassword(salt, nativeScramble("pw", salt), "other") || VerifyNativePassword(salt, []byte{1}, "pw") {
		t.Fatal("verificacion de mysql_native_password incorrecta")
	}
}

// ---------- end-to-end sobre TCP con SQLite real ----------

type env struct {
	srv  *Server
	svc  token.Service
	repo token.Repository
	evs  event.Repository
	db   *core.DB
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := core.InitDB(&core.Config{DBDriver: "sqlite", DBDSN: filepath.Join(t.TempDir(), "m.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cache := core.NewMemoryCache()
	t.Cleanup(cache.Close)
	repo := token.NewRepository(db)
	evRepo := event.NewRepository(db)
	evSvc := event.NewService(evRepo, repo.IncrementHitCount, &geoip.NopProvider{}, cache, nil)
	svc := token.NewService(repo)
	svc.RegisterGenerator(NewWithPublic("db.example.com", 3306))
	svc.RegisterGenerator(fakeType("pdf"))
	srv := NewServer(0, NewConnectionHandler(repo, evSvc))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return &env{srv: srv, svc: svc, repo: repo, evs: evRepo, db: db}
}

type fakeType string

func (f fakeType) Type() string { return string(f) }
func (f fakeType) Generate(context.Context, token.GenerateRequest) (*token.GenerateResult, error) {
	return &token.GenerateResult{}, nil
}

func (e *env) create(t *testing.T, typ, label string) (*token.CreateTokenResponse, string, string) {
	t.Helper()
	r, err := e.svc.CreateToken(context.Background(), token.CreateTokenRequest{Type: typ, Label: label}, "https://ops.example.com")
	if err != nil {
		t.Fatal(err)
	}
	user, _ := r.Metadata["username"].(string)
	if user == "" {
		user = seed.MySQLUser(r.Token.ID)
	}
	tok, _ := e.repo.GetByID(context.Background(), r.Token.ID)
	return r, user, seed.MySQLPassword(seed.FromMetadata(tok.Metadata), r.Token.ID)
}

// login realiza un intento de conexion completo y devuelve el paquete de error del servidor.
func (e *env) login(t *testing.T, user, pw string, attrs map[string]string) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", e.srv.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	_, greeting, err := ReadPacket(c)
	if err != nil {
		t.Fatalf("sin saludo: %v", err)
	}
	salt := saltFromGreeting(greeting)
	var auth []byte
	if pw != "" {
		auth = nativeScramble(pw, salt)
	}
	if err := WritePacket(c, 1, clientResponse(user, auth, "production", attrs)); err != nil {
		t.Fatal(err)
	}
	_, resp, err := ReadPacket(c)
	if err != nil {
		t.Fatalf("sin respuesta: %v", err)
	}
	return resp
}

func (e *env) waitEvents(t *testing.T, tokenID string, want int) []*event.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		evs, _, _ := e.evs.ListByToken(context.Background(), tokenID, 50, 0)
		if len(evs) >= want || time.Now().After(deadline) {
			return evs
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// REGRESION PRINCIPAL: las credenciales del token A generaban el evento en el token de OTRO usuario (B),
// y cualquier bot que probase "root" tambien se atribuia a un token ajeno.
func TestAttributionIsExactAndNeverFallsBackToAnotherToken(t *testing.T) {
	e := newEnv(t)
	a, userA, pwA := e.create(t, "mysql", "VICTIMA-A")
	b, _, _ := e.create(t, "mysql", "OTRO-USUARIO-B")

	resp := e.login(t, userA, pwA, map[string]string{"_client_name": "libmysql", "_client_version": "8.0.36", "program_name": "mysql"})
	if resp[0] != 0xff || binary.LittleEndian.Uint16(resp[1:3]) != 1045 || !strings.Contains(string(resp), "using password: YES") {
		t.Fatalf("respuesta de error invalida: %q", resp)
	}
	evs := e.waitEvents(t, a.Token.ID, 1)
	if len(evs) != 1 || evs[0].Protocol != "MYSQL" || !strings.Contains(evs[0].Fingerprint, `"password_match":"yes"`) ||
		!strings.Contains(evs[0].Fingerprint, "libmysql") || !strings.HasPrefix(evs[0].UserAgent, "mysql") {
		t.Fatalf("evento del token A incorrecto: %+v", evs)
	}
	if evsB, _, _ := e.evs.ListByToken(context.Background(), b.Token.ID, 10, 0); len(evsB) != 0 {
		t.Fatal("el evento se atribuyo al token de otro usuario")
	}

	// contrasena incorrecta: sigue atribuido, pero se sabe que no uso la credencial plantada
	e.login(t, userA, "guess", nil)
	evs = e.waitEvents(t, a.Token.ID, 2)
	if len(evs) != 2 || !strings.Contains(evs[0].Fingerprint, `"password_match":"no"`) {
		t.Fatalf("password_match=no esperado: %+v", evs)
	}

	// trafico de fondo de internet: NO es una deteccion
	before := core.SnapshotMetrics().MySQLUnattributed
	for _, u := range []string{"root", "admin", "canary_" + a.Token.ID[:12], "svc_short", "svc_" + strings.Repeat("0", 24)} {
		if r := e.login(t, u, "x", nil); r[0] != 0xff {
			t.Fatalf("%s: se esperaba ERR", u)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if total, _ := e.evs.CountAll(context.Background()); total != 2 {
		t.Fatalf("el ruido de fondo genero eventos: total=%d (esperado 2)", total)
	}
	if core.SnapshotMetrics().MySQLUnattributed-before != 5 {
		t.Fatal("las conexiones sin atribuir deben contabilizarse en las metricas")
	}
}

func TestOnlyMySQLAndEnvfileTokensAreAttributable(t *testing.T) {
	e := newEnv(t)
	pdf, userPDF, _ := e.create(t, "pdf", "no-mysql")
	e.login(t, userPDF, "x", nil)
	time.Sleep(100 * time.Millisecond)
	if evs, _, _ := e.evs.ListByToken(context.Background(), pdf.Token.ID, 10, 0); len(evs) != 0 {
		t.Fatal("un token de otro tipo no debe atribuirse")
	}
}

func TestDisabledTokenNotAttributed(t *testing.T) {
	e := newEnv(t)
	a, user, pw := e.create(t, "mysql", "A")
	e.svc.SetActiveByID(context.Background(), a.Token.ID, false)
	e.login(t, user, pw, nil)
	time.Sleep(100 * time.Millisecond)
	if n, _, _ := e.evs.ListByToken(context.Background(), a.Token.ID, 10, 0); len(n) != 0 {
		t.Fatal("un token desactivado no debe registrar eventos")
	}
}

// Regresion DoS: un cliente sin autenticar podia forzar 16 MiB de reserva por conexion, sin limite de conexiones.
func TestOversizedPacketAndConnectionFloodAreContained(t *testing.T) {
	e := newEnv(t)
	e.srv.SetLimits(100, 2) // 2 por IP

	// paquete gigante: la conexion se cierra y el servidor sigue operativo
	c, _ := net.Dial("tcp", e.srv.Addr().String())
	c.SetDeadline(time.Now().Add(2 * time.Second))
	ReadPacket(c)
	c.Write([]byte{0xff, 0xff, 0xff, 0x01})
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("el servidor debia cerrar la conexion")
	}
	c.Close()
	time.Sleep(100 * time.Millisecond)

	// inundacion desde una misma IP: solo 2 conexiones simultaneas reciben saludo
	var conns []net.Conn
	greeted := 0
	for i := 0; i < 6; i++ {
		cc, err := net.Dial("tcp", e.srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, cc)
		cc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		if _, _, err := ReadPacket(cc); err == nil {
			greeted++
		}
	}
	for _, cc := range conns {
		cc.Close()
	}
	if greeted != 2 {
		t.Fatalf("conexiones atendidas=%d, esperado 2 (limite por IP)", greeted)
	}
	time.Sleep(150 * time.Millisecond)
	_, user, pw := e.create(t, "mysql", "ok")
	if r := e.login(t, user, pw, nil); r[0] != 0xff { // tras liberar, vuelve a atender
		t.Fatal("el servidor no se recupero tras la inundacion")
	}
}
