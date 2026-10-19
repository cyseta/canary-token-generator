package token_test

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/docx"
	"canary-token-generator/backend/internal/token/generators/envfile"
	"canary-token-generator/backend/internal/token/generators/kubeconfig"
	mysqlGen "canary-token-generator/backend/internal/token/generators/mysql"
	"canary-token-generator/backend/internal/token/generators/pdf"
	"canary-token-generator/backend/internal/token/generators/seed"
	"canary-token-generator/backend/internal/token/generators/slowredirect"
	"canary-token-generator/backend/internal/token/generators/webbug"
)

const realID = "c0123456789abcdef01234567" // formato REAL: "c" + 24 hex (los tests antiguos usaban "tok_..." y ocultaban bugs)

func req(extra ...func(*token.GenerateRequest)) token.GenerateRequest {
	r := token.GenerateRequest{TokenID: realID, Label: "Q3 report", TriggerURL: "https://ops.example.com/t/" + realID, BaseURL: "https://ops.example.com", Seed: "00112233445566778899aabbccddeeff"}
	for _, f := range extra {
		f(&r)
	}
	return r
}

func gen(t *testing.T, g token.Generator, r token.GenerateRequest) *token.GenerateResult {
	t.Helper()
	res, err := g.Generate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// ---------------------------------------------------------------- PDF
func TestPDFStructureIsValidForAnyURLLength(t *testing.T) {
	for _, base := range []string{"https://c.io", "https://canary-detection.internal.corp.example-company.com:8443/very/long/prefix/path"} {
		uri := base + "/t/" + realID // el diseno anterior fallaba si superaba 76 bytes (el token quedaba ya persistido)
		b := pdf.BuildPDF(uri)
		s := string(b)
		xrefPos := strings.LastIndex(s, "\nxref\n") + 1 // (un "xref\n" a secas coincide tambien con "startxref\n")
		sx, _ := strconv.Atoi(strings.Fields(s[strings.LastIndex(s, "startxref"):])[1])
		if sx != xrefPos {
			t.Fatalf("startxref=%d, xref real=%d", sx, xrefPos)
		}
		entries := regexp.MustCompile(`(\d{10}) 00000 n `).FindAllStringSubmatch(s[xrefPos:], -1)
		if len(entries) != 4 {
			t.Fatalf("entradas xref=%d", len(entries))
		}
		for i, e := range entries {
			off, _ := strconv.Atoi(e[1])
			if !strings.HasPrefix(s[off:], fmt.Sprintf("%d 0 obj", i+1)) {
				t.Fatalf("offset del objeto %d incorrecto (%d)", i+1, off)
			}
		}
		m := regexp.MustCompile(`/Length (\d+) >>\nstream\n`).FindStringSubmatchIndex(s)
		declared, _ := strconv.Atoi(s[m[2]:m[3]])
		start := m[1]
		if end := strings.Index(s[start:], "\nendstream"); end != declared {
			t.Fatalf("/Length declarado %d, real %d", declared, end)
		}
		if !strings.Contains(s, "/URI ("+uri+")") {
			t.Fatal("falta la URI")
		}
	}
}

func TestPDFPassesQpdfWithoutWarnings(t *testing.T) {
	if _, err := exec.LookPath("qpdf"); err != nil {
		t.Skip("qpdf no disponible")
	}
	f := filepath.Join(t.TempDir(), "x.pdf")
	os.WriteFile(f, pdf.BuildPDF("https://ops.example.com/t/"+realID), 0o600)
	out, err := exec.Command("qpdf", "--check", f).CombinedOutput()
	if err != nil || strings.Contains(string(out), "WARNING") {
		t.Fatalf("qpdf: %v\n%s", err, out)
	}
}

func TestPDFEscapesSpecialCharacters(t *testing.T) {
	s := string(pdf.BuildPDF(`https://x/a)b(c\d`))
	if !strings.Contains(s, `/URI (https://x/a\)b\(c\\d)`) {
		t.Fatal("caracteres especiales sin escapar")
	}
}

// ---------------------------------------------------------------- DOCX
func readZip(t *testing.T, b []byte) ([]string, map[string]string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		c, _ := io.ReadAll(rc)
		rc.Close()
		names = append(names, f.Name)
		files[f.Name] = string(c)
	}
	return names, files
}

func TestDocxDeterministicOrderedWellFormedAndNoTells(t *testing.T) {
	g := docx.New()
	nasty := "Pay <roll> & \"bonus\"\x00\x01 '26"
	r := req(func(r *token.GenerateRequest) { r.Label = nasty })
	a, b := gen(t, g, r).Artifact, gen(t, g, r).Artifact
	if !bytes.Equal(a, b) {
		t.Fatal("el docx debe ser byte a byte identico entre descargas (antes el orden del zip era aleatorio)")
	}
	names, files := readZip(t, a)
	if names[0] != "[Content_Types].xml" {
		t.Fatalf("primer elemento %q", names[0])
	}
	for n, c := range files {
		d := xml.NewDecoder(strings.NewReader(c))
		for {
			if _, err := d.Token(); err != nil {
				if err != io.EOF {
					t.Fatalf("%s no es XML valido: %v", n, err)
				}
				break
			}
		}
		if strings.Contains(strings.ToLower(c), "canary") {
			t.Fatalf("%s contiene la palabra 'canary' (delata el senuelo)", n)
		}
	}
	if !strings.Contains(files["word/_rels/footer1.xml.rels"], "/t/"+realID) {
		t.Fatal("falta la URL de disparo")
	}
}

// ---------------------------------------------------------------- ENVFILE
func TestEnvfileCredentialFormatsAreRealistic(t *testing.T) {
	g := envfile.New()
	res := gen(t, g, req(func(r *token.GenerateRequest) { r.Options = map[string]any{"recipe": "all"} }))
	env := string(res.Artifact)
	if strings.Contains(strings.ToLower(env), "canary") {
		t.Fatal("el .env contiene 'canary'")
	}
	must := map[string]string{
		"aws id":     `(?m)^AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}$`,
		"aws secret": `(?m)^AWS_SECRET_ACCESS_KEY=[A-Za-z0-9+/]{40}$`,
		"aws ep":     `(?m)^AWS_ENDPOINT_URL=https://ops\.example\.com/t/` + realID + `$`,
		"gh":         `(?m)^GITHUB_TOKEN=ghp_[A-Za-z0-9]{36}$`,
		"stripe":     `(?m)^STRIPE_SECRET_KEY=sk_live_[A-Za-z0-9]{32}$`,
		"whsec":      `(?m)^STRIPE_WEBHOOK_SECRET=whsec_[A-Za-z0-9]{32}$`,
		"db user":    `(?m)^DB_USERNAME=svc_0123456789abcdef01234567$`,
		"db host":    `(?m)^DB_HOST=ops\.example\.com$`,
	}
	for k, re := range must {
		if !regexp.MustCompile(re).MatchString(env) {
			t.Errorf("%s: no coincide %s\n%s", k, re, env)
		}
	}
	// checksum de GitHub valido
	tok := regexp.MustCompile(`ghp_([A-Za-z0-9]{36})`).FindStringSubmatch(env)[1]
	sum := crc32.ChecksumIEEE([]byte(tok[:30]))
	var want [6]byte
	for i := 5; i >= 0; i-- {
		want[i] = seed.Base62[sum%62]
		sum /= 62
	}
	if tok[30:] != string(want[:]) {
		t.Fatal("checksum de GitHub invalido")
	}
	// ningun secreto es prefijo de otro (antes whsec_ y webhook secret eran un trozo de la clave principal)
	vals := regexp.MustCompile(`(?m)^[A-Z_]+=(.+)$`).FindAllStringSubmatch(env, -1)
	for i, a := range vals {
		for j, b := range vals {
			if i != j && len(a[1]) >= 12 && strings.Contains(b[1], a[1][len(a[1])-12:]) && a[1] != b[1] && !strings.Contains(a[1], "://") && !strings.Contains(b[1], "://") {
				t.Fatalf("secretos derivados entre si: %q / %q", a[1], b[1])
			}
		}
	}
	// agrupado y estable: cada comentario de grupo precede a su bloque
	if !strings.Contains(env, "# AWS credentials\nAWS_ACCESS_KEY_ID=") {
		t.Fatal("el contenido no esta agrupado")
	}
}

func TestEnvfileDeterministicAndRecipeSelection(t *testing.T) {
	g := envfile.New()
	stripe := func(s string) []byte {
		return gen(t, g, req(func(r *token.GenerateRequest) { r.Seed = s; r.Options = map[string]any{"recipe": "stripe"} })).Artifact
	}
	if !bytes.Equal(stripe("aa"), stripe("aa")) || bytes.Equal(stripe("aa"), stripe("bb")) {
		t.Fatal("determinismo/semilla")
	}
	if !strings.Contains(string(stripe("aa")), "sk_live_") || strings.Contains(string(stripe("aa")), "AKIA") {
		t.Fatal("la receta stripe no se respeta")
	}
	if _, err := g.Generate(context.Background(), req(func(r *token.GenerateRequest) { r.Options = map[string]any{"recipe": "nope"} })); err == nil {
		t.Fatal("receta desconocida debe fallar")
	}
}

// ---------------------------------------------------------------- KUBECONFIG
func TestKubeconfigJWTIsRealisticAndAttributable(t *testing.T) {
	res := gen(t, kubeconfig.New(), req())
	body := string(res.Artifact)
	if !strings.Contains(body, "server: https://ops.example.com/k/"+realID) {
		t.Fatal("endpoint incorrecto")
	}
	jwt := regexp.MustCompile(`token: (\S+)`).FindStringSubmatch(body)[1]
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 || len(parts[2]) < 300 || strings.Contains(jwt, "k8s-admin-signature") {
		t.Fatalf("JWT no realista: %d partes", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload no es base64url: %v", err)
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil || claims["jti"] != realID || claims["iss"] != "kubernetes/serviceaccount" {
		t.Fatalf("claims: %v", claims)
	}
	if strings.Contains(strings.ToLower(body), "canary") && !strings.Contains(body, "ops.example.com") {
		t.Fatal("marca delatora")
	}
}

// ---------------------------------------------------------------- WEBBUG / SLOWREDIRECT
func TestWebbugArtifactActuallyContainsTrigger(t *testing.T) {
	res := gen(t, webbug.New(), req())
	if !strings.Contains(string(res.Artifact), "https://ops.example.com/t/"+realID) || !strings.HasPrefix(res.ContentType, "text/html") {
		t.Fatal("el artefacto debe poder disparar el token (antes era un JPEG estatico que nunca hacia ninguna peticion)")
	}
}

// Regresion XSS: html.EscapeString dentro de un literal JavaScript era el contexto de escape equivocado.
func TestSlowRedirectNeutralisesDangerousTargets(t *testing.T) {
	bad := []string{`javascript:alert(document.domain)`, `data:text/html,<script>alert(1)</script>`, `vbscript:x`, "https://x.test/a\nb", `//evil.test`}
	for _, target := range bad {
		page := slowredirect.RenderInterstitialHTML(realID, target, "https://c.example.com/f/"+realID, "N0NCE")
		if strings.Contains(strings.ToLower(page), "javascript:") || strings.Contains(page, "<script>alert") {
			t.Fatalf("target peligroso %q llego a la pagina", target)
		}
		if !strings.Contains(page, `var target = "https://www.google.com"`) {
			t.Fatalf("target %q debe sustituirse por el seguro", target)
		}
	}
	// una barra invertida final ya no rompe el literal JS (antes: "https://x.test/\" dejaba la cadena sin cerrar)
	bs := slowredirect.RenderInterstitialHTML(realID, "https://x.test/\\", "https://c.example.com/f/"+realID, "")
	if !strings.Contains(bs, `var target = "https://x.test/%5C";`) {
		t.Fatalf("la barra invertida debe quedar codificada: %s", regexp.MustCompile(`var target.*`).FindString(bs))
	}
	// un destino legitimo con comillas/etiquetas queda correctamente escapado para JS
	page := slowredirect.RenderInterstitialHTML(realID, `https://ok.test/a?x="</script><script>alert(1)</script>`, "https://c.example.com/f/"+realID, "")
	if strings.Contains(page, "</script><script>alert(1)") {
		t.Fatal("ruptura de contexto <script>")
	}
	if !strings.Contains(page, `var target = "https://ok.test/a?x=\"\u003c/script\u003e`) {
		t.Fatal("el destino legitimo debe conservarse")
	}
}

func TestSlowRedirectBeaconAbsoluteAndNonce(t *testing.T) {
	res := gen(t, slowredirect.New(), req(func(r *token.GenerateRequest) { r.TargetURL = "https://example.org/"; r.Nonce = "abc123" }))
	page := string(res.Artifact)
	if !strings.Contains(page, `var beacon = "https://ops.example.com/f/`+realID+`"`) {
		t.Fatal("el beacon debe ser absoluto (con ruta relativa el HTML descargado y alojado fuera nunca reportaba)")
	}
	if strings.Count(page, `nonce="abc123"`) != 2 || strings.Contains(strings.ToLower(page), "canaryfp") {
		t.Fatal("nonce CSP / marcas delatoras")
	}
}

// ---------------------------------------------------------------- MYSQL generator
func TestMySQLGeneratorEncodesFullTokenID(t *testing.T) {
	res := gen(t, mysqlGen.NewWithPublic("db.example.com", 13306), req())
	user := res.Metadata["username"].(string)
	id, ok := seed.TokenIDFromMySQLUser(user)
	if !ok || id != realID {
		t.Fatalf("el usuario %q no codifica el ID completo (antes: canary_+12 chars, que nunca coincidia)", user)
	}
	if res.Metadata["port"] != 13306 || res.Metadata["host"] != "db.example.com" || strings.Contains(user, "canary") {
		t.Fatalf("metadata: %v", res.Metadata)
	}
	again := gen(t, mysqlGen.NewWithPublic("db.example.com", 13306), req())
	if again.Metadata["password"] != res.Metadata["password"] {
		t.Fatal("la contrasena debe ser estable entre descargas")
	}
}

// ---------------------------------------------------------------- SERVICE (SQLite real)
type failingGen struct{}

func (failingGen) Type() string { return "failing" }
func (failingGen) Generate(context.Context, token.GenerateRequest) (*token.GenerateResult, error) {
	return nil, errors.New("boom")
}

func newSvc(t *testing.T, opts ...token.Option) (token.Service, token.Repository, *core.DB) {
	t.Helper()
	db, err := core.InitDB(&core.Config{DBDriver: "sqlite", DBDSN: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := token.NewRepository(db)
	svc := token.NewService(repo, opts...)
	for _, g := range []token.Generator{webbug.New(), pdf.New(), docx.New(), envfile.New(), kubeconfig.New(), mysqlGen.New(), slowredirect.New(), failingGen{}} {
		svc.RegisterGenerator(g)
	}
	return svc, repo, db
}

func TestServiceCreateValidation(t *testing.T) {
	svc, _, _ := newSvc(t)
	bad := []token.CreateTokenRequest{
		{Type: "nope"},
		{Type: "slowredirect", TargetURL: "javascript:alert(1)"},
		{Type: "pdf", Label: strings.Repeat("x", 500)},
		{Type: "pdf", NotifyChannel: "sms"},
		{Type: "pdf", NotifyChannel: "webhook", WebhookURL: "http://169.254.169.254/latest/meta-data"},
		{Type: "pdf", NotifyChannel: "webhook", WebhookURL: "https://127.0.0.1/hook"},
		{Type: "pdf", NotifyChannel: "webhook", WebhookURL: ""},
		{Type: "pdf", NotifyChannel: "telegram", TelegramChatID: "abc;drop"},
		{Type: "envfile", Options: map[string]any{"recipe": "../../x"}},
	}
	for i, r := range bad {
		if _, err := svc.CreateToken(context.Background(), r, "https://c.example.com"); !errors.Is(err, core.ErrInvalidInput) {
			t.Errorf("caso %d (%+v): se esperaba ErrInvalidInput, got %v", i, r, err)
		}
	}
	if _, err := svc.CreateToken(context.Background(), token.CreateTokenRequest{Type: "pdf", NotifyChannel: "webhook", WebhookURL: "https://hooks.example.com/x", WebhookSecret: "s"}, "https://c.example.com"); err != nil {
		t.Fatalf("webhook valido debe aceptarse: %v", err)
	}
}

// Regresion: el token se guardaba ANTES de generar el artefacto; si fallaba quedaba un token huerfano y activo.
func TestNoOrphanTokenWhenGenerationFails(t *testing.T) {
	svc, repo, _ := newSvc(t)
	if _, err := svc.CreateToken(context.Background(), token.CreateTokenRequest{Type: "failing"}, "https://c.example.com"); err == nil {
		t.Fatal("debe fallar")
	}
	if n, _ := repo.Count(context.Background()); n != 0 {
		t.Fatalf("quedaron %d tokens huerfanos", n)
	}
}

func TestManageKeyStoredHashedAndSecretsNeverSerialized(t *testing.T) {
	svc, _, db := newSvc(t)
	resp, err := svc.CreateToken(context.Background(), token.CreateTokenRequest{
		Type: "pdf", Label: "L", NotifyChannel: "webhook", WebhookURL: "https://hooks.example.com/services/SECRETPATH", WebhookSecret: "hmac-secret",
	}, "https://c.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	db.QueryRow(`SELECT manage_key FROM tokens WHERE id=?`, resp.Token.ID).Scan(&stored)
	if stored == resp.ManageKey || len(stored) != 64 || stored != token.HashManageKey(resp.ManageKey) {
		t.Fatalf("la clave de gestion debe almacenarse como SHA-256: %q", stored)
	}
	got, err := svc.GetByManageKey(context.Background(), resp.ManageKey)
	if err != nil || got.ID != resp.Token.ID {
		t.Fatalf("lookup por clave en claro: %v", err)
	}
	if _, err := svc.GetByManageKey(context.Background(), stored); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("el HASH almacenado NO debe servir como clave (una fuga de BD no da acceso)")
	}
	j, _ := json.Marshal(got)
	for _, secret := range []string{resp.ManageKey, stored, "hmac-secret", "SECRETPATH", "notify_config", "manage_key", "seed"} {
		if strings.Contains(string(j), secret) {
			t.Fatalf("el JSON del token expone %q: %s", secret, j)
		}
	}
	if !strings.Contains(string(j), `"webhook_host":"hooks.example.com"`) || !strings.Contains(string(j), `"has_webhook_secret":true`) {
		t.Fatalf("falta el resumen seguro: %s", j)
	}
	if !strings.Contains(resp.ManageURL, "/#/manage/"+resp.ManageKey) {
		t.Fatalf("la URL de gestion debe usar fragmento: %s", resp.ManageURL)
	}
}

// Regresion: la descarga ignoraba la receta elegida y producia credenciales distintas en cada descarga.
func TestArtifactDownloadMatchesCreationAndIsStable(t *testing.T) {
	svc, _, _ := newSvc(t)
	resp, err := svc.CreateToken(context.Background(), token.CreateTokenRequest{Type: "envfile", Options: map[string]any{"recipe": "stripe"}}, "https://c.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := svc.GetByManageKey(context.Background(), resp.ManageKey)
	a, _ := svc.GenerateArtifact(context.Background(), tok, "https://c.example.com")
	b, _ := svc.GenerateArtifact(context.Background(), tok, "https://c.example.com")
	if !bytes.Equal(a.Artifact, b.Artifact) {
		t.Fatal("dos descargas deben ser identicas")
	}
	if resp.Snippet != string(a.Artifact) || !strings.Contains(string(a.Artifact), "sk_live_") {
		t.Fatal("la descarga debe coincidir con lo mostrado al crear y respetar la receta")
	}
}

func TestOwnerCanDeleteAndEventsCascade(t *testing.T) {
	svc, _, db := newSvc(t)
	resp, _ := svc.CreateToken(context.Background(), token.CreateTokenRequest{Type: "webbug"}, "https://c.example.com")
	db.Exec(`INSERT INTO events (id, token_id, source_ip) VALUES ('e1', ?, '1.1.1.1')`, resp.Token.ID)
	if err := svc.DeleteByManageKey(context.Background(), resp.ManageKey); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if _, err := svc.GetByManageKey(context.Background(), resp.ManageKey); !errors.Is(err, core.ErrNotFound) || n != 0 {
		t.Fatalf("token/eventos no borrados (eventos=%d)", n)
	}
}

func TestLegacyPlaintextManageKeysAreMigrated(t *testing.T) {
	_, repo, db := newSvc(t)
	legacy := "k" + strings.Repeat("ab", 16)
	if _, err := db.Exec(`INSERT INTO tokens (id,type,label,manage_key) VALUES ('cold','pdf','old',?)`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByManageKey(context.Background(), legacy); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("antes de migrar la clave en claro no coincide con ningun hash")
	}
	n, err := repo.HashLegacyManageKeys(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("migrados=%d err=%v", n, err)
	}
	if tok, err := repo.GetByManageKey(context.Background(), legacy); err != nil || tok.ID != "cold" {
		t.Fatalf("tras migrar la clave original debe seguir funcionando: %v", err)
	}
	if n, _ := repo.HashLegacyManageKeys(context.Background()); n != 0 {
		t.Fatal("la migracion debe ser idempotente")
	}
	var _ sql.NullString
}
