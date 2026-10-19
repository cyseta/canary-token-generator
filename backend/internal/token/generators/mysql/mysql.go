package mysql

import (
	"context"
	"fmt"
	"net/url"

	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/seed"
)

type Generator struct {
	host string
	port int
}

// New deriva el host de BASE_URL y usa el puerto 3306.
func New() *Generator { return &Generator{port: 3306} }

// NewWithPublic fija el host/puerto con los que los atacantes alcanzaran el honeypot. Antes el puerto
// estaba fijado a 3306 e ignoraba MYSQL_PORT, generando credenciales que nunca podian conectar.
func NewWithPublic(host string, port int) *Generator { return &Generator{host: host, port: port} }

func (g *Generator) Type() string { return "mysql" }

func (g *Generator) Generate(ctx context.Context, req token.GenerateRequest) (*token.GenerateResult, error) {
	host := g.host
	if host == "" {
		host = "localhost"
		if u, err := url.Parse(req.Base()); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
	}
	// El usuario codifica el ID COMPLETO del token y la contrasena se deriva de la semilla guardada:
	// estable entre descargas y verificable por el honeypot.
	username := seed.MySQLUser(req.TokenID)
	password := seed.MySQLPassword(req.Seed, req.TokenID)
	database := "production"

	cnf := fmt.Sprintf("[client]\nhost=%s\nport=%d\nuser=%s\npassword=%s\ndatabase=%s\n", host, g.port, username, password, database)
	cmd := fmt.Sprintf("mysql -h %s -P %d -u %s -p'%s' %s", host, g.port, username, password, database)
	fileName := fmt.Sprintf("my_%s.cnf", req.TokenID[:8])

	return &token.GenerateResult{
		Artifact:     []byte(cnf),
		ArtifactName: fileName,
		ContentType:  "text/plain",
		Snippet:      cmd,
		Instructions: "Place this client config (~/.my.cnf or an app config) where an intruder would look. Any login attempt with these credentials " +
			"is recorded with the source IP, client program and whether the exact planted password was used. The honeypot port must be reachable " +
			"from where the attacker sits (HTTP-only tunnels such as Cloudflare Tunnel do not forward it).",
		Metadata: map[string]any{"host": host, "port": g.port, "username": username, "password": password, "database": database, "filename": fileName},
	}, nil
}
