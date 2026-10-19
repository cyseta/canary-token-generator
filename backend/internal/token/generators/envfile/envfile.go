package envfile

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/envfile/recipes"
	"canary-token-generator/backend/internal/token/generators/seed"
)

type Generator struct {
	mysqlHost string
	mysqlPort int
}

// New deriva el host del honeypot MySQL de BASE_URL y usa el puerto 3306.
func New() *Generator { return &Generator{mysqlPort: 3306} }

// NewWithMySQL fija explicitamente el host/puerto publicos del honeypot MySQL.
func NewWithMySQL(host string, port int) *Generator {
	return &Generator{mysqlHost: host, mysqlPort: port}
}

func (g *Generator) Type() string { return "envfile" }

func (g *Generator) host(req token.GenerateRequest) string {
	if g.mysqlHost != "" {
		return g.mysqlHost
	}
	if u, err := url.Parse(req.Base()); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "localhost"
}

func (g *Generator) Generate(ctx context.Context, req token.GenerateRequest) (*token.GenerateResult, error) {
	recipe, _ := req.Options["recipe"].(string)
	if recipe == "" {
		recipe = "aws"
	}
	// Streams independientes por grupo: la receta elegida no altera los valores de las demas.
	endpoint := req.TriggerURL
	group := func(name string) *seed.Stream { return seed.New(req.Seed, "env:"+name) }
	db := func() []string {
		return recipes.DB(seed.MySQLUser(req.TokenID), seed.MySQLPassword(req.Seed, req.TokenID), g.host(req), g.mysqlPort)
	}

	var blocks [][]string
	switch recipe {
	case "aws":
		blocks = append(blocks, recipes.AWS(group("aws"), endpoint))
	case "db", "database":
		blocks = append(blocks, db())
	case "github":
		blocks = append(blocks, recipes.GitHub(group("github"), endpoint))
	case "stripe":
		blocks = append(blocks, recipes.Stripe(group("stripe"), endpoint))
	case "combo":
		blocks = append(blocks, recipes.AWS(group("aws"), endpoint), db())
	case "all":
		blocks = append(blocks, recipes.AWS(group("aws"), endpoint), db(), recipes.GitHub(group("github"), endpoint), recipes.Stripe(group("stripe"), endpoint))
	default:
		return nil, fmt.Errorf("unknown env recipe %q", recipe)
	}

	var sb strings.Builder
	for i, b := range blocks {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(strings.Join(b, "\n"))
		sb.WriteString("\n")
	}
	content := sb.String()
	fileName := fmt.Sprintf(".env.%s", req.TokenID[:8])

	return &token.GenerateResult{
		Artifact:     []byte(content),
		ArtifactName: fileName,
		ContentType:  "text/plain",
		Snippet:      content,
		Instructions: "Plant this file as .env in repositories, backups or servers. IMPORTANT about what it can detect: the secrets are NOT real " +
			"credentials, so an attacker who tries them against AWS/GitHub/Stripe does not touch this server. Detection happens when tooling follows " +
			"the endpoint variables (AWS_ENDPOINT_URL, GITHUB_API_URL, STRIPE_API_BASE) or when someone connects to the database host with the " +
			"planted DB credentials (handled by the MySQL honeypot, which must be reachable on the published port). For real cloud-credential " +
			"detection use provider-native canaries (e.g. an IAM user with no permissions + CloudTrail alerts).",
		Metadata: map[string]any{"filename": fileName, "recipe": recipe},
	}, nil
}
