package webbug

import (
	"context"
	"fmt"
	"html"

	"canary-token-generator/backend/internal/token"
)

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() string { return "webbug" }

// El artefacto es una pagina HTML: una imagen (JPEG) estatica NO puede hacer ninguna peticion, asi que la
// version anterior daba una falsa sensacion de proteccion (nunca disparaba). El disparo ocurre cuando
// un cliente renderiza el HTML con la carga de contenido remoto habilitada.
func (g *Generator) Generate(ctx context.Context, req token.GenerateRequest) (*token.GenerateResult, error) {
	snippet := fmt.Sprintf(`<img src="%s" width="1" height="1" style="display:none;" alt="" />`, html.EscapeString(req.TriggerURL))
	page := fmt.Sprintf("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Internal</title></head>\n<body>\n<p>Internal document.</p>\n%s\n</body></html>\n", snippet)

	return &token.GenerateResult{
		Artifact:     []byte(page),
		ArtifactName: fmt.Sprintf("document_%s.html", req.TokenID[:8]),
		ContentType:  "text/html; charset=utf-8",
		Snippet:      snippet,
		Instructions: "Embed the pixel in HTML emails, web pages or Markdown. It fires when a client renders the content AND loads remote images " +
			"(many mail clients block remote images by default, and proxies such as Gmail's image proxy hide the real IP). " +
			"A static image file cannot trigger anything by itself; use the provided .html page or the snippet.",
		Metadata: map[string]any{
			"html_snippet":     snippet,
			"markdown_snippet": fmt.Sprintf("![](%s)", req.TriggerURL),
			"direct_url":       req.TriggerURL,
		},
	}, nil
}
