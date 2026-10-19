package slowredirect

import (
	"context"
	"fmt"

	"canary-token-generator/backend/internal/token"
)

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() string { return "slowredirect" }

func (g *Generator) Generate(ctx context.Context, req token.GenerateRequest) (*token.GenerateResult, error) {
	base := req.Base()
	redirectLink := fmt.Sprintf("%s/r/%s", base, req.TokenID)
	beacon := fmt.Sprintf("%s/f/%s", base, req.TokenID) // ABSOLUTA: la version anterior usaba una ruta relativa y se rompia al alojar el HTML fuera
	htmlPage := RenderInterstitialHTML(req.TokenID, req.TargetURL, beacon, req.Nonce)

	return &token.GenerateResult{
		Artifact:     []byte(htmlPage),
		ArtifactName: "redirect.html",
		ContentType:  "text/html; charset=utf-8",
		Snippet:      redirectLink,
		Instructions: "Send this link to suspicious recipients or place it in decoy portals. When opened, an interstitial page collects browser " +
			"signals (canvas hash, WebGL renderer, screen, timezone, CPU cores) via a beacon and then redirects to your target URL. " +
			"Fingerprint values are reported by the client and can be forged: treat them as indicators, not proof. " +
			"Be aware that link scanners and preview bots may also open this link.",
		Metadata: map[string]any{"link": redirectLink, "target_url": req.TargetURL},
	}, nil
}
